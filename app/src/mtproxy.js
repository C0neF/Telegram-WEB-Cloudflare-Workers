/**
 * MTProxy outer obfuscation — client init parsing and direct Telegram init.
 * Implements the 16-byte and dd-prefixed secret handling from
 * telegramdesktop/tdesktop and TelegramMessenger/MTProxy.
 *
 * Security: secrets are only handled as Buffers, never logged.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const TRANSPORT_TAGS = Object.freeze({
  abridged: 0xefefefef,
  intermediate: 0xeeeeeeee,
  'padded-intermediate': 0xdddddddd,
});

const TRANSPORT_BY_TAG = new Map(
  Object.entries(TRANSPORT_TAGS).map(([name, tag]) => [tag, name]),
);

function secretBytes(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  const text = String(value ?? '').trim();
  if (!/^[0-9a-f]+$/i.test(text) || text.length % 2 !== 0) {
    throw new Error('MTProxy secret must be hexadecimal');
  }
  return Buffer.from(text, 'hex');
}

/**
 * Parse proxy secret; supports plain 16-byte and dd-prefixed form.
 * The `dd` prefix selects padded-intermediate; the 16-byte key itself is unwrapped.
 */
export function parseProxySecret(value) {
  const credential = secretBytes(value);
  if (credential.length === 16) {
    return {
      mode: 'abridged',
      credential,
      key: Buffer.from(credential),
    };
  }
  if (credential.length === 17 && credential[0] === 0xdd) {
    return {
      mode: 'padded-intermediate',
      credential,
      key: Buffer.from(credential.subarray(1)),
    };
  }
  throw new Error('MTProxy secret must be 16 bytes or dd plus 16 bytes');
}

function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function reverse(bytes) {
  return Buffer.from(bytes).reverse();
}

/**
 * Validate that a 64-byte init does not collide with known MTProto abuse signatures
 * and transport tags. Mirrors tdesktop's init validation.
 */
function validInitNonce(bytes) {
  const nonce = Buffer.from(bytes);
  if (nonce.length !== 64 || nonce[0] === 0xef) return false;
  const first = nonce.readUInt32LE(0);
  const second = nonce.readUInt32LE(4);
  return !new Set([
    0x44414548, // HEAD
    0x54534f50, // POST
    0x20544547, // GET
    0x4954504f, // OPTI
    0x02010316,
    0xdddddddd,
    0xeeeeeeee,
  ]).has(first) && second !== 0;
}

/**
 * Accumulates fragmented DATA frames until a full 64-byte MTProxy init is available.
 * Preserves exact byte boundaries — never resets CTR state on frame edges.
 */
export class MtproxyInitAccumulator {
  constructor(secret) {
    this.secret = secret;
    this.pending = Buffer.alloc(0);
    this.parsed = null;
  }

  push(chunk) {
    if (this.parsed) throw new Error('MTProxy init is already complete');
    const bytes = Buffer.from(chunk);
    const needed = 64 - this.pending.length;
    const initPart = bytes.subarray(0, needed);
    this.pending = Buffer.concat([this.pending, initPart]);
    if (this.pending.length < 64) {
      return { ready: false, remaining: Buffer.from(bytes.subarray(initPart.length)) };
    }
    this.parsed = parseMtproxyClientInit(this.pending, this.secret);
    return {
      ready: true,
      parsed: this.parsed,
      remaining: Buffer.from(bytes.subarray(initPart.length)),
    };
  }
}

/** Derive the four MTProxy obfuscation keys/IVs from the 56-byte header prefix */
export function deriveProxyKeyMaterial(headerPrefix, secret) {
  const prefix = Buffer.from(headerPrefix);
  if (prefix.length !== 56) throw new RangeError('MTProxy header prefix must be exactly 56 bytes');
  const { key } = parseProxySecret(secret);
  const reversed = reverse(prefix.subarray(8, 56));
  return {
    clientToProxyKey: sha256(prefix.subarray(8, 40), key),
    clientToProxyIv: Buffer.from(prefix.subarray(40, 56)),
    proxyToClientKey: sha256(reversed.subarray(0, 32), key),
    proxyToClientIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

function transportForTag(tag) {
  const transport = TRANSPORT_BY_TAG.get(tag);
  if (!transport) {
    throw new Error(`Unsupported MTProxy transport tag 0x${tag.toString(16)}`);
  }
  return transport;
}

/** Parse and decrypt the 64-byte client MTProxy init into streaming ciphers */
export function parseMtproxyClientInit(transmittedInit, secret) {
  const init = Buffer.from(transmittedInit);
  if (init.length !== 64) throw new RangeError('MTProxy client init must be exactly 64 bytes');

  const material = deriveProxyKeyMaterial(init.subarray(0, 56), secret);
  const clientRx = createDecipheriv('aes-256-ctr', material.clientToProxyKey, material.clientToProxyIv);
  const decryptedInit = clientRx.update(init);
  const transportTag = decryptedInit.readUInt32LE(56);
  const transport = transportForTag(transportTag);
  const dcId = decryptedInit.readInt16LE(60);
  const baseDcId = Math.abs(dcId);
  if (dcId === 0 || baseDcId > 5) throw new Error(`Unsupported Telegram DC id ${dcId}`);

  return {
    transport,
    transportTag,
    dcId,
    baseDcId,
    media: dcId < 0,
    headerPrefix: Buffer.from(init.subarray(0, 56)),
    clientRx,
    clientTx: createCipheriv('aes-256-ctr', material.proxyToClientKey, material.proxyToClientIv),
  };
}

/**
 * Generate a fresh direct Telegram obfuscated init from the parsed client transport.
 * Reuses the client's transport tag; DC field is random (Telegram ignores it for WSS).
 * Returns four independent streaming CTR contexts — callers must not reset them on frame boundaries.
 */
export function createDirectTelegramInit(parsedClient, options = {}) {
  const transportTag = parsedClient?.transportTag;
  transportForTag(transportTag);
  const getRandomBytes = options.randomBytes ?? randomBytes;
  let rawInit;
  for (let attempt = 0; attempt < 128; attempt += 1) {
    rawInit = Buffer.from(getRandomBytes(64));
    if (rawInit.length !== 64) throw new RangeError('Direct Telegram init randomness must be exactly 64 bytes');
    rawInit.writeUInt32LE(transportTag, 56);
    if (validInitNonce(rawInit)) break;
    rawInit = null;
  }
  if (!rawInit) throw new Error('Unable to generate a valid Telegram init nonce');

  const reversed = reverse(rawInit.subarray(8, 56));
  const sendKey = Buffer.from(rawInit.subarray(8, 40));
  const sendIv = Buffer.from(rawInit.subarray(40, 56));
  const receiveKey = Buffer.from(reversed.subarray(0, 32));
  const receiveIv = Buffer.from(reversed.subarray(32, 48));
  const telegramTx = createCipheriv('aes-256-ctr', sendKey, sendIv);
  const encryptedInit = telegramTx.update(rawInit);

  return {
    rawInit,
    transmittedInit: Buffer.concat([rawInit.subarray(0, 56), encryptedInit.subarray(56, 64)]),
    telegramTx,
    telegramRx: createDecipheriv('aes-256-ctr', receiveKey, receiveIv),
  };
}
