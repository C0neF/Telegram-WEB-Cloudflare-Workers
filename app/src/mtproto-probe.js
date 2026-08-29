/**
 * Minimal MTProto abridged probe — req_pq_multi → resPQ
 * Used for public data-plane verification without Telegram credentials.
 */
import { randomBytes } from 'node:crypto';

const REQ_PQ_MULTI = 0xbe7e8ef1;
const RES_PQ = 0x05162463;
const VECTOR = 0x1cb5c415;

function validNonce(nonce) {
  const bytes = Buffer.from(nonce);
  if (bytes.length !== 16) throw new RangeError('nonce must be exactly 16 bytes');
  return bytes;
}

function defaultMessageId() {
  const now = BigInt(Date.now());
  const seconds = now / 1000n;
  const fraction = (((now % 1000n) << 32n) / 1000n) & 0xfffffffcn;
  return (seconds << 32n) | (fraction || 4n);
}

export function buildAbridgedReqPqMulti(nonce = randomBytes(16), options = {}) {
  const nonceBytes = validNonce(nonce);
  const messageId = BigInt(options.messageId ?? defaultMessageId());
  const body = Buffer.alloc(20);
  body.writeUInt32LE(REQ_PQ_MULTI, 0);
  nonceBytes.copy(body, 4);

  const envelope = Buffer.alloc(20 + body.length);
  envelope.writeBigUInt64LE(0n, 0);
  envelope.writeBigUInt64LE(messageId, 8);
  envelope.writeUInt32LE(body.length, 16);
  body.copy(envelope, 20);
  const words = envelope.length / 4;
  if (words >= 0x7f) throw new Error('probe packet unexpectedly exceeds short abridged framing');
  return Buffer.concat([Buffer.of(words), envelope]);
}

function readTlBytes(bytes, offset) {
  if (offset >= bytes.length) throw new Error('truncated TL bytes');
  const first = bytes[offset];
  let length;
  let header;
  if (first < 254) {
    length = first;
    header = 1;
  } else {
    if (bytes.length - offset < 4) throw new Error('truncated TL bytes length');
    length = bytes.readUIntLE(offset + 1, 3);
    header = 4;
  }
  const end = offset + header + length;
  if (end > bytes.length) throw new Error('truncated TL bytes payload');
  const paddedEnd = end + ((4 - ((header + length) % 4)) % 4);
  if (paddedEnd > bytes.length) throw new Error('truncated TL bytes padding');
  return { value: Buffer.from(bytes.subarray(offset + header, end)), next: paddedEnd };
}

function parseResPqEnvelope(envelope, expectedNonce) {
  if (envelope.length < 20) throw new Error('truncated unencrypted response');
  if (envelope.readBigUInt64LE(0) !== 0n) throw new Error('resPQ is not unencrypted');
  const bodyLength = envelope.readUInt32LE(16);
  if (bodyLength < 40 || bodyLength % 4 || 20 + bodyLength !== envelope.length) {
    throw new Error('invalid resPQ message length');
  }
  const body = envelope.subarray(20);
  const constructor = body.readUInt32LE(0);
  if (constructor !== RES_PQ) throw new Error('expected resPQ constructor');
  const nonce = Buffer.from(body.subarray(4, 20));
  if (!nonce.equals(expectedNonce)) throw new Error('resPQ nonce mismatch');
  const serverNonce = Buffer.from(body.subarray(20, 36));
  const pq = readTlBytes(body, 36);
  if (body.length - pq.next < 8 || body.readUInt32LE(pq.next) !== VECTOR) {
    throw new Error('invalid resPQ fingerprint vector');
  }
  const count = body.readInt32LE(pq.next + 4);
  if (count < 1 || count > 64 || body.length !== pq.next + 8 + count * 8) {
    throw new Error('invalid resPQ fingerprint count');
  }
  const fingerprints = [];
  for (let index = 0; index < count; index += 1) {
    fingerprints.push(body.readBigInt64LE(pq.next + 8 + index * 8));
  }
  return { constructor, nonce, serverNonce, pq: pq.value, fingerprints };
}

export function parseAbridgedResPq(expectedNonce) {
  const nonce = validNonce(expectedNonce);
  let pending = Buffer.alloc(0);
  return {
    push(chunk) {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      if (!pending.length) return null;
      let headerSize;
      let words;
      if (pending[0] === 0x7f) {
        if (pending.length < 4) return null;
        words = pending.readUIntLE(1, 3);
        if (words < 0x7f) throw new Error('non-canonical abridged length');
        headerSize = 4;
      } else {
        words = pending[0];
        if (!words || words >= 0x7f) throw new Error('invalid abridged length');
        headerSize = 1;
      }
      const packetSize = words * 4;
      if (pending.length < headerSize + packetSize) return null;
      if (pending.length !== headerSize + packetSize) throw new Error('unexpected bytes after resPQ');
      const result = parseResPqEnvelope(
        pending.subarray(headerSize, headerSize + packetSize),
        nonce,
      );
      pending = Buffer.alloc(0);
      return result;
    },
  };
}
