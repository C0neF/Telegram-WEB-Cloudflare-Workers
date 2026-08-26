import { createCipheriv, createDecipheriv, createHash } from 'node:crypto';

export const ABRIDGED_TAG = 0xefefefef;

function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest();
}

function reverse(bytes) {
  return Buffer.from(bytes).reverse();
}

export function deriveMtproxyKeyMaterial(headerPrefix, secret) {
  const prefix = Buffer.from(headerPrefix);
  const secretBytes = Buffer.from(secret);
  if (prefix.length !== 56) {
    throw new RangeError('MTProxy header prefix must be exactly 56 bytes');
  }
  if (secretBytes.length !== 16) {
    throw new RangeError('This validation slice requires a 16-byte secret');
  }

  const reversed = reverse(prefix.subarray(8, 56));
  return {
    clientToProxyKey: sha256(prefix.subarray(8, 40), secretBytes),
    clientToProxyIv: Buffer.from(prefix.subarray(40, 56)),
    proxyToClientKey: sha256(reversed.subarray(0, 32), secretBytes),
    proxyToClientIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

export function parseMtproxyClientInit(transmittedInit, secret) {
  const init = Buffer.from(transmittedInit);
  if (init.length !== 64) {
    throw new RangeError('MTProxy client init must be exactly 64 bytes');
  }

  const keys = deriveMtproxyKeyMaterial(init.subarray(0, 56), secret);
  const clientRx = createDecipheriv(
    'aes-256-ctr',
    keys.clientToProxyKey,
    keys.clientToProxyIv,
  );
  const decryptedInit = clientRx.update(init);
  const transportTag = decryptedInit.readUInt32LE(56);
  if (transportTag !== ABRIDGED_TAG) {
    throw new Error(
      `Expected abridged transport tag 0x${ABRIDGED_TAG.toString(16)}, got 0x${transportTag.toString(16)}`,
    );
  }

  const dcId = decryptedInit.readInt16LE(60);
  if (dcId === 0) {
    throw new Error('MTProxy client init contains invalid DC id 0');
  }

  return {
    transportTag,
    dcId,
    baseDcId: Math.abs(dcId),
    media: dcId < 0,
    clientRx,
    clientTx: createCipheriv(
      'aes-256-ctr',
      keys.proxyToClientKey,
      keys.proxyToClientIv,
    ),
  };
}
