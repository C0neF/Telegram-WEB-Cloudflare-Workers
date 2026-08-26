import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

import {
  ABRIDGED_TAG,
  deriveMtproxyKeyMaterial,
  parseMtproxyClientInit,
} from '../src/mtproxy.js';

const secret = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');

function deterministicNonce(dcId = -2) {
  const nonce = Buffer.from(Array.from({ length: 64 }, (_, index) => index + 1));
  nonce.writeUInt32LE(ABRIDGED_TAG, 56);
  nonce.writeInt16LE(dcId, 60);
  nonce[62] = 0xaa;
  nonce[63] = 0x55;
  return nonce;
}

async function webCryptoCtr(key, iv, bytes) {
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt']);
  const encrypted = await webcrypto.subtle.encrypt(
    { name: 'AES-CTR', counter: iv, length: 128 },
    cryptoKey,
    bytes,
  );
  return Buffer.from(encrypted);
}

async function makeClientFixture(payload) {
  const nonce = deterministicNonce();
  const keys = deriveMtproxyKeyMaterial(nonce.subarray(0, 56), secret);
  const encrypted = await webCryptoCtr(
    keys.clientToProxyKey,
    keys.clientToProxyIv,
    Buffer.concat([nonce, payload]),
  );
  return {
    nonce,
    keys,
    transmittedInit: Buffer.concat([nonce.subarray(0, 56), encrypted.subarray(56, 64)]),
    encryptedPayload: encrypted.subarray(64),
  };
}

test('16-byte secret derives the MTProxy server read/write keys used by the pinned C implementation', () => {
  const keys = deriveMtproxyKeyMaterial(deterministicNonce().subarray(0, 56), secret);

  assert.equal(
    keys.clientToProxyKey.toString('hex'),
    '817506a548ac9804ccf84bd37ca4f7173d340ff627b734d37345631c5797163f',
  );
  assert.equal(keys.clientToProxyIv.toString('hex'), '292a2b2c2d2e2f303132333435363738');
  assert.equal(
    keys.proxyToClientKey.toString('hex'),
    '0b83f8468ab5e228aad0998bfcaa17190addfd75063e113f4c11c877e47f5a62',
  );
  assert.equal(keys.proxyToClientIv.toString('hex'), '1817161514131211100f0e0d0c0b0a09');
});

test('client init parser detects abridged media DC and preserves RX CTR state across fragments', async () => {
  const plaintext = Buffer.from('abridged-payload-after-the-64-byte-init');
  const fixture = await makeClientFixture(plaintext);
  const parsed = parseMtproxyClientInit(fixture.transmittedInit, secret);

  assert.equal(parsed.transportTag, ABRIDGED_TAG);
  assert.equal(parsed.dcId, -2);
  assert.equal(parsed.baseDcId, 2);
  assert.equal(parsed.media, true);

  const decrypted = [];
  for (const byte of fixture.encryptedPayload) {
    decrypted.push(parsed.clientRx.update(Buffer.of(byte)));
  }
  assert.deepEqual(Buffer.concat(decrypted), plaintext);
});

test('proxy-to-client TX CTR output matches independent WebCrypto for arbitrary fragments', async () => {
  const fixture = await makeClientFixture(Buffer.alloc(0));
  const parsed = parseMtproxyClientInit(fixture.transmittedInit, secret);
  const response = Buffer.from('server-response-split-across-non-block-boundaries');
  const expected = await webCryptoCtr(
    fixture.keys.proxyToClientKey,
    fixture.keys.proxyToClientIv,
    response,
  );

  const sizes = [1, 7, 2, 19, 3, 11, 5];
  const encrypted = [];
  let offset = 0;
  for (const size of sizes) {
    if (offset >= response.length) break;
    encrypted.push(parsed.clientTx.update(response.subarray(offset, offset + size)));
    offset += size;
  }
  if (offset < response.length) {
    encrypted.push(parsed.clientTx.update(response.subarray(offset)));
  }

  assert.deepEqual(Buffer.concat(encrypted), expected);
});

test('client init parser rejects the wrong secret, non-abridged tag, and invalid header size', async () => {
  const fixture = await makeClientFixture(Buffer.alloc(0));
  assert.throws(
    () => parseMtproxyClientInit(fixture.transmittedInit, Buffer.alloc(16, 0xff)),
    /transport tag/i,
  );
  assert.throws(() => parseMtproxyClientInit(fixture.transmittedInit.subarray(0, 63), secret), /64 bytes/i);

  const nonce = deterministicNonce(2);
  nonce.writeUInt32LE(0xdddddddd, 56);
  const keys = deriveMtproxyKeyMaterial(nonce.subarray(0, 56), secret);
  const encrypted = await webCryptoCtr(keys.clientToProxyKey, keys.clientToProxyIv, nonce);
  const transmitted = Buffer.concat([nonce.subarray(0, 56), encrypted.subarray(56)]);
  assert.throws(() => parseMtproxyClientInit(transmitted, secret), /abridged/i);
});
