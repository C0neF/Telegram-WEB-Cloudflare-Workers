import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import test from 'node:test';

import * as mtproxy from '../src/mtproxy.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';
const SECRET = Buffer.from(SECRET_HEX, 'hex');
const TAGS = Object.freeze({
  abridged: 0xefefefef,
  intermediate: 0xeeeeeeee,
  'padded-intermediate': 0xdddddddd,
});

function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function reverse(bytes) {
  return Buffer.from(bytes).reverse();
}

function clientKeys(rawInit, secret = SECRET) {
  const reversed = reverse(rawInit.subarray(8, 56));
  return {
    sendKey: sha256(rawInit.subarray(8, 40), secret),
    sendIv: Buffer.from(rawInit.subarray(40, 56)),
    receiveKey: sha256(reversed.subarray(0, 32), secret),
    receiveIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

async function aesCtr(key, iv, bytes) {
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt']);
  return Buffer.from(await webcrypto.subtle.encrypt(
    { name: 'AES-CTR', counter: iv, length: 128 },
    cryptoKey,
    bytes,
  ));
}

function rawClientInit(transport = 'abridged', dcId = -2) {
  const raw = Buffer.from(Array.from({ length: 64 }, (_, index) => index + 1));
  raw.writeUInt32LE(TAGS[transport], 56);
  raw.writeInt16LE(dcId, 60);
  raw[62] = 0xaa;
  raw[63] = 0x55;
  return raw;
}

function rawDirectKeys(rawInit) {
  const reversed = reverse(rawInit.subarray(8, 56));
  return {
    sendKey: Buffer.from(rawInit.subarray(8, 40)),
    sendIv: Buffer.from(rawInit.subarray(40, 56)),
    receiveKey: Buffer.from(reversed.subarray(0, 32)),
    receiveIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

async function clientFixture({ transport = 'abridged', dcId = -2, secret = SECRET } = {}) {
  const rawInit = rawClientInit(transport, dcId);
  const keys = clientKeys(rawInit, secret);
  const encrypted = await aesCtr(keys.sendKey, keys.sendIv, rawInit);
  return {
    rawInit,
    keys,
    transmittedInit: Buffer.concat([rawInit.subarray(0, 56), encrypted.subarray(56)]),
  };
}

test('proxy secret parser accepts plain and dd-prefixed 16-byte secrets without hashing the mode byte', () => {
  const plain = mtproxy.parseProxySecret(SECRET_HEX);
  assert.equal(plain.mode, 'abridged');
  assert.equal(plain.credential.toString('hex'), SECRET_HEX);
  assert.equal(plain.key.toString('hex'), SECRET_HEX);

  const padded = mtproxy.parseProxySecret(`dd${SECRET_HEX}`);
  assert.equal(padded.mode, 'padded-intermediate');
  assert.equal(padded.credential.toString('hex'), `dd${SECRET_HEX}`);
  assert.equal(padded.key.toString('hex'), SECRET_HEX);

  for (const invalid of ['', '00', 'ee' + SECRET_HEX, SECRET_HEX + '00', 'z'.repeat(32)]) {
    assert.throws(() => mtproxy.parseProxySecret(invalid), /secret/i, invalid);
  }
});

test('client init parser identifies supported transport tags, DC, media sign, and preserves both CTR directions', async () => {
  for (const transport of Object.keys(TAGS)) {
    const fixture = await clientFixture({ transport });
    const parsed = mtproxy.parseMtproxyClientInit(fixture.transmittedInit, SECRET_HEX);

    assert.equal(parsed.transport, transport);
    assert.equal(parsed.transportTag, TAGS[transport]);
    assert.equal(parsed.dcId, -2);
    assert.equal(parsed.baseDcId, 2);
    assert.equal(parsed.media, true);

    const plaintext = Buffer.from(`client-to-relay-${transport}-fragmented`);
    const expectedClientCiphertext = await aesCtr(
      fixture.keys.sendKey,
      fixture.keys.sendIv,
      Buffer.concat([fixture.rawInit, plaintext]),
    );
    const encryptedPayload = expectedClientCiphertext.subarray(64);
    const decrypted = [];
    for (const byte of encryptedPayload) decrypted.push(parsed.clientRx.update(Buffer.of(byte)));
    assert.deepEqual(Buffer.concat(decrypted), plaintext);

    const response = Buffer.from(`relay-to-client-${transport}-fragmented`);
    const expectedResponse = await aesCtr(
      fixture.keys.receiveKey,
      fixture.keys.receiveIv,
      response,
    );
    const actualResponse = [];
    for (let offset = 0; offset < response.length; offset += 3) {
      actualResponse.push(parsed.clientTx.update(response.subarray(offset, offset + 3)));
    }
    assert.deepEqual(Buffer.concat(actualResponse), expectedResponse);
  }
});

test('client init parser rejects invalid length, secret, transport tag, and unsupported DC', async () => {
  const fixture = await clientFixture();
  assert.throws(
    () => mtproxy.parseMtproxyClientInit(fixture.transmittedInit.subarray(0, 63), SECRET_HEX),
    /64 bytes/i,
  );
  assert.throws(
    () => mtproxy.parseMtproxyClientInit(fixture.transmittedInit, 'ff'.repeat(16)),
    /transport/i,
  );

  for (const options of [
    { transport: 'abridged', dcId: 0 },
    { transport: 'abridged', dcId: 6 },
  ]) {
    const invalid = await clientFixture(options);
    assert.throws(
      () => mtproxy.parseMtproxyClientInit(invalid.transmittedInit, SECRET_HEX),
      /DC/i,
    );
  }

  const rawInit = rawClientInit('abridged', 2);
  rawInit.writeUInt32LE(0x12345678, 56);
  const keys = clientKeys(rawInit);
  const encrypted = await aesCtr(keys.sendKey, keys.sendIv, rawInit);
  const transmitted = Buffer.concat([rawInit.subarray(0, 56), encrypted.subarray(56)]);
  assert.throws(
    () => mtproxy.parseMtproxyClientInit(transmitted, SECRET_HEX),
    /transport/i,
  );
});

test('direct Telegram init keeps the transport tag, removes the MTProxy DC field, and exposes independent streaming ciphers', async () => {
  for (const transport of Object.keys(TAGS)) {
    const fixture = await clientFixture({ transport, dcId: -4 });
    const parsed = mtproxy.parseMtproxyClientInit(fixture.transmittedInit, SECRET_HEX);
    const seed = Buffer.from(Array.from({ length: 64 }, (_, index) => 0xa0 + index));
    const direct = mtproxy.createDirectTelegramInit(parsed, { randomBytes: () => seed });

    assert.equal(direct.rawInit.readUInt32LE(56), TAGS[transport]);
    assert.equal(direct.rawInit.readUInt32LE(60), seed.readUInt32LE(60));
    assert.notEqual(direct.rawInit.readInt16LE(60), parsed.dcId);
    assert.deepEqual(direct.transmittedInit.subarray(0, 56), direct.rawInit.subarray(0, 56));

    const directKeys = rawDirectKeys(direct.rawInit);
    const encryptedInit = await aesCtr(directKeys.sendKey, directKeys.sendIv, direct.rawInit);
    assert.deepEqual(direct.transmittedInit.subarray(56), encryptedInit.subarray(56));

    const clientPlaintext = Buffer.from(`client-to-telegram-${transport}`);
    const telegramCiphertext = direct.telegramTx.update(clientPlaintext);
    const expectedTx = await aesCtr(
      directKeys.sendKey,
      directKeys.sendIv,
      Buffer.concat([direct.rawInit, clientPlaintext]),
    );
    assert.deepEqual(telegramCiphertext, expectedTx.subarray(64));

    const telegramPlaintext = Buffer.from(`telegram-to-client-${transport}`);
    const telegramEncrypted = await aesCtr(
      directKeys.receiveKey,
      directKeys.receiveIv,
      telegramPlaintext,
    );
    const decrypted = [];
    for (const byte of telegramEncrypted) {
      decrypted.push(direct.telegramRx.update(Buffer.of(byte)));
    }
    assert.deepEqual(Buffer.concat(decrypted), telegramPlaintext);
  }
});

test('translation preserves all four cipher streams across random non-block-aligned fragmentation', async () => {
  const fixture = await clientFixture({ transport: 'padded-intermediate', dcId: 3 });
  const parsed = mtproxy.parseMtproxyClientInit(fixture.transmittedInit, `dd${SECRET_HEX}`);
  const seed = Buffer.from(Array.from({ length: 64 }, (_, index) => 0x40 + index));
  const direct = mtproxy.createDirectTelegramInit(parsed, { randomBytes: () => seed });
  const directKeys = rawDirectKeys(direct.rawInit);
  const clientPlaintext = Buffer.from(Array.from({ length: 513 }, (_, index) => index & 0xff));

  const clientCiphertext = (await aesCtr(
    fixture.keys.sendKey,
    fixture.keys.sendIv,
    Buffer.concat([fixture.rawInit, clientPlaintext]),
  )).subarray(64);
  const translatedUp = [];
  let offset = 0;
  for (const size of [1, 15, 2, 31, 7, 64, 3, 127, 5, 258]) {
    if (offset >= clientCiphertext.length) break;
    const encrypted = clientCiphertext.subarray(offset, offset + size);
    translatedUp.push(direct.telegramTx.update(parsed.clientRx.update(encrypted)));
    offset += encrypted.length;
  }
  const expectedUp = (await aesCtr(
    directKeys.sendKey,
    directKeys.sendIv,
    Buffer.concat([direct.rawInit, clientPlaintext]),
  )).subarray(64);
  assert.deepEqual(Buffer.concat(translatedUp), expectedUp);

  const telegramPlaintext = Buffer.from(clientPlaintext).reverse();
  const telegramCiphertext = await aesCtr(
    directKeys.receiveKey,
    directKeys.receiveIv,
    telegramPlaintext,
  );
  const translatedDown = [];
  offset = 0;
  for (const size of [9, 1, 33, 2, 87, 4, 128, 6, 244]) {
    if (offset >= telegramCiphertext.length) break;
    const encrypted = telegramCiphertext.subarray(offset, offset + size);
    translatedDown.push(parsed.clientTx.update(direct.telegramRx.update(encrypted)));
    offset += encrypted.length;
  }
  const expectedDown = await aesCtr(
    fixture.keys.receiveKey,
    fixture.keys.receiveIv,
    telegramPlaintext,
  );
  assert.deepEqual(Buffer.concat(translatedDown), expectedDown);
});

test('client init accumulator accepts one-byte fragmentation and returns bytes after the 64-byte init exactly once', async () => {
  const fixture = await clientFixture({ transport: 'abridged', dcId: 5 });
  const tail = Buffer.from('payload-after-init');
  const accumulator = new mtproxy.MtproxyInitAccumulator(SECRET_HEX);
  for (let index = 0; index < 63; index += 1) {
    const result = accumulator.push(fixture.transmittedInit.subarray(index, index + 1));
    assert.equal(result.ready, false);
    assert.equal(result.remaining.length, 0);
  }
  const complete = accumulator.push(Buffer.concat([fixture.transmittedInit.subarray(63), tail]));
  assert.equal(complete.ready, true);
  assert.equal(complete.parsed.baseDcId, 5);
  assert.deepEqual(complete.remaining, tail);
  assert.throws(() => accumulator.push(Buffer.of(1)), /already complete/i);
});
