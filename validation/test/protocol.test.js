import assert from 'node:assert/strict';
import test from 'node:test';

import {
  FRAME_TYPES,
  computeBridgeCapability,
  createFrameDecoder,
  encodeFrame,
  normalizeWebProxyHost,
} from '../src/protocol.js';

const frameTypes = {
  OPEN: 0x01,
  DATA: 0x02,
  CLOSE: 0x03,
  WINDOW: 0x04,
  PING: 0x05,
  PONG: 0x06,
  HELLO: 0x10,
  WELCOME: 0x11,
  AUTH_CHALLENGE: 0x12,
  AUTH_RESPONSE: 0x13,
  BYE: 0x1f,
};

test('bridge capability matches the two pinned Telegram Desktop vectors', () => {
  assert.equal(
    computeBridgeCapability(
      'proxy.example.com',
      Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'),
    ),
    'MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk',
  );
  assert.equal(
    computeBridgeCapability(
      'proxy.example.com',
      Buffer.from('dd000102030405060708090a0b0c0d0e0f', 'hex'),
    ),
    'IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA',
  );
});

test('hostname canonicalization matches the pinned Telegram Desktop vectors', () => {
  assert.equal(normalizeWebProxyHost(' Proxy.Example.COM '), 'proxy.example.com');
  assert.equal(normalizeWebProxyHost('bücher.example'), 'xn--bcher-kva.example');
  assert.equal(normalizeWebProxyHost('bücher.de'), 'xn--bcher-kva.de');
  assert.equal(normalizeWebProxyHost('xn--strae-oqa.example'), 'xn--strae-oqa.example');

  for (const invalid of [
    'localhost',
    '127.0.0.1',
    '127.1',
    '0x7f.1',
    '0177.0.0.1',
    '1.2.3',
    'site.example:443',
    'site..example',
  ]) {
    assert.equal(normalizeWebProxyHost(invalid), '', invalid);
  }
});

test('frame constants include every type in Telegram Desktop v7.1.2', () => {
  assert.deepEqual(FRAME_TYPES, frameTypes);
});

test('HELLO and WELCOME encode to their exact pinned wire bytes', () => {
  assert.equal(encodeFrame(FRAME_TYPES.HELLO, 0, Buffer.of(1)).toString('hex'), '100000000000000101');
  assert.equal(encodeFrame(FRAME_TYPES.WELCOME, 0).toString('hex'), '1100000000000000');
});

test('streaming decoder restores frames across every one-byte boundary', () => {
  const encoded = Buffer.concat([
    encodeFrame(FRAME_TYPES.OPEN, 0x010203),
    encodeFrame(FRAME_TYPES.DATA, 0x010203, Buffer.from('fragment-safe')),
    encodeFrame(FRAME_TYPES.AUTH_CHALLENGE, 0, Buffer.from('reserved')),
  ]);
  const decoder = createFrameDecoder();
  const frames = [];

  for (const byte of encoded) {
    frames.push(...decoder.push(Buffer.of(byte)));
  }

  assert.deepEqual(
    frames.map(({ type, streamId, payload }) => ({
      type,
      streamId,
      payload: payload.toString(),
    })),
    [
      { type: FRAME_TYPES.OPEN, streamId: 0x010203, payload: '' },
      { type: FRAME_TYPES.DATA, streamId: 0x010203, payload: 'fragment-safe' },
      { type: FRAME_TYPES.AUTH_CHALLENGE, streamId: 0, payload: 'reserved' },
    ],
  );
  assert.equal(decoder.pendingBytes(), 0);
});

test('decoder rejects unknown types and payloads above one MiB', () => {
  const unknown = Buffer.from('7f00000000000000', 'hex');
  assert.throws(() => createFrameDecoder().push(unknown), /unknown frame type/i);

  const oversized = Buffer.from('0200000100100001', 'hex');
  assert.throws(() => createFrameDecoder().push(oversized), /payload/i);
});

test('encoder rejects invalid stream ids and payloads above one MiB', () => {
  assert.throws(() => encodeFrame(FRAME_TYPES.OPEN, 0x01000000), /stream id/i);
  assert.throws(
    () => encodeFrame(FRAME_TYPES.DATA, 1, Buffer.alloc(1024 * 1024 + 1)),
    /payload/i,
  );
});
