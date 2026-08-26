import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  webcrypto,
} from 'node:crypto';
import test from 'node:test';

import { openTelegramWss, RelayEngine } from '../src/relay.js';
import {
  decodeFrames,
  decodeWindow,
  encodeWindow,
  encodeFrame,
  FRAME_TYPES,
} from '../src/protocol.js';
import { buildAbridgedReqPqMulti, parseAbridgedResPq } from '../src/mtproto-probe.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';
const SECRET = Buffer.from(SECRET_HEX, 'hex');
const ABRIDGED_TAG = 0xefefefef;

function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function reverse(bytes) {
  return Buffer.from(bytes).reverse();
}

async function aesCtr(key, iv, bytes) {
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt']);
  return Buffer.from(await webcrypto.subtle.encrypt(
    { name: 'AES-CTR', counter: iv, length: 128 },
    cryptoKey,
    bytes,
  ));
}

function clientKeys(rawInit) {
  const reversed = reverse(rawInit.subarray(8, 56));
  return {
    sendKey: sha256(rawInit.subarray(8, 40), SECRET),
    sendIv: Buffer.from(rawInit.subarray(40, 56)),
    receiveKey: sha256(reversed.subarray(0, 32), SECRET),
    receiveIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

async function clientRequestFixture(plaintext, dcId = 2) {
  const rawInit = Buffer.from(Array.from({ length: 64 }, (_, index) => index + 1));
  rawInit.writeUInt32LE(ABRIDGED_TAG, 56);
  rawInit.writeInt16LE(dcId, 60);
  const keys = clientKeys(rawInit);
  const encrypted = await aesCtr(
    keys.sendKey,
    keys.sendIv,
    Buffer.concat([rawInit, plaintext]),
  );
  return {
    rawInit,
    keys,
    transmitted: Buffer.concat([rawInit.subarray(0, 56), encrypted.subarray(56)]),
  };
}

function rawDirectInit(transmitted) {
  const prefix = Buffer.from(transmitted.subarray(0, 56));
  const key = prefix.subarray(8, 40);
  const iv = prefix.subarray(40, 56);
  const decipher = createDecipheriv('aes-256-ctr', key, iv);
  const decrypted = decipher.update(transmitted.subarray(0, 64));
  return Buffer.concat([prefix, decrypted.subarray(56)]);
}

function directKeys(rawInit) {
  const reversed = reverse(rawInit.subarray(8, 56));
  return {
    sendKey: Buffer.from(rawInit.subarray(8, 40)),
    sendIv: Buffer.from(rawInit.subarray(40, 56)),
    receiveKey: Buffer.from(reversed.subarray(0, 32)),
    receiveIv: Buffer.from(reversed.subarray(32, 48)),
  };
}

class FakeWebSocket {
  constructor() {
    this.sent = [];
    this.listeners = new Map();
    this.closed = null;
    this.readyState = 1;
  }

  send(value) {
    this.sent.push(Buffer.from(value));
  }

  close(code = 1000, reason = '') {
    this.closed = { code, reason };
    this.readyState = 3;
  }

  addEventListener(type, handler) {
    const handlers = this.listeners.get(type) ?? [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }

  emit(type, event = {}) {
    for (const handler of this.listeners.get(type) ?? []) handler(event);
  }
}

test('OPEN plus fragmented MTProxy bytes relays through the correct Telegram WSS with bit-exact translation', async () => {
  const requestPlaintext = Buffer.from('abridged-request-after-init');
  const fixture = await clientRequestFixture(requestPlaintext, -2);
  const upstream = new FakeWebSocket();
  const dials = [];
  const carrier = [];
  const carrierCloses = [];
  const directSeed = Buffer.from(Array.from({ length: 64 }, (_, index) => 0x70 + index));
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    randomBytes: () => directSeed,
    dialTelegram: async (target) => {
      dials.push(target);
      return upstream;
    },
    sendCarrier: (frame) => carrier.push(Buffer.from(frame)),
    closeCarrier: (code, reason) => carrierCloses.push({ code, reason }),
  });

  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 7, payload: Buffer.alloc(0) });
  for (let offset = 0; offset < fixture.transmitted.length; offset += 5) {
    relay.handleFrame({
      type: FRAME_TYPES.DATA,
      streamId: 7,
      payload: fixture.transmitted.subarray(offset, offset + 5),
    });
  }
  await relay.whenIdle();

  assert.deepEqual(dials, [{ dcId: -2, baseDcId: 2, media: true, host: 'venus.web.telegram.org' }]);
  assert.equal(carrierCloses.length, 0);
  assert.ok(upstream.sent.length >= 1);
  const upstreamBytes = Buffer.concat(upstream.sent);
  const directInit = rawDirectInit(upstreamBytes.subarray(0, 64));
  const keys = directKeys(directInit);
  assert.equal(directInit.readUInt32LE(56), ABRIDGED_TAG);
  assert.notEqual(directInit.readInt16LE(60), -2);
  const expectedUpstream = await aesCtr(
    keys.sendKey,
    keys.sendIv,
    Buffer.concat([directInit, requestPlaintext]),
  );
  assert.deepEqual(upstreamBytes.subarray(64), expectedUpstream.subarray(64));

  const sentFrames = carrier.flatMap((batch) => decodeFrames(batch));
  const granted = sentFrames
    .filter((frame) => frame.type === FRAME_TYPES.WINDOW && frame.streamId === 7)
    .reduce((total, frame) => total + decodeWindow(frame.payload), 0);
  assert.equal(granted, fixture.transmitted.length);

  const responsePlaintext = Buffer.from('telegram-response-over-wss');
  const encryptedResponse = await aesCtr(keys.receiveKey, keys.receiveIv, responsePlaintext);
  upstream.emit('message', { data: encryptedResponse.subarray(0, 7) });
  upstream.emit('message', { data: encryptedResponse.subarray(7) });

  const afterResponse = carrier.flatMap((batch) => decodeFrames(batch));
  const responseForClient = Buffer.concat(afterResponse
    .filter((frame) => frame.type === FRAME_TYPES.DATA && frame.streamId === 7)
    .map((frame) => frame.payload));
  const clientRx = createDecipheriv(
    'aes-256-ctr',
    fixture.keys.receiveKey,
    fixture.keys.receiveIv,
  );
  assert.deepEqual(clientRx.update(responseForClient), responsePlaintext);
});

test('downstream DATA stops at stream credit and resumes exactly after WINDOW', async () => {
  const fixture = await clientRequestFixture(Buffer.alloc(0), 1);
  const upstream = new FakeWebSocket();
  const carrier = [];
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    initialWindow: 64,
    maxDataChunk: 16,
    randomBytes: () => Buffer.from(Array.from({ length: 64 }, (_, index) => 0x30 + index)),
    dialTelegram: async () => upstream,
    sendCarrier: (frame) => carrier.push(Buffer.from(frame)),
    closeCarrier: () => assert.fail('carrier should remain open'),
  });
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 1, payload: Buffer.alloc(0) });
  for (let offset = 0; offset < fixture.transmitted.length; offset += 16) {
    relay.handleFrame({
      type: FRAME_TYPES.DATA,
      streamId: 1,
      payload: fixture.transmitted.subarray(offset, offset + 16),
    });
  }
  await relay.whenIdle();

  const directInit = rawDirectInit(Buffer.concat(upstream.sent).subarray(0, 64));
  const keys = directKeys(directInit);
  const responsePlaintext = Buffer.from(Array.from({ length: 80 }, (_, index) => 255 - index));
  upstream.emit('message', {
    data: await aesCtr(keys.receiveKey, keys.receiveIv, responsePlaintext),
  });

  let dataFrames = carrier.flatMap((batch) => decodeFrames(batch))
    .filter((frame) => frame.type === FRAME_TYPES.DATA);
  assert.equal(dataFrames.reduce((total, frame) => total + frame.payload.length, 0), 64);
  assert.equal(dataFrames.length, 4);

  relay.handleFrame({
    type: FRAME_TYPES.WINDOW,
    streamId: 1,
    payload: encodeWindow(16),
  });
  dataFrames = carrier.flatMap((batch) => decodeFrames(batch))
    .filter((frame) => frame.type === FRAME_TYPES.DATA);
  assert.equal(dataFrames.reduce((total, frame) => total + frame.payload.length, 0), 80);
  const clientRx = createDecipheriv('aes-256-ctr', fixture.keys.receiveKey, fixture.keys.receiveIv);
  assert.deepEqual(
    clientRx.update(Buffer.concat(dataFrames.map((frame) => frame.payload))),
    responsePlaintext,
  );
});

test('one Telegram WSS failure closes only its logical stream and tombstones its id', async () => {
  const firstFixture = await clientRequestFixture(Buffer.from('first'), 1);
  const secondFixture = await clientRequestFixture(Buffer.from('second'), 2);
  const sockets = [new FakeWebSocket(), new FakeWebSocket()];
  const carrier = [];
  const carrierCloses = [];
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    randomBytes: () => Buffer.from(Array.from({ length: 64 }, (_, index) => 0x50 + index)),
    dialTelegram: async () => sockets.shift(),
    sendCarrier: (frame) => carrier.push(Buffer.from(frame)),
    closeCarrier: (code, reason) => carrierCloses.push({ code, reason }),
  });
  const first = sockets[0];
  const second = sockets[1];
  for (const [streamId, fixture] of [[11, firstFixture], [12, secondFixture]]) {
    relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId, payload: Buffer.alloc(0) });
    relay.handleFrame({ type: FRAME_TYPES.DATA, streamId, payload: fixture.transmitted });
  }
  await relay.whenIdle();
  first.emit('error');

  const closeFrames = carrier.flatMap((batch) => decodeFrames(batch))
    .filter((frame) => frame.type === FRAME_TYPES.CLOSE);
  assert.deepEqual(closeFrames.map((frame) => frame.streamId), [11]);
  assert.equal(carrierCloses.length, 0);
  assert.equal(second.closed, null);

  relay.handleFrame({ type: FRAME_TYPES.DATA, streamId: 11, payload: Buffer.of(1) });
  assert.equal(carrierCloses.length, 0);
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 11, payload: Buffer.alloc(0) });
  assert.deepEqual(carrierCloses, [{ code: 1002, reason: 'invalid OPEN' }]);
  assert.ok(second.closed);
});

test('stream and global pending bounds fail only the new stream without growing the queue', async () => {
  const fixture = await clientRequestFixture(Buffer.alloc(0), 3);
  let resolveDial;
  const delayedSocket = new FakeWebSocket();
  const dial = new Promise((resolve) => { resolveDial = resolve; });
  const carrier = [];
  const carrierCloses = [];
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    maxStreams: 1,
    maxPendingBytes: 70,
    maxStreamPendingBytes: 70,
    randomBytes: () => Buffer.from(Array.from({ length: 64 }, (_, index) => 0x20 + index)),
    dialTelegram: async () => dial,
    sendCarrier: (frame) => carrier.push(Buffer.from(frame)),
    closeCarrier: (code, reason) => carrierCloses.push({ code, reason }),
  });
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 20, payload: Buffer.alloc(0) });
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 21, payload: Buffer.alloc(0) });
  relay.handleFrame({ type: FRAME_TYPES.DATA, streamId: 20, payload: fixture.transmitted });
  relay.handleFrame({ type: FRAME_TYPES.DATA, streamId: 20, payload: Buffer.alloc(7, 0xaa) });

  const closeFrames = carrier.flatMap((batch) => decodeFrames(batch))
    .filter((frame) => frame.type === FRAME_TYPES.CLOSE);
  assert.deepEqual(closeFrames.map((frame) => frame.streamId), [21, 20]);
  assert.equal(carrierCloses.length, 0);
  assert.equal(relay.pendingBytes, 0);

  resolveDial(delayedSocket);
  await relay.whenIdle();
  assert.ok(delayedSocket.closed);
});

test('malformed direction, oversized DATA, and excess WINDOW close the whole carrier', () => {
  for (const frame of [
    { type: FRAME_TYPES.DATA, streamId: 99, payload: Buffer.of(1) },
    { type: FRAME_TYPES.OPEN, streamId: 0, payload: Buffer.alloc(0) },
  ]) {
    const closes = [];
    const relay = new RelayEngine({
      secret: SECRET_HEX,
      dialTelegram: async () => new FakeWebSocket(),
      sendCarrier: () => {},
      closeCarrier: (code, reason) => closes.push({ code, reason }),
    });
    relay.handleFrame(frame);
    assert.equal(closes[0].code, 1002);
  }

  const closes = [];
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    maxDataChunk: 4,
    dialTelegram: async () => new FakeWebSocket(),
    sendCarrier: () => {},
    closeCarrier: (code, reason) => closes.push({ code, reason }),
  });
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 1, payload: Buffer.alloc(0) });
  relay.handleFrame({ type: FRAME_TYPES.DATA, streamId: 1, payload: Buffer.alloc(5) });
  assert.deepEqual(closes, [{ code: 1002, reason: 'invalid DATA' }]);
});

test('fake Telegram WSS completes req_pq_multi -> resPQ through both obfuscation layers', async () => {
  const requestNonce = Buffer.from('112233445566778899aabbccddeeff00', 'hex');
  const fixture = await clientRequestFixture(Buffer.alloc(0), 1);
  const upstream = new FakeWebSocket();
  const carrier = [];
  const relay = new RelayEngine({
    secret: SECRET_HEX,
    randomBytes: () => Buffer.from(Array.from({ length: 64 }, (_, index) => 0x90 + index)),
    dialTelegram: async () => upstream,
    sendCarrier: (frame) => carrier.push(Buffer.from(frame)),
    closeCarrier: (code, reason) => assert.fail(`${code}:${reason}`),
  });
  relay.handleFrame({ type: FRAME_TYPES.OPEN, streamId: 44, payload: Buffer.alloc(0) });
  const clientRequest = buildAbridgedReqPqMulti(requestNonce, { messageId: 0x0102030405060708n });
  const encryptedClient = await aesCtr(
    fixture.keys.sendKey,
    fixture.keys.sendIv,
    Buffer.concat([fixture.rawInit, clientRequest]),
  );
  const transmitted = Buffer.concat([
    fixture.transmitted,
    encryptedClient.subarray(64),
  ]);
  for (let offset = 0; offset < transmitted.length; offset += 13) {
    relay.handleFrame({
      type: FRAME_TYPES.DATA,
      streamId: 44,
      payload: transmitted.subarray(offset, offset + 13),
    });
  }
  await relay.whenIdle();

  const directInit = rawDirectInit(Buffer.concat(upstream.sent).subarray(0, 64));
  const direct = directKeys(directInit);
  const upstreamRequestCipher = Buffer.concat(upstream.sent).subarray(64);
  const upstreamRequest = (await aesCtr(
    direct.sendKey,
    direct.sendIv,
    Buffer.concat([directInit, upstreamRequestCipher]),
  )).subarray(64);
  // The request parser is intentionally the same bounded transport parser; decode the
  // request envelope here to ensure the relay did not alter the MTProto bytes.
  assert.equal(upstreamRequest[0], 10);
  assert.equal(upstreamRequest.readUInt32LE(21), 0xbe7e8ef1);
  assert.deepEqual(upstreamRequest.subarray(25), requestNonce);

  const responseBody = Buffer.alloc(56);
  responseBody.writeUInt32LE(0x05162463, 0);
  requestNonce.copy(responseBody, 4);
  Buffer.from('ffeeddccbbaa99887766554433221100', 'hex').copy(responseBody, 20);
  responseBody[36] = 3;
  Buffer.from([0x17, 0xed, 0x48]).copy(responseBody, 37);
  responseBody.writeUInt32LE(0x1cb5c415, 40);
  responseBody.writeInt32LE(1, 44);
  responseBody.writeBigInt64LE(0x1020304050607080n, 48);
  const envelope = Buffer.alloc(20 + responseBody.length);
  envelope.writeBigUInt64LE(0n, 0);
  envelope.writeBigUInt64LE(0x1112131415161718n, 8);
  envelope.writeUInt32LE(responseBody.length, 16);
  responseBody.copy(envelope, 20);
  const upstreamResponse = Buffer.concat([
    Buffer.of(envelope.length / 4),
    envelope,
  ]);
  upstream.emit('message', {
    data: await aesCtr(direct.receiveKey, direct.receiveIv, upstreamResponse),
  });

  const clientCiphertext = Buffer.concat(carrier.flatMap((batch) => decodeFrames(batch))
    .filter((frame) => frame.type === FRAME_TYPES.DATA && frame.streamId === 44)
    .map((frame) => frame.payload));
  const clientResponse = await aesCtr(fixture.keys.receiveKey, fixture.keys.receiveIv, clientCiphertext);
  const parsed = parseAbridgedResPq(requestNonce).push(clientResponse);
  assert.equal(parsed.constructor, 0x05162463);
  assert.deepEqual(parsed.nonce, requestNonce);
  assert.deepEqual(parsed.fingerprints, [0x1020304050607080n]);
});

test('outbound WSS dialer opts into ArrayBuffer binary delivery and half-open proxy close semantics', async () => {
  const calls = [];
  const socket = {
    binaryType: 'blob',
    accept(options) { calls.push(options); },
  };
  const opened = await openTelegramWss(
    { host: 'pluto.web.telegram.org' },
    {
      fetchImpl: async (url, options) => {
        assert.equal(url, 'https://pluto.web.telegram.org/apiws');
        assert.equal(options.headers['Sec-WebSocket-Protocol'], 'binary');
        return {
          status: 101,
          headers: new Headers({ 'Sec-WebSocket-Protocol': 'binary' }),
          webSocket: socket,
        };
      },
      timeoutMs: 100,
    },
  );
  assert.equal(opened, socket);
  assert.equal(socket.binaryType, 'arraybuffer');
  assert.deepEqual(calls, [{ allowHalfOpen: true }]);
});
