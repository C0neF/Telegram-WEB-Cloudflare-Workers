import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import test from 'node:test';

import * as entry from '../src/index.js';
import { DialLimiter, RelayBudget, RelayEngine, openTelegramWss } from '../src/relay.js';
import { deriveProxyKeyMaterial } from '../src/mtproxy.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';

const SECRET = '000102030405060708090a0b0c0d0e0f';
const frame = (type, streamId, payload = Buffer.alloc(0)) => ({ type, streamId, payload });
const turn = () => new Promise(resolve => setImmediate(resolve));
const socket = () => ({ send() {}, close() {}, addEventListener() {} });

function clientInit() {
  const raw = Buffer.from(Array.from({ length: 64 }, (_, i) => i + 1));
  raw.writeUInt32LE(0xefefefef, 56);
  raw.writeInt16LE(2, 60);
  const keys = deriveProxyKeyMaterial(raw.subarray(0, 56), SECRET);
  const encrypted = createCipheriv('aes-256-ctr', keys.clientToProxyKey, keys.clientToProxyIv).update(raw);
  return Buffer.concat([raw.subarray(0, 56), encrypted.subarray(56)]);
}

test('dial queue rejects excess waiting work and removes cancelled entries immediately', async () => {
  const limiter = new DialLimiter(1, 2);
  let release;
  const active = limiter.run(() => new Promise(resolve => { release = resolve; }));
  await turn();
  const abort = new AbortController();
  let cancelledRan = false;
  const cancelled = limiter.run(() => { cancelledRan = true; }, { signal: abort.signal }).catch(() => 'cancelled');
  const waiting = limiter.run(() => 'waiting');
  const overflow = limiter.run(() => 'overflow').catch(() => 'rejected');
  try {
    assert.equal(limiter.queue.length, 2);
    abort.abort();
    assert.equal(limiter.queue.length, 1);
    assert.equal(await cancelled, 'cancelled');
    assert.equal(await overflow, 'rejected');
    assert.equal(cancelledRan, false);
  } finally {
    abort.abort();
    release();
    await Promise.allSettled([active, cancelled, waiting, overflow]);
  }
});

test('closed streams cannot retain a backlog behind a busy dialer', async () => {
  const limiter = new DialLimiter(1);
  let release;
  const active = limiter.run(() => new Promise(resolve => { release = resolve; }));
  await turn();
  const engine = new RelayEngine({ secret: SECRET, dialLimiter: limiter,
    dialTelegram: async () => socket(), sendCarrier() {}, closeCarrier() {} });
  try {
    for (let id = 1; id <= 200; id++) {
      engine.handleFrame(frame(FRAME_TYPES.OPEN, id));
      engine.handleFrame(frame(FRAME_TYPES.DATA, id, clientInit()));
      engine.handleFrame(frame(FRAME_TYPES.CLOSE, id));
    }
    assert.equal(limiter.queue.length, 0);
    await turn();
    assert.equal(engine.tasks.size, 0);
    assert.equal(engine.budget.pendingBytes, 0);
  } finally {
    release();
    await active;
    await engine.whenIdle();
    engine.shutdown();
  }
});

test('closing a stream aborts its in-flight handshake', async () => {
  let signal;
  let release;
  const engine = new RelayEngine({ secret: SECRET, sendCarrier() {}, closeCarrier() {},
    dialTelegram: (_target, options = {}) => {
      signal = options.signal;
      return new Promise(resolve => { release = () => resolve(socket()); });
    } });
  engine.handleFrame(frame(FRAME_TYPES.OPEN, 1));
  engine.handleFrame(frame(FRAME_TYPES.DATA, 1, clientInit()));
  await turn();
  try {
    engine.handleFrame(frame(FRAME_TYPES.CLOSE, 1));
    assert.equal(signal?.aborted, true);
  } finally { release(); await engine.whenIdle(); engine.shutdown(); }
});

for (const operation of ['CLOSE', 'DATA', 'WINDOW']) {
  test(`carrier ${operation} send failure releases streams and every budget`, () => {
    const closes = [];
    const engine = new RelayEngine({ secret: SECRET, dialTelegram: async () => socket(),
      sendCarrier() { throw new Error('closed carrier'); }, closeCarrier: code => closes.push(code) });
    engine.handleFrame(frame(FRAME_TYPES.OPEN, 1));
    const stream = engine.streams.get(1);
    engine.queueUp(stream, Buffer.alloc(8), 8);
    try {
      assert.doesNotThrow(() => {
        if (operation === 'CLOSE') engine.failStream(stream, 'upstream closed');
        else if (operation === 'DATA') engine.enqueueDown(stream, Buffer.alloc(16));
        else { stream.socket = socket(); engine.flushUp(stream); }
      });
      assert.equal(engine.carrierClosed, true);
      assert.equal(engine.streams.size, 0);
      assert.equal(engine.budget.pendingBytes, 0);
      assert.equal(engine.budget.pendingItems, 0);
      assert.equal(engine.budget.outstandingBytes, 0);
      assert.equal(engine.budget.outstandingItems, 0);
      assert.deepEqual(closes, [1011]);
    } finally { engine.shutdown(); }
  });
}

test('failed carrier flush during shared-budget release cannot strand either engine', () => {
  const budget = new RelayBudget({ maxOutstandingBytes: 8 });
  const engines = [false, true].map(fails => new RelayEngine({ secret: SECRET, budget,
    sendCarrier() { if (fails) throw new Error('closed'); }, closeCarrier() {} }));
  budget.onOutstandingAvailable = () => engines.forEach(engine => engine.flushAllDown());
  for (const engine of engines) engine.handleFrame(frame(FRAME_TYPES.OPEN, 1));
  engines[0].enqueueDown(engines[0].streams.get(1), Buffer.alloc(8));
  engines[1].enqueueDown(engines[1].streams.get(1), Buffer.alloc(8));
  try {
    assert.doesNotThrow(() => engines[0].shutdown());
    assert.equal(engines[1].streams.size, 0);
    assert.equal(budget.pendingBytes, 0);
    assert.equal(budget.outstandingBytes, 0);
  } finally { engines.forEach(engine => { try { engine.shutdown(); } catch {} }); }
});

test('used stream IDs remain forbidden after tombstone eviction, without requiring monotonic IDs', () => {
  const engine = new RelayEngine({ secret: SECRET, maxTombstones: 2, sendCarrier() {}, closeCarrier() {} });
  for (const id of [10, 2, 9]) {
    engine.handleFrame(frame(FRAME_TYPES.OPEN, id));
    assert.equal(engine.streams.has(id), true);
    engine.handleFrame(frame(FRAME_TYPES.CLOSE, id));
  }
  assert.equal(engine.tombstones.has(10), false);
  engine.handleFrame(frame(FRAME_TYPES.OPEN, 10));
  assert.equal(engine.carrierClosed, true);
  engine.shutdown();
});

test('carrier decoder rejects text, including strings containing a valid OPEN', () => {
  assert.throws(() => decodeFrames(encodeFrame(FRAME_TYPES.OPEN, 1).toString('utf8')), /binary/i);
});

test('upstream text cannot be converted into bytes and fed to stream ciphers', () => {
  const engine = new RelayEngine({ secret: SECRET, sendCarrier() {}, closeCarrier() {} });
  engine.handleFrame(frame(FRAME_TYPES.OPEN, 1));
  const stream = engine.streams.get(1);
  stream.direct = { telegramRx: { update() { assert.fail('must reject text before crypto'); } } };
  assert.doesNotThrow(() => engine.handleTelegramData(stream, 'not binary'));
  assert.equal(engine.streams.size, 0);
});

test('downstream crypto processes at most a DATA chunk at a time', () => {
  const engine = new RelayEngine({ secret: SECRET, sendCarrier() {}, closeCarrier() {} });
  engine.handleFrame(frame(FRAME_TYPES.OPEN, 1));
  const stream = engine.streams.get(1);
  const lengths = [];
  stream.direct = { telegramRx: { update(bytes) { lengths.push(bytes.length); return bytes; } } };
  stream.parsed = { clientTx: { update: bytes => bytes } };
  engine.handleTelegramData(stream, new Uint8Array(200000).buffer);
  assert.ok(lengths.length > 1);
  assert.ok(lengths.every(length => length <= 65536));
  assert.equal(lengths.reduce((a, b) => a + b, 0), 200000);
  engine.shutdown();
});

test('session rejects a bootstrap expired or revoked while its request body was pending', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    const relay = new entry.RelayDO({}, { PROXY_SECRET: SECRET });
    const token = 'A'.repeat(43);
    relay.issueBootstrap(new Request('https://relay/internal/bootstrap', {
      headers: { 'X-Bootstrap-Token': token } }));
    let source;
    const pending = relay.session(new Request('https://relay/api/v1/session', {
      method: 'POST', duplex: 'half',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
      body: new ReadableStream({ start(controller) { source = controller; } }),
    }));
    now += 121000;
    relay.sweepExpiredBootstraps();
    source.enqueue(encodeFrame(FRAME_TYPES.HELLO, 0, Buffer.of(1)));
    source.close();
    assert.equal((await pending).status, 404);
    assert.equal(relay.sessionSet.size, 0);
  } finally { Date.now = realNow; }
});

test('session body reader cancels a stalled body under a hard deadline', async () => {
  assert.equal(typeof entry.readBodyAtMost, 'function');
  let cancelled = false;
  const request = new Request('https://relay', { method: 'POST', duplex: 'half',
    body: new ReadableStream({ cancel() { cancelled = true; } }) });
  assert.equal(await entry.readBodyAtMost(request, 64, 10), null);
  assert.equal(cancelled, true);
});

test('readiness fails without a runtime secret or reachable relay, while health stays live', async () => {
  const health = await entry.handleRequest(new Request('https://relay.example.com/healthz'), {});
  assert.equal(health.status, 200);
  for (const env of [{}, { PROXY_SECRET: SECRET }, { PROXY_SECRET: 'bad', RELAY: {} }]) {
    const response = await entry.handleRequest(new Request('https://relay.example.com/readyz'), env);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).ok, false);
  }
  const relay = new entry.RelayDO({}, { PROXY_SECRET: SECRET });
  const response = await entry.handleRequest(new Request('https://relay.example.com/readyz'), {
    PROXY_SECRET: SECRET, RELAY: { getByName: () => relay } });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
});

test('outbound handshake propagates caller cancellation to fetch', async () => {
  const abort = new AbortController();
  const pending = openTelegramWss({ host: 'venus.web.telegram.org' }, {
    signal: abort.signal,
    fetchImpl: (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }), timeoutMs: 30,
  });
  const expected = new Error('stream closed');
  abort.abort(expected);
  await assert.rejects(pending, error => error === expected);
});
