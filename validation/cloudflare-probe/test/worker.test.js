import assert from 'node:assert/strict';
import test from 'node:test';
import { DurableObject } from 'cloudflare:workers';

import {
  RelayProbe,
  handleRequest,
  telegramHostForDc,
} from '../src/index.js';

test('RelayProbe uses the current Cloudflare DurableObject base class', () => {
  assert.equal(RelayProbe.prototype instanceof DurableObject, true);
});

test('worker health endpoint is independent of the Durable Object', async () => {
  const response = await handleRequest(new Request('https://probe.example/healthz'), {});
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: 'telegram-web-proxy-cloudflare-probe',
  });
});

test('worker forwards internal probe routes to one deterministic Durable Object', async () => {
  const calls = [];
  const env = {
    PROBE_TOKEN: 'test-probe-token',
    RELAY_PROBE: {
      getByName(name) {
        assert.equal(name, 'personal-telegram-relay-validation-v1');
        return {
          fetch(request) {
            calls.push(new URL(request.url).pathname);
            return new Response('forwarded', { status: 202 });
          },
        };
      },
      idFromName() {
        assert.fail('legacy idFromName routing must not be used');
      },
    },
  };

  const response = await handleRequest(
    new Request('https://probe.example/probe/sqlite', {
      headers: { Authorization: 'Bearer test-probe-token' },
    }),
    env,
  );
  assert.equal(response.status, 202);
  assert.deepEqual(calls, ['/probe/sqlite']);
});

test('worker rejects unauthenticated probe requests before touching the Durable Object', async () => {
  let touched = false;
  const env = {
    PROBE_TOKEN: 'test-probe-token',
    RELAY_PROBE: {
      idFromName() {
        touched = true;
      },
    },
  };

  const response = await handleRequest(
    new Request('https://probe.example/probe/sqlite'),
    env,
  );
  assert.equal(response.status, 404);
  assert.equal(touched, false);
});

test('Durable Object sqlite probe executes SELECT 1 and returns its boot identity', async () => {
  const statements = [];
  const ctx = {
    storage: {
      sql: {
        exec(statement) {
          statements.push(statement);
          return [{ ok: 1 }];
        },
      },
    },
  };
  const probe = new RelayProbe(ctx, {});
  const response = await probe.fetch(new Request('https://do/probe/sqlite'));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.sqlite, 1);
  assert.equal(typeof body.bootId, 'string');
  assert.deepEqual(statements, ['SELECT 1 AS ok']);
});

test('unknown worker paths return a plain 404 without touching the Durable Object', async () => {
  const response = await handleRequest(new Request('https://probe.example/nope'), {});
  assert.equal(response.status, 404);
  assert.equal(await response.text(), 'Not found');
});

test('Telegram WSS mapping accepts media DC signs but only production DC 1 through 5', () => {
  assert.equal(telegramHostForDc(1), 'pluto.web.telegram.org');
  assert.equal(telegramHostForDc(-2), 'venus.web.telegram.org');
  assert.equal(telegramHostForDc(5), 'flora.web.telegram.org');
  assert.throws(() => telegramHostForDc(0), /dc/i);
  assert.throws(() => telegramHostForDc(6), /dc/i);
});

test('Durable Object outbound probe reports the requested Telegram binary WSS handshake', async () => {
  const calls = [];
  const probe = new RelayProbe(
    { storage: { sql: { exec: () => [{ ok: 1 }] } } },
    {
      __dialTelegram: async (host, options) => {
        calls.push({ host, options });
        return { ok: true, host, protocol: 'binary', elapsedMs: 12 };
      },
    },
  );

  const response = await probe.fetch(
    new Request('https://do/probe/outbound-wss?dc=-2&holdMs=25'),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    host: 'venus.web.telegram.org',
    protocol: 'binary',
    elapsedMs: 12,
  });
  assert.deepEqual(calls, [
    { host: 'venus.web.telegram.org', options: { holdMs: 25, timeoutMs: 10000 } },
  ]);
});

test('Cloudflare probe lets the runtime generate WebSocket handshake headers', async () => {
  const originalFetch = globalThis.fetch;
  let accepted = false;
  let closed = false;
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'https://pluto.web.telegram.org/apiws');
      assert.deepEqual(options.headers, {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': 'binary',
      });
      return {
        status: 101,
        headers: new Headers({ 'Sec-WebSocket-Protocol': 'binary' }),
        webSocket: {
          accept() { accepted = true; },
          close() { closed = true; },
        },
      };
    };
    const probe = new RelayProbe(
      { storage: { sql: { exec: () => [{ ok: 1 }] } } },
      {},
    );
    const response = await probe.fetch(new Request('https://do/probe/outbound-wss?dc=1'));
    assert.equal(response.status, 200);
    assert.equal((await response.json()).ok, true);
    assert.equal(accepted, true);
    assert.equal(closed, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Durable Object dial probe starts up to eight handshakes together and cycles DC hosts', async () => {
  const releases = [];
  const calls = [];
  const probe = new RelayProbe(
    { storage: { sql: { exec: () => [{ ok: 1 }] } } },
    {
      __dialTelegram: (host) => new Promise((resolve) => {
        calls.push(host);
        releases.push(() => resolve({ ok: true, host, protocol: 'binary', elapsedMs: 1 }));
      }),
    },
  );

  const responsePromise = probe.fetch(new Request('https://do/probe/dials?count=8'));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 8);
  assert.deepEqual(calls, [
    'pluto.web.telegram.org',
    'venus.web.telegram.org',
    'aurora.web.telegram.org',
    'vesta.web.telegram.org',
    'flora.web.telegram.org',
    'pluto.web.telegram.org',
    'venus.web.telegram.org',
    'aurora.web.telegram.org',
  ]);
  releases.forEach((release) => release());

  const response = await responsePromise;
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.count, 8);
  assert.equal(body.holdMs, 0);
  assert.equal(body.results.length, 8);
});

test('Durable Object rejects unsafe dial counts without opening a socket', async () => {
  let calls = 0;
  const probe = new RelayProbe(
    { storage: { sql: { exec: () => [{ ok: 1 }] } } },
    { __dialTelegram: async () => { calls += 1; } },
  );

  const response = await probe.fetch(new Request('https://do/probe/dials?count=9'));
  assert.equal(response.status, 400);
  assert.match(await response.text(), /count/i);
  assert.equal(calls, 0);
});

test('Durable Object WebSocket handler echoes text and binary messages unchanged', async () => {
  const sent = [];
  const probe = new RelayProbe(
    { storage: { sql: { exec: () => [{ ok: 1 }] } } },
    {},
  );
  const socket = { send: (message) => sent.push(message) };
  const binary = new Uint8Array([1, 2, 3]).buffer;

  await probe.webSocketMessage(socket, 'echo-text');
  await probe.webSocketMessage(socket, binary);
  assert.equal(sent[0], 'echo-text');
  assert.equal(sent[1], binary);
});

test('lifecycle probe persists its run identity and advances only from its internal heartbeat', async () => {
  const stored = new Map();
  const intervalCallbacks = [];
  const socketListeners = new Map();
  const fakeSocket = {
    addEventListener(type, callback) {
      socketListeners.set(type, callback);
    },
    close() {},
  };
  const probe = new RelayProbe(
    {
      storage: {
        sql: { exec: () => [{ ok: 1 }] },
        get: async (key) => stored.get(key),
        put: async (key, value) => stored.set(key, value),
      },
    },
    {
      __openTelegram: async () => ({
        socket: fakeSocket,
        protocol: 'binary',
        elapsedMs: 9,
      }),
      __setInterval: (callback, milliseconds) => {
        assert.equal(milliseconds, 60000);
        intervalCallbacks.push(callback);
        return 'timer-id';
      },
      __clearInterval: () => {},
    },
  );

  const start = await probe.fetch(
    new Request('https://do/probe/lifecycle/start?dc=1&heartbeatMs=60000'),
  );
  const started = await start.json();
  assert.equal(started.ok, true);
  assert.equal(started.active, true);
  assert.equal(started.host, 'pluto.web.telegram.org');
  assert.equal(started.protocol, 'binary');
  assert.equal(started.heartbeatCount, 0);
  assert.equal(stored.get('lifecycle-run').startBootId, started.bootId);

  intervalCallbacks[0]();
  intervalCallbacks[0]();
  const status = await probe.fetch(new Request('https://do/probe/lifecycle/status'));
  const body = await status.json();
  assert.equal(body.active, true);
  assert.equal(body.lifecycle.heartbeatCount, 2);
  assert.equal(body.persisted.startBootId, started.bootId);
  assert.equal(socketListeners.has('close'), true);
  assert.equal(socketListeners.has('error'), true);
});

test('lifecycle status exposes a persisted prior run when current in-memory state is gone', async () => {
  const persisted = {
    runId: 'prior-run',
    startBootId: 'prior-boot',
    startedAt: '2026-08-25T00:00:00.000Z',
  };
  const probe = new RelayProbe(
    {
      storage: {
        sql: { exec: () => [{ ok: 1 }] },
        get: async () => persisted,
      },
    },
    {},
  );

  const response = await probe.fetch(new Request('https://do/probe/lifecycle/status'));
  const body = await response.json();
  assert.equal(body.active, false);
  assert.equal(body.lifecycle, null);
  assert.deepEqual(body.persisted, persisted);
  assert.notEqual(body.bootId, persisted.startBootId);
});
