import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

import {
  RelayDO,
  FRAME_TYPES,
  encodeFrame,
  handleRequest,
  parseCarrierProtocol,
} from '../src/index.js';
import { deriveProxyKeyMaterial, TRANSPORT_TAGS } from '../src/mtproxy.js';
import { decodeFrames } from '../src/protocol.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';
const HOST = 'relay.example.com';

function makeStorage() {
  return {
    sql: { exec: () => [{ ok: 1 }] },
  };
}

function makeRuntime(doEnv = {}) {
  const relay = new RelayDO({ storage: makeStorage() }, {
    PROXY_SECRET: SECRET_HEX,
    RELAY_DEBUG: '0',
    USE_HIBERNATION: '1',
    ...doEnv,
  });
  const stub = {
    fetch: (request) => relay.fetch(request),
  };
  const env = {
    PROXY_SECRET: SECRET_HEX,
    RELAY: {
      getByName(name) {
        assert.equal(name, 'personal-telegram-relay-v1');
        return stub;
      },
    },
  };
  return { relay, env };
}

function clientInit(dcId = 2) {
  const raw = Buffer.from(Array.from({ length: 64 }, (_, index) => index + 1));
  raw.writeUInt32LE(TRANSPORT_TAGS.abridged, 56);
  raw.writeInt16LE(dcId, 60);
  const material = deriveProxyKeyMaterial(raw.subarray(0, 56), SECRET_HEX);
  const cipher = createCipheriv(
    'aes-256-ctr',
    material.clientToProxyKey,
    material.clientToProxyIv,
  );
  const encrypted = cipher.update(raw);
  return Buffer.concat([raw.subarray(0, 56), encrypted.subarray(56)]);
}

async function capabilityFor(host = HOST) {
  const { computeCapability } = await import('../src/index.js');
  return computeCapability(host, SECRET_HEX);
}

function hello() {
  return encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(1));
}

async function runBridgeSessionScript(html, fetchImpl, first) {
  const match = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(match, 'bridge script missing');
  const listeners = new Map();
  const posted = [];
  const sockets = [];
  const delays = [];
  const events = [];
  const parent = {};
  class BrowserSocket {
    static OPEN = 1;

    constructor(url, protocol) {
      events.push('websocket-created');
      this.url = url;
      this.protocol = protocol;
      this.readyState = 0;
      sockets.push(this);
      queueMicrotask(() => {
        this.readyState = BrowserSocket.OPEN;
        this.onopen?.();
      });
    }

    send() {}

    close() {
      this.readyState = 3;
    }
  }
  const context = {
    ArrayBuffer,
    URL,
    WebSocket: BrowserSocket,
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    clearTimeout() {},
    fetch: fetchImpl,
    history: { replaceState() {} },
    location: { hash: '', pathname: '/' },
    parent,
    queueMicrotask,
    setTimeout(callback, delay) {
      delays.push(delay);
      queueMicrotask(callback);
      return 1;
    },
  };
  runInNewContext(match[1], context);
  const port = {
    close() {},
    onmessage: null,
    postMessage(value) {
      if (value instanceof ArrayBuffer) events.push('client-frame');
      posted.push(value);
    },
    start() {},
  };
  listeners.get('message')({
    data: { t: 'tproxy-init', v: 1 },
    origin: 'http://127.0.0.1:8765',
    ports: [port],
    source: parent,
  });
  port.onmessage({ data: first });
  for (let attempt = 0; attempt < 10; attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
    if (posted.some((value) => value instanceof ArrayBuffer)) break;
  }
  return { delays, events, posted, sockets };
}

test('invalid bridge query stays on the ordinary public response', async () => {
  const { env } = makeRuntime();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=wrong`),
    env,
  );
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Telegram WEB Proxy/);
});

test('worker routes the personal relay through DurableObjectNamespace.getByName', async () => {
  const { relay, env } = makeRuntime();
  let routedName = '';
  env.RELAY = {
    getByName(name) {
      routedName = name;
      return { fetch: (request) => relay.fetch(request) };
    },
    idFromName() {
      assert.fail('legacy idFromName routing must not be used');
    },
  };
  const capability = await capabilityFor();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=${capability}`),
    env,
  );
  assert.equal(response.status, 200);
  assert.equal(routedName, 'personal-telegram-relay-v1');
});

test('dd-prefixed proxy secret derives a distinct capability and is accepted by the bridge', async () => {
  const { env } = makeRuntime();
  const { computeCapability } = await import('../src/index.js');
  const plain = computeCapability(HOST, SECRET_HEX);
  const padded = computeCapability(HOST, `dd${SECRET_HEX}`);
  assert.notEqual(padded, plain);
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=${padded}`),
    { ...env, PROXY_SECRET: `dd${SECRET_HEX}` },
  );
  assert.equal(response.status, 200);
  assert.match(await response.text(), /tproxy-init/);
});

test('valid capability returns a no-store bridge page with a bootstrap token', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=${capability}`),
    env,
  );
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('content-security-policy'), /script-src 'nonce-/);
  assert.match(body, /bootstrap="[A-Za-z0-9_-]{43}"/);
  assert.match(body, /tproxy-init/);
  assert.match(body, /TelegramWebProxy/);
  assert.match(body, /new WebSocket\(target,'tproxy-v1\.'\+sessionToken\)/);
  assert.match(body, /port\.postMessage\(welcome,\[welcome\]\)/);
  assert.match(body, /MAX_PENDING_BYTES=32\*1024\*1024/);
  assert.match(body, /MAX_PENDING_ITEMS=4096/);
  assert.match(body, /pendingBytes\+data\.byteLength>MAX_PENDING_BYTES/);
  assert.match(body, /socket\.bufferedAmount\+data\.byteLength>MAX_PENDING_BYTES/);
  assert.doesNotMatch(body, new RegExp(SECRET_HEX));
});

test('bridge retries a 503 session creation with the byte-identical HELLO body', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  const html = await page.text();
  const first = Uint8Array.from(hello()).buffer;
  const calls = [];
  const result = await runBridgeSessionScript(html, async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) {
      return new Response(null, { status: 503, headers: { 'Retry-After': '0' } });
    }
    return new Response(encodeFrame(FRAME_TYPES.WELCOME, 0), {
      status: 200,
      headers: {
        'X-Carrier-Mode': 'websocket',
        'X-Session-Token': 'S'.repeat(43),
      },
    });
  }, first);

  assert.equal(calls.length, 2);
  assert.strictEqual(calls[0].options.body, first);
  assert.strictEqual(calls[1].options.body, first);
  assert.equal(result.sockets.length, 1);
  const welcome = result.posted.find((value) => value instanceof ArrayBuffer);
  assert.equal(Buffer.from(welcome).toString('hex'), '1100000000000000');
});

test('bridge retries an ambiguous session network failure with the byte-identical HELLO body', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  const first = Uint8Array.from(hello()).buffer;
  const calls = [];
  const result = await runBridgeSessionScript(await page.text(), async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) throw new TypeError('network interrupted');
    return new Response(encodeFrame(FRAME_TYPES.WELCOME, 0), {
      status: 200,
      headers: {
        'X-Carrier-Mode': 'websocket',
        'X-Session-Token': 'T'.repeat(43),
      },
    });
  }, first);

  assert.equal(calls.length, 2);
  assert.strictEqual(calls[0].options.body, first);
  assert.strictEqual(calls[1].options.body, first);
  const welcome = result.posted.find((value) => value instanceof ArrayBuffer);
  assert.equal(Buffer.from(welcome).toString('hex'), '1100000000000000');
});

test('bridge applies exponential backoff when a 503 omits Retry-After', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  let calls = 0;
  const result = await runBridgeSessionScript(await page.text(), async () => {
    calls += 1;
    if (calls === 1) return new Response(null, { status: 503 });
    return new Response(encodeFrame(FRAME_TYPES.WELCOME, 0), {
      status: 200,
      headers: {
        'X-Carrier-Mode': 'websocket',
        'X-Session-Token': 'U'.repeat(43),
      },
    });
  }, Uint8Array.from(hello()).buffer);

  assert.equal(calls, 2);
  assert.deepEqual(result.delays, [250]);
});

test('bridge delivers WELCOME before it creates the carrier WebSocket', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  const result = await runBridgeSessionScript(await page.text(), async () => (
    new Response(encodeFrame(FRAME_TYPES.WELCOME, 0), {
      status: 200,
      headers: {
        'X-Carrier-Mode': 'websocket',
        'X-Session-Token': 'V'.repeat(43),
      },
    })
  ), Uint8Array.from(hello()).buffer);

  assert.deepEqual(result.events.slice(0, 2), ['client-frame', 'websocket-created']);
});

test('HELLO creates an idempotent WELCOME session and rejects a different body', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  const match = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(await page.text());
  assert.ok(match);
  const bootstrap = match[1];

  const create = () => handleRequest(new Request('https://relay/api/v1/session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bootstrap}`,
      'Content-Type': 'application/octet-stream',
    },
    body: hello(),
  }), env);

  const first = await create();
  const firstBody = new Uint8Array(await first.arrayBuffer());
  const sessionToken = first.headers.get('x-session-token');
  assert.equal(first.status, 200);
  assert.equal(first.headers.get('x-carrier-mode'), 'websocket');
  assert.equal(Buffer.from(firstBody).toString('hex'), '1100000000000000');
  assert.match(sessionToken, /^[A-Za-z0-9_-]{43}$/);

  const retry = await create();
  assert.equal(retry.status, 200);
  assert.equal(retry.headers.get('x-session-token'), sessionToken);
  assert.equal(
    Buffer.from(await retry.arrayBuffer()).toString('hex'),
    '1100000000000000',
  );

  const wrong = await handleRequest(new Request('https://relay/api/v1/session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bootstrap}`,
      'Content-Type': 'application/octet-stream',
    },
    body: encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(2)),
  }), env);
  assert.equal(wrong.status, 404);

  const invalidDelete = await handleRequest(new Request('https://relay/api/v1/session', {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${'B'.repeat(43)}` },
  }), env);
  assert.equal(invalidDelete.status, 404);
});

test('expired bootstrap tokens are removed when they are rejected', async () => {
  const { relay } = makeRuntime();
  const bootstrap = 'D'.repeat(43);
  const originalNow = Date.now;
  try {
    Date.now = () => 1_000;
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    assert.equal(relay.bootstraps.size, 1);

    Date.now = () => 121_001;
    const response = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));

    assert.equal(response.status, 404);
    assert.equal(relay.bootstraps.size, 0);
  } finally {
    Date.now = originalNow;
  }
});

test('bootstrap and unattached session registries are capacity bounded', async () => {
  const relay = new RelayDO({ storage: makeStorage() }, { PROXY_SECRET: SECRET_HEX });
  const tokens = Array.from({ length: 65 }, (_, index) => Buffer.alloc(32, index).toString('base64url'));
  for (const token of tokens.slice(0, 64)) {
    const response = relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': token },
    }));
    assert.equal(response.status, 204);
  }
  const overflow = relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
    method: 'POST',
    headers: { 'X-Bootstrap-Token': tokens[64] },
  }));
  assert.equal(overflow.status, 503);
  assert.equal(relay.bootstraps.size, 64);

  for (const token of tokens.slice(0, 8)) {
    const response = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    assert.equal(response.status, 200);
  }
  const sessionOverflow = await relay.session(new Request('https://do/api/v1/session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${tokens[8]}`,
      'Content-Type': 'application/octet-stream',
    },
    body: hello(),
  }));
  assert.equal(sessionOverflow.status, 503);
  assert.equal(new Set(relay.sessions.values()).size, 8);
});

test('unattached sessions expire after the 120-second attach window', async () => {
  const relay = new RelayDO({ storage: makeStorage() }, { PROXY_SECRET: SECRET_HEX });
  const bootstrap = 'G'.repeat(43);
  const originalNow = Date.now;
  try {
    Date.now = () => 1_000;
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');

    Date.now = () => 121_001;
    const response = relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));

    assert.equal(response.status, 404);
    assert.equal(relay.sessions.size, 0);
    assert.equal(relay.bootstraps.size, 0);
  } finally {
    Date.now = originalNow;
  }
});

test('duplicate bridge parameters do not mint a bootstrap', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=${capability}&bridge=${capability}`),
    env,
  );
  assert.equal(response.status, 200);
  assert.match(await response.text(), /ordinary public response|Telegram WEB Proxy/);
});

test('invalid API routes and request shapes are rejected before touching the Durable Object', async () => {
  let doCalls = 0;
  const env = {
    RELAY: {
      idFromName() { doCalls += 1; return 'id'; },
      get() { throw new Error('invalid request must not reach Durable Object'); },
    },
  };
  const requests = [
    new Request('https://relay.example.com/api/v1/unknown'),
    new Request('https://relay.example.com/api/v1/session', { method: 'POST' }),
    new Request('https://relay.example.com/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${'A'.repeat(43)}`,
        'Content-Type': 'application/octet-stream',
        'Content-Length': '65',
      },
      body: Buffer.alloc(65),
    }),
    new Request('https://relay.example.com/api/v1/ws', {
      headers: { Upgrade: 'websocket' },
    }),
  ];

  for (const request of requests) {
    const response = await handleRequest(request, env);
    assert.equal(response.status, 404);
  }
  assert.equal(doCalls, 0);
});

test('session creation cancels a streaming body as soon as it exceeds 64 bytes', async () => {
  const relay = new RelayDO({ storage: makeStorage() }, { PROXY_SECRET: SECRET_HEX });
  const bootstrap = 'H'.repeat(43);
  relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
    method: 'POST',
    headers: { 'X-Bootstrap-Token': bootstrap },
  }));
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) controller.enqueue(Buffer.alloc(65));
      else controller.close();
    },
    cancel() { cancelled = true; },
  });
  const response = await relay.session(new Request('https://do/api/v1/session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bootstrap}`,
      'Content-Type': 'application/octet-stream',
    },
    body,
    duplex: 'half',
  }));

  assert.equal(response.status, 404);
  assert.equal(pulls, 1);
  assert.equal(cancelled, true);
});

test('carrier protocol parsing accepts only the exact websocket v1 bearer', () => {
  const token = 'A'.repeat(43);
  assert.deepEqual(parseCarrierProtocol(`tproxy-v1.${token}`), { token });
  for (const value of [
    '',
    'tproxy-v1.',
    'tproxy-v1.ABC.extra',
    `tproxy-lane-v1.${token}.1`,
  ]) {
    assert.equal(parseCarrierProtocol(value), null, value);
  }
});

test('carrier attach emits no application frame or heartbeat timer', async () => {
  const sent = [];
  const timers = [];
  const server = {
    send(value) { sent.push(value); },
    close() {},
    accept() {},
    addEventListener() {},
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const relay = new RelayDO({ storage: makeStorage() }, {
      PROXY_SECRET: SECRET_HEX,
      __setTimeout(handler, delay) {
        timers.push({ handler, delay });
        return timers.length;
      },
    });
    const bootstrap = 'W'.repeat(43);
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${created.headers.get('x-session-token')}`,
      },
    }));

    assert.equal(sent.length, 0);
    assert.equal(timers.length, 0);
  } finally {
    globalThis.WebSocketPair = previous;
  }
});

test('carrier standard WebSocket path keeps session state in memory for active upstream ciphers', async () => {
  const accepted = [];
  const listeners = new Map();
  const server = {
    send() {},
    close() {},
    accept(options) { accepted.push(options); },
    addEventListener(type, handler) {
      listeners.set(type, handler);
    },
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const relay = new RelayDO({
      storage: makeStorage(),
      acceptWebSocket() { assert.fail('hibernation must not be used for active ciphers'); },
    }, { PROXY_SECRET: SECRET_HEX, USE_HIBERNATION: '1' });
    const bootstrap = 'A'.repeat(43);
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');
    const response = relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    assert.equal(response.status, 101);
    assert.deepEqual(accepted, [{ allowHalfOpen: true }]);
  } finally {
    globalThis.WebSocketPair = previous;
  }
});

test('carrier loss destroys the session token and all registry entries', async () => {
  const server = {
    send() {},
    close() {},
    accept() {},
    addEventListener() {},
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const relay = new RelayDO({ storage: makeStorage() }, { PROXY_SECRET: SECRET_HEX });
    const bootstrap = 'E'.repeat(43);
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');
    relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    assert.equal(relay.sessions.size, 2);

    relay.webSocketClose(server);

    assert.equal(relay.sessions.size, 0);
    assert.equal(relay.sockets.size, 0);
    const retry = relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    assert.equal(retry.status, 404);
  } finally {
    globalThis.WebSocketPair = previous;
  }
});

test('standard WebSocket message events reject unsupported zero-stream control frames', async () => {
  const listeners = new Map();
  const server = {
    sent: [],
    send(value) { this.sent.push(Buffer.from(value)); },
    close(code, reason) { this.closed = { code, reason }; },
    accept() {},
    addEventListener(type, handler) {
      listeners.set(type, handler);
    },
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const relay = new RelayDO({ storage: makeStorage() }, { PROXY_SECRET: SECRET_HEX });
    const bootstrap = 'B'.repeat(43);
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');
    relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));

    const message = listeners.get('message');
    assert.equal(typeof message, 'function');
    message({ data: encodeFrame(FRAME_TYPES.PONG, 0) });
    assert.deepEqual(server.closed, { code: 1002, reason: 'unsupported frame' });
  } finally {
    globalThis.WebSocketPair = previous;
  }
});

test('standard WebSocket message events register outbound dial work with waitUntil', async () => {
  const listeners = new Map();
  const waitUntilPromises = [];
  const upstream = {
    sent: [],
    send(value) { this.sent.push(Buffer.from(value)); },
    close() {},
    addEventListener() {},
  };
  const server = {
    sent: [],
    send(value) { this.sent.push(Buffer.from(value)); },
    close() {},
    accept() {},
    addEventListener(type, handler) { listeners.set(type, handler); },
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const relay = new RelayDO({
      storage: makeStorage(),
      waitUntil(promise) { waitUntilPromises.push(promise); },
    }, {
      PROXY_SECRET: SECRET_HEX,
      __randomBytes: (size) => Buffer.alloc(size, 0x61),
      __dialTelegram: async () => upstream,
    });
    const bootstrap = 'C'.repeat(43);
    relay.issueBootstrap(new Request('https://do/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    const created = await relay.session(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');
    relay.attachWebSocket(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));

    const message = listeners.get('message');
    message({
      data: Buffer.concat([
        encodeFrame(FRAME_TYPES.OPEN, 3),
        encodeFrame(FRAME_TYPES.DATA, 3, clientInit(-2)),
      ]),
    });

    assert.equal(waitUntilPromises.length, 1);
    await waitUntilPromises[0];
    assert.equal(upstream.sent.reduce((sum, value) => sum + value.length, 0), 64);
  } finally {
    globalThis.WebSocketPair = previous;
  }
});

test('carrier forwards OPEN and MTProxy DATA into an injected Telegram WSS dialer', async () => {
  const upstream = {
    sent: [],
    listeners: new Map(),
    send(value) { this.sent.push(Buffer.from(value)); },
    close(code, reason) { this.closed = { code, reason }; },
    addEventListener(type, handler) { this.listeners.set(type, handler); },
  };
  const dials = [];
  const sent = [];
  const server = {
    send(value) { sent.push(Buffer.from(value)); },
    close(code, reason) { this.closed = { code, reason }; },
  };
  const client = {};
  const previous = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = client;
      this[1] = server;
    }
  };
  try {
    const { relay, env } = makeRuntime({
      __randomBytes: (size) => Buffer.from(Array.from({ length: size }, (_, index) => 0x60 + index)),
      __dialTelegram: async (target) => {
        dials.push(target);
        return upstream;
      },
    });
    const capability = await capabilityFor();
    const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
    const bootstrap = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(await page.text())[1];
    const created = await relay.fetch(new Request('https://do/api/v1/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: hello(),
    }));
    const token = created.headers.get('x-session-token');
    await relay.fetch(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    relay.webSocketMessage(server, encodeFrame(FRAME_TYPES.OPEN, 3));
    relay.webSocketMessage(server, encodeFrame(FRAME_TYPES.DATA, 3, clientInit(-2)));
    await relay.sockets.get(server).engine.whenIdle();

    assert.deepEqual(dials, [{
      dcId: -2,
      baseDcId: 2,
      media: true,
      host: 'venus.web.telegram.org',
    }]);
    assert.equal(upstream.sent.reduce((sum, value) => sum + value.length, 0), 64);
    assert.equal(server.closed, undefined);
    assert.ok(sent.some((batch) => batch[0] === FRAME_TYPES.WINDOW));
  } finally {
    globalThis.WebSocketPair = previous;
  }
});
