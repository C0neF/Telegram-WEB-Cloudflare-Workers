import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import test from 'node:test';

import {
  RelayDO,
  FRAME_TYPES,
  encodeFrame,
  handleRequest,
  parseCarrierProtocol,
} from '../src/index.js';
import { deriveProxyKeyMaterial, TRANSPORT_TAGS } from '../src/mtproxy.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';
const HOST = 'canary.example.com';

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
      idFromName(name) {
        assert.equal(name, 'personal-telegram-relay-canary-v1');
        return 'canary-id';
      },
      get(id) {
        assert.equal(id, 'canary-id');
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

test('invalid bridge query stays on the ordinary public response', async () => {
  const { env } = makeRuntime();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=wrong`),
    env,
  );
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Telegram WEB Proxy canary/);
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
  assert.doesNotMatch(body, new RegExp(SECRET_HEX));
});

test('HELLO creates an idempotent WELCOME session and rejects a different body', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const page = await handleRequest(new Request(`https://${HOST}/?bridge=${capability}`), env);
  const match = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(await page.text());
  assert.ok(match);
  const bootstrap = match[1];

  const create = () => handleRequest(new Request('https://canary/api/v1/session', {
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

  const wrong = await handleRequest(new Request('https://canary/api/v1/session', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bootstrap}`,
      'Content-Type': 'application/octet-stream',
    },
    body: encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(2)),
  }), env);
  assert.equal(wrong.status, 404);

  const invalidDelete = await handleRequest(new Request('https://canary/api/v1/session', {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${'B'.repeat(43)}` },
  }), env);
  assert.equal(invalidDelete.status, 404);
});

test('duplicate bridge parameters do not mint a bootstrap', async () => {
  const { env } = makeRuntime();
  const capability = await capabilityFor();
  const response = await handleRequest(
    new Request(`https://${HOST}/?bridge=${capability}&bridge=${capability}`),
    env,
  );
  assert.equal(response.status, 200);
  assert.match(await response.text(), /ordinary public response|Telegram WEB Proxy canary/);
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

test('carrier accepts a PONG only for the server challenge', async () => {
  const sent = [];
  const server = {
    send(value) { sent.push(value); },
    close(code) { this.closed = code; },
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
    const { relay, env } = makeRuntime();
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
    const response = await relay.fetch(new Request('https://do/api/v1/ws', {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    assert.equal(response.status, 101);
    assert.equal(sent.length, 1);
    const challenge = Buffer.from(sent[0]);
    assert.equal(challenge[0], FRAME_TYPES.PING);
    await relay.webSocketMessage(server, encodeFrame(FRAME_TYPES.PONG, 0, challenge.subarray(8)));
    assert.equal(server.closed, undefined);
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
    }, { PROXY_SECRET: SECRET_HEX });
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

test('standard WebSocket message events are forwarded to the relay handler', async () => {
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

    const challenge = server.sent[0].subarray(8);
    const message = listeners.get('message');
    assert.equal(typeof message, 'function');
    message({ data: encodeFrame(FRAME_TYPES.PONG, 0, challenge) });
    assert.equal(relay.sockets.get(server).challenge, null);
    assert.equal(server.closed, undefined);
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
    const challenge = sent[0].subarray(8);
    relay.webSocketMessage(server, encodeFrame(FRAME_TYPES.PONG, 0, challenge));
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
