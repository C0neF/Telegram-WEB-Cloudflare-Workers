/**
 * Telegram WEB Proxy — Cloudflare Worker entry + Relay Durable Object
 *
 * Compatible with telegramdesktop/tproxy-server@52a5feb7 and
 * Telegram Desktop v7.1.2 WEB Proxy v1 (websocket carrier).
 *
 * - Validates bridge capability (HMAC) and mints bootstrap tokens
 * - Terminates MTProxy outer obfuscation and relays to Telegram official WSS
 * - Enforces bounded flow control and constant-time secret comparison
 */
import { createHash, randomBytes } from 'node:crypto';
import { DurableObject } from 'cloudflare:workers';

import { matchesBridgeCapability } from './capability.js';
import { parseProxySecret } from './mtproxy.js';
import { bridgePage } from './bridge.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from './protocol.js';
import {
  DialLimiter,
  openTelegramWss,
  RelayBudget,
  RelayEngine,
} from './relay.js';

export { encodeFrame, FRAME_TYPES } from './protocol.js';
export { computeCapability, normalizeWebProxyHost } from './capability.js';

/** Bootstrap token TTL — single-use, 120s */
const BOOTSTRAP_TTL_MS = 120_000;
/** Unattached session must bind its carrier promptly. */
const SESSION_ATTACH_TTL_MS = BOOTSTRAP_TTL_MS;
const MAX_BOOTSTRAPS = 64;
const MAX_SESSIONS = 8;
/** Singleton DO name for the personal relay */
const PROXY_OBJECT_NAME = 'personal-telegram-relay-v1';

function json(value, init = {}) {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify(value), { ...init, headers });
}

function notFound() {
  return new Response('Not found', {
    status: 404,
    headers: { 'cache-control': 'no-store' },
  });
}

function busy() {
  return new Response('Service unavailable', {
    status: 503,
    headers: { 'cache-control': 'no-store', 'retry-after': '1' },
  });
}

function validApiRequest(request, url) {
  if (url.search) return false;
  if (url.pathname === '/api/v1/session') {
    if (request.headers.has('Cookie') || !bearer(request.headers.get('Authorization'))) return false;
    if (request.method === 'DELETE') return true;
    if (request.method !== 'POST'
      || request.headers.get('Content-Type') !== 'application/octet-stream') return false;
    const length = request.headers.get('Content-Length');
    return length === null || (/^\d+$/.test(length) && Number(length) <= 64);
  }
  if (url.pathname === '/api/v1/ws') {
    return request.method === 'GET'
      && request.headers.get('Upgrade')?.toLowerCase() === 'websocket'
      && parseCarrierProtocol(request.headers.get('Sec-WebSocket-Protocol') || '') !== null;
  }
  return false;
}

export async function readBodyAtMost(request, maxBytes, timeoutMs = 10_000) {
  const length = request.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    void request.body?.cancel('body too large').catch(() => {});
    return null;
  }
  if (!request.body) return Buffer.alloc(0);
  const reader = request.body.getReader();
  let timer;
  const read = async () => {
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) return Buffer.concat(chunks, total);
        if (total + value.byteLength > maxBytes) {
          void reader.cancel('body too large').catch(() => {});
          return null;
        }
        const bytes = Buffer.from(value);
        total += bytes.length;
        chunks.push(bytes);
      }
    } catch { return null; }
  };
  try {
    return await Promise.race([read(), new Promise(resolve => {
      timer = setTimeout(() => {
        resolve(null);
        void reader.cancel('body deadline exceeded').catch(() => {});
      }, timeoutMs);
    })]);
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }
}

function hasRuntimeSecret(env) {
  try { parseProxySecret(env.PROXY_SECRET); return true; } catch { return false; }
}

function randomToken() {
  return randomBytes(32).toString('base64url');
}

function tokenHash(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function parseCarrierProtocol(protocol) {
  if (typeof protocol !== 'string' || !protocol.startsWith('tproxy-v1.')) return null;
  const token = protocol.slice('tproxy-v1.'.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return { token };
}

function validRootCapability(request, env) {
  const url = new URL(request.url);
  if (url.pathname !== '/' || request.method !== 'GET') return false;
  const entries = [...url.searchParams.entries()];
  if (entries.length !== 1 || entries[0][0] !== 'bridge') return false;
  const value = entries[0][1];
  return matchesBridgeCapability(value, url.hostname, env.PROXY_SECRET);
}

export async function handleRequest(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/healthz' && request.method === 'GET') {
    return json({ ok: true, service: 'telegram-web-proxy' });
  }
  if (url.pathname === '/readyz' && request.method === 'GET') {
    let ok = false;
    if (hasRuntimeSecret(env) && typeof env.RELAY?.getByName === 'function') {
      try {
        const response = await env.RELAY.getByName(PROXY_OBJECT_NAME).fetch(new Request('https://relay/internal/readyz'));
        ok = response.ok;
        void response.body?.cancel().catch(() => {});
      } catch {}
    }
    return json({ ok, service: 'telegram-web-proxy' }, { status: ok ? 200 : 503 });
  }
  if (validRootCapability(request, env)) {
    const bootstrap = randomToken();
    const relay = env.RELAY.getByName(PROXY_OBJECT_NAME);
    const response = await relay.fetch(new Request('https://relay/internal/bootstrap', {
      method: 'POST',
      headers: { 'X-Bootstrap-Token': bootstrap },
    }));
    if (!response.ok) return notFound();
    const nonce = randomBytes(18).toString('base64url');
    const page = bridgePage(url.hostname, bootstrap, nonce);
    return new Response(page.body, {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': page.csp,
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
        'x-dns-prefetch-control': 'off',
      },
    });
  }
  if (url.pathname === '/' && request.method === 'GET') {
    return new Response('<!doctype html><title>Telegram WEB Proxy</title><p>Telegram WEB Proxy</p>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }
  if (!validApiRequest(request, url)) return notFound();
  return env.RELAY.getByName(PROXY_OBJECT_NAME).fetch(request);
}

export default { fetch: handleRequest };

export class RelayDO extends DurableObject {
  constructor(ctx, env = {}) {
    super(ctx, env);
    // A live Telegram upstream carries non-persistable AES-CTR state. Keep the
    // carrier on the standard in-memory WebSocket API; on eviction/restart the
    // socket closes and Telegram rebuilds the stream instead of reusing cipher
    // state in a new object instance.
    this.bootId = randomBytes(16).toString('hex');
    this.bootstraps = new Map();
    this.sessions = new Map();
    this.sessionSet = new Set();
    this.sockets = new Map();
    this.relayBudget = new RelayBudget({
      onOutstandingAvailable: () => this.flushRelayDown(),
    });
    this.dialLimiter = new DialLimiter();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/internal/readyz') {
      const ok = hasRuntimeSecret(this.env);
      return json({ ok }, { status: ok ? 200 : 503 });
    }
    if (url.pathname === '/internal/bootstrap') return this.issueBootstrap(request);
    if (url.pathname === '/api/v1/session') return this.session(request);
    if (url.pathname === '/api/v1/ws') return this.attachWebSocket(request);
    if (url.pathname === '/healthz') return json({ ok: true, bootId: this.bootId });
    return notFound();
  }

  issueBootstrap(request) {
    const token = request.headers.get('X-Bootstrap-Token') || '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
    this.sweepExpiredBootstraps();
    this.sweepExpiredSessions();
    const hash = tokenHash(token);
    if (!this.bootstraps.has(hash) && this.bootstraps.size >= MAX_BOOTSTRAPS) return busy();
    this.bootstraps.set(hash, {
      tokenHash: hash,
      createdAt: Date.now(),
    });
    return new Response(null, { status: 204 });
  }

  async session(request) {
    this.sweepExpiredBootstraps();
    this.sweepExpiredSessions();
    const token = bearer(request.headers.get('Authorization'));
    if (!token) return notFound();
    const hash = tokenHash(token);
    if (request.method === 'DELETE') {
      const session = this.sessions.get(hash);
      if (!session || session.hash !== hash) return notFound();
      this.disposeSession(session, 'session deleted');
      return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    }
    if (request.method !== 'POST' || request.headers.get('Content-Type') !== 'application/octet-stream') return notFound();
    const bootstrap = this.bootstraps.get(hash);
    if (!bootstrap || Date.now() - bootstrap.createdAt > BOOTSTRAP_TTL_MS) return notFound();
    const body = await readBodyAtMost(request, 64);
    if (body === null || this.bootstraps.get(hash) !== bootstrap
      || Date.now() - bootstrap.createdAt > BOOTSTRAP_TTL_MS) return notFound();
    let frames;
    try { frames = decodeFrames(body); } catch { return notFound(); }
    if (frames.length !== 1 || frames[0].type !== FRAME_TYPES.HELLO || frames[0].streamId !== 0 || Buffer.compare(frames[0].payload, Buffer.of(1)) !== 0) return notFound();
    const fingerprint = Buffer.from(body).toString('base64url');
    const existing = this.sessions.get(hash);
    if (existing) {
      if (existing.fingerprint !== fingerprint) return notFound();
      return this.sessionResponse(existing.token, existing.welcome);
    }
    if (this.sessionSet.size >= MAX_SESSIONS) return busy();
    const sessionToken = randomToken();
    const welcome = encodeFrame(FRAME_TYPES.WELCOME, 0);
    const session = {
      token: sessionToken,
      hash: tokenHash(sessionToken),
      bootstrapHash: hash,
      fingerprint,
      welcome,
      createdAt: Date.now(),
      socket: null,
    };
    this.sessions.set(hash, session);
    this.sessions.set(session.hash, session);
    this.sessionSet.add(session);
    return this.sessionResponse(sessionToken, welcome);
  }

  sessionResponse(token, welcome) {
    return new Response(welcome, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store',
        'x-session-token': token,
        'x-down-cursor': '0',
        'x-carrier-mode': 'websocket',
      },
    });
  }

  sweepExpiredBootstraps(now = Date.now()) {
    for (const [hash, bootstrap] of this.bootstraps) {
      if (now - bootstrap.createdAt > BOOTSTRAP_TTL_MS) this.bootstraps.delete(hash);
    }
  }

  sweepExpiredSessions(now = Date.now()) {
    for (const session of this.sessionSet) {
      if (!session.socket && now - session.createdAt > SESSION_ATTACH_TTL_MS) {
        this.disposeSession(session, 'session expired');
      }
    }
  }

  attachWebSocket(request) {
    this.sweepExpiredBootstraps();
    this.sweepExpiredSessions();
    const parsed = parseCarrierProtocol(request.headers.get('Sec-WebSocket-Protocol') || '');
    if (!parsed) return notFound();
    const session = this.sessions.get(tokenHash(parsed.token));
    if (!session || session.token !== parsed.token || session.socket) return notFound();
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return notFound();
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    session.socket = server;
    const dialTelegram = this.env.__dialTelegram
      ?? ((target, options) => openTelegramWss(target, { ...options, fetchImpl: this.env.__fetch ?? fetch }));
    session.engine = new RelayEngine({
      secret: this.env.PROXY_SECRET,
      randomBytes: this.env.__randomBytes,
      dialTelegram,
      sendCarrier: (frame) => server.send(frame),
      closeCarrier: (code, reason) => {
        try { server.close?.(code, reason); }
        finally { this.disposeSession(session, reason, false); }
      },
      debug: this.env.RELAY_DEBUG === '1',
      budget: this.relayBudget,
      dialLimiter: this.dialLimiter,
    });
    this.sockets.set(server, session);
    try { server.binaryType = 'arraybuffer'; } catch {}
    if (typeof server.accept === 'function') {
      server.accept();
      server.addEventListener?.('message', (event) => {
        const idle = this.webSocketMessage(server, event.data);
        if (idle && typeof this.ctx.waitUntil === 'function') this.ctx.waitUntil(idle);
      });
    }
    server.addEventListener?.('close', () => this.detach(server));
    server.addEventListener?.('error', () => this.detach(server));
    const protocol = `tproxy-v1.${session.token}`;
    try {
      return new Response(null, {
        status: 101,
        webSocket: client,
        headers: { 'sec-websocket-protocol': protocol },
      });
    } catch (error) {
      // Node's standard Response rejects 101, while the Workers runtime
      // provides the WebSocket upgrade response extension.
      if (!(error instanceof RangeError)) throw error;
      return {
        status: 101,
        webSocket: client,
        headers: new Headers({ 'sec-websocket-protocol': protocol }),
      };
    }
  }

  webSocketMessage(socket, message) {
    const session = this.sockets.get(socket);
    if (!session) return;
    const work = [];
    let frames;
    try {
      frames = decodeFrames(message);
    } catch (error) {
      const msg = String(error?.message ?? error).slice(0, 80);
      if (this.env.RELAY_DEBUG === '1') console.log(JSON.stringify({ diag: 'ws-decode-fail', error: msg }));
      session.engine.protocolError(msg || 'protocol error');
      return;
    }
    for (const frame of frames) {
      if (frame.streamId === 0) {
        session.engine.protocolError('unsupported frame');
        return work.length ? Promise.all(work) : undefined;
      }
      const pending = session.engine.handleFrame(frame);
      if (pending) work.push(pending);
      if (!session.engine || session.engine.carrierClosed) {
        return work.length ? Promise.all(work) : undefined;
      }
    }
    return work.length ? Promise.all(work) : undefined;
  }

  webSocketClose(socket) {
    this.detach(socket);
  }

  webSocketError(socket) {
    this.detach(socket);
  }

  detach(socket) {
    const session = this.sockets.get(socket);
    if (!session) return;
    this.disposeSession(session, 'carrier detached');
  }

  disposeSession(session, reason, closeSocket = true) {
    const engine = session.engine, socket = session.socket;
    session.engine = null;
    session.socket = null;
    if (socket) this.sockets.delete(socket);
    this.sessions.delete(session.hash);
    this.sessions.delete(session.bootstrapHash);
    this.sessionSet.delete(session);
    this.bootstraps.delete(session.bootstrapHash);
    try { engine?.shutdown(reason); }
    finally {
      if (closeSocket) {
        try { socket?.close?.(1000, reason); } catch { try { socket?.close?.(); } catch {} }
      }
    }
  }

  flushRelayDown() {
    for (const session of this.sessionSet) session.engine?.flushAllDown();
  }
}

function bearer(value) {
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) return '';
  const token = value.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : '';
}
