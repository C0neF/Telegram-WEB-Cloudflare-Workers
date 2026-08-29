import { DurableObject } from 'cloudflare:workers';

import {
  TELEGRAM_HOSTS,
  telegramHostForDc,
} from '../../../shared/telegram-dc.js';

const PROBE_OBJECT_NAME = 'personal-telegram-relay-validation-v1';

export { telegramHostForDc } from '../../../shared/telegram-dc.js';

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

function parsePositiveInt(value, fallback) {
  const parsed = Number(value ?? fallback);
  return Number.isInteger(parsed) ? parsed : NaN;
}

async function openTelegramWss(host, { timeoutMs = 10000 } = {}) {
  const controller = new AbortController();
  let timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const response = await fetch(`https://${host}/apiws`, {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': 'binary',
      },
      signal: controller.signal,
    });
    const protocol = response.headers.get('Sec-WebSocket-Protocol');
    if (response.status !== 101 || protocol !== 'binary' || !response.webSocket) {
      throw new Error(`Telegram WSS handshake failed: ${response.status}/${protocol ?? 'none'}`);
    }
    clearTimeout(timeout);
    timeout = null;
    if (typeof response.webSocket.accept === 'function') {
      response.webSocket.accept();
    }
    return {
      socket: response.webSocket,
      protocol,
      elapsedMs: Date.now() - started,
    };
  } finally {
    if (timeout !== null) clearTimeout(timeout);
  }
}

async function dialTelegramWss(host, { holdMs = 0, timeoutMs = 10000 } = {}) {
  const opened = await openTelegramWss(host, { timeoutMs });
  if (holdMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, holdMs));
  }
  opened.socket.close(1000, 'validation probe complete');
  return {
    ok: true,
    host,
    protocol: opened.protocol,
    elapsedMs: opened.elapsedMs + holdMs,
  };
}

export async function handleRequest(request, env) {
  const { pathname } = new URL(request.url);
  if (pathname === '/healthz') {
    return json({
      ok: true,
      service: 'telegram-web-proxy-cloudflare-probe',
    });
  }
  if (!pathname.startsWith('/probe/')) {
    return notFound();
  }
  if (!env.PROBE_TOKEN || request.headers.get('Authorization') !== `Bearer ${env.PROBE_TOKEN}`) {
    return notFound();
  }

  return env.RELAY_PROBE.getByName(PROBE_OBJECT_NAME).fetch(request);
}

export default {
  fetch: handleRequest,
};

export class RelayProbe extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.bootId = crypto.randomUUID();
    this.bootedAt = new Date().toISOString();
    this.lifecycle = null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;
    if (pathname === '/probe/sqlite') {
      const rows = Array.from(this.ctx.storage.sql.exec('SELECT 1 AS ok'));
      return json({
        ok: rows[0]?.ok === 1,
        sqlite: rows[0]?.ok ?? null,
        bootId: this.bootId,
        bootedAt: this.bootedAt,
      });
    }
    if (pathname === '/probe/state') {
      return json({
        ok: true,
        bootId: this.bootId,
        bootedAt: this.bootedAt,
      });
    }
    if (pathname === '/probe/outbound-wss') {
      const rawDcId = Number(url.searchParams.get('dc') ?? '1');
      try {
        const host = telegramHostForDc(rawDcId);
        const dial = this.env.__dialTelegram ?? dialTelegramWss;
        const result = await dial(host, {
          holdMs: parsePositiveInt(url.searchParams.get('holdMs'), 0),
          timeoutMs: 10000,
        });
        return json(result);
      } catch (error) {
        return json({ ok: false, error: String(error?.message ?? error) }, { status: 502 });
      }
    }
    if (pathname === '/probe/dials') {
      const count = parsePositiveInt(url.searchParams.get('count'), 1);
      const holdMs = parsePositiveInt(url.searchParams.get('holdMs'), 0);
      if (count < 1 || count > 8) {
        return new Response('count must be between 1 and 8', { status: 400 });
      }
      const dial = this.env.__dialTelegram ?? dialTelegramWss;
      const results = await Promise.all(
        Array.from({ length: count }, (_, index) =>
          dial(TELEGRAM_HOSTS[index % TELEGRAM_HOSTS.length], { holdMs, timeoutMs: 10000 })),
      );
      return json({ ok: results.every((result) => result.ok), count, holdMs, results });
    }
    if (pathname === '/probe/ws') {
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
        return new Response('Upgrade required', { status: 426 });
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      if (typeof this.ctx.acceptWebSocket === 'function') {
        this.ctx.acceptWebSocket(server);
      } else {
        server.accept();
        server.addEventListener('message', (event) => this.webSocketMessage(server, event.data));
      }
      return new Response(null, { status: 101, webSocket: client });
    }
    if (pathname === '/probe/lifecycle/start') {
      const dcId = Number(url.searchParams.get('dc') ?? '1');
      const heartbeatMs = parsePositiveInt(url.searchParams.get('heartbeatMs'), 60000);
      if (heartbeatMs < 1000 || heartbeatMs >= 70000) {
        return new Response('heartbeatMs must be between 1000 and 69999', { status: 400 });
      }
      if (this.lifecycle) {
        this.stopLifecycle('replaced');
      }
      try {
        const host = telegramHostForDc(dcId);
        const open = this.env.__openTelegram ?? openTelegramWss;
        const opened = await open(host, { timeoutMs: 10000 });
        const summary = {
          runId: crypto.randomUUID(),
          bootId: this.bootId,
          active: true,
          host,
          protocol: opened.protocol,
          startedAt: new Date().toISOString(),
          handshakeMs: opened.elapsedMs,
          heartbeatMs,
          heartbeatCount: 0,
          lastHeartbeatAt: null,
          socketState: 'open',
          socketClosedAt: null,
          closeCode: null,
          error: null,
        };
        opened.socket.addEventListener?.('close', (event) => {
          summary.socketState = 'closed';
          summary.socketClosedAt = new Date().toISOString();
          summary.closeCode = event.code;
        });
        opened.socket.addEventListener?.('error', () => {
          summary.socketState = 'error';
          summary.error = 'outbound websocket error';
        });
        const schedule = this.env.__setInterval ?? setInterval;
        const timer = schedule(() => {
          summary.heartbeatCount += 1;
          summary.lastHeartbeatAt = new Date().toISOString();
        }, heartbeatMs);
        this.lifecycle = { summary, socket: opened.socket, timer };
        await this.ctx.storage.put('lifecycle-run', {
          runId: summary.runId,
          startBootId: this.bootId,
          startedAt: summary.startedAt,
          host,
          heartbeatMs,
        });
        return json({ ok: true, ...summary });
      } catch (error) {
        return json({ ok: false, error: String(error?.message ?? error) }, { status: 502 });
      }
    }
    if (pathname === '/probe/lifecycle/status') {
      const persisted = await this.ctx.storage.get('lifecycle-run');
      return json({
        ok: true,
        bootId: this.bootId,
        bootedAt: this.bootedAt,
        active: Boolean(this.lifecycle?.summary.active),
        lifecycle: this.lifecycle ? { ...this.lifecycle.summary } : null,
        persisted: persisted ?? null,
      });
    }
    if (pathname === '/probe/lifecycle/stop') {
      const stopped = this.stopLifecycle('requested');
      return json({ ok: true, stopped });
    }
    return notFound();
  }

  async webSocketMessage(ws, message) {
    ws.send(message);
  }

  stopLifecycle(reason) {
    if (!this.lifecycle) return false;
    const cancel = this.env.__clearInterval ?? clearInterval;
    cancel(this.lifecycle.timer);
    this.lifecycle.summary.active = false;
    this.lifecycle.socket.close(1000, reason);
    this.lifecycle = null;
    return true;
  }
}
