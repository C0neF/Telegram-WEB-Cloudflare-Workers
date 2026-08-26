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
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { domainToASCII } from 'node:url';

import { decodeFrames, encodeFrame, FRAME_TYPES } from './protocol.js';
import { openTelegramWss, RelayEngine } from './relay.js';

export { encodeFrame, FRAME_TYPES } from './protocol.js';

/** Bootstrap token TTL — single-use, 120s */
const BOOTSTRAP_TTL_MS = 120_000;
/** Session token TTL (informational — memory-only in DO) */
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
/** Singleton DO name for the personal relay */
const PROXY_OBJECT_NAME = 'personal-telegram-relay-canary-v1';

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

function randomToken() {
  return randomBytes(32).toString('base64url');
}

function tokenHash(token) {
  return createHash('sha256').update(token).digest('hex');
}

function equalText(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function decodeSecret(value) {
  const text = String(value ?? '').trim();
  if (!/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/i.test(text)) {
    throw new Error('PROXY_SECRET must be 16 bytes, or dd plus 16 bytes, in hex');
  }
  return Buffer.from(text, 'hex');
}

function normalizeHost(value) {
  const input = String(value).trim();
  if (!input || /[:/?#@]/.test(input) || input.endsWith('.')) return '';
  const ascii = domainToASCII(input).toLowerCase();
  if (!ascii || ascii.length > 253 || !ascii.includes('.')) return '';
  const labels = ascii.split('.');
  if (labels.some((label) =>
    !label || label.length > 63 || label.startsWith('-') || label.endsWith('-') ||
    !/^[a-z0-9-]+$/i.test(label))) return '';
  if (/(?:^|\.)\d+$/.test(ascii) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ascii)) return '';
  return ascii;
}

export function computeCapability(host, secretHex) {
  const canonical = normalizeHost(host);
  if (!canonical) throw new Error('invalid public hostname');
  const secret = decodeSecret(secretHex);
  return createHmac('sha256', secret)
    .update(`tdesktop-web-proxy-bridge-v1\n${canonical}`)
    .digest('base64url');
}

export function parseCarrierProtocol(protocol) {
  if (typeof protocol !== 'string' || !protocol.startsWith('tproxy-v1.')) return null;
  const token = protocol.slice('tproxy-v1.'.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return { token };
}

function bridgePage(host, bootstrap, nonce) {
  const origin = `https://${host}`;
  const csp = [
    "default-src 'none'",
    'base-uri \'none\'',
    'connect-src \'self\' wss://' + host,
    'frame-ancestors http://127.0.0.1:*',
    "script-src 'nonce-" + nonce + "'",
    "style-src 'none'",
    'object-src \'none\'',
    'worker-src \'none\'',
    'sandbox allow-same-origin allow-scripts',
  ].join('; ');
  const body = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connection</title></head>
<body>
<script nonce="${nonce}">
(()=>{
'use strict';
const relayOrigin=${JSON.stringify(origin)},bootstrap=${JSON.stringify(bootstrap)};
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',socket=null,creating=false;
const pending=[];
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
const requestOptions=(method,token,body,keepalive=false)=>({
 method,body,keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{})
});
function fail(){
 if(closed)return;
 status('failed');
 if(port)port.postMessage({t:'close'});
 close(true);
}
function close(notifyServer){
 if(closed)return;
 closed=true;
 if(socket)try{socket.close()}catch(error){}
 if(notifyServer&&sessionToken)fetch(relayOrigin+'/api/v1/session',requestOptions('DELETE',sessionToken,null,true)).catch(()=>{});
 if(port)port.close();
}
function queueCarrier(data){
 if(!(data instanceof ArrayBuffer)||!data.byteLength){fail();return}
 if(!socket||socket.readyState!==WebSocket.OPEN){pending.push(data);return}
 try{socket.send(data)}catch(error){fail()}
}
function openWebSocket(){
 return new Promise((resolve,reject)=>{
  const target=relayOrigin.replace(/^https:/,'wss:')+'/api/v1/ws';
  socket=new WebSocket(target,'tproxy-v1.'+sessionToken);
  socket.binaryType='arraybuffer';
  socket.onopen=()=>resolve();
  socket.onmessage=event=>{
   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});
   port.postMessage(event.data,[event.data]);
   status('connected');
  };
  socket.onerror=()=>reject(new Error('websocket failed'));
  socket.onclose=()=>{if(!closed)fail()};
 });
}
async function createSession(first){
 try{
  status('connecting');
  const response=await fetch(relayOrigin+'/api/v1/session',requestOptions('POST',bootstrap,first));
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!=='websocket')throw new Error('session rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';
  if(!/^[A-Za-z0-9_-]{43}$/.test(sessionToken))throw new Error('missing session token');
  const welcome=await response.arrayBuffer();
  await openWebSocket();
  if(closed)return;
  port.postMessage(welcome,[welcome]);
  status('connected');
  for(const data of pending.splice(0))queueCarrier(data);
 }catch(error){fail()}
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  const data=message.data;
  if(data instanceof ArrayBuffer){
   if(!creating){creating=true;createSession(data)}else queueCarrier(data);
  }else if(data&&data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  androidBridge.postMessage(value instanceof ArrayBuffer?value:JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{
  let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}
  if(androidPort.onmessage)androidPort.onmessage({data});
 };
 activatePort(androidPort);
 androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script>
</body>
</html>`;
  return { body, csp };
}

function validRootCapability(request, env) {
  const url = new URL(request.url);
  if (url.pathname !== '/' || request.method !== 'GET') return false;
  const entries = [...url.searchParams.entries()];
  if (entries.length !== 1 || entries[0][0] !== 'bridge') return false;
  const value = entries[0][1];
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  let expected;
  try {
    expected = computeCapability(url.hostname, env.PROXY_SECRET);
  } catch {
    return false;
  }
  return equalText(value, expected);
}

export async function handleRequest(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') {
    return json({ ok: true, service: 'telegram-web-proxy-canary' });
  }
  if (validRootCapability(request, env)) {
    const bootstrap = randomToken();
    const id = env.RELAY.idFromName(PROXY_OBJECT_NAME);
    const relay = env.RELAY.get(id);
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
    return new Response('<!doctype html><title>Telegram WEB Proxy canary</title><p>Telegram WEB Proxy canary</p>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }
  if (!url.pathname.startsWith('/api/v1/')) return notFound();
  const id = env.RELAY.idFromName(PROXY_OBJECT_NAME);
  return env.RELAY.get(id).fetch(request);
}

export default { fetch: handleRequest };

export class RelayDO {
  constructor(ctx, env = {}) {
    this.ctx = ctx;
    this.env = env;
    // A live Telegram upstream carries non-persistable AES-CTR state. Keep the
    // carrier on the standard in-memory WebSocket API; on eviction/restart the
    // socket closes and Telegram rebuilds the stream instead of reusing cipher
    // state in a new object instance.
    this.useHibernation = env.USE_HIBERNATION === '1';
    this.bootId = randomBytes(16).toString('hex');
    this.bootstraps = new Map();
    this.sessions = new Map();
    this.sockets = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/internal/bootstrap') return this.issueBootstrap(request);
    if (url.pathname === '/api/v1/session') return this.session(request);
    if (url.pathname === '/api/v1/ws') return this.attachWebSocket(request);
    if (url.pathname === '/healthz') return json({ ok: true, bootId: this.bootId });
    return notFound();
  }

  issueBootstrap(request) {
    const token = request.headers.get('X-Bootstrap-Token') || '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
    this.bootstraps.set(tokenHash(token), {
      tokenHash: tokenHash(token),
      createdAt: Date.now(),
    });
    return new Response(null, { status: 204 });
  }

  async session(request) {
    const token = bearer(request.headers.get('Authorization'));
    if (!token) return notFound();
    const hash = tokenHash(token);
    if (request.method === 'DELETE') {
      const session = this.sessions.get(hash);
      if (!session || session.hash !== hash) return notFound();
      session.engine?.shutdown('session deleted');
      try { session.socket?.close?.(1000, 'session deleted'); } catch { try { session.socket?.close?.(); } catch {} }
      this.sessions.delete(session.hash);
      for (const [key, value] of this.sessions) {
        if (value === session) this.sessions.delete(key);
      }
      return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    }
    if (request.method !== 'POST' || request.headers.get('Content-Type') !== 'application/octet-stream') return notFound();
    const bootstrap = this.bootstraps.get(hash);
    if (!bootstrap || Date.now() - bootstrap.createdAt > BOOTSTRAP_TTL_MS) return notFound();
    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > 64) return notFound();
    let frames;
    try { frames = decodeFrames(body); } catch { return notFound(); }
    if (frames.length !== 1 || frames[0].type !== FRAME_TYPES.HELLO || frames[0].streamId !== 0 || Buffer.compare(frames[0].payload, Buffer.of(1)) !== 0) return notFound();
    const fingerprint = Buffer.from(body).toString('base64url');
    const existing = this.sessions.get(hash);
    if (existing) {
      if (existing.fingerprint !== fingerprint) return notFound();
      return this.sessionResponse(existing.token, existing.welcome);
    }
    const sessionToken = randomToken();
    const session = {
      token: sessionToken,
      hash: tokenHash(sessionToken),
      fingerprint,
      createdAt: Date.now(),
      socket: null,
      challenge: null,
    };
    this.sessions.set(hash, session);
    this.sessions.set(session.hash, session);
    return this.sessionResponse(sessionToken, encodeFrame(FRAME_TYPES.WELCOME, 0));
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

  attachWebSocket(request) {
    const parsed = parseCarrierProtocol(request.headers.get('Sec-WebSocket-Protocol') || '');
    if (!parsed) return notFound();
    const session = this.sessions.get(tokenHash(parsed.token));
    if (!session || session.token !== parsed.token || session.socket) return notFound();
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return notFound();
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    session.socket = server;
    session.challenge = randomBytes(16);
    const dialTelegram = this.env.__dialTelegram
      ?? ((target) => openTelegramWss(target, { fetchImpl: this.env.__fetch ?? fetch }));
    session.engine = new RelayEngine({
      secret: this.env.PROXY_SECRET,
      randomBytes: this.env.__randomBytes,
      dialTelegram,
      sendCarrier: (frame) => server.send(frame),
      closeCarrier: (code, reason) => server.close?.(code, reason),
      debug: this.env.RELAY_DEBUG === '1',
    });
    this.sockets.set(server, session);
    try { server.binaryType = 'arraybuffer'; } catch {}
    if (this.useHibernation && typeof this.ctx.acceptWebSocket === 'function') {
      this.ctx.acceptWebSocket(server);
    } else if (typeof server.accept === 'function') {
      server.accept({ allowHalfOpen: true });
      server.addEventListener?.('message', (event) => {
        const idle = this.webSocketMessage(server, event.data);
        if (idle && typeof this.ctx.waitUntil === 'function') this.ctx.waitUntil(idle);
      });
    } else if (typeof this.ctx.acceptWebSocket === 'function') {
      this.ctx.acceptWebSocket(server);
    }
    server.addEventListener?.('close', () => this.detach(server));
    server.addEventListener?.('error', () => this.detach(server));
    server.send(encodeFrame(FRAME_TYPES.PING, 0, session.challenge));
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
    let frames;
    try {
      frames = decodeFrames(message);
    } catch (error) {
      const msg = String(error?.message ?? error).slice(0, 80);
      if (this.env.RELAY_DEBUG === '1') console.log(JSON.stringify({ diag: 'ws-decode-fail', error: msg }));
      socket.close?.(1002, msg || 'protocol error');
      return;
    }
    for (const frame of frames) {
      if (frame.type === FRAME_TYPES.PONG && frame.streamId === 0 && session.challenge && Buffer.compare(frame.payload, session.challenge) === 0) {
        session.challenge = null;
        continue;
      }
      if (frame.streamId === 0) {
        socket.close?.(1002, 'unsupported frame');
        return;
      }
      session.engine.handleFrame(frame);
      if (session.engine.carrierClosed) return;
    }
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
    this.sockets.delete(socket);
    if (session.socket === socket) session.socket = null;
    session.engine?.shutdown('carrier detached');
    session.engine = null;
  }
}

function bearer(value) {
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) return '';
  const token = value.slice(7);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : '';
}
