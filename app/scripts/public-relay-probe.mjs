/** Public req_pq_multi -> resPQ verification; credentials never enter the report. */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { computeCapability } from '../src/capability.js';
import { buildReqPqMulti, parseResPq } from '../src/mtproto-probe.js';
import { deriveProxyKeyMaterial } from '../src/mtproxy.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';
import { resolveProbeConfig } from './probe-config.mjs';
import { recordElapsed, timeOperation } from './probe-timing.mjs';

export async function runPublicRelayProbe({
  config = resolveProbeConfig(), fetchImpl = fetch, WebSocketImpl = WebSocket, timeoutMs = 20000,
} = {}) {
  const { secretHex, host, base, transportTag } = config;
  const transport = transportTag === 0xdddddddd ? 'padded-intermediate' : 'abridged';
  const report = { host, transport, dcId: -2 };
  report.timings = {};
  const probeStarted = performance.now();
  let sessionToken = '', socket = null;
  const http = (path, options = {}) => fetchImpl(`${base}${path}`, {
    ...options, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
  });
  async function boundedBody(response, maxBytes) {
    if (!response.body) return Buffer.alloc(0);
    const reader = response.body.getReader();
    const parts = [];
    let length = 0;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) return Buffer.concat(parts, length);
        length += next.value.byteLength;
        if (length > maxBytes) {
          void reader.cancel().catch(() => {});
          throw new Error('response exceeds probe limit');
        }
        parts.push(Buffer.from(next.value));
      }
    } finally { reader.releaseLock(); }
  }
  try {
    const health = await timeOperation(report.timings, 'healthMs', () => http('/healthz'));
    report.healthStatus = health.status;
    void health.body?.cancel().catch(() => {});
    const capability = computeCapability(host, secretHex);
    const { bridge, body } = await timeOperation(report.timings, 'bridgeMs', async () => {
      const bridge = await http(`/?bridge=${capability}`);
      return { bridge, body: await boundedBody(bridge, 65536) };
    });
    report.bridgeStatus = bridge.status;
    const bootstrap = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(body.toString())?.[1] ?? '';
    report.bootstrapPresent = Boolean(bootstrap);
    if (bridge.status !== 200 || !bootstrap) { report.result = 'bridge-failed'; return report; }
    const { session, welcome } = await timeOperation(report.timings, 'sessionMs', async () => {
      const session = await http('/api/v1/session', {
        method: 'POST', headers: { Authorization: `Bearer ${bootstrap}`, 'Content-Type': 'application/octet-stream' },
        body: encodeFrame(FRAME_TYPES.HELLO, 0, Buffer.of(1)),
      });
      return { session, welcome: await boundedBody(session, 64) };
    });
    report.sessionStatus = session.status;
    sessionToken = session.headers.get('x-session-token') ?? '';
    report.sessionTokenPresent = /^[A-Za-z0-9_-]{43}$/.test(sessionToken);
    if (session.status !== 200 || !report.sessionTokenPresent
      || session.headers.get('x-carrier-mode') !== 'websocket'
      || !welcome.equals(encodeFrame(FRAME_TYPES.WELCOME, 0))) {
      report.result = 'session-failed'; return report;
    }
    const rawInit = randomBytes(64);
    if (rawInit[0] === 0xef) rawInit[0] = 0xee;
    rawInit.writeUInt32LE(transportTag, 56);
    rawInit.writeInt16LE(-2, 60);
    const material = deriveProxyKeyMaterial(rawInit.subarray(0, 56), secretHex);
    const clientTx = createCipheriv('aes-256-ctr', material.clientToProxyKey, material.clientToProxyIv);
    const clientRx = createDecipheriv('aes-256-ctr', material.proxyToClientKey, material.proxyToClientIv);
    const encryptedInit = clientTx.update(rawInit);
    const transmittedInit = Buffer.concat([rawInit.subarray(0, 56), encryptedInit.subarray(56)]);
    const nonce = randomBytes(16);
    const encryptedRequest = clientTx.update(buildReqPqMulti(nonce, { transport }));
    const parser = parseResPq(nonce, { transport });
    const streamId = 1;
    const carrierStarted = performance.now();
    let carrierOpenedAt = null;
    socket = new WebSocketImpl(`${base.replace('https:', 'wss:')}/api/v1/ws`, `tproxy-v1.${sessionToken}`);
    socket.binaryType = 'arraybuffer';
    report.relay = await new Promise(resolve => {
      let settled = false, phase = 'connecting', windowSeen = false, responseBytes = 0;
      const finish = value => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ phase, windowSeen, ...value });
      };
      const timer = setTimeout(() => finish({ ok: false, reason: 'timeout' }), timeoutMs);
      socket.addEventListener('open', () => {
        if (settled) return;
        phase = 'open';
        carrierOpenedAt = performance.now();
        recordElapsed(report.timings, 'carrierOpenMs', carrierStarted, () => carrierOpenedAt);
        try {
          socket.send(encodeFrame(FRAME_TYPES.OPEN, streamId));
          socket.send(encodeFrame(FRAME_TYPES.DATA, streamId, Buffer.concat([transmittedInit, encryptedRequest])));
        } catch { finish({ ok: false, reason: 'carrier-send-failed' }); }
      });
      socket.addEventListener('message', event => {
        if (settled) return;
        try {
          for (const frame of decodeFrames(event.data)) {
            if (frame.streamId !== streamId) throw new Error('unexpected stream');
            if (frame.type === FRAME_TYPES.WINDOW) {
              windowSeen = true;
              phase = 'window';
              if (carrierOpenedAt !== null && report.timings.openToWindowMs === undefined) {
                recordElapsed(report.timings, 'openToWindowMs', carrierOpenedAt);
              }
            } else if (frame.type === FRAME_TYPES.DATA) {
              phase = 'data';
              responseBytes += frame.payload.length;
              const parsed = parser.push(clientRx.update(frame.payload));
              if (parsed) {
                recordElapsed(report.timings, 'openToResPqMs', carrierOpenedAt);
                finish({ ok: true, constructor: parsed.constructor, nonceMatches: parsed.nonce.equals(nonce), responseBytes });
              }
            } else if (frame.type === FRAME_TYPES.CLOSE) {
              finish({ ok: false, reason: 'stream-closed' });
            } else throw new Error('unexpected frame');
            if (settled) break;
          }
        } catch { finish({ ok: false, reason: 'invalid-response' }); }
      });
      socket.addEventListener('close', event => finish({ ok: false, reason: 'websocket-closed', code: event.code }));
      socket.addEventListener('error', () => finish({ ok: false, reason: 'websocket-error' }));
    });
    report.result = report.relay.ok ? 'public-respq-pass' : 'public-respq-fail';
  } catch {
    // Fetch errors can include URLs with the capability: report a fixed label.
    report.result = 'public-respq-fail';
    report.reason = 'request-failed';
  } finally {
    if (socket) {
      try { socket.send(encodeFrame(FRAME_TYPES.CLOSE, 1)); } catch {}
      try { socket.close(); } catch {}
    }
    if (/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
      try {
        const response = await http('/api/v1/session', { method: 'DELETE', headers: { Authorization: `Bearer ${sessionToken}` } });
        void response.body?.cancel().catch(() => {});
      } catch {}
    }
    recordElapsed(report.timings, 'totalMs', probeStarted);
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await runPublicRelayProbe();
    console.log(JSON.stringify(report));
    process.exitCode = report.result === 'public-respq-pass' ? 0 : 1;
  } catch (error) {
    // Config validation errors contain fixed, non-sensitive messages.
    console.error(error.message);
    process.exitCode = 2;
  }
}
