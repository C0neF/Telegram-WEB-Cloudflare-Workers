/**
 * Public relay probe — verifies deployed carrier can complete
 * MTProxy → direct Telegram MTProto translation (req_pq_multi → resPQ).
 *
 * Usage: TASK_PROXY_SECRET=<hex> TASK_PROXY_HOST=<host> node app/scripts/public-relay-probe.mjs
 * Host resolves from TASK_PROXY_HOST or the first CLI argument (see probe-config.mjs).
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';

import { computeCapability } from '../src/capability.js';
import { buildAbridgedReqPqMulti } from '../src/mtproto-probe.js';
import { deriveProxyKeyMaterial } from '../src/mtproxy.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';
import { resolveProbeConfig } from './probe-config.mjs';
import { recordElapsed, timeOperation } from './probe-timing.mjs';

const { secretHex, host, base, transportTag } = resolveProbeConfig();
const report = { host };
report.timings = {};
const probeStarted = performance.now();

function outputReport(result, exitCode = 0) {
  report.result = result;
  recordElapsed(report.timings, 'totalMs', probeStarted);
  console.log(JSON.stringify(report));
  if (exitCode) process.exitCode = exitCode;
}

const capability = computeCapability(host, secretHex);

const health = await timeOperation(
  report.timings,
  'healthMs',
  () => fetch(`${base}/healthz`),
);
report.healthStatus = health.status;
try { await health.body?.cancel(); } catch {}
const { bridge, bridgeBody } = await timeOperation(
  report.timings,
  'bridgeMs',
  async () => {
    const response = await fetch(`${base}/?bridge=${capability}`);
    return { bridge: response, bridgeBody: await response.text() };
  },
);
report.bridgeStatus = bridge.status;
const bootstrap = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(bridgeBody)?.[1] ?? '';
report.bootstrapPresent = Boolean(bootstrap);
if (!bootstrap) {
  outputReport('bridge-failed', 2);
} else {
  const hello = encodeFrame(FRAME_TYPES.HELLO, 0, Buffer.of(1));
  const { session, welcome } = await timeOperation(
    report.timings,
    'sessionMs',
    async () => {
      const response = await fetch(`${base}/api/v1/session`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${bootstrap}`,
          'Content-Type': 'application/octet-stream',
        },
        body: hello,
      });
      return {
        session: response,
        welcome: Buffer.from(await response.arrayBuffer()),
      };
    },
  );
  report.sessionStatus = session.status;
  report.welcomeHex = welcome.toString('hex');
  const sessionToken = session.headers.get('x-session-token') ?? '';
  report.sessionTokenPresent = Boolean(sessionToken);
  if (!sessionToken) {
    outputReport('session-failed', 2);
  } else {
    const rawInit = randomBytes(64);
    if (rawInit[0] === 0xef) rawInit[0] = 0xee;
    rawInit.writeUInt32LE(transportTag, 56);
    rawInit.writeInt16LE(-2, 60);
    const clientMaterial = deriveProxyKeyMaterial(rawInit.subarray(0, 56), secretHex);
    const clientTx = createCipheriv(
      'aes-256-ctr',
      clientMaterial.clientToProxyKey,
      clientMaterial.clientToProxyIv,
    );
    const clientRx = createDecipheriv(
      'aes-256-ctr',
      clientMaterial.proxyToClientKey,
      clientMaterial.proxyToClientIv,
    );
    const encryptedInit = clientTx.update(rawInit);
    const transmittedInit = Buffer.concat([
      rawInit.subarray(0, 56),
      encryptedInit.subarray(56),
    ]);
    const nonce = randomBytes(16);
    const request = buildAbridgedReqPqMulti(nonce);
    const encryptedRequest = clientTx.update(request);
    const streamId = 1;
    const carrierStarted = performance.now();
    let carrierOpenedAt = null;
    const socket = new WebSocket(
      `${base.replace('https:', 'wss:')}/api/v1/ws`,
      `tproxy-v1.${sessionToken}`,
    );
    socket.binaryType = 'arraybuffer';

    const result = await new Promise((resolve) => {
      let settled = false;
      let timer;
      let phase = 'connecting';
      let controlFrameSeen = false;
      let windowSeen = false;
      let closeReason = null;
      let clearResponse = Buffer.alloc(0);
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };
      const tryParseResponse = () => {
        if (clearResponse.length < 25) return;
        const extended = clearResponse[0] === 0x7f;
        const headerSize = extended ? 4 : 1;
        const words = extended
          ? (clearResponse.length >= 4 ? clearResponse.readUIntLE(1, 3) : 0)
          : clearResponse[0];
        if (!words || clearResponse.length < headerSize + words * 4) return;
        const packet = clearResponse.subarray(headerSize, headerSize + words * 4);
        if (packet.length < 20) return;
        const bodyLength = packet.readUInt32LE(16);
        if (bodyLength < 20 || packet.length < 20 + bodyLength) return;
        const body = packet.subarray(20, 20 + bodyLength);
        if (carrierOpenedAt !== null && report.timings.openToResPqMs === undefined) {
          recordElapsed(report.timings, 'openToResPqMs', carrierOpenedAt);
        }
        finish({
          ok: true,
          phase,
          controlFrameSeen,
          windowSeen,
          closeReason,
          constructor: body.readUInt32LE(0),
          nonceMatches: body.subarray(4, 20).equals(nonce),
          responseBytes: clearResponse.length,
        });
      };
      timer = setTimeout(() => finish({
        ok: false,
        phase,
        controlFrameSeen,
        windowSeen,
        closeReason,
        reason: 'timeout',
      }), 20000);
      socket.addEventListener('open', () => {
        phase = 'open';
        carrierOpenedAt = performance.now();
        recordElapsed(report.timings, 'carrierOpenMs', carrierStarted, () => carrierOpenedAt);
        const bytes = Buffer.concat([transmittedInit, encryptedRequest]);
        socket.send(encodeFrame(FRAME_TYPES.OPEN, streamId));
        for (let offset = 0; offset < bytes.length; offset += 65536) {
          socket.send(encodeFrame(
            FRAME_TYPES.DATA,
            streamId,
            bytes.subarray(offset, offset + 65536),
          ));
        }
      });
      socket.addEventListener('message', (event) => {
        let frames;
        try {
          frames = decodeFrames(Buffer.from(event.data));
        } catch {
          finish({ ok: false, phase, reason: 'invalid-carrier-frame' });
          return;
        }
        for (const frame of frames) {
          if (frame.streamId === 0) {
            controlFrameSeen = true;
            finish({ ok: false, phase, controlFrameSeen, reason: 'unexpected-control-frame' });
            return;
          } else if (frame.type === FRAME_TYPES.WINDOW && frame.streamId === streamId) {
            windowSeen = true;
            phase = 'window';
            if (carrierOpenedAt !== null && report.timings.openToWindowMs === undefined) {
              recordElapsed(report.timings, 'openToWindowMs', carrierOpenedAt);
            }
          } else if (frame.type === FRAME_TYPES.DATA && frame.streamId === streamId) {
            phase = 'data';
            clearResponse = Buffer.concat([clearResponse, clientRx.update(frame.payload)]);
            tryParseResponse();
          } else if (frame.type === FRAME_TYPES.CLOSE && frame.streamId === streamId) {
            closeReason = 'stream-close';
          }
        }
      });
      socket.addEventListener('close', (event) => {
        closeReason = `ws-${event.code}`;
        if (!settled) finish({
          ok: false,
          phase,
          controlFrameSeen,
          windowSeen,
          closeReason,
          reason: 'websocket-closed',
        });
      });
      socket.addEventListener('error', () => finish({
        ok: false,
        phase,
        controlFrameSeen,
        windowSeen,
        closeReason,
        reason: 'websocket-error',
      }));
    });
    report.relay = result;
    try {
      socket.send(encodeFrame(FRAME_TYPES.CLOSE, streamId));
      socket.close();
    } catch {}
    await fetch(`${base}/api/v1/session`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${sessionToken}` },
    }).catch(() => {});
    const resultName = result.ok && result.constructor === 0x05162463 && result.nonceMatches
      ? 'public-respq-pass'
      : 'public-respq-fail';
    outputReport(resultName, resultName === 'public-respq-pass' ? 0 : 1);
  }
}
