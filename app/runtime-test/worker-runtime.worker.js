import { DurableObject, env, exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { computeCapability } from '../src/capability.js';
import { RelayDO } from '../src/index.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';

const HOST = 'relay.example.com';
const request = (path, init) => exports.default.fetch(new Request(`https://${HOST}${path}`, init));
function nextEvent(socket, type) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.removeEventListener(type, done); reject(new Error(`${type} deadline exceeded`)); }, 1000);
    function done(event) { clearTimeout(timer); resolve(event); }
    socket.addEventListener(type, done, { once: true });
  });
}
async function connect() {
  const capability = computeCapability(HOST, env.PROXY_SECRET);
  const bridge = await request(`/?bridge=${capability}`);
  expect(bridge.status).toBe(200);
  const bootstrap = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(await bridge.text())?.[1];
  expect(bootstrap).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const create = () => request('/api/v1/session', {
    method: 'POST', headers: { Authorization: `Bearer ${bootstrap}`, 'Content-Type': 'application/octet-stream' },
    body: encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(1)),
  });
  const session = await create();
  expect(session.status).toBe(200);
  expect(Buffer.from(await session.arrayBuffer()).toString('hex')).toBe('1100000000000000');
  const token = session.headers.get('x-session-token');
  const retry = await create();
  expect(retry.headers.get('x-session-token')).toBe(token);
  await retry.arrayBuffer();
  const upgrade = await request('/api/v1/ws', { headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': `tproxy-v1.${token}` } });
  expect(upgrade.status).toBe(101);
  const socket = upgrade.webSocket;
  socket.binaryType = 'arraybuffer';
  socket.accept();
  return { socket, token, bootstrap };
}
async function expectRevoked(token, bootstrap) {
  const attach = await request('/api/v1/ws', { headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': `tproxy-v1.${token}` } });
  expect(attach.status).toBe(404);
  const replay = await request('/api/v1/session', {
    method: 'POST', headers: { Authorization: `Bearer ${bootstrap}`, 'Content-Type': 'application/octet-stream' },
    body: encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(1)),
  });
  expect(replay.status).toBe(404);
}

describe('Workers runtime carrier', () => {
  it('uses the Cloudflare DurableObject base class and checks readiness', async () => {
    expect(RelayDO.prototype instanceof DurableObject).toBe(true);
    expect((await request('/readyz')).status).toBe(200);
  });
  it('completes the peer Close handshake and revokes its session and bootstrap', async () => {
    const { socket, token, bootstrap } = await connect();
    const closed = nextEvent(socket, 'close');
    socket.close(1000, 'runtime test complete');
    expect((await closed).code).toBe(1000);
    expect(socket.readyState).toBe(WebSocket.CLOSED);
    await expectRevoked(token, bootstrap);
  });
  for (const binary of [false, true]) {
    it(`rejects ${binary ? 'malformed binary' : 'text'} messages and cleans up immediately`, async () => {
      const { socket, token, bootstrap } = await connect();
      const closed = nextEvent(socket, 'close');
      socket.send(binary ? Uint8Array.of(255) : encodeFrame(FRAME_TYPES.OPEN, 1).toString('utf8'));
      expect((await closed).code).toBe(1002);
      expect(socket.readyState).toBe(WebSocket.CLOSED);
      await expectRevoked(token, bootstrap);
    });
  }
  it('isolates a malformed MTProxy init while retaining other streams and the carrier', async () => {
    const { socket, token, bootstrap } = await connect();
    const failed = nextEvent(socket, 'message');
    socket.send(Buffer.concat([
      encodeFrame(FRAME_TYPES.OPEN, 1), encodeFrame(FRAME_TYPES.OPEN, 2),
      encodeFrame(FRAME_TYPES.DATA, 1, Buffer.alloc(64)),
    ]));
    const frames = decodeFrames((await failed).data);
    expect(frames.map(({ type, streamId }) => [type, streamId])).toEqual([[FRAME_TYPES.CLOSE, 1]]);
    expect(socket.readyState).toBe(WebSocket.OPEN);
    socket.send(encodeFrame(FRAME_TYPES.CLOSE, 2));
    const closed = nextEvent(socket, 'close');
    socket.close(1000, 'done');
    await closed;
    await expectRevoked(token, bootstrap);
  });
});
