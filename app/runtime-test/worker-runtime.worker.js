import { DurableObject, env, exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

import { computeCapability } from '../src/capability.js';
import { RelayDO } from '../src/index.js';
import { encodeFrame, FRAME_TYPES } from '../src/protocol.js';

const HOST = 'relay.example.com';

describe('Workers runtime carrier', () => {
  it('uses the current Cloudflare DurableObject base class', () => {
    expect(RelayDO.prototype instanceof DurableObject).toBe(true);
  });

  it('completes capability, session, WebSocket attach, and cleanup in workerd', async () => {
    const capability = computeCapability(HOST, env.PROXY_SECRET);
    const bridge = await exports.default.fetch(`https://${HOST}/?bridge=${capability}`);
    expect(bridge.status).toBe(200);
    const bootstrap = /bootstrap="([A-Za-z0-9_-]{43})"/.exec(await bridge.text())?.[1];
    expect(bootstrap).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const createSession = () => exports.default.fetch(new Request(`https://${HOST}/api/v1/session`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bootstrap}`,
        'Content-Type': 'application/octet-stream',
      },
      body: encodeFrame(FRAME_TYPES.HELLO, 0, Uint8Array.of(1)),
    }));
    const session = await createSession();
    expect(session.status).toBe(200);
    expect(Buffer.from(await session.arrayBuffer()).toString('hex')).toBe('1100000000000000');
    const token = session.headers.get('x-session-token');
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const retry = await createSession();
    expect(retry.headers.get('x-session-token')).toBe(token);
    expect(Buffer.from(await retry.arrayBuffer()).toString('hex')).toBe('1100000000000000');

    const upgrade = await exports.default.fetch(new Request(`https://${HOST}/api/v1/ws`, {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': `tproxy-v1.${token}`,
      },
    }));
    expect(upgrade.status).toBe(101);
    const socket = upgrade.webSocket;
    expect(socket).toBeTruthy();
    socket.binaryType = 'arraybuffer';
    socket.accept();
    const unsolicitedFrame = await new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(false), 100);
      socket.addEventListener('message', () => {
        clearTimeout(timeout);
        resolve(true);
      }, { once: true });
    });
    expect(unsolicitedFrame).toBe(false);
    socket.close(1000, 'runtime test complete');
  });
});
