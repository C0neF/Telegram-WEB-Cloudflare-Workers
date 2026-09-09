import assert from 'node:assert/strict';
import test from 'node:test';
import { runPublicRelayProbe } from '../scripts/public-relay-probe.mjs';
import { resolveProbeConfig } from '../scripts/probe-config.mjs';
import { parseMtproxyClientInit } from '../src/mtproxy.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';

for (const padded of [false, true]) {
  test(`public probe sends a valid ${padded ? 'dd' : 'plain'} packet and verifies the reply`, async () => {
    const secret = `${padded ? 'dd' : ''}000102030405060708090a0b0c0d0e0f`;
    let deleted = false, packetChecked = false;
    class Peer extends EventTarget {
      constructor() { super(); queueMicrotask(() => this.dispatchEvent(new Event('open'))); }
      close() {}
      send(batch) {
        const [frame] = decodeFrames(batch);
        if (frame.type !== FRAME_TYPES.DATA) return;
        const parsed = parseMtproxyClientInit(frame.payload.subarray(0, 64), secret);
        assert.equal(parsed.transport, padded ? 'padded-intermediate' : 'abridged');
        const request = parsed.clientRx.update(frame.payload.subarray(64));
        const offset = padded ? 4 : 1;
        assert.equal(padded ? request.readUInt32LE(0) : request[0] * 4, request.length - offset);
        assert.equal(request.readUInt32LE(offset + 20), 0xbe7e8ef1);
        const nonce = request.subarray(offset + 24, offset + 40);
        packetChecked = true;
        const body = Buffer.alloc(56);
        body.writeUInt32LE(0x05162463);
        nonce.copy(body, 4);
        body.fill(0x13, 20, 36);
        body.set([3, 0x17, 0xed, 0x48], 36);
        body.writeUInt32LE(0x1cb5c415, 40);
        body.writeInt32LE(1, 44);
        body.writeBigInt64LE(0x1234567890n, 48);
        const envelope = Buffer.alloc(76);
        envelope.writeBigUInt64LE(1n, 8);
        envelope.writeUInt32LE(56, 16);
        body.copy(envelope, 20);
        const prefix = padded ? Buffer.alloc(4) : Buffer.of(19);
        if (padded) prefix.writeUInt32LE(83);
        const response = Buffer.concat([prefix, envelope, padded ? Buffer.alloc(7, 4) : Buffer.alloc(0)]);
        const ciphertext = parsed.clientTx.update(response);
        queueMicrotask(() => {
          for (const part of [ciphertext.subarray(0, 3), ciphertext.subarray(3)]) {
            this.dispatchEvent(new MessageEvent('message', { data: encodeFrame(FRAME_TYPES.DATA, frame.streamId, part) }));
          }
        });
      }
    }
    const report = await runPublicRelayProbe({
      config: resolveProbeConfig({ argv: ['relay.example.com'], env: { TASK_PROXY_SECRET: secret } }),
      WebSocketImpl: Peer,
      fetchImpl: async (url, options) => {
        if (new URL(url).pathname === '/healthz') return Response.json({ ok: true });
        if (new URL(url).pathname === '/') return new Response(`bootstrap="${'A'.repeat(43)}"`);
        if (options.method === 'DELETE') { deleted = true; return new Response(null, { status: 204 }); }
        return new Response(encodeFrame(FRAME_TYPES.WELCOME, 0), { headers: {
          'x-session-token': 'B'.repeat(43), 'x-carrier-mode': 'websocket',
        } });
      },
    });
    assert.equal(packetChecked, true);
    assert.equal(deleted, true);
    assert.equal(report.result, 'public-respq-pass');
    assert.equal(report.relay.nonceMatches, true);
    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes(secret));
    assert.ok(!serialized.includes('B'.repeat(43)));
  });
}
