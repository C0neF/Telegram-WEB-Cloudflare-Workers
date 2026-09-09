import { createCipheriv, createDecipheriv } from 'node:crypto';
import { expect, it } from 'vitest';
import { RelayEngine, openTelegramWss } from '../src/relay.js';
import { deriveProxyKeyMaterial } from '../src/mtproxy.js';
import { decodeFrames, encodeFrame, FRAME_TYPES } from '../src/protocol.js';

for (const padded of [false, true]) {
  it(`relays ${padded ? 'dd' : 'plain'} encrypted fragments through real workerd WebSocket pairs`, async () => {
    const secret = `${padded ? 'dd' : ''}000102030405060708090a0b0c0d0e0f`;
    const tag = padded ? 0xdddddddd : 0xefefefef;
    const raw = new Uint8Array(64);
    crypto.getRandomValues(raw);
    const init = Buffer.from(raw);
    init.writeUInt32LE(tag, 56);
    init.writeInt16LE(-2, 60);
    const keys = deriveProxyKeyMaterial(init.subarray(0, 56), secret);
    const clientTx = createCipheriv('aes-256-ctr', keys.clientToProxyKey, keys.clientToProxyIv);
    const clientRx = createDecipheriv('aes-256-ctr', keys.proxyToClientKey, keys.proxyToClientIv);
    const encryptedInit = clientTx.update(init);
    const input = Buffer.from('real workerd request fragment');
    const expected = Buffer.from('real workerd reply split at a non-block boundary');
    const bytes = Buffer.concat([init.subarray(0, 56), encryptedInit.subarray(56), clientTx.update(input)]);
    const carrierPair = new WebSocketPair();
    const [client, carrier] = Object.values(carrierPair);
    for (const ws of [client, carrier]) { ws.binaryType = 'arraybuffer'; ws.accept(); }
    let peer, received = Buffer.alloc(0), engine, timer;
    const done = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('data-plane timeout')), 2000);
      client.addEventListener('message', event => {
        try {
          for (const frame of decodeFrames(event.data)) {
            if (frame.type === FRAME_TYPES.DATA) {
              received = Buffer.concat([received, clientRx.update(frame.payload)]);
              if (received.length === expected.length) resolve();
            } else if (frame.type === FRAME_TYPES.CLOSE) reject(new Error('stream closed'));
          }
        } catch (error) { reject(error); }
      });
      engine = new RelayEngine({
        secret, sendCarrier: frame => carrier.send(frame), closeCarrier: code => carrier.close(code),
        dialTelegram: (target, options) => openTelegramWss(target, {
          ...options,
          fetchImpl: async () => {
            const pair = new WebSocketPair();
            const [upstream, server] = Object.values(pair);
            peer = server;
            peer.binaryType = 'arraybuffer'; peer.accept();
            let telegramRx, telegramTx, request = Buffer.alloc(0);
            peer.addEventListener('message', event => {
              try {
                let encrypted = Buffer.from(event.data);
                if (!telegramRx) {
                  const prefix = encrypted.subarray(0, 56);
                  telegramRx = createDecipheriv('aes-256-ctr', prefix.subarray(8, 40), prefix.subarray(40, 56));
                  const directInit = telegramRx.update(encrypted.subarray(0, 64));
                  expect(directInit.readUInt32LE(56)).toBe(tag);
                  const reverse = Buffer.from(prefix.subarray(8, 56)).reverse();
                  telegramTx = createCipheriv('aes-256-ctr', reverse.subarray(0, 32), reverse.subarray(32));
                  encrypted = encrypted.subarray(64);
                }
                request = Buffer.concat([request, telegramRx.update(encrypted)]);
                if (request.length === input.length) {
                  expect(request.equals(input)).toBe(true);
                  const ciphertext = telegramTx.update(expected);
                  peer.send(ciphertext.subarray(0, 7)); peer.send(ciphertext.subarray(7));
                }
              } catch (error) { reject(error); }
            });
            return new Response(null, { status: 101, webSocket: upstream, headers: { 'Sec-WebSocket-Protocol': 'binary' } });
          },
        }),
      });
      carrier.addEventListener('message', event => {
        for (const frame of decodeFrames(event.data)) {
          const task = engine.handleFrame(frame);
          if (task) void task.catch(reject);
        }
      });
    });
    try {
      client.send(encodeFrame(FRAME_TYPES.OPEN, 1));
      for (const part of [bytes.subarray(0, 7), bytes.subarray(7, 64), bytes.subarray(64)]) {
        client.send(encodeFrame(FRAME_TYPES.DATA, 1, part));
      }
      await done;
      expect(received.equals(expected)).toBe(true);
    } finally {
      clearTimeout(timer);
      engine?.shutdown();
      for (const ws of [client, carrier, peer]) { try { ws?.close(1000); } catch {} }
    }
    expect(engine.budget.pendingBytes).toBe(0);
    expect(engine.budget.outstandingBytes).toBe(0);
  });
}
