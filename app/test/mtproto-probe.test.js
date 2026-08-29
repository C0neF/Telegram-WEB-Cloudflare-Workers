import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildAbridgedReqPqMulti,
  parseAbridgedResPq,
} from '../src/mtproto-probe.js';

test('req_pq_multi probe builds a valid abridged unencrypted MTProto packet', () => {
  const nonce = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const packet = buildAbridgedReqPqMulti(nonce, {
    messageId: 0x1122334455667788n,
  });

  assert.equal(packet[0], 10);
  assert.equal(packet.readBigUInt64LE(1), 0n);
  assert.equal(packet.readBigUInt64LE(9), 0x1122334455667788n);
  assert.equal(packet.readUInt32LE(17), 20);
  assert.equal(packet.readUInt32LE(21), 0xbe7e8ef1);
  assert.deepEqual(packet.subarray(25), nonce);
});

test('default req_pq_multi message id is current, nonzero-fractional, and client-divisible by four', () => {
  const originalNow = Date.now;
  try {
    Date.now = () => 1_700_000_000_500;
    const packet = buildAbridgedReqPqMulti(Buffer.alloc(16));
    const messageId = packet.readBigUInt64LE(9);
    assert.equal(messageId % 4n, 0n);
    assert.notEqual(messageId & 0xffffffffn, 0n);
    assert.equal(messageId >> 32n, 1_700_000_000n);
  } finally {
    Date.now = originalNow;
  }
});

test('resPQ parser accepts fragmented abridged response and verifies the original nonce', () => {
  const nonce = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const serverNonce = Buffer.from('ffeeddccbbaa99887766554433221100', 'hex');
  const body = Buffer.alloc(56);
  body.writeUInt32LE(0x05162463, 0);
  nonce.copy(body, 4);
  serverNonce.copy(body, 20);
  body[36] = 3;
  Buffer.from([0x17, 0xed, 0x48]).copy(body, 37);
  body.writeUInt32LE(0x1cb5c415, 40);
  body.writeInt32LE(1, 44);
  body.writeBigInt64LE(0x0102030405060708n, 48);
  const envelope = Buffer.alloc(20 + body.length);
  envelope.writeBigUInt64LE(0n, 0);
  envelope.writeBigUInt64LE(0x8877665544332211n, 8);
  envelope.writeUInt32LE(body.length, 16);
  body.copy(envelope, 20);
  const packet = Buffer.concat([Buffer.of(envelope.length / 4), envelope]);

  const parser = parseAbridgedResPq(nonce);
  assert.equal(parser.push(packet.subarray(0, 3)), null);
  const result = parser.push(packet.subarray(3));
  assert.equal(result.constructor, 0x05162463);
  assert.deepEqual(result.nonce, nonce);
  assert.deepEqual(result.serverNonce, serverNonce);
  assert.deepEqual(result.pq, Buffer.from([0x17, 0xed, 0x48]));
  assert.deepEqual(result.fingerprints, [0x0102030405060708n]);
});

test('resPQ parser rejects nonce mismatch and invalid constructor', () => {
  const nonce = Buffer.alloc(16, 1);
  const parser = parseAbridgedResPq(nonce);
  const invalidBody = Buffer.alloc(36);
  invalidBody.writeUInt32LE(0x12345678, 0);
  const envelope = Buffer.alloc(20 + invalidBody.length);
  envelope.writeBigUInt64LE(0n, 0);
  envelope.writeBigUInt64LE(1n, 8);
  envelope.writeUInt32LE(invalidBody.length, 16);
  invalidBody.copy(envelope, 20);
  assert.throws(() => parser.push(Buffer.concat([
    Buffer.of(envelope.length / 4),
    envelope,
  ])), /resPQ/i);
});
