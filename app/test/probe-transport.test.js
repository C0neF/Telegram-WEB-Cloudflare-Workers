import assert from 'node:assert/strict';
import test from 'node:test';
import * as probe from '../src/mtproto-probe.js';

const nonce = Buffer.alloc(16, 0x19);
function response(transport, padding = 0) {
  const body = Buffer.alloc(56);
  body.writeUInt32LE(0x05162463);
  nonce.copy(body, 4);
  body.fill(7, 20, 36);
  body.set([3, 0x17, 0xed, 0x48], 36);
  body.writeUInt32LE(0x1cb5c415, 40);
  body.writeInt32LE(1, 44);
  body.writeBigInt64LE(0x0102030405060708n, 48);
  const envelope = Buffer.alloc(20 + body.length);
  envelope.writeBigUInt64LE(1n, 8);
  envelope.writeUInt32LE(body.length, 16);
  body.copy(envelope, 20);
  if (transport === 'abridged') return Buffer.concat([Buffer.of(envelope.length / 4), envelope]);
  const header = Buffer.alloc(4);
  header.writeUInt32LE(envelope.length + padding);
  return Buffer.concat([header, envelope, Buffer.alloc(padding, 0x73)]);
}

for (const transport of ['abridged', 'padded-intermediate']) {
  test(`${transport} probe encodes and validates its transport envelope end to end`, () => {
    assert.equal(typeof probe.buildReqPqMulti, 'function');
    assert.equal(typeof probe.parseResPq, 'function');
    const request = probe.buildReqPqMulti(nonce, { transport, padding: Buffer.alloc(7), messageId: 4n });
    const offset = transport === 'abridged' ? 1 : 4;
    assert.equal(transport === 'abridged' ? request[0] * 4 : request.readUInt32LE(), request.length - offset);
    assert.equal(request.readBigUInt64LE(offset), 0n);
    assert.equal(request.readUInt32LE(offset + 20), 0xbe7e8ef1);
    assert.deepEqual(request.subarray(offset + 24, offset + 40), nonce);
    for (const padding of transport === 'abridged' ? [0] : [0, 1, 7, 15]) {
      const bytes = response(transport, padding);
      const parser = probe.parseResPq(nonce, { transport });
      for (let i = 0; i < bytes.length - 1; i++) assert.equal(parser.push(bytes.subarray(i, i + 1)), null);
      const result = parser.push(bytes.subarray(-1));
      assert.equal(result.constructor, 0x05162463);
      assert.deepEqual(result.nonce, nonce);
      assert.deepEqual(result.fingerprints, [0x0102030405060708n]);
    }
  });
  test(`${transport} probe rejects malformed resPQ and caps response buffering`, () => {
    assert.equal(typeof probe.parseResPq, 'function');
    assert.throws(() => probe.parseResPq(Buffer.alloc(16), { transport }).push(response(transport)), /nonce/i);
    const invalid = response(transport);
    const offset = transport === 'abridged' ? 1 : 4;
    invalid[offset] = 1;
    assert.throws(() => probe.parseResPq(nonce, { transport }).push(invalid), /unencrypted/i);
    assert.throws(() => probe.parseResPq(nonce, { transport }).push(Buffer.alloc(4097)), /large|limit/i);
    const header = transport === 'abridged' ? Buffer.from([0x7f, 0xff, 0xff, 0xff]) : Buffer.from([0xff, 0xff, 0xff, 0x7f]);
    assert.throws(() => probe.parseResPq(nonce, { transport }).push(header), /large|limit/i);
  });
}

test('padded probe rejects excessive padding and unsupported transports', () => {
  assert.equal(typeof probe.parseResPq, 'function');
  assert.throws(() => probe.parseResPq(nonce, { transport: 'padded-intermediate' }).push(response('padded-intermediate', 16)), /padding/i);
  assert.throws(() => probe.buildReqPqMulti(nonce, { transport: 'padded-intermediate', padding: Buffer.alloc(16) }), /padding/i);
  assert.throws(() => probe.parseResPq(nonce, { transport: 'unknown' }), /transport/i);
});
