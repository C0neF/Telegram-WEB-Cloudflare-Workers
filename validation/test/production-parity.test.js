import assert from 'node:assert/strict';
import test from 'node:test';

import {
  computeCapability,
  normalizeWebProxyHost as normalizeProductionHost,
} from '../../app/src/capability.js';
import { TRANSPORT_TAGS } from '../../app/src/mtproxy.js';
import * as productionProtocol from '../../app/src/protocol.js';
import { ABRIDGED_TAG } from '../src/mtproxy.js';
import {
  computeBridgeCapability,
  normalizeWebProxyHost as normalizeValidationHost,
} from '../src/protocol.js';
import * as validationProtocol from '../src/protocol.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';

function protocolContract(protocol) {
  return {
    frameTypes: protocol.FRAME_TYPES,
    frameHeaderSize: protocol.FRAME_HEADER_SIZE,
    maxFramePayload: protocol.MAX_FRAME_PAYLOAD,
    maxBatchFrames: protocol.MAX_BATCH_FRAMES,
    initialStreamWindow: protocol.INITIAL_STREAM_WINDOW,
    hello: protocol.encodeFrame(protocol.FRAME_TYPES.HELLO, 0, Buffer.of(1)).toString('hex'),
    welcome: protocol.encodeFrame(protocol.FRAME_TYPES.WELCOME, 0).toString('hex'),
  };
}

function assertProtocolParity(production, validation) {
  assert.deepEqual(protocolContract(production), protocolContract(validation));
}

test('independent validation oracle stays wire-compatible with production', () => {
  assertProtocolParity(productionProtocol, validationProtocol);
  assert.equal(TRANSPORT_TAGS.abridged, ABRIDGED_TAG);
});

test('protocol parity guard rejects a deliberately drifted production contract', () => {
  assert.throws(
    () => assertProtocolParity(
      { ...productionProtocol, MAX_FRAME_PAYLOAD: productionProtocol.MAX_FRAME_PAYLOAD + 1 },
      validationProtocol,
    ),
    assert.AssertionError,
  );
});

test('independent hostname and capability rules stay compatible with production', () => {
  const hosts = [
    'relay.example.com',
    ' RELAY.EXAMPLE.COM ',
    'b\u00fccher.example',
    'relay.example.0x12',
    '127.0.0.1',
    'single-label',
    'relay.example.com.',
  ];
  for (const host of hosts) {
    assert.equal(normalizeProductionHost(host), normalizeValidationHost(host), host);
  }

  for (const secretHex of [SECRET_HEX, `dd${SECRET_HEX}`]) {
    const canonicalHost = normalizeValidationHost('RELAY.EXAMPLE.COM');
    assert.equal(
      computeCapability('RELAY.EXAMPLE.COM', secretHex),
      computeBridgeCapability(canonicalHost, Buffer.from(secretHex, 'hex')),
    );
  }
});
