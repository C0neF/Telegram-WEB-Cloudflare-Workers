import assert from 'node:assert/strict';
import test from 'node:test';

import {
  computeCapability,
  matchesBridgeCapability,
  normalizeWebProxyHost,
} from '../src/capability.js';

const SECRET_HEX = '000102030405060708090a0b0c0d0e0f';

test('canonical capability module normalizes the public host and preserves the fixed vector', () => {
  assert.equal(normalizeWebProxyHost(' RELAY.EXAMPLE.COM '), 'relay.example.com');
  assert.equal(
    computeCapability('RELAY.EXAMPLE.COM', SECRET_HEX),
    'aNQ8R-WMZNgKDbfI2vzmQ6lqpRq6BvcjxA2AbeKQ3YQ',
  );
});

test('canonical capability module owns capability validation and comparison', () => {
  const capability = computeCapability('relay.example.com', SECRET_HEX);
  assert.equal(
    matchesBridgeCapability(capability, 'RELAY.EXAMPLE.COM', SECRET_HEX),
    true,
  );
  assert.equal(
    matchesBridgeCapability(`${capability.slice(0, -1)}A`, 'relay.example.com', SECRET_HEX),
    false,
  );
  assert.equal(matchesBridgeCapability('not-a-capability', 'relay.example.com', SECRET_HEX), false);
  assert.equal(matchesBridgeCapability(capability, 'relay.example.0x12', SECRET_HEX), false);
});
