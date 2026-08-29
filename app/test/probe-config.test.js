import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveProbeConfig } from '../scripts/probe-config.mjs';

const SECRET = '000102030405060708090a0b0c0d0e0f';

test('probe config accepts dd secrets and targets the caller-selected host', () => {
  assert.deepEqual(resolveProbeConfig({
    argv: ['https://proxy.example.com/'],
    env: { TASK_PROXY_SECRET: `dd${SECRET}` },
  }), {
    secretHex: `dd${SECRET}`,
    host: 'proxy.example.com',
    base: 'https://proxy.example.com',
    transportTag: 0xdddddddd,
  });

  assert.deepEqual(resolveProbeConfig({
    argv: [],
    env: { TASK_PROXY_SECRET: SECRET, TASK_PROXY_HOST: 'fork.example.com' },
  }), {
    secretHex: SECRET,
    host: 'fork.example.com',
    base: 'https://fork.example.com',
    transportTag: 0xefefefef,
  });
});

test('probe config rejects malformed secrets and non-HTTPS targets', () => {
  assert.throws(() => resolveProbeConfig({
    argv: [],
    env: { TASK_PROXY_SECRET: SECRET },
  }), /host/i);
  assert.throws(() => resolveProbeConfig({
    argv: ['proxy.example.com'],
    env: { TASK_PROXY_SECRET: `ee${SECRET}` },
  }), /secret/i);
  assert.throws(() => resolveProbeConfig({
    argv: ['http://proxy.example.com'],
    env: { TASK_PROXY_SECRET: SECRET },
  }), /host/i);
});
