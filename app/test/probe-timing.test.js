import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { recordElapsed, timeOperation } from '../scripts/probe-timing.mjs';

test('timeOperation records rounded elapsed milliseconds and preserves the result', async () => {
  const ticks = [10, 25.678];
  const report = {};
  const result = await timeOperation(
    report,
    'healthMs',
    async () => 'ok',
    () => ticks.shift(),
  );

  assert.equal(result, 'ok');
  assert.equal(report.healthMs, 15.68);
});

test('recordElapsed records event-driven phase timing with the same rounding', () => {
  const report = {};
  const elapsed = recordElapsed(report, 'carrierOpenMs', 100, () => 123.456);

  assert.equal(elapsed, 23.46);
  assert.equal(report.carrierOpenMs, 23.46);
});

test('public relay probe wires every latency phase into its sanitized report', () => {
  const source = readFileSync(
    new URL('../scripts/public-relay-probe.mjs', import.meta.url),
    'utf8',
  );
  for (const key of [
    'healthMs',
    'bridgeMs',
    'sessionMs',
    'carrierOpenMs',
    'openToWindowMs',
    'openToResPqMs',
    'totalMs',
  ]) {
    assert.match(source, new RegExp(`['"]${key}['"]`), key);
  }
  assert.match(source, /report\.timings\s*=\s*\{\}/);
});
