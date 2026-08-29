function roundedMilliseconds(value) {
  return Math.round(value * 100) / 100;
}

export function recordElapsed(
  report,
  key,
  started,
  now = () => performance.now(),
) {
  const elapsed = roundedMilliseconds(now() - started);
  report[key] = elapsed;
  return elapsed;
}

export async function timeOperation(
  report,
  key,
  operation,
  now = () => performance.now(),
) {
  const started = now();
  const result = await operation();
  recordElapsed(report, key, started, now);
  return result;
}
