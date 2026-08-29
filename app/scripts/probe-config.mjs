import { domainToASCII } from 'node:url';

export function resolveProbeConfig({
  argv = process.argv.slice(2),
  env = process.env,
} = {}) {
  const secretHex = String(env.TASK_PROXY_SECRET ?? '').trim().toLowerCase();
  if (!/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/.test(secretHex)) {
    throw new Error('TASK_PROXY_SECRET is missing or invalid');
  }

  const input = String(argv[0] ?? env.TASK_PROXY_HOST ?? '').trim();
  if (!input) throw new Error('TASK_PROXY_HOST or a CLI host argument is required');
  let url;
  try {
    url = new URL(input.includes('://') ? input : `https://${input}`);
  } catch {
    throw new Error('TASK_PROXY_HOST is invalid');
  }
  const host = domainToASCII(url.hostname).toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port
    || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash
    || !host || !host.includes('.')) {
    throw new Error('TASK_PROXY_HOST must be a public HTTPS hostname');
  }

  return {
    secretHex,
    host,
    base: `https://${host}`,
    transportTag: secretHex.length === 34 ? 0xdddddddd : 0xefefefef,
  };
}
