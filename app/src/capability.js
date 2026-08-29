import { createHmac, timingSafeEqual } from 'node:crypto';
import { domainToASCII } from 'node:url';

function decodeProxySecret(value) {
  const text = String(value ?? '').trim();
  if (!/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/i.test(text)) {
    throw new Error('PROXY_SECRET must be 16 bytes, or dd plus 16 bytes, in hex');
  }
  return Buffer.from(text, 'hex');
}

function lastLabelIsNumeric(host) {
  const label = host.slice(host.lastIndexOf('.') + 1);
  if (!label) return false;
  const isHex = /^0x/i.test(label);
  const digits = isHex ? label.slice(2) : label;
  return digits.length > 0 && [...digits].every((char) =>
    /[0-9]/.test(char) || (isHex && /[a-f]/i.test(char)));
}

export function normalizeWebProxyHost(value) {
  const input = String(value).trim();
  if (!input || /[:/?#@]/.test(input) || input.endsWith('.')) return '';
  const ascii = domainToASCII(input).toLowerCase();
  if (!ascii || ascii.length > 253 || !ascii.includes('.')) return '';
  const labels = ascii.split('.');
  if (labels.some((label) =>
    !label || label.length > 63 || label.startsWith('-') || label.endsWith('-') ||
    !/^[a-z0-9-]+$/i.test(label))) return '';
  if (lastLabelIsNumeric(ascii) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ascii)) return '';
  return ascii;
}

export function computeCapability(host, secretHex) {
  const canonical = normalizeWebProxyHost(host);
  if (!canonical) throw new Error('invalid public hostname');
  const secret = decodeProxySecret(secretHex);
  return createHmac('sha256', secret)
    .update(`tdesktop-web-proxy-bridge-v1\n${canonical}`)
    .digest('base64url');
}

export function matchesBridgeCapability(value, host, secretHex) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  let expected;
  try {
    expected = computeCapability(host, secretHex);
  } catch {
    return false;
  }
  const actualBytes = Buffer.from(value);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.length === expectedBytes.length
    && timingSafeEqual(actualBytes, expectedBytes);
}
