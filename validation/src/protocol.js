import { createHmac } from 'node:crypto';
import { domainToASCII } from 'node:url';

export const FRAME_TYPES = Object.freeze({
  OPEN: 0x01,
  DATA: 0x02,
  CLOSE: 0x03,
  WINDOW: 0x04,
  PING: 0x05,
  PONG: 0x06,
  HELLO: 0x10,
  WELCOME: 0x11,
  AUTH_CHALLENGE: 0x12,
  AUTH_RESPONSE: 0x13,
  BYE: 0x1f,
});

export const FRAME_HEADER_SIZE = 8;
export const MAX_FRAME_PAYLOAD = 1024 * 1024;
export const MAX_BATCH_FRAMES = 4096;
export const INITIAL_STREAM_WINDOW = 4 * 1024 * 1024;

const KNOWN_FRAME_TYPES = new Set(Object.values(FRAME_TYPES));

export function computeBridgeCapability(host, secret) {
  const context = Buffer.from(`tdesktop-web-proxy-bridge-v1\n${host}`, 'ascii');
  return createHmac('sha256', secret).update(context).digest('base64url');
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
  if (lastLabelIsNumeric(ascii) ||
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ascii) ||
      /^[0-9a-f:]+$/i.test(ascii)) return '';
  return ascii;
}

export function encodeFrame(type, streamId, payload = Buffer.alloc(0)) {
  if (!KNOWN_FRAME_TYPES.has(type)) {
    throw new RangeError(`Unknown frame type: ${type}`);
  }
  if (!Number.isInteger(streamId) || streamId < 0 || streamId > 0x00ffffff) {
    throw new RangeError(`Invalid stream id: ${streamId}`);
  }

  const bytes = Buffer.from(payload);
  if (bytes.length > MAX_FRAME_PAYLOAD) {
    throw new RangeError(`Frame payload exceeds ${MAX_FRAME_PAYLOAD} bytes`);
  }

  const result = Buffer.allocUnsafe(FRAME_HEADER_SIZE + bytes.length);
  result[0] = type;
  result.writeUIntBE(streamId, 1, 3);
  result.writeUInt32BE(bytes.length, 4);
  bytes.copy(result, FRAME_HEADER_SIZE);
  return result;
}

export function createFrameDecoder() {
  let pending = Buffer.alloc(0);

  return {
    push(chunk) {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      const frames = [];
      let offset = 0;

      while (pending.length - offset >= FRAME_HEADER_SIZE) {
        const type = pending[offset];
        if (!KNOWN_FRAME_TYPES.has(type)) {
          throw new Error(`Unknown frame type: ${type}`);
        }

        const streamId = pending.readUIntBE(offset + 1, 3);
        const payloadLength = pending.readUInt32BE(offset + 4);
        if (payloadLength > MAX_FRAME_PAYLOAD) {
          throw new Error(`Frame payload exceeds ${MAX_FRAME_PAYLOAD} bytes`);
        }

        const frameLength = FRAME_HEADER_SIZE + payloadLength;
        if (pending.length - offset < frameLength) {
          break;
        }
        if (frames.length >= MAX_BATCH_FRAMES) {
          throw new Error(`Frame batch exceeds ${MAX_BATCH_FRAMES} frames`);
        }

        frames.push({
          type,
          streamId,
          payload: Buffer.from(
            pending.subarray(offset + FRAME_HEADER_SIZE, offset + frameLength),
          ),
        });
        offset += frameLength;
      }

      if (offset > 0) {
        pending = Buffer.from(pending.subarray(offset));
      }
      return frames;
    },

    pendingBytes() {
      return pending.length;
    },
  };
}
