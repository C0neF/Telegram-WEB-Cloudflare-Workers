/**
 * WEB Proxy v1 shared frame codec — pinned to telegramdesktop/tproxy-server@52a5feb7
 * and Telegram Desktop v7.1.2 frame envelope.
 *
 * Wire format: type:u8 | stream_id:u24 | payload_length:u32 | payload
 * All numeric fields are big-endian. Carrier batches concatenate frames.
 */

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

/** Frame header size in bytes: type(1) + stream_id(3) + length(4) */
export const FRAME_HEADER_SIZE = 8;
/** Max payload per frame — matches tproxy-server carrier_batch_bytes semantics */
export const MAX_FRAME_PAYLOAD = 1024 * 1024;
/** Max frames decoded per carrier batch */
export const MAX_BATCH_FRAMES = 4096;
/** Hard max for a single carrier WebSocket message (2 MiB Desktop-compatible) */
export const MAX_CARRIER_BATCH = 2 * 1024 * 1024;
/** Initial flow-control window per direction per stream */
export const INITIAL_STREAM_WINDOW = 4 * 1024 * 1024;
/** Relay DATA chunk size — separates frame chunking from carrier flush */
export const MAX_DATA_CHUNK = 64 * 1024;

const KNOWN_FRAME_TYPES = new Set(Object.values(FRAME_TYPES));

/**
 * Encode a single WEB Proxy frame.
 * @param {number} type - FRAME_TYPES value
 * @param {number} streamId - 0..0xffffff (0 reserved for control)
 * @param {Uint8Array|ArrayBuffer|Buffer} [payload]
 */
export function encodeFrame(type, streamId, payload = new Uint8Array()) {
  if (!KNOWN_FRAME_TYPES.has(type)) throw new RangeError(`unknown frame type: ${type}`);
  if (!Number.isInteger(streamId) || streamId < 0 || streamId > 0xffffff) {
    throw new RangeError(`invalid stream id: ${streamId}`);
  }
  let bytes;
  if (payload instanceof ArrayBuffer) bytes = Buffer.from(new Uint8Array(payload));
  else if (ArrayBuffer.isView(payload)) bytes = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  else bytes = Buffer.from(payload);
  if (bytes.length > MAX_FRAME_PAYLOAD) throw new RangeError('payload too large');
  const frame = Buffer.alloc(FRAME_HEADER_SIZE + bytes.length);
  frame[0] = type;
  frame.writeUIntBE(streamId, 1, 3);
  frame.writeUInt32BE(bytes.length, 4);
  bytes.copy(frame, FRAME_HEADER_SIZE);
  return frame;
}

/**
 * Decode a carrier batch into frames. Validates hard limits to avoid unbounded allocations.
 * @param {ArrayBuffer|Uint8Array|Buffer} input
 */
export function decodeFrames(input) {
  let bytes;
  if (input instanceof ArrayBuffer) bytes = Buffer.from(new Uint8Array(input));
  else if (ArrayBuffer.isView(input)) bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  else bytes = Buffer.from(input);
  if (bytes.length > MAX_CARRIER_BATCH) throw new Error('carrier batch too large');
  const frames = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < FRAME_HEADER_SIZE) throw new Error('truncated frame header');
    const type = bytes[offset];
    const streamId = bytes.readUIntBE(offset + 1, 3);
    const size = bytes.readUInt32BE(offset + 4);
    if (!KNOWN_FRAME_TYPES.has(type)) throw new Error('unknown frame type');
    if (size > MAX_FRAME_PAYLOAD) throw new Error('payload too large');
    const end = offset + FRAME_HEADER_SIZE + size;
    if (end > bytes.length) throw new Error('truncated frame payload');
    if (frames.length >= MAX_BATCH_FRAMES) throw new Error('too many frames');
    frames.push({ type, streamId, payload: bytes.subarray(offset + FRAME_HEADER_SIZE, end) });
    offset = end;
  }
  if (!frames.length) throw new Error('empty frame batch');
  return frames;
}

/** Encode WINDOW increment (4-byte BE uint32) */
export function encodeWindow(amount) {
  if (!Number.isInteger(amount) || amount <= 0 || amount > 0xffffffff) {
    throw new RangeError('invalid window amount');
  }
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE(amount);
  return payload;
}

/** Decode and validate WINDOW payload */
export function decodeWindow(payload) {
  let bytes;
  if (payload instanceof ArrayBuffer) bytes = Buffer.from(new Uint8Array(payload));
  else if (ArrayBuffer.isView(payload)) bytes = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  else bytes = Buffer.from(payload);
  if (bytes.length !== 4) throw new Error('WINDOW payload must be 4 bytes');
  const amount = bytes.readUInt32BE(0);
  if (!amount) throw new Error('WINDOW amount must be nonzero');
  return amount;
}
