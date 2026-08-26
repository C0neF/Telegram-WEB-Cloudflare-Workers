/**
 * Bounded logical stream relay — multiplexes WEB Proxy DATA over Telegram WSS.
 *
 * Design constraints:
 * - 32 streams max, 4 MiB initial window per direction
 * - 32 MiB global pending cap (prevents OOM on large files)
 * - DATA chunks ≤ 64 KiB; carrier batch ≤ 2 MiB
 * - Tombstones prevent stream-id reuse races
 */
import {
  createDirectTelegramInit,
  MtproxyInitAccumulator,
} from './mtproxy.js';
import {
  decodeWindow,
  encodeFrame,
  encodeWindow,
  FRAME_TYPES,
  INITIAL_STREAM_WINDOW,
  MAX_DATA_CHUNK,
} from './protocol.js';

const TELEGRAM_HOSTS = Object.freeze([
  'pluto.web.telegram.org',
  'venus.web.telegram.org',
  'aurora.web.telegram.org',
  'vesta.web.telegram.org',
  'flora.web.telegram.org',
]);
const DEFAULT_MAX_STREAMS = 32;
const DEFAULT_MAX_PENDING_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_STREAM_PENDING_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_TOMBSTONES = 4096;

/** Resolve official Telegram WSS host for a DC id (supports media sign via abs) */
export function telegramHostForDc(dcId) {
  const baseDcId = Math.abs(dcId);
  if (!Number.isInteger(dcId) || dcId === 0 || baseDcId > TELEGRAM_HOSTS.length) {
    throw new RangeError(`Unsupported Telegram DC id ${dcId}`);
  }
  return TELEGRAM_HOSTS[baseDcId - 1];
}

/** Open an outbound Telegram WSS with timeout and strict subprotocol check */
export async function openTelegramWss(target, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`https://${target.host}/apiws`, {
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Protocol': 'binary',
      },
      signal: controller.signal,
    });
    const protocol = response.headers.get('Sec-WebSocket-Protocol');
    if (response.status !== 101 || protocol !== 'binary' || !response.webSocket) {
      throw new Error(`Telegram WSS handshake failed: ${response.status}/${protocol ?? 'none'}`);
    }
    const socket = response.webSocket;
    // Workers defaults can deliver binary WebSocket messages as Blob-like
    // values. The relay is a byte stream, so force ArrayBuffer delivery before
    // accepting the outbound socket (Cloudflare runtime API contract).
    socket.binaryType = 'arraybuffer';
    socket.accept?.({ allowHalfOpen: true });
    return socket;
  } finally {
    clearTimeout(timeout);
  }
}

function empty(payload) {
  return Buffer.from(payload).length === 0;
}

function closeSocket(socket, code, reason) {
  try {
    socket?.close?.(code, reason);
  } catch {
    // Some standard WebSocket implementations reject application-defined
    // close codes. The stream is already being torn down; avoid an unhandled
    // exception and let the peer observe the carrier close.
    try { socket?.close?.(); } catch {}
  }
}

export class RelayEngine {
  constructor(options) {
    this.secret = options.secret;
    this.randomBytes = options.randomBytes;
    this.dialTelegram = options.dialTelegram;
    this.sendCarrier = options.sendCarrier;
    this.closeCarrier = options.closeCarrier;
    this.initialWindow = options.initialWindow ?? INITIAL_STREAM_WINDOW;
    this.maxDataChunk = options.maxDataChunk ?? MAX_DATA_CHUNK;
    this.maxStreams = options.maxStreams ?? DEFAULT_MAX_STREAMS;
    this.maxPendingBytes = options.maxPendingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxStreamPendingBytes = options.maxStreamPendingBytes
      ?? DEFAULT_MAX_STREAM_PENDING_BYTES;
    this.maxOutstandingBytes = options.maxOutstandingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxTombstones = options.maxTombstones ?? DEFAULT_MAX_TOMBSTONES;
    this.streams = new Map();
    this.tombstones = new Set();
    this.tombstoneOrder = [];
    this.tasks = new Set();
    this.carrierClosed = false;
    this.pendingBytes = 0;
    this.downOutstanding = 0;
    this.debug = options.debug === true;
  }

  log(event, details = {}) {
    if (this.debug) console.log(JSON.stringify({ relay: event, ...details }));
  }

  handleFrame(frame) {
    if (this.carrierClosed) return;
    const { type, streamId } = frame;
    const payload = Buffer.from(frame.payload);
    if (streamId === 0) {
      this.protocolError('invalid stream-zero frame');
      return;
    }
    if (type === FRAME_TYPES.OPEN) {
      if (!empty(payload) || this.streams.has(streamId) || this.tombstones.has(streamId)) {
        this.protocolError('invalid OPEN');
        return;
      }
      if (this.streams.size >= this.maxStreams) {
        this.rejectStream(streamId);
        return;
      }
      this.streams.set(streamId, this.createStream(streamId));
      return;
    }
    const stream = this.streams.get(streamId);
    if (!stream) {
      if (this.tombstones.has(streamId)
        && ((type === FRAME_TYPES.DATA && payload.length > 0)
          || (type === FRAME_TYPES.CLOSE && empty(payload))
          || (type === FRAME_TYPES.WINDOW && this.validWindow(payload)))) {
        return;
      }
      this.protocolError('unknown stream');
      return;
    }
    if (type === FRAME_TYPES.DATA) {
      if (!payload.length || payload.length > this.maxDataChunk || payload.length > stream.clientCredit) {
        this.protocolError('invalid DATA');
        return;
      }
      stream.clientCredit -= payload.length;
      this.handleClientData(stream, payload);
      return;
    }
    if (type === FRAME_TYPES.WINDOW) {
      let amount;
      try { amount = decodeWindow(payload); } catch { this.protocolError('invalid WINDOW'); return; }
      if (amount > stream.downOutstanding) {
        this.protocolError('WINDOW exceeds outstanding bytes');
        return;
      }
      stream.downOutstanding -= amount;
      this.downOutstanding -= amount;
      stream.relayCredit += amount;
      this.flushAllDown();
      return;
    }
    if (type === FRAME_TYPES.CLOSE && empty(payload)) {
      this.closeStream(stream, false);
      return;
    }
    this.protocolError('unsupported stream frame');
  }

  createStream(id) {
    return {
      id,
      accumulator: new MtproxyInitAccumulator(this.secret),
      parsed: null,
      direct: null,
      socket: null,
      dialing: false,
      closed: false,
      preinitCredit: 0,
      clientCredit: this.initialWindow,
      relayCredit: this.initialWindow,
      downOutstanding: 0,
      pendingUp: [],
      pendingUpBytes: 0,
      pendingDown: [],
      pendingDownBytes: 0,
    };
  }

  handleClientData(stream, payload) {
    if (!stream.parsed) {
      stream.preinitCredit += payload.length;
      let result;
      try {
        result = stream.accumulator.push(payload);
      } catch {
        this.failStream(stream, 'invalid MTProxy init');
        return;
      }
      if (!result.ready) return;
      stream.parsed = result.parsed;
      try {
        stream.direct = createDirectTelegramInit(stream.parsed, {
          randomBytes: this.randomBytes,
        });
      } catch {
        this.failStream(stream, 'direct init failed');
        return;
      }
      let data = stream.direct.transmittedInit;
      if (result.remaining.length) {
        const plain = stream.parsed.clientRx.update(result.remaining);
        data = Buffer.concat([data, stream.direct.telegramTx.update(plain)]);
      }
      if (!this.queueUp(stream, data, stream.preinitCredit)) return;
      stream.preinitCredit = 0;
      this.startDial(stream);
      return;
    }
    const plain = stream.parsed.clientRx.update(payload);
    if (!this.queueUp(
      stream,
      stream.direct.telegramTx.update(plain),
      payload.length,
    )) return;
    this.flushUp(stream);
  }

  queueUp(stream, data, credit) {
    const bytes = Buffer.from(data);
    if (stream.pendingUpBytes + bytes.length > this.maxStreamPendingBytes
      || this.pendingBytes + bytes.length > this.maxPendingBytes) {
      this.failStream(stream, 'uplink pending limit');
      return false;
    }
    stream.pendingUp.push({ data: bytes, credit });
    stream.pendingUpBytes += bytes.length;
    this.pendingBytes += bytes.length;
    return true;
  }

  startDial(stream) {
    if (stream.dialing || stream.socket || stream.closed) return;
    stream.dialing = true;
    const target = {
      dcId: stream.parsed.dcId,
      baseDcId: stream.parsed.baseDcId,
      media: stream.parsed.media,
      host: telegramHostForDc(stream.parsed.dcId),
    };
    this.log('dial-start', { streamId: stream.id, dcId: target.dcId, host: target.host });
    this.track((async () => {
      try {
        const socket = await this.dialTelegram(target);
        if (stream.closed) {
          closeSocket(socket, 1000, 'stream closed');
          return;
        }
        stream.socket = socket;
        this.log('dial-open', { streamId: stream.id });
        socket.addEventListener?.('message', (event) => this.handleTelegramData(stream, event.data));
        socket.addEventListener?.('close', (event) => {
          this.log('upstream-close', { streamId: stream.id, code: event?.code ?? null });
          this.failStream(stream, 'Telegram WSS closed');
        });
        socket.addEventListener?.('error', () => {
          this.log('upstream-error', { streamId: stream.id });
          this.failStream(stream, 'Telegram WSS error');
        });
        this.flushUp(stream);
      } catch {
        this.log('dial-failed', { streamId: stream.id });
        this.failStream(stream, 'Telegram WSS dial failed');
      } finally {
        stream.dialing = false;
      }
    })());
  }

  flushUp(stream) {
    if (!stream.socket || stream.closed) return;
    while (stream.pendingUp.length) {
      const item = stream.pendingUp.shift();
      stream.pendingUpBytes -= item.data.length;
      this.pendingBytes -= item.data.length;
      try {
        stream.socket.send(item.data);
      } catch {
        this.failStream(stream, 'Telegram WSS write failed');
        return;
      }
      stream.clientCredit += item.credit;
      this.sendCarrier(encodeFrame(
        FRAME_TYPES.WINDOW,
        stream.id,
        encodeWindow(item.credit),
      ));
    }
  }

  handleTelegramData(stream, value) {
    if (stream.closed) return;
    let encrypted;
    try {
      encrypted = Buffer.from(value);
    } catch {
      this.log('upstream-nonbinary', { streamId: stream.id });
      this.failStream(stream, 'non-binary Telegram WSS message');
      return;
    }
    if (!encrypted.length) return;
    this.log('upstream-data', { streamId: stream.id, bytes: encrypted.length });
    const plaintext = stream.direct.telegramRx.update(encrypted);
    const clientCiphertext = stream.parsed.clientTx.update(plaintext);
    for (let offset = 0; offset < clientCiphertext.length; offset += this.maxDataChunk) {
      if (!this.enqueueDown(stream, Buffer.from(
        clientCiphertext.subarray(offset, offset + this.maxDataChunk),
      ))) return;
    }
  }

  enqueueDown(stream, chunk) {
    if (!stream.pendingDown.length
      && chunk.length <= stream.relayCredit
      && this.downOutstanding + chunk.length <= this.maxOutstandingBytes) {
      this.sendDown(stream, chunk);
      return true;
    }
    if (stream.pendingDownBytes + chunk.length > this.maxStreamPendingBytes
      || this.pendingBytes + chunk.length > this.maxPendingBytes) {
      this.failStream(stream, 'downlink pending limit');
      return false;
    }
    stream.pendingDown.push(chunk);
    stream.pendingDownBytes += chunk.length;
    this.pendingBytes += chunk.length;
    this.flushDown(stream);
    return true;
  }

  flushDown(stream) {
    while (!stream.closed && stream.pendingDown.length) {
      const chunk = stream.pendingDown[0];
      if (chunk.length > stream.relayCredit
        || this.downOutstanding + chunk.length > this.maxOutstandingBytes) return;
      stream.pendingDown.shift();
      stream.pendingDownBytes -= chunk.length;
      this.pendingBytes -= chunk.length;
      this.sendDown(stream, chunk);
    }
  }

  sendDown(stream, chunk) {
    stream.relayCredit -= chunk.length;
    stream.downOutstanding += chunk.length;
    this.downOutstanding += chunk.length;
    this.sendCarrier(encodeFrame(FRAME_TYPES.DATA, stream.id, chunk));
  }

  flushAllDown() {
    for (const stream of this.streams.values()) this.flushDown(stream);
  }

  failStream(stream, reason) {
    if (stream.closed) return;
    this.log('stream-fail', { streamId: stream.id, reason });
    this.sendCarrier(encodeFrame(FRAME_TYPES.CLOSE, stream.id));
    this.closeStream(stream, true, reason);
  }

  closeStream(stream, failed, reason = '') {
    if (stream.closed) return;
    stream.closed = true;
    closeSocket(stream.socket, failed ? 1011 : 1000, reason.slice(0, 120));
    this.pendingBytes -= stream.pendingUpBytes + stream.pendingDownBytes;
    this.downOutstanding -= stream.downOutstanding;
    stream.pendingUpBytes = 0;
    stream.pendingDownBytes = 0;
    stream.downOutstanding = 0;
    stream.pendingUp.length = 0;
    stream.pendingDown.length = 0;
    this.streams.delete(stream.id);
    this.rememberTombstone(stream.id);
  }

  rejectStream(streamId) {
    this.sendCarrier(encodeFrame(FRAME_TYPES.CLOSE, streamId));
    this.rememberTombstone(streamId);
  }

  rememberTombstone(streamId) {
    if (this.tombstones.has(streamId)) return;
    this.tombstones.add(streamId);
    this.tombstoneOrder.push(streamId);
    while (this.tombstoneOrder.length > this.maxTombstones) {
      this.tombstones.delete(this.tombstoneOrder.shift());
    }
  }

  validWindow(payload) {
    try { decodeWindow(payload); return true; } catch { return false; }
  }

  protocolError(reason) {
    if (this.debug) console.log(JSON.stringify({ diag: 'protocolError', reason }));
    if (this.carrierClosed) return;
    this.carrierClosed = true;
    for (const stream of [...this.streams.values()]) this.closeStream(stream, true, reason);
    this.closeCarrier(1002, reason);
  }

  shutdown(reason = 'carrier closed') {
    if (this.carrierClosed) return;
    this.carrierClosed = true;
    for (const stream of [...this.streams.values()]) this.closeStream(stream, false, reason);
  }

  track(promise) {
    this.tasks.add(promise);
    promise.finally(() => this.tasks.delete(promise));
  }

  async whenIdle() {
    while (this.tasks.size) await Promise.all([...this.tasks]);
  }
}
