/**
 * Bounded logical stream relay — multiplexes WEB Proxy DATA over Telegram WSS.
 *
 * Design constraints:
 * - 32 streams max, 4 MiB initial window per direction
 * - DO-wide 32 MiB / 32K-item pending and outstanding caps
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
import { telegramHostForDc } from '../../shared/telegram-dc.js';

export { telegramHostForDc } from '../../shared/telegram-dc.js';
const DEFAULT_MAX_STREAMS = 32;
const DEFAULT_MAX_PENDING_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_STREAM_PENDING_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_PENDING_ITEMS = 32 * 1024;
const DEFAULT_MAX_STREAM_PENDING_ITEMS = 4 * 1024;
const DEFAULT_MAX_TOMBSTONES = 4096;
const DEFAULT_MAX_CONCURRENT_DIALS = 4;

export class DialLimiter {
  constructor(maxConcurrent = DEFAULT_MAX_CONCURRENT_DIALS, maxQueued = 256) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1
      || !Number.isInteger(maxQueued) || maxQueued < 0) {
      throw new RangeError('dial limits must be bounded nonnegative integers with positive concurrency');
    }
    this.maxConcurrent = maxConcurrent;
    this.maxQueued = maxQueued;
    this.active = 0;
    this.queue = [];
  }

  run(task, { signal } = {}) {
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (this.active >= this.maxConcurrent && this.queue.length >= this.maxQueued) {
      return Promise.reject(new Error('dial queue full'));
    }
    return new Promise((resolve, reject) => {
      const item = { task, resolve, reject, signal, cancel: null };
      item.cancel = () => {
        const index = this.queue.indexOf(item);
        if (index < 0) return;
        this.queue.splice(index, 1);
        signal.removeEventListener('abort', item.cancel);
        reject(signal.reason);
      };
      signal?.addEventListener('abort', item.cancel, { once: true });
      this.queue.push(item);
      this.drain();
    });
  }

  drain() {
    while (this.active < this.maxConcurrent && this.queue.length) {
      const item = this.queue.shift();
      item.signal?.removeEventListener('abort', item.cancel);
      this.active += 1;
      // In-flight work owns cancellation; don't release its slot before it settles.
      void Promise.resolve().then(item.task).then(
        value => { item.resolve(value); this.finish(); },
        error => { item.reject(error); this.finish(); },
      );
    }
  }

  finish() {
    this.active -= 1;
    this.drain();
  }
}

export class RelayBudget {
  constructor(options = {}) {
    this.maxPendingBytes = options.maxPendingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxPendingItems = options.maxPendingItems ?? DEFAULT_MAX_PENDING_ITEMS;
    this.maxOutstandingBytes = options.maxOutstandingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxOutstandingItems = options.maxOutstandingItems ?? DEFAULT_MAX_PENDING_ITEMS;
    this.pendingBytes = 0;
    this.pendingItems = 0;
    this.outstandingBytes = 0;
    this.outstandingItems = 0;
    this.onOutstandingAvailable = options.onOutstandingAvailable;
  }

  reserve(bytes, items = 1) {
    if (this.pendingBytes + bytes > this.maxPendingBytes
      || this.pendingItems + items > this.maxPendingItems) return false;
    this.pendingBytes += bytes;
    this.pendingItems += items;
    return true;
  }

  release(bytes, items = 1) {
    this.pendingBytes -= bytes;
    this.pendingItems -= items;
    if (this.pendingBytes < 0 || this.pendingItems < 0) {
      throw new Error('relay pending budget underflow');
    }
  }

  reserveOutstanding(bytes, items = 1) {
    if (this.outstandingBytes + bytes > this.maxOutstandingBytes
      || this.outstandingItems + items > this.maxOutstandingItems) return false;
    this.outstandingBytes += bytes;
    this.outstandingItems += items;
    return true;
  }

  releaseOutstanding(bytes, items = 1) {
    this.outstandingBytes -= bytes;
    this.outstandingItems -= items;
    if (this.outstandingBytes < 0 || this.outstandingItems < 0) {
      throw new Error('relay outstanding budget underflow');
    }
    if (bytes || items) this.onOutstandingAvailable?.();
  }
}

/** Open an outbound Telegram WSS with timeout and strict subprotocol check */
export async function openTelegramWss(target, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const abort = () => controller.abort(options.signal.reason);
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) abort();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`https://${target.host}/apiws`, {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': 'binary',
      },
      signal: controller.signal,
    });
    if (controller.signal.aborted) {
      closeSocket(response.webSocket, 1000, 'dial cancelled');
      throw controller.signal.reason;
    }
    const protocol = response.headers.get('Sec-WebSocket-Protocol');
    if (response.status !== 101 || protocol !== 'binary' || !response.webSocket) {
      closeSocket(response.webSocket, 1002, 'invalid handshake');
      void response.body?.cancel().catch(() => {});
      throw new Error(`Telegram WSS handshake failed: ${response.status}/${protocol ?? 'none'}`);
    }
    const socket = response.webSocket;
    // Workers defaults can deliver binary WebSocket messages as Blob-like
    // values. The relay is a byte stream, so force ArrayBuffer delivery before
    // accepting the outbound socket (Cloudflare runtime API contract).
    socket.binaryType = 'arraybuffer';
    socket.accept?.();
    return socket;
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
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
    this.writeCarrier = options.sendCarrier;
    this.closeCarrier = options.closeCarrier;
    this.dialLimiter = options.dialLimiter ?? new DialLimiter();
    this.initialWindow = options.initialWindow ?? INITIAL_STREAM_WINDOW;
    this.maxDataChunk = options.maxDataChunk ?? MAX_DATA_CHUNK;
    this.maxStreams = options.maxStreams ?? DEFAULT_MAX_STREAMS;
    this.maxPendingBytes = options.maxPendingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxStreamPendingBytes = options.maxStreamPendingBytes
      ?? DEFAULT_MAX_STREAM_PENDING_BYTES;
    this.maxPendingItems = options.maxPendingItems ?? DEFAULT_MAX_PENDING_ITEMS;
    this.maxStreamPendingItems = options.maxStreamPendingItems
      ?? DEFAULT_MAX_STREAM_PENDING_ITEMS;
    this.budget = options.budget ?? new RelayBudget({
      maxPendingBytes: this.maxPendingBytes,
      maxPendingItems: this.maxPendingItems,
      maxOutstandingBytes: options.maxOutstandingBytes,
      maxOutstandingItems: options.maxOutstandingItems,
    });
    this.maxOutstandingBytes = options.maxOutstandingBytes ?? DEFAULT_MAX_PENDING_BYTES;
    this.maxTombstones = options.maxTombstones ?? DEFAULT_MAX_TOMBSTONES;
    this.streams = new Map();
    // Lazily allocate a fixed 24-bit ID bitmap (2 MiB per active session).
    // Recent tombstones are only for late-frame races, not uniqueness.
    this.usedStreamIds = null;
    this.tombstones = new Set();
    this.tombstoneOrder = [];
    this.tasks = new Set();
    this.carrierClosed = false;
    this.pendingBytes = 0;
    this.pendingItems = 0;
    this.downOutstanding = 0;
    this.debug = options.debug === true;
  }

  log(event, details = {}) {
    if (this.debug) console.log(JSON.stringify({ relay: event, ...details }));
  }

  sendCarrier(frame) {
    if (this.carrierClosed) return false;
    try {
      this.writeCarrier(frame);
      return true;
    } catch {
      this.terminateCarrier(1011, 'carrier write failed');
      return false;
    }
  }

  handleFrame(frame) {
    if (this.carrierClosed) return;
    const { type, streamId } = frame;
    const payload = Buffer.from(frame.payload);
    if (!Number.isInteger(streamId) || streamId <= 0 || streamId > 0xffffff) {
      this.protocolError('invalid stream-zero frame');
      return;
    }
    if (type === FRAME_TYPES.OPEN) {
      const index = streamId >>> 3, mask = 1 << (streamId & 7);
      if (!empty(payload) || (this.usedStreamIds?.[index] & mask)) {
        this.protocolError('invalid OPEN');
        return;
      }
      this.usedStreamIds ??= new Uint8Array(1 << 21);
      this.usedStreamIds[index] |= mask;
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
      return this.handleClientData(stream, payload);
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
      this.releaseDownOutstanding(stream, amount);
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
      dialAbort: new AbortController(),
      closed: false,
      preinitCredit: 0,
      clientCredit: this.initialWindow,
      relayCredit: this.initialWindow,
      downOutstanding: 0,
      sentDown: [],
      pendingUp: [],
      pendingUpBytes: 0,
      pendingUpItems: 0,
      pendingDown: [],
      pendingDownBytes: 0,
      pendingDownItems: 0,
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
      return this.startDial(stream);
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
      || stream.pendingUpItems + 1 > this.maxStreamPendingItems
      || !this.budget.reserve(bytes.length)) {
      this.failStream(stream, 'uplink pending limit');
      return false;
    }
    stream.pendingUp.push({ data: bytes, credit });
    stream.pendingUpBytes += bytes.length;
    stream.pendingUpItems += 1;
    this.pendingBytes += bytes.length;
    this.pendingItems += 1;
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
    const signal = stream.dialAbort.signal;
    return this.track(this.dialLimiter.run(async () => {
      if (stream.closed) return;
      const socket = await this.dialTelegram(target, { signal });
      if (stream.closed) {
        closeSocket(socket, 1000, 'stream closed');
        return;
      }
      stream.socket = socket;
      this.log('dial-open', { streamId: stream.id });
      socket.addEventListener?.('message', event => this.handleTelegramData(stream, event.data));
      socket.addEventListener?.('close', event => {
        this.log('upstream-close', { streamId: stream.id, code: event?.code ?? null });
        this.failStream(stream, 'Telegram WSS closed');
      });
      socket.addEventListener?.('error', () => this.failStream(stream, 'Telegram WSS error'));
      this.flushUp(stream);
    }, { signal }).catch(() => {
      if (!stream.closed) this.failStream(stream, 'Telegram WSS dial failed');
    }).finally(() => { stream.dialing = false; }));
  }

  flushUp(stream) {
    if (!stream.socket || stream.closed) return;
    while (!stream.closed && stream.pendingUp.length) {
      const item = stream.pendingUp.shift();
      stream.pendingUpBytes -= item.data.length;
      stream.pendingUpItems -= 1;
      this.pendingBytes -= item.data.length;
      this.pendingItems -= 1;
      this.budget.release(item.data.length);
      try {
        stream.socket.send(item.data);
      } catch {
        this.failStream(stream, 'Telegram WSS write failed');
        return;
      }
      stream.clientCredit += item.credit;
      if (!this.sendCarrier(encodeFrame(
        FRAME_TYPES.WINDOW,
        stream.id,
        encodeWindow(item.credit),
      ))) return;
    }
  }

  handleTelegramData(stream, value) {
    if (stream.closed) return;
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) {
      this.failStream(stream, 'non-binary Telegram WSS message');
      return;
    }
    // View the incoming buffer, then transform bounded slices instead of making
    // multiple copies of an entire (potentially 32 MiB) WebSocket message.
    const encrypted = value instanceof ArrayBuffer ? Buffer.from(value)
      : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    for (let offset = 0; offset < encrypted.length; offset += this.maxDataChunk) {
      const plaintext = stream.direct.telegramRx.update(encrypted.subarray(offset, offset + this.maxDataChunk));
      if (!this.enqueueDown(stream, stream.parsed.clientTx.update(plaintext))) return;
    }
  }

  enqueueDown(stream, chunk) {
    if (stream.closed || this.carrierClosed) return false;
    if (!stream.pendingDown.length
      && this.trySendDown(stream, chunk)) {
      return true;
    }
    if (stream.closed || this.carrierClosed) return false;
    if (stream.pendingDownBytes + chunk.length > this.maxStreamPendingBytes
      || stream.pendingDownItems + 1 > this.maxStreamPendingItems
      || !this.budget.reserve(chunk.length)) {
      this.failStream(stream, 'downlink pending limit');
      return false;
    }
    stream.pendingDown.push(chunk);
    stream.pendingDownBytes += chunk.length;
    stream.pendingDownItems += 1;
    this.pendingBytes += chunk.length;
    this.pendingItems += 1;
    this.flushDown(stream);
    return !stream.closed;
  }

  flushDown(stream) {
    while (!stream.closed && stream.pendingDown.length) {
      const chunk = stream.pendingDown[0];
      if (!this.trySendDown(stream, chunk)) return;
      stream.pendingDown.shift();
      stream.pendingDownBytes -= chunk.length;
      stream.pendingDownItems -= 1;
      this.pendingBytes -= chunk.length;
      this.pendingItems -= 1;
      this.budget.release(chunk.length);
    }
  }

  trySendDown(stream, chunk) {
    if (stream.closed || this.carrierClosed || chunk.length > stream.relayCredit
      || this.downOutstanding + chunk.length > this.maxOutstandingBytes
      || !this.budget.reserveOutstanding(chunk.length)) return false;
    stream.relayCredit -= chunk.length;
    stream.downOutstanding += chunk.length;
    stream.sentDown.push(chunk.length);
    this.downOutstanding += chunk.length;
    return this.sendCarrier(encodeFrame(FRAME_TYPES.DATA, stream.id, chunk));
  }

  releaseDownOutstanding(stream, amount) {
    let remaining = amount;
    let releasedItems = 0;
    while (remaining > 0) {
      const first = stream.sentDown[0];
      if (!first) throw new Error('stream outstanding accounting underflow');
      if (remaining >= first) {
        remaining -= first;
        stream.sentDown.shift();
        releasedItems += 1;
      } else {
        stream.sentDown[0] = first - remaining;
        remaining = 0;
      }
    }
    this.budget.releaseOutstanding(amount, releasedItems);
  }

  flushAllDown() {
    if (!this.carrierClosed) for (const stream of this.streams.values()) this.flushDown(stream);
  }

  failStream(stream, reason) {
    if (stream.closed) return;
    this.log('stream-fail', { streamId: stream.id, reason });
    this.closeStream(stream, true, reason);
    this.sendCarrier(encodeFrame(FRAME_TYPES.CLOSE, stream.id));
  }

  closeStream(stream, failed, reason = '') {
    if (stream.closed) return;
    stream.closed = true;
    stream.dialAbort.abort(new Error('stream closed'));
    closeSocket(stream.socket, failed ? 1011 : 1000, reason.slice(0, 120));
    this.pendingBytes -= stream.pendingUpBytes + stream.pendingDownBytes;
    this.pendingItems -= stream.pendingUpItems + stream.pendingDownItems;
    this.budget.release(
      stream.pendingUpBytes + stream.pendingDownBytes,
      stream.pendingUpItems + stream.pendingDownItems,
    );
    this.downOutstanding -= stream.downOutstanding;
    this.budget.releaseOutstanding(stream.downOutstanding, stream.sentDown.length);
    stream.pendingUpBytes = 0;
    stream.pendingUpItems = 0;
    stream.pendingDownBytes = 0;
    stream.pendingDownItems = 0;
    stream.downOutstanding = 0;
    stream.sentDown.length = 0;
    stream.pendingUp.length = 0;
    stream.pendingDown.length = 0;
    stream.socket = null;
    stream.parsed = null;
    stream.direct = null;
    stream.accumulator = null;
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
    this.log('protocolError', { reason });
    this.terminateCarrier(1002, reason);
  }

  terminateCarrier(code, reason) {
    if (this.carrierClosed) return;
    this.shutdown(reason);
    try { this.closeCarrier(code, reason); } catch {}
  }

  shutdown(reason = 'carrier closed') {
    if (this.carrierClosed) return;
    this.carrierClosed = true;
    for (const stream of [...this.streams.values()]) this.closeStream(stream, false, reason);
    this.usedStreamIds = null;
  }

  track(promise) {
    this.tasks.add(promise);
    void promise.then(
      () => this.tasks.delete(promise),
      () => this.tasks.delete(promise),
    );
    return promise;
  }

  async whenIdle() {
    while (this.tasks.size) await Promise.all([...this.tasks]);
  }
}
