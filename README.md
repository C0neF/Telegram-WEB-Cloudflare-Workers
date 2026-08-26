# Telegram WEB Proxy — Cloudflare Workers

> Zero-cost, single-user Telegram WEB Proxy on **Cloudflare Workers Free + SQLite Durable Objects** — WebSocket carrier, MTProxy obfuscation translation, bounded multiplexed relay.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Workers](https://img.shields.io/badge/Cloudflare-Workers%20Free-orange)](https://developers.cloudflare.com/workers/)
[![Node](https://img.shields.io/badge/node-%3E%3D18-green)](https://nodejs.org)

Pinned upstream: [`telegramdesktop/tproxy-server@52a5feb7`](https://github.com/telegramdesktop/tproxy-server/tree/52a5feb7fac38f68da5afef9cedd9b3bfc8473ca) / `Telegram Desktop v7.1.2@3772337d`.

[中文说明](#中文说明) · [Architecture](#architecture) · [Deploy](#deploy) · [Cost](#cost)

---

## Why

Host a personal Telegram WEB Proxy without a VPS, containers, or paid backends.

- **$0 / month** — Workers Free (100k req/day) + SQLite Durable Objects Free (100k req/day, 13k GB-s/day)
- **No VPS / no containers / no origin TCP servers**
- **Native WEB Proxy v1** — WebSocket carrier multiplexing `OPEN / DATA / WINDOW / CLOSE / PING / PONG`
- **Full TL surface** — text, updates, photos, video, files (1 GB+ verified; design supports bounded streaming)
- **Privacy-preserving** — proxy only terminates the outer MTProxy layer; MTProto payloads are treated as opaque bytes, never logged or persisted

> Voice/video calls are out of scope — WEB Proxy v1 does not relay UDP.

---

## Architecture

```
Telegram Desktop / Android (WEB Proxy v1)
        │  HTTPS / WSS  wss://proxy.example.com/api/v1/ws  tproxy-v1.<token>
        ▼
  Cloudflare Worker  ── capability check (HMAC) + bridge page
        │
        ▼
  Relay Durable Object (SQLite)  ── single DO: personal-telegram-relay-v1
        │  WEB Proxy session │ multiplexed logical streams
        │  MTProxy outer decrypt → direct Telegram obfuscation re-encrypt (streaming AES-256-CTR)
        │
        ├──► pluto.web.telegram.org /apiws  (DC1)
        ├──► venus.web.telegram.org /apiws  (DC2)
        ├──► aurora.web.telegram.org /apiws (DC3)
        ├──► vesta.web.telegram.org /apiws  (DC4)
        └──► flora.web.telegram.org /apiws  (DC5)   Sec-WebSocket-Protocol: binary
```

**Worker** = routing + bridge capability + bootstrap/session + WSS upgrade.  
**RelayDO** = long-lived state (stream windows, CTR ciphers, tombstones) + outbound Telegram WSS.

Single DO billing: `0.128 GB × 86 400 s = 11 059 GB-s/day` → **85% of the Free 13 000 GB-s/day** budget.

---

## Features

- **Bridge compatibility** — canonical hostname + `HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v1\n"+host)` (plain 16-byte and `dd`+16-byte secrets)
- **Secure handshake** — 256-bit CSPRNG bootstrap/session tokens, constant-time comparison, `no-store` / `no-cache`, CSP `nonce` bridge page
- **Bounded relay** — 32 streams max, 4 MiB window per direction, 32 MiB global pending, 64 KiB DATA chunks, 2 MiB carrier hard max
- **Streaming crypto** — 4 independent AES-256-CTR contexts per stream; never resets CTR on `DATA` boundaries; arbitrary fragmentation safe
- **Resilience** — tombstones for stream-id reuse, per-stream failure isolation (only the faulting stream gets `CLOSE`), carrier `1002` on protocol violation
- **Lifecycle-aware** — no fake heartbeats; DO eviction / upstream `1006` close is surfaced; Telegram client rebuilds the session

---

## Quick Start

### 1. Prerequisites

- Node.js ≥ 18, Wrangler ≥ 4, a Cloudflare Free account

### 2. Install

```bash
git clone <your-repo> telegram-web-proxy
cd telegram-web-proxy/app
npm install
npm test          # 26 tests — protocol / MTProxy / relay / carrier
```

### 3. Configure secret

Generate a 16-byte secret (32 hex chars) or `dd` + 16-byte for padded-intermediate:

```bash
# example — generate random secret
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
# → 000102030405060708090a0b0c0d0e0f

npx wrangler secret put PROXY_SECRET
# paste the hex string (dd + 32 hex is also accepted)
```

> Secret never touches source. Capability is `base64url(HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v1\n"+canonical_host))`.

### 4. Deploy (Free)

```bash
npm run deploy:dry   # 38 KiB / gzip ~10 KiB, check binding
npm run deploy       # → https://telegram-web-proxy.<your-subdomain>.workers.dev
```

Custom domain: add a Cloudflare zone route — domain cost is outside the `$0` infra constraint.

### 5. Verify

```bash
# health
curl https://<your-host>/healthz

# full data-plane probe (requires TASK_PROXY_SECRET env = PROXY_SECRET)
TASK_PROXY_SECRET=<same-hex> npm run probe
# expect: {"result":"public-respq-pass", ...}
```

The probe performs `OPEN → MTProxy init → req_pq_multi → resPQ` through your own carrier — the strongest proof the cipher translation is bit-exact.

---

## Use with Telegram Desktop

1. Open `https://<your-host>/?bridge=<capability>` in a browser.
   Capability is printed by the probe or derived locally:

   ```js
   import { createHmac } from 'node:crypto';
   const cap = createHmac('sha256', Buffer.from(secretHex,'hex'))
     .update(`tdesktop-web-proxy-bridge-v1\n${host}`).digest('base64url');
   ```

2. The bridge page negotiates `tproxy-v1.<session-token>` over `wss://<host>/api/v1/ws`.

3. In Telegram Desktop: **Settings → Data and Storage → Proxy → Add Proxy → WEB Proxy** → enter `<host>` and the same secret. Use “Add” and enable.

> Baseline: **Telegram Desktop v7.1.2**. Android `DrKLO/Telegram` and iOS official trees do not ship WEB Proxy in the examined commits; use the Desktop build for verification.

---

## Configuration

| Variable | Where | Purpose |
|---|---|---|
| `PROXY_SECRET` | `wrangler secret` | 32 hex or `dd`+32 hex — the only credential |
| `RELAY_DEBUG` | `wrangler vars / env` | `"1"` enables verbose relay logs (`wrangler tail`) |
| `USE_HIBERNATION` | DO env | `"1"` opts into hibernation API (ciphers stay in-memory — eviction still tears down streams) |

---

## Development

```bash
# all unit + carrier tests (now 26 + 25 validation)
npm --prefix app test
npm --prefix validation test

# local Cloudflare runtime
npm --prefix app run dev
# → http://127.0.0.1:8792

# probe against local dev (set PROXY_SECRET accordingly)
```

Project layout:

```
app/
  src/
    index.js          # Worker routing + RelayDO
    protocol.js       # WEB Proxy frame codec
    mtproxy.js        # MTProxy init / direct init / AES-CTR
    relay.js          # bounded multiplexed engine + Telegram WSS
    mtproto-probe.js  # req_pq_multi → resPQ helper
  test/               # 26 tests (product + relay + crypto)
  wrangler.toml
validation/
  src/ / test/ / scripts/   # upstream-pinned fixtures & public WSS probes
  cloudflare-probe/         # minimal Free runtime canary
docs/                       # architecture / verification records
```

---

## Cost

| Resource | Free quota | This project (single active DO) |
|---|---|---|
| Workers requests | 100k / day | carrier batch 2 MiB → ~25k billed/day at 100 Mbps; 64 KiB un-batched would be ~824k — **always batch** |
| Durable Objects requests | 100k / day | WebSocket application messages billed 20:1; inbound only |
| Durable Objects duration | 13k GB-s / day | One 128 MB DO all day = 11.06k (85%); budget for a second actor ≈ 4.2 h/day |
| Egress / storage | negligible for personal use | objects not persisted; logs contain only hashes |

> Hot path: keep carrier messages near 2 MiB; avoid flushing each 64 KiB DATA as its own WS message.

---

## Security Model

- Secrets and tokens: CSPRNG (`randomBytes(32)` → `base64url` 43 chars), hashed with SHA-256 before storage, never logged
- Capability comparison: `timingSafeEqual` + canonical hostname
- Host canonicalization: `domainToASCII`, lowercase, label checks, reject IPs / numeric TLD / bare hosts
- Frame validation: unknown types, illegal stream-ids, oversize payloads → immediate `1002` carrier close
- No payload persistence: `bootstrap / session / MTProto bytes` never written to durable storage
- Bridge CSP: `default-src 'none'`, `script-src 'nonce-…'`, `frame-ancestors http://127.0.0.1:*` (Desktop WebView), `sandbox allow-same-origin allow-scripts`

---

## Limitations & Non-Goals

- Voice/video calls (UDP) not supported — out of WEB Proxy v1 scope
- Single-user personal use; no multi-tenant management, channel promotion, or paid scaling
- `ee` TLS-emulation secrets and arbitrary upstream target selection not supported
- Active ciphers live in memory; DO eviction or upstream `1006` closes streams — clients reconnect (Telegram does this automatically)
- `websocket-lanes` and raw-TCP fallback are deferred — only enabled if single-carrier HOL/throughput or WSS compatibility gates fail

---

## Docs

- [`docs/architecture.md`](docs/architecture.md) — detailed design and hard constraints
- [`docs/verification.md`](docs/verification.md) — what was verified and how
- [`COMPLETE_PRODUCT_GOAL.md`](COMPLETE_PRODUCT_GOAL.md) — five-gate completion definition
- [`PLAN_VERIFICATION.md`](PLAN_VERIFICATION.md) — 1 200-line audit of the original plan against real platform limits
- [`DEPLOYMENT_GOAL.md`](DEPLOYMENT_GOAL.md), [`VALIDATION_GOAL.md`](VALIDATION_GOAL.md) — scoped goals
- `app/test/` and `validation/test/` — executable specification

---

## Acknowledgments

- Telegram Desktop and [`tproxy-server`](https://github.com/telegramdesktop/tproxy-server) for the WEB Proxy v1 protocol
- Telegram core docs: [MTProto transports](https://core.telegram.org/mtproto/transports)
- Cloudflare Workers & Durable Objects documentation

---

## License

MIT — see [LICENSE](LICENSE).

---

## 中文说明

这是一个基于 **Cloudflare Workers Free + SQLite Durable Objects** 的个人自用 Telegram WEB Proxy，使用 WebSocket 载体完整兼容 `telegramdesktop/tproxy-server@52a5feb7` 与 Desktop v7.1.2。

- 月服务器成本 **0 美元**，无 VPS / 无 Containers
- 单一 Durable Object 承载多路逻辑流，流控有界（2 MiB / 32 MiB 全局）
- 仅终止 MTProxy 外层混淆，MTProto 业务内容按不透明字节透传，不落盘、不记录
- 通过 `req_pq_multi → resPQ` 公网探针可独立验证加解密正确性

部署与验证见上文英文部分；`docs/` 下为完整的架构与核实报告。
