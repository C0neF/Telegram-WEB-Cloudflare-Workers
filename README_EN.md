# Telegram WEB Proxy — Cloudflare Workers

> Zero-cost, single-user Telegram WEB Proxy on **Cloudflare Workers Free + SQLite Durable Objects** — WebSocket carrier, MTProxy obfuscation translation, bounded multiplexed relay.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Workers](https://img.shields.io/badge/Cloudflare-Workers%20Free-orange)](https://developers.cloudflare.com/workers/)
[![Node](https://img.shields.io/badge/node-%3E%3D18-green)](https://nodejs.org)

Pinned upstream: [`telegramdesktop/tproxy-server@52a5feb7`](https://github.com/telegramdesktop/tproxy-server/tree/52a5feb7fac38f68da5afef9cedd9b3bfc8473ca) / `Telegram Desktop v7.1.2@3772337d`.

> **⚠️ Disclaimer — Cloudflare Violation Risk**
>
> This project is for **educational and research purposes only**. The authors assume no liability for any consequences. Users must ensure compliance with local laws, Telegram ToS and Cloudflare policies. **Cloudflare-specific risk: Workers used as a proxy may be flagged as abusive under Cloudflare Terms / Self-Serve Subscription Agreement, leading to throttling, suspension of Workers/routes, or account termination. This risk scales with traffic and public sharing. Use cautiously: personal low-volume self-use only, do not share publicly or use commercially, and accept that service may become unavailable at any time.** The full Chinese disclaimer in [`README.md`](README.md) shall prevail.

[中文 README](README.md) · [Architecture](#architecture) · [Deploy](#deploy) · [Cost](#cost)

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
curl https://<your-host>/healthz
TASK_PROXY_SECRET=<same-hex> npm run probe
# expect: {"result":"public-respq-pass", ...}
```

The probe performs `OPEN → MTProxy init → req_pq_multi → resPQ` through your own carrier.

---

## Use with Telegram Desktop

1. Open `https://<your-host>/?bridge=<capability>` in a browser.
   ```js
   import { createHmac } from 'node:crypto';
   const cap = createHmac('sha256', Buffer.from(secretHex,'hex'))
     .update(`tdesktop-web-proxy-bridge-v1\n${host}`).digest('base64url');
   ```
2. The bridge page negotiates `tproxy-v1.<session-token>` over `wss://<host>/api/v1/ws`.
3. In Telegram Desktop: **Settings → Data and Storage → Proxy → Add Proxy → WEB Proxy** → enter `<host>` and the same secret.

> Baseline: **Telegram Desktop v7.1.2**.

---

## Configuration

| Variable | Where | Purpose |
|---|---|---|
| `PROXY_SECRET` | `wrangler secret` | 32 hex or `dd`+32 hex — the only credential |
| `RELAY_DEBUG` | `wrangler vars / env` | `"1"` enables verbose relay logs (`wrangler tail`) |
| `USE_HIBERNATION` | DO env | `"1"` opts into hibernation API |

---

## Development

```bash
npm --prefix app test
npm --prefix validation test
npm --prefix app run dev  # → http://127.0.0.1:8792
```

Project layout: `app/src/{index,protocol,mtproxy,relay,mtproto-probe}.js` + `validation/` + `docs/`

---

## Cost

| Resource | Free quota | This project |
|---|---|---|
| Workers requests | 100k / day | carrier batch 2 MiB → ~25k at 100 Mbps |
| Durable Objects requests | 100k / day | WebSocket 20:1 billed, inbound only |
| Durable Objects duration | 13k GB-s / day | One 128 MB DO all day = 11.06k (85%) |

---

## Security Model

- Secrets and tokens: CSPRNG, hashed with SHA-256, never logged
- Capability: `timingSafeEqual` + canonical hostname
- Host canonicalization: `domainToASCII`, reject IPs
- Frame validation: immediate `1002` on violation
- No payload persistence
- Bridge CSP: `default-src 'none'`, `script-src 'nonce-…'` etc.

---

## Limitations

- No voice/video calls, single-user, no `ee` secrets

---

## Docs

- `docs/architecture.md`, `docs/verification.md`, `COMPLETE_PRODUCT_GOAL.md`, `app/test/`

## License

MIT — see [LICENSE](LICENSE).
