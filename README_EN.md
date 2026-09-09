# Telegram WEB Proxy — Cloudflare Workers

> Zero-cost, single-user Telegram WEB Proxy on **Cloudflare Workers Free + SQLite Durable Objects** — WebSocket carrier, MTProxy obfuscation translation, bounded multiplexed relay.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Workers](https://img.shields.io/badge/Cloudflare-Workers%20Free-orange)](https://developers.cloudflare.com/workers/)
[![Node](https://img.shields.io/badge/node-%3E%3D22-green)](https://nodejs.org)

Pinned upstream: [`telegramdesktop/tproxy-server@52a5feb7`](https://github.com/telegramdesktop/tproxy-server/tree/52a5feb7fac38f68da5afef9cedd9b3bfc8473ca) / `Telegram Desktop v7.1.2@3772337d`.

> **Current verification boundary:** local unit tests, real `workerd` carrier/session, close-handshake and protocol-error cleanup tests, pinned-source assertions, and both Wrangler dry-run entry points pass. Public `req_pq_multi → resPQ`, real Telegram Desktop text/media, 1 GB transfer, throughput, and the 24-hour soak are still pending and must not be treated as verified.

> **⚠️ Disclaimer — Cloudflare Violation Risk**
>
> This project is for **educational and research purposes only**. The authors assume no liability for any consequences. Users must ensure compliance with local laws, Telegram ToS and Cloudflare policies. **Cloudflare-specific risk: Workers used as a proxy may be flagged as abusive under Cloudflare Terms / Self-Serve Subscription Agreement, leading to throttling, suspension of Workers/routes, or account termination. This risk scales with traffic and public sharing. Use cautiously: personal low-volume self-use only, do not share publicly or use commercially, and accept that service may become unavailable at any time.** The full Chinese disclaimer in [`README.md`](README.md) shall prevail.

[中文 README](README.md) · [Architecture](#architecture) · [Deploy](#deploy) · [Cost](#cost)

---

## Why

Host a personal Telegram WEB Proxy without a VPS, containers, or paid backends.

- **$0 target** — Workers Free (100k req/day) + SQLite Durable Objects Free (100k req/day, 13k GB-s/day); final feasibility depends on real usage analytics
- **Native WEB Proxy v1** — WebSocket carrier multiplexing `OPEN / DATA / WINDOW / CLOSE`
- **Opaque data plane** — the architecture can carry text, updates, photos, video, and file bytes; real Desktop/media/1 GB E2E remains unverified
- **Privacy-preserving** — proxy only terminates the outer MTProxy layer; MTProto payloads are treated as opaque bytes, never logged or persisted

> Voice/video calls are out of scope — WEB Proxy v1 does not relay UDP.

---

## Architecture

```
Telegram Desktop (pinned WEB Proxy v1 client)
        │  HTTPS / WSS  wss://proxy.example.com/api/v1/ws  tproxy-v1.<token>
        ▼
  Cloudflare Worker  ── capability check (HMAC) + bridge page
        │
        ▼
  Relay Durable Object (SQLite)  ── single DO: personal-telegram-relay-v1
        │  WEB Proxy session │ multiplexed logical streams
        │  MTProxy outer decrypt → direct Telegram obfuscation re-encrypt (streaming AES-256-CTR)
        │
        └──► Telegram DC1–DC5 official WSS /apiws
             host map: shared/telegram-dc.js   Sec-WebSocket-Protocol: binary
```

**Worker** = routing + bridge capability + bootstrap/session + WSS upgrade.  
**RelayDO** = long-lived state (stream windows, CTR ciphers, tombstones) + outbound Telegram WSS.

Single DO billing: `0.128 GB × 86 400 s = 11 059 GB-s/day` → **85% of the Free 13 000 GB-s/day** budget.

---

## Features

- **Bridge compatibility** — canonical hostname + HMAC capability, with the rule owned by [`app/src/capability.js`](app/src/capability.js) (plain 16-byte and `dd`+16-byte secrets)
- **Secure handshake** — 256-bit CSPRNG bootstrap/session tokens, constant-time comparison, `no-store` / `no-cache`, CSP `nonce` bridge page
- **Bounded relay** — 32 streams/session; DO-wide 32 MiB/32K-item pending and outstanding budgets; 4 MiB/4K-item pending per direction and a 4 MiB initial window per stream; 64 KiB DATA chunks; 2 MiB carrier hard max
- **Streaming crypto** — 4 independent AES-256-CTR contexts per stream; never resets CTR on `DATA` boundaries; arbitrary fragmentation safe
- **Resilience** — a bounded session-wide used-ID bitmap (up to 2 MiB), recent tombstones, per-stream failure isolation, carrier `1002` on protocol violation, four concurrent dials and at most 256 cancellable queued dials
- **Lifecycle-aware** — bounded bootstrap/session registries and whole-session rebuild after carrier close or error

---

## Quick Start

### 1. Prerequisites

- Node.js ≥ 22, Wrangler 4, and a Cloudflare Free account

### 2. Install

```bash
git clone <your-repo> telegram-web-proxy
cd telegram-web-proxy/app
npm ci
npm test          # protocol / MTProxy / relay / carrier / config tests
npm run test:runtime # real workerd session, close and protocol-error tests
```

### 3. Configure secret

Generate a 16-byte secret (32 hex chars) or `dd` + 16-byte for padded-intermediate:

```bash
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
# → 000102030405060708090a0b0c0d0e0f

npx wrangler secret put PROXY_SECRET --config ../wrangler.toml
# paste the hex string (dd + 32 hex is also accepted)
```

> Secret never touches source. Compute the capability with the canonical module shown below.

### 4. Deploy (Free)

```bash
npm run deploy:dry   # validate the bundle, root config, and RELAY binding
npm run deploy       # → https://telegram-web-cloudflare-workers.<your-subdomain>.workers.dev
```

For Workers Builds, use the repository root, build command `npm --prefix app ci`, and deploy command `npm --prefix app run deploy`. After the initial deployment, set `PROXY_SECRET` under the Worker’s **Settings → Variables & Secrets** and save/deploy. Build variables and secrets are build-only and do not configure the runtime. [Cloudflare configuration](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/)

Custom domain: add a Cloudflare zone route — domain cost is outside the `$0` infra constraint.

### 5. Verify

```bash
curl https://<your-host>/healthz  # liveness only
curl https://<your-host>/readyz   # runtime secret + RELAY readiness; 503 if unavailable
TASK_PROXY_SECRET=<same-hex> TASK_PROXY_HOST=<your-host> npm run probe
# equivalent: TASK_PROXY_SECRET=<same-hex> npm run probe -- https://<your-host>
# expect: {"result":"public-respq-pass", ...}
```

The probe uses abridged for a plain secret and padded-intermediate for a `dd` secret. It validates the resPQ structure and nonce for this DC2 media (`-2`) connection. A pass does not replace real Desktop, other DCs, media, reconnect or soak verification.

---

## Use with Telegram Desktop

> The steps below are experimental. A real Desktop text/media/file E2E pass has not yet been recorded.

1. Complete readiness and the public data-plane probe.
2. In Telegram Desktop: **Settings → Data and Storage → Proxy → Add Proxy → WEB Proxy** → enter the hostname and the same secret.
3. The client must load the bridge and initialize its trusted MessagePort or injected WebView boundary. Only then does the bridge create the session and WebSocket.

Opening a bridge URL in a standalone browser is a diagnostic step; an idle blank tab does not establish a proxy connection. Real Desktop verification remains required.

> Baseline: **Telegram Desktop v7.1.2**.

---

## Configuration

| Variable | Where | Purpose |
|---|---|---|
| `PROXY_SECRET` | `wrangler secret` | 32 hex or `dd`+32 hex — the only credential |
| `RELAY_DEBUG` | `wrangler vars / env` | `"1"` enables verbose relay logs (`wrangler tail`) |

The root [`wrangler.toml`](wrangler.toml) is the only Wrangler configuration; deployment, development, runtime tests, and CI explicitly consume it.

The Worker deliberately uses the standard WebSocket API: active AES-CTR state is memory-only and is never resumed through Durable Object hibernation.

---

## Development

```bash
npm --prefix app test
npm --prefix app run test:runtime
npm --prefix validation test
npm --prefix app run lint
npm --prefix app run dev  # → http://127.0.0.1:8792
```

The bridge implementation is in `app/src/bridge.js`; session creation has a 90-second total deadline and aborts when the client closes. Server session body reads have a 10-second deadline and recheck bootstrap validity before committing.

Tracked executable evidence lives in `app/test/`, `app/runtime-test/`, and `validation/test/`.

---

## Cost

| Resource | Free quota | This project |
|---|---|---|
| Workers requests | 100k / day | HTTP requests and WebSocket upgrades; WebSocket messages are not Worker requests |
| Durable Objects requests | 100k / day | incoming WebSocket messages use the 20:1 billing ratio; actual batching determines usage |
| Durable Objects duration | 13k GB-s / day | One 128 MB DO all day = 11.06k (85%) |

---

## Security Model

- Secrets and tokens: CSPRNG; SHA-256 lookup keys; raw session token only in the response and active memory
- Capability: `timingSafeEqual` + canonical hostname
- Host canonicalization: `domainToASCII`, reject IPs
- Frame validation: immediate `1002` on violation
- No payload persistence
- Invocation logs containing full request URLs are disabled because capability is a query parameter
- DO-wide pending/outstanding byte+item budgets, bounded registries, and dial concurrency limits
- Bridge CSP: `default-src 'none'`, `script-src 'nonce-…'` etc.

---

## Limitations

- No voice/video calls, single-user, no `ee` secrets
- Shared PING/PONG remain codec constants; the carrier does not emit PING and rejects unsupported stream-zero controls
- No cipher recovery through hibernation; eviction or carrier loss requires a new session. Upstream `1006` closes its logical stream
- Cloudflare outbound WebSocket `send()` exposes no drain/ack signal; application memory is bounded, but large-file reliability still requires a real soak
- Public `resPQ`, Desktop, media, performance, quota, and 24-hour gates remain unverified

---

## Docs

- `app/test/` — Node unit and regression specifications
- `app/runtime-test/` — real Workers runtime carrier/session specification
- `validation/test/` — pinned-upstream, Cloudflare probe, and config-parity specifications
- `app/src/capability.js` — production source of truth for capability and public-host rules
- `shared/telegram-dc.js` — source of truth for Telegram DC-to-WSS host mapping
- root `wrangler.toml` — the only deployment, development, runtime-test, and CI contract

## License

MIT — see [LICENSE](LICENSE).
