# SGProxy

> **SGProxy is a stripped-down version of [gproxy](https://github.com/LeenHawk/gproxy)**, keeping only ClaudeCode single-channel + native Anthropic format. Need multi-channel (Codex, OpenAI, etc.) or format conversions? Use the full-featured **[gproxy](https://github.com/LeenHawk/gproxy)**.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/leenhawk)

A ClaudeCode credential gateway built on Cloudflare Workers + Durable Objects, with OAuth import, credential rotation, quota inspection, and header-only `/v1/*` proxying.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/LeenHawk/sgproxy)

The Deploy Button reads [`.dev.vars.example`](/home/linhuan/develop/sgproxy/.dev.vars.example) and will prompt for the required `ADMIN_TOKEN` secret during setup.

[中文](./README.md)

## Features

- **ClaudeCode only** — Anthropic ClaudeCode proxy only
- **Header-only forwarding** — request/response bodies pass through untouched
- **OAuth import** — OAuth2 + PKCE credential import
- **Auto refresh** — refresh before expiry, mark invalid credentials as `dead`
- **Quota tracking** — 5h / 7d / 7d Sonnet usage windows
- **429 rotation** — no replay for the current request, only switch later requests
- **Admin UI** — embedded web UI with Chinese / English support
- **Public usage page** — inspect credential state without login

## Tech Stack

- **Runtime**: Cloudflare Workers + Durable Objects (SQLite)
- **Language**: Rust -> WebAssembly
- **Build**: generate `build/` locally with `worker-build`; the Deploy Button uses committed build artifacts

## Quick Start

Look at Cloudflare button.

## Development

### Prerequisites

- [Rust](https://rustup.rs/) toolchain
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- Cloudflare account

### Local Development

```bash
git clone <repo-url> && cd sgproxy
echo 'ADMIN_TOKEN=your-secret-token' > .env
wrangler dev
```

Open `http://localhost:8787/`.

### Deploy

```bash
worker-build --release
wrangler deploy
```

If you did not use the Deploy Button prompt, set the `ADMIN_TOKEN` secret in Cloudflare Dashboard.

## Usage

### Add Credentials

1. **OAuth import** — use the `OAuth` tab in the admin page
2. **JSON import** — paste:
   ```json
   {
     "access_token": "sk-...",
     "refresh_token": "sk-..."
   }
   ```
3. **API import**
   ```bash
   curl -X POST https://your-worker.dev/api/credentials \
     -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"access_token":"sk-...","refresh_token":"sk-..."}'
   ```

### Proxy Requests

Point your client at:

- `https://your-worker.dev/v1/...`

The gateway overwrites upstream `authorization` and ensures the required Anthropic headers.

### Pages

- `/` admin page
- `/usage` public usage page

## API Endpoints

### Proxy

| Method | Path | Description |
|--------|------|-------------|
| ANY | `/v1/*` | Proxy ClaudeCode requests |

### Admin

Supports `Authorization: Bearer <ADMIN_TOKEN>` and `x-api-key: <ADMIN_TOKEN>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/public/credentials` | Public credential usage |
| GET | `/api/credentials` | List credentials |
| POST | `/api/credentials` | Import credentials |
| PUT | `/api/credentials/{id}` | Update credentials |
| DELETE | `/api/credentials/{id}` | Delete credentials |
| POST | `/api/credentials/{id}/enable` | Enable credential |
| POST | `/api/credentials/{id}/disable` | Disable credential |
| GET | `/api/credentials/usage` | List usage |
| GET | `/api/credentials/usage/{id}` | Get usage for one credential |
| POST | `/api/oauth/start` | Start OAuth |
| POST | `/api/oauth/callback` | Complete OAuth |

## Project Structure

```text
src/
├── lib.rs
├── do_state.rs
├── config.rs
├── proxy.rs
├── oauth.rs
├── state.rs
└── web/
    └── index.html
```

## Community Discusion
Thanks to the technical feedback from enthusiasts on [V2EX](https://www.v2ex.com/t/1200134#reply0), [Linux.do](https://linux.do/), and other communities.