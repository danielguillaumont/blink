# Dashboard and API (`blink serve`)

```bash
python -m pip install "blink-checkout[server]"
blink serve                       # http://127.0.0.1:8765, API docs at /docs
blink serve --port 9000
```

A FastAPI app with server-rendered Jinja2 pages and [htmx](https://htmx.org) (vendored, no build
step). The Blink 1.0 Streamlit compare workspace (`app.py`) is unchanged and separate.

| Page | What it shows |
|---|---|
| **Targets** (`/`) | Each target and profile: baseline snapshot, last run, status, max severity, open alerts |
| **Runs** (`/runs`, `/runs/{id}`) | The run timeline, and each run's per-target results and findings |
| **Finding** (`/findings/{run}/{id}`) | "Why it matters"; baseline vs current payment-region screenshots with the Blink overlay and heatmap; script or DOM diff; static-analysis factors; header diff; HAR excerpt (query strings removed); raw evidence |
| **Inventory** (`/inventory`) | Every script with its approval state; approve and justify inline (writes `blink.inventory.yaml` and the ledger) |
| **Alerts** (`/alerts`) | Acknowledge, resolve, accept a change (rebaselines; a note is required), reopen |
| **Settings** (`/settings`) | The effective `blink.yaml`, read-only, with webhook URLs redacted |

Also: `/healthz`, `/metrics` (Prometheus, see [operations.md](operations.md)) and the JSON
API under `/api/` (OpenAPI at `/openapi.json`, Swagger UI at `/docs`).

## Security model

- **Loopback by default.** `blink serve` binds to `127.0.0.1`. With `--host` set to any other
  address, every page also needs a login (`/login`, which sets an HttpOnly, `SameSite=Strict`
  session cookie). Put it behind TLS if you do that.
- **Bearer token for every change.** Every non-GET endpoint needs
  `Authorization: Bearer <token>`. The token is created by `blink init` in `.blink/blink.token`
  (mode 0600, git-ignored), or set with `$BLINK_TOKEN`. In the browser, click **Unlock** and
  paste it: it is kept in `sessionStorage` for that tab and added to requests by
  `static/blink.js`.
- **CSRF.** Browser requests must echo the double-submit CSRF token (an HttpOnly,
  `SameSite=Strict` cookie plus the `X-CSRF-Token` header). API clients without cookies need
  only the bearer token.
- **Strict CSP and headers on every response:** `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self';
  frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, plus HSTS, `X-Frame-Options:
  DENY`, `nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and
  `Cache-Control: no-store`. There are no inline scripts or styles; htmx runs with `allowEval`
  off. Blink passes its own header detector (`tests/test_server_e2e.py`, the dogfood test).
- `/docs` serves Swagger UI 5.17.14 from `/static` (vendored, Apache-2.0), pinned with SRI
  hashes. Nothing is loaded from a CDN, so the dashboard works fully offline.
- Evidence is served only as PNG images. Captured scripts are never served (they could run
  under `script-src 'self'`); diffs are rendered as escaped text.

## API examples

```bash
TOKEN=$(cat .blink/blink.token)
curl -s http://127.0.0.1:8765/api/alerts?state=open
curl -s -X POST http://127.0.0.1:8765/api/alerts/3f2a9c1d0e4b5a67/ack \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"by": "alice", "note": "investigating"}'
curl -s -X POST http://127.0.0.1:8765/api/inventory/cdn-example-tag-js/approve \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"justification": "Tag manager", "owner": "marketing", "approved_by": "alice", "dynamic": true}'
curl -s http://127.0.0.1:8765/api/ledger        # verification result
```
