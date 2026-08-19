# ARGUS API Reference

Covers every HTTP endpoint ARGUS exposes: the core detection API (`/detect`,
`/explain`, `/health`), auth + vault (Phase 8), and the Phase 2 platform
surfaces (`/scan`, `/v1/*`, API-key management). Every response includes
`latency_ms` (Iron Law #4). Every error response is `{"error": "<message>"}`.

**Risk bands (Phase 3, F5):** wherever a response includes `risk_score`
(0.0-1.0), it also includes `risk_band` — one of `"low"`, `"caution"`,
`"suspicious"`, `"high"`, `"critical"`. Bands are calibrated against real
validation-set phishing rates (see `scripts/calibrate_risk_bands.py` and
`reports/risk_band_calibration.json`), not invented; the `"suspicious"`
floor (0.30) intentionally equals the model's calibrated decision threshold
(DEC-017), so `risk_band` and the binary `label`/`verdict` never disagree —
`label == "phishing"` iff the band is `suspicious`, `high`, or `critical`.
`risk_score`/`risk_band` are additive fields: the pre-Phase-1 fast path
(`/detect` with `enrich: false`, or with the detection layer disabled)
never includes them, preserving that response's exact legacy shape.

---

## Conventions

- **Content type:** `application/json` for all requests/responses.
- **Auth tiers:**
  - *Public, unauthenticated:* `/detect`, `/explain`, `/health`, `/scan`, `/scan/<id>`, `/v1/health`.
  - *User JWT (`Authorization: Bearer <access_token>`):* `/auth/*`, `/vault`, `/auth/api-keys*`.
  - *API key (`Authorization: Bearer argus_<key>`):* `/v1/scan`, `/v1/scan/batch`, `/v1/explain`.
- **Rate limits:** enforced via `flask-limiter`. `memory://` storage in dev; point `configs/api_config.yaml -> rate_limit_storage_uri` at `redis://...` for multi-worker production (required before `/scan`/`/v1/*` are exposed publicly — see DEC-025/DEC-027).

---

## Core Detection API

### `POST /detect`

```json
// Request
{"url": "https://example.com", "enrich": false}

// Response (enrich=false)
{"url": "...", "label": "phishing", "confidence": 0.92, "verdict": "phishing", "source": "model", "latency_ms": 12.3}

// Response (enrich=true, detection fusion layer enabled — Phase 1/2/3)
{
  "url": "...", "label": "phishing", "confidence": 0.98, "verdict": "phishing",
  "source": "favicon_match", "risk_score": 0.98, "risk_band": "critical",
  "signals": [{"name": "favicon_match", "triggered": true, "score": 0.99, "direction": "phishing", "evidence": {...}}],
  "latency_ms": 812.4
}
```

`enrich=false` (default) is hostname-only, no page fetch. `enrich=true` fetches the page and runs the full detection fusion layer: typosquat/homograph (A3), favicon/logo match (A2), brand-vs-domain mismatch (A1), TLS certificate intelligence (A4), redirect-chain unwrapping (A5), credential-harvesting taxonomy (F4), free/shared-hosting-platform risk awareness (F3), social-engineering content taxonomy (F17). `source` reflects what decided the label: `"model"`, `"phishtank"` or `"gsb"` (threat-intel pre-filter — `"gsb"` only appears when Google Safe Browsing is configured, see F6/DEC-035), `"fusion"` (weighted combination), or a specific signal name (a hard override, e.g. an exact favicon-hash match). Results are cached (short TTL, `configs/api_config.yaml -> cache`) — see G1.

### `POST /explain`

```json
// Request
{"url": "https://example.com"}

// Response
{
  "url": "...", "top5_features": [{"feature": "domain_age_cat", "shap_value": 0.21, "feature_value": -1}],
  "signals": [...], "risk_score": 0.62, "risk_band": "high",
  "plain_explanation": "Flagged as phishing because ...", "latency_ms": 934.1
}
```

Always fully enriches. `plain_explanation` is a deterministic, human-readable sentence composed from SHAP + triggered signals (Phase 1, B2).

### `GET /health`

```json
{"status": "ok", "model_loaded": true, "latency_ms": 1.1}
```

---

## Public Scan Web App (Phase 2, C1; Phase 4, F11/F13)

Backs the self-contained web app at `/app/` (`webapp/index.html`, `webapp/scan.html`) — scan a URL without an account or the browser extension. An account is entirely optional: signing in via `webapp/login.html` (reusing the `/auth/*` endpoints below) unlocks a per-user scan history at `webapp/dashboard.html`, with export.

### `POST /scan`

Always fully enriched, full URL. Persists a shareable report.

```json
// Request
{"url": "https://example.com"}

// Response (201)
{
  "scan_id": "s_9fJ2kQ7xB3", "url": "...", "label": "legitimate", "confidence": 0.91,
  "risk_score": 0.12, "risk_band": "low", "signals": [], "plain_explanation": "No phishing indicators found...",
  "report_url": "/app/scan.html?id=s_9fJ2kQ7xB3", "expires_at": "2026-08-15T00:00:00Z", "latency_ms": 1043.7
}
```

- **Rate limit:** `scan_rate_limit` in `api_config.yaml` (default 20/min per IP) — stricter than the global default, since this triggers a real outbound fetch of a user-supplied URL.
- **`scan_id`** is an opaque, randomly-generated token (never sequential) — prevents report enumeration.
- **Retention:** `scan_store.ttl_days` (default 7). An expired report 404s and is lazily purged on the read that discovers it.
- **Errors:** `400` invalid URL, `429` rate limited, `503` model not ready.

### `GET /scan/<scan_id>`

```json
{"scan_id": "...", "url": "...", "label": "...", "confidence": ..., "risk_score": ..., "risk_band": "...", "signals": [...], "plain_explanation": "...", "source": "...", "created_at": "...", "expires_at": "...", "latency_ms": ...}
```

Public, read-only — the report exposes only the submitted URL and verdict; no requester identity is stored. `404` for an unknown or expired id.

### `POST /scan` with `Authorization: Bearer <access_token>` — per-user history (Phase 4, F11)

`POST /scan` optionally accepts the same JWT access token used elsewhere (see Auth & Vault below). If a valid token is presented, the scan is *additionally* recorded against that account (in a separate `user_scans` table — the anonymous `scans` row above is written exactly as before, with no requester identity, regardless). An invalid, expired, or missing token never rejects the request — it's simply treated as anonymous.

### `GET /scan/history` (auth required)

```json
{"scans": [{"id": 1, "scan_id": "s_...", "url": "...", "label": "...", "confidence": ..., "risk_score": ..., "risk_band": "...", "signals": [...], "plain_explanation": "...", "source": "...", "created_at": "..."}], "latency_ms": ...}
```

The caller's own scans, newest first. `?limit=` (default 50, max 200). No separate risk-band/source-breakdown endpoint — `webapp/dashboard.html` computes those client-side from this same list.

### `GET /scan/<scan_id>/export?format=json|csv|pdf` and `GET /scan/history/<id>/export?format=json|csv|pdf` (Phase 4, F13)

Downloads the same report data as `GET /scan/<scan_id>` / a `GET /scan/history` row, serialized as JSON, CSV, or a formatted PDF (`Content-Disposition: attachment`). The first has the same no-auth permission model as `GET /scan/<scan_id>`; the second requires auth and is scoped to the caller's own history (`404`, not `403`, for another user's id — no enumeration signal). These are file downloads, not JSON API responses, so unlike every other endpoint here they don't carry `latency_ms` — no inference/enrichment work happens, only re-serialization of already-stored data.

---

## Developer API `/v1/*` (Phase 2, C3)

Versioned, API-key-authenticated, programmatic access. `POST /auth/api-keys` (below) mints a key.

**Auth header:** `Authorization: Bearer argus_<key>`. Missing/invalid/revoked → `401`.

**Rate limits:** per-API-key (not per-IP), tiered via `api_key_tiers` in `api_config.yaml` — `free: 60/min`, `pro: 600/min` by default. Requires the shared Redis rate-limit store (G2) to actually hold across multiple worker processes.

### `GET /v1/health`

No auth required.

```json
{"status": "ok", "version": "v1", "model_loaded": true, "latency_ms": 0.9}
```

### `POST /v1/scan`

Same detection core as `/detect`, stateless (no report persisted).

```json
// Request
{"url": "https://example.com", "enrich": true}

// Response
{"url": "...", "label": "legitimate", "confidence": 0.9, "verdict": "legitimate", "risk_score": 0.1, "risk_band": "low", "signals": [], "source": "model", "latency_ms": 210.5}
```

### `POST /v1/scan/batch`

```json
// Request — 1..batch_max (default 50) URLs
{"urls": ["https://a.com", "https://b.com"], "enrich": false}

// Response
{
  "results": [
    {"url": "https://a.com", "label": "legitimate", ...},
    {"url": "ftp://bad", "error": "url scheme must be http or https, got 'ftp'"}
  ],
  "count": 2, "latency_ms": 640.0
}
```

An invalid/erroring individual URL yields a per-item `{"url", "error"}` entry rather than failing the whole batch. Each URL in a batch counts individually toward the caller's per-key rate budget.

### `POST /v1/explain`

Same shape as `POST /explain`, API-key authenticated.

### `POST /v1/scan/async` (F19)

Submits a scan job and returns immediately — for callers that don't want to hold a connection open for the enriched-path latency (p95 < 1500ms), or that want a webhook callback instead of polling.

```json
// Request
{"url": "https://example.com", "enrich": true, "webhook_url": "https://your-service.example.com/hooks/argus"}

// Response — 202 Accepted
{"job_id": "job_xxxxx", "status": "queued", "latency_ms": 3.1}
```

`webhook_url` is optional. If given, it's validated the same way ARGUS validates any outbound-fetch target (`src.utils.ssrf.is_safe_fetch_url` — rejects private/loopback/link-local/CGNAT/reserved addresses) — `400` if it fails that check.

### `GET /v1/scan/async/<job_id>` (F19)

Poll for a job's status/result. `404` (not `403`) for a job that exists but belongs to another key.

```json
// While running
{"job_id": "job_xxxxx", "status": "running", "url": "...", "webhook_status": "pending", "webhook_attempts": 0, "created_at": "...", "completed_at": null, "latency_ms": 1.2}

// Once completed — same result shape as POST /v1/scan
{"job_id": "job_xxxxx", "status": "completed", "url": "...", "result": {"label": "legitimate", "confidence": 0.9, ...}, "webhook_status": "delivered", "webhook_attempts": 1, "created_at": "...", "completed_at": "...", "latency_ms": 1.4}

// Once failed
{"job_id": "job_xxxxx", "status": "failed", "url": "...", "error": "...", "webhook_status": null, ...}
```

**Webhook delivery.** When the job finishes, ARGUS `POST`s the same payload shape (`{"job_id", "status", "url", "result"|"error", "completed_at"}`) to `webhook_url`, signed with an `X-Argus-Signature: sha256=<hex>` header — an HMAC-SHA256 of the exact raw request body, keyed by the caller's `webhook_secret` (shown once at key-mint time, below). Verify it the same way GitHub/Stripe-style webhooks are verified: recompute the HMAC over the raw body you received and compare.

Delivery retries up to `webhook_delivery.max_attempts` times (default 3, with a short fixed backoff) — all in-process, no persistent retry queue. If every attempt fails, `webhook_status` becomes `"failed"` and ARGUS does **not** keep retrying later; the job's result is still available via this same `GET` endpoint regardless of webhook outcome, so a caller whose endpoint was briefly down never loses data — it just needs to poll instead.

---

## API Key Management (Phase 2, C3)

JWT-authenticated (`Authorization: Bearer <access_token>` from `/auth/login`). Every route is scoped to the caller's own keys (`g.user_id`) — a key belonging to another user 404s, not 403 (avoids confirming existence to a non-owner, matching the vault's IDOR-safe pattern).

### `POST /auth/api-keys`

Mints a new key. **The raw key — and `webhook_secret` (F19), used to sign `/v1/scan/async` webhook payloads — are shown exactly once, in this response** — neither is ever retrievable again.

```json
{"api_key": "argus_9fJ2kQ...", "key_prefix": "argus_9fJ2", "tier": "free", "webhook_secret": "...", "created_at": "...", "latency_ms": ...}
```

### `GET /auth/api-keys`

Lists the caller's own keys — metadata only, never the raw value.

```json
{"keys": [{"key_prefix": "argus_9fJ2", "tier": "free", "revoked": false, "created_at": "...", "last_used_at": "..."}], "latency_ms": ...}
```

### `DELETE /auth/api-keys/<key_prefix>`

Revokes one of the caller's own keys.

```json
{"revoked": true, "latency_ms": ...}
```

---

## SDKs

Thin, dependency-minimal clients wrapping `/v1/*` — see `sdk/python/argus_client.py` and `sdk/js/argus-client.js`. Not published as packages; vendor the file directly.

```python
from argus_client import ArgusClient
client = ArgusClient(api_key="argus_...", base_url="https://argus.example.com")
result = client.scan("https://example.com")
```

```javascript
import { ArgusClient } from "./argus-client.js";
const client = new ArgusClient({ apiKey: "argus_...", baseUrl: "https://argus.example.com" });
const result = await client.scan("https://example.com");
```

### CLI (Phase 3, F12)

`sdk/python/argus_cli.py` wraps `argus_client.py` for shell/CI use — copy both files together. API key and base URL come from `--api-key`/`--base-url` flags or the `ARGUS_API_KEY`/`ARGUS_BASE_URL` environment variables.

```bash
export ARGUS_API_KEY=argus_...
python argus_cli.py scan https://example.com
python argus_cli.py scan https://example.com --enrich --format json
python argus_cli.py scan-batch urls.txt --format csv --output report.csv
python argus_cli.py explain https://example.com
python argus_cli.py health   # no API key required
```

Exit codes are CI-gate-friendly: `0` — ran, nothing flagged; `1` — ran, at least one URL flagged as phishing; `2` — couldn't run at all (missing key, bad input, API error).

---

## Auth & Vault (Phase 8 — unchanged by Phase 1/2)

See `docs/DECISIONS.md` DEC-009/DEC-021/DEC-022/DEC-024 for full history. Endpoints: `POST /auth/signup`, `POST /auth/verify-otp`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /vault`, `PUT /vault`.

---

## Error Codes

| Code | Meaning | Applies to |
|---|---|---|
| `400` | Invalid request body / URL | all URL-taking endpoints |
| `401` | Missing/invalid JWT or API key | `/v1/*`, `/auth/api-keys*`, `/vault` |
| `404` | Unknown/expired resource, or a resource not owned by the caller | `/scan/<id>`, API key management |
| `409` | Version conflict | `/vault` |
| `429` | Rate limit exceeded | all rate-limited endpoints |
| `503` | Model not ready, or the Redis rate-limit backend is unreachable | `/detect`, `/explain`, `/scan`, `/v1/*`, any rate-limited route |
