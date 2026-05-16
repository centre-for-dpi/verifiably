# Branch Summary: `add-credebl`

> **Base:** `main` → **Head:** `add-credebl`
> **Commits:** 55 · **Files changed:** 75 · **Lines:** +13 371 / −1 357
> **Last updated:** 2026-05-16

---

## Goal

Integrate **CREDEBL** as a third DPG (Digital Public Good) into verifiably-go,
along with the production infrastructure needed to run all three backends
(walt.id, Inji Certify, CREDEBL) under a single domain with TLS,
automatic subdomains, and reproducible deployment from a single command.

---

## 1. New adapter: CREDEBL

### Package `internal/adapters/credebl/`

| File | Responsibility |
|------|---------------|
| `adapter.go` | HTTP client bootstrap; CREDEBL session management; `isTransient` with anti-double-issuance protection; `sfGroup` singleflight. |
| `config.go` | OID4VCI config resolution (issuer ID, credential template ID, DID). |
| `issuer.go` | OID4VCI issuance via CREDEBL API: credential creation, offer URL, acceptance polling. Singleflight on `resolveTemplateID` to avoid duplicate writes under load. |
| `verifier.go` | OID4VP via CREDEBL: verification request creation, SD-JWT field extraction from `vp_token`, deterministic routing by state. |
| `adapter_test.go` | Test suite: SD-JWT extraction, `isTransient` logic, OID4VP routing. |

### Technical highlights

- **Singleflight** (`sfGroup`/`sfCall`): stdlib-only implementation (no `golang.org/x/sync`) that collapses concurrent calls to `resolveTemplateID`. Prevents race conditions under issuance bursts.
- **`isTransient`**: `context.DeadlineExceeded` and `context.Canceled` are NOT retryable (double-issuance risk). `net.OpError` IS retryable. HTTP 5xx also retryable.
- **DPoP**: domain URL extracted from `VERIFIABLY_PUBLIC_URL` so DPoP tokens are valid externally.
- **SD-JWT extraction**: supports `vp_token` as string and as JSON array; extracts claims from tilde-separated disclosures.

---

## 2. Multi-vendor routing

### `internal/adapters/registry/`

- `registry.go`: `schemaID → adapter` routing table; supports walt.id, Inji Certify, Inji Certify Pre-auth, and CREDEBL on the same server.
- `registry_test.go`: test suite for multi-vendor OID4VP (same request, different backends).

---

## 3. REST API and handlers

### New endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/issue` | Issuance (all backends) |
| `POST` | `/api/v1/bulk/issue` | Bulk issuance CSV |
| `GET`  | `/api/v1/bulk/status/:id` | Bulk job status |
| `GET`  | `/api/v1/bulk/progress/:id` | Real-time SSE progress |
| `GET`  | `/api/v1/credentials` | Listing with filters |
| `POST` | `/api/v1/credentials/:id/revoke` | Revocation |
| `POST` | `/api/v1/credentials/:id/reinstate` | Reinstatement |
| `POST` | `/api/v1/verify` | Start OID4VP |
| `GET`  | `/api/v1/verify/:state` | Poll verification result |
| `GET`  | `/metrics` | Prometheus text (protected by API key) |
| `GET`  | `/openapi` | OpenAPI 3.0 spec + Scalar UI |

### `internal/handlers/ratelimit.go` (new)

Per-IP rate limiter with trusted proxy whitelist. `VERIFIABLY_TRUSTED_PROXIES` (list of CIDRs) controls when `X-Forwarded-For` is trusted. Without a list, the direct IP is used (backwards-compatible). Prevents IP spoofing in rate limiting.

### `internal/handlers/session.go`

Exports `SessionEncrypt` / `SessionDecrypt` (AES-256-GCM) so the PG and Redis backends reuse exactly the same encryption as the file store. Adds `SessionStore` interface to decouple the store from the handler.

---

## 4. New packages

### `internal/jobs/` — Bulk issuance queue

```
queue.go       Async job queue; non-blocking Submit; configurable worker pool
queue_test.go  6 tests (happy path, errors, SSE, cancel, full, shutdown abort)
```

- Submit returns immediately (`HTTP 202`); if the 256-slot buffer is full, cleans up the entry and returns an error.
- Workers receive the shutdown `context.Context`: on SIGTERM, they mark the job as error with `"server shutdown"`.
- Cleanup loop: deletes `bulk_jobs` rows with `status IN ('done','error')` older than 7 days, every hour.
- Dual backend: PostgreSQL when a pool is available; in-memory for dev/test.

### `internal/metrics/` — Prometheus text-format

```
metrics.go       Registry; Counter, Gauge, Histogram; labStr with anti-injection escaping
metrics_test.go  Label escaping tests (\n \r " \)
```

Label values escape `\n`, `\r`, `"`, and `\` to prevent false line injection in the `/metrics` endpoint.

### `internal/tracing/` — W3C traceability

```
tracer.go       Span, SpanContext, Sampler; SpanFromContext / ContextWithSpan
exporter.go     OTLPJSONExporter (HTTP POST to Grafana Tempo/Jaeger); SlogExporter
propagation.go  Extract/Inject W3C traceparent (RFC 9180)
middleware.go   HTTP middleware that starts spans and propagates trace_id to logger
global.go       Global tracer; safe to use from handlers without injection
```

- `Inject` propagates `traceparent` with `flags=00` for unsampled spans — downstream services maintain the same `trace_id` for log correlation.
- `Shutdown` uses `sync.Once` to be idempotent (safe for multiple calls).
- Stackable exporters: OTLP active when `VERIFIABLY_OTEL_ENDPOINT` is set; SlogExporter always active (one structured line per span).

### `internal/storage/` — Persistent backends

```
pg/db.go          Open pool + runMigrations (DDL auto-applied)
pg/sessions.go    PG SessionStore with AES-256-GCM
pg/issuance.go    PG IssuanceLog; hash chain integrity; PII excluded
pg/statuslist.go  Token Status List store in PG
redis/client.go   Client wrapper with configurable TLS and timeout
redis/sessions.go Redis SessionStore with AES-256-GCM
```

AES key derived via `sha256.Sum256([]byte(VERIFIABLY_SESSION_SECRET))[:]` — same algorithm across all three backends (file, PG, Redis).

---

## 5. Deploy infrastructure

### `deploy.sh` → modular `scripts/`

| Script | Responsibility |
|--------|---------------|
| `scripts/common.sh` | `.env` loading; `url_for`, `bold/green/red/yellow` helpers; defaults for all variables. |
| `scripts/gen-backends.sh` | Generates `config/backends.json` and `auth-providers.*.json` per scenario. |
| `scripts/start-container.sh` | Build + run of `verifiably-go` as a Docker container. |
| `scripts/bootstrap-credebl.sh` | Full CREDEBL bootstrap: Keycloak realm, platform-admin, DID, OID4VCI issuer, credential template, container patches. |
| `scripts/gen-caddy.sh` | Generates `Caddyfile.public` for subdomain mode. |

`deploy.sh` acts as a pure dispatcher that sources the scripts and delegates.

### Setup wizard (`./deploy.sh setup`)

Interactive first-time configuration wizard. Writes `.env` with:
- Server IP
- Base domain (e.g. `verifiably.ysalabs.work`)
- Let's Encrypt email
- Keycloak admin password
- CREDEBL platform-admin email

### Deploy scenarios

```bash
./deploy.sh up all      # Walt.id + Inji + CREDEBL + WSO2IS + LibreTranslate
./deploy.sh up waltid   # Walt.id + Keycloak only
./deploy.sh up inji     # Inji Certify + Verify + Web + WSO2IS
./deploy.sh up credebl  # CREDEBL only
./deploy.sh status      # Summary of what is running
```

### Compose stack

- **`deploy/compose/stack/docker-compose.yml`**: adds `verifiably-pg`, `verifiably-redis`, `citizens-postgres`, profiles `injiweb`, `subdomain`, and `credebl`.
- **`deploy/compose/credebl/docker-compose.yml`**: complete stack of 18 CREDEBL microservices with isolated `credebl_*` volumes.
- **`Caddyfile.public`**: automatic TLS via Let's Encrypt for all subdomains (`*.verifiably.ysalabs.work`).

### Key new environment variables

| Variable | Description |
|----------|-------------|
| `VERIFIABLY_PUBLIC_DOMAIN` | Base domain for subdomain mode |
| `VERIFIABLY_HOSTS_PATTERN` | Pattern `https://%s.domain` for service URLs |
| `VERIFIABLY_LE_EMAIL` | Email for Let's Encrypt certificates |
| `VERIFIABLY_DATABASE_URL` | verifiably-go PostgreSQL DSN |
| `VERIFIABLY_REDIS_URL` | Redis URL for multi-replica sessions |
| `VERIFIABLY_SESSION_SECRET` | Secret for deriving AES-256-GCM key |
| `VERIFIABLY_TRUSTED_PROXIES` | Trusted proxy CIDRs (for XFF) |
| `VERIFIABLY_OTEL_ENDPOINT` | OTLP endpoint for Grafana Tempo/Jaeger |
| `VERIFIABLY_BULK_WORKERS` | Job queue workers (default: 4) |
| `CREDEBL_EMAIL` | CREDEBL platform-admin account email |
| `CREDEBL_PASSWORD` | CREDEBL password (auto-generated if empty) |

---

## 6. Security hardening (2026-05-16 review)

| Severity | Item | Fix |
|----------|------|-----|
| P0 | PII in DB | `SubjectFields` tagged `json:"-"`; `subjectJSON` nulled on PG INSERT |
| P0 | Unencrypted sessions in PG/Redis | AES-256-GCM on both backends |
| P1 | Race condition in `resolveTemplateID` | Stdlib-only singleflight |
| P1 | Blocking queue (goroutine leak) | `select/default` with cleanup |
| P1 | Prometheus metrics label injection | Escape `\n \r " \` in labels |
| P1 | XFF spoofing in rate limiter | Trusted proxy CIDR whitelist |
| P2 | Job queue without graceful shutdown | Workers respect `shutCtx` |
| P2 | TCP error as non-retryable | `net.OpError` → retryable; `DeadlineExceeded` → not |
| P2 | `OTLPJSONExporter.Shutdown` panic on double-call | `sync.Once` |
| P2 | `chainHashOf` duplicated | Exported as `issuance.ChainHashOf` |
| P3 | bulk_jobs without TTL | Cleanup loop: rows >7 days deleted hourly |
| P3 | traceparent not propagated for unsampled spans | `flags=00` per W3C spec |

---

## 7. Documentation added

| File | Content |
|------|---------|
| `TODO.md` | 2026-05-16 review: 13 P0–P3 items resolved + long-tail pending (Vault/SSM, mTLS, Docker backup, push revocation, VERIFIABLY_MODE) |
| `docs/haip-conformance.md` | HAIP (High Assurance Interop Profile) gap analysis for OID4VCI/OID4VP |
| `docs/spec-versions.md` | Pinned versions of OID4VCI, OID4VP, SD-JWT VC, W3C VC 2.0, HAIP |
| `docs/branch-summary-add-credebl.md` | This file |

---

## 8. Notable operational fixes

- **`ctx → shutCtx`** in `main.go`: the job queue received `ctx` (not defined in that scope); corrected to `shutCtx`.
- **`python3` → `grep`** in `bootstrap-credebl.sh`: `python3 open('/c/...')` does not work on Windows/Git Bash because the bash path is not a valid Windows path.
- **`bootstrap-keycloak.sh`**: supports `--skip-tls-verify` when Let's Encrypt has not yet propagated.
- **`.env` removed from git**: was accidentally tracked; the deletion is in commit `761a620`. The file was already in `.gitignore`.

---

## 9. Stack state at end of branch

```
Containers (docker compose ls):
  waltid: 52 services (walt.id + Inji + CREDEBL + verifiably-go)

Public access (subdomain mode):
  https://verifiably.verifiably.ysalabs.work   ← verifiably-go
  https://keycloak.verifiably.ysalabs.work     ← Keycloak
  https://credebl.verifiably.ysalabs.work      ← CREDEBL API gateway + agent
  https://walt-issuer.verifiably.ysalabs.work  ← walt.id issuer-api
  https://walt-wallet.verifiably.ysalabs.work  ← walt.id wallet-api
  https://walt-verifier.verifiably.ysalabs.work ← walt.id verifier-api
  https://inji-web.verifiably.ysalabs.work     ← Inji Web UI
  https://esignet.verifiably.ysalabs.work      ← eSignet OIDC
  https://wso2.verifiably.ysalabs.work         ← WSO2IS
```

---

## 10. Long-tail pending (not in this branch)

| Tag | Item |
|-----|------|
| `[SEC]` | Integrate with Vault KV v2 / AWS SSM for CREDEBL credentials and API keys |
| `[OPS]` | mTLS between verifiably-go and DPG backends |
| `[OPS]` | Automatic Docker volume backup to S3/GCS |
| `[ARCH]` | Push revocation notification to holder (webhook / OID4VC Notification) |
| `[ARCH]` | Resolve Docker socket risk of CREDEBL (static agents) |
| `[ARCH]` | Separate UI and API: `VERIFIABLY_MODE=ui\|api\|all` |
