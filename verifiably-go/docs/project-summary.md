# Project Summary — Verifiable Credentials Ecosystem
*verifiably-go · Status presentation · May 18, 2026*

---

## Executive Summary

We built a complete platform for issuing and verifying W3C Verifiable Credentials
(OID4VC) targeting digital government ecosystems. The platform scales from a
single standalone deployment to a **federated ecosystem of N ministries** with a
central Hub operating the trust infrastructure and a citizen-facing verification
portal — no vendor lock-in, no proprietary wallet, privacy by design.

The project was delivered in three stages on the `federated-issuance` branch
(99 commits, ~7,000 lines of Go code and ~3,000 lines of configuration/infrastructure).

---

## 1. Starting point — `main` baseline

The `main` codebase already had:

| Component | Status |
|---|---|
| DPG adapters | walt.id, Inji Certify, Inji Verify, Inji Web |
| Unified `backend.Adapter` interface | Complete — swap vendors without touching the UI |
| OIDC sign-in | Keycloak + WSO2 IS |
| Translation | LibreTranslate (English / French / Spanish) |
| Deployment | `deploy.sh` — interactive wizard, TLS subdomains via Caddy |

What **did not exist**: CREDEBL, Trust Registry, metrics, PostgreSQL persistence,
headless API, or any federation component.

---

## 2. Stage 1 — CREDEBL Integration + Codebase Maturity (`add-credebl`)

### CREDEBL adapter
- OID4VCI pre-auth issuance + OID4VP verification with DCQL
- Fully automated bootstrap: Keycloak realm, platform-admin, DID, issuer,
  credential template — zero manual steps
- 18 microservices orchestrated with a single command: `./deploy.sh up credebl`

### Trust Registry (Option A — JWT ES256)
- `GET /trust-registry` → ES256-signed JWT with the list of trusted issuers
- `GET /.well-known/jwks.json` → public key for external verification
- Storage: PostgreSQL (+ in-memory fallback for dev)
- Upgrade path to OpenID Federation 1.0 with no interface changes

### Observability and quality
- **Prometheus + Grafana**: issuance/verification counters, per-adapter latency
  histograms, 6 real-time metric panels
- **stdlib-only OpenTelemetry**: W3C traceparent traces propagated to all adapters;
  Slog (Loki) + OTLP JSON (Tempo/Jaeger) exporters
- **PostgreSQL backend**: sessions (AES-GCM encrypted), issuance log (SHA-256
  tamper-evident hash chain), status lists
- **Redis**: distributed sessions for horizontal scaling with L7 sticky sessions

### Security and reliability (P0–P3 review)
**26 items** resolved across security, bugs, and observability, classified into
four priority tiers. Critical items include:
- PII removed from the issuance log and the PostgreSQL backend
- CREDEBL credentials moved from `backends.json` to environment variables
- Race conditions fixed in sessions, the global translator, and `resolveTemplateID`
- Rate limiting per API key (60 req/min) + per IP with proxy allowlist
- Secure session mode: `Secure` cookie flag, validated redirect URI, `/lang` open redirect closed
- Tamper-evident hash chain in the issuance log

---

## 3. Stage 2 — Federated Ecosystem (`federated-issuance`)

### Ecosystem architecture

```
┌──────────────────────── HUB (verify.cdpi.dev) ──────────────────────────┐
│  Trust Registry    — ES256 JWT, public JWKS                             │
│  Schema Registry   — aggregated + cached from all issuers               │
│  Portal /verify    — no login required, citizen-facing                  │
│  Admin             — member CRUD, API keys, health dashboard             │
│  Grafana           — full ecosystem dashboard                            │
└───────────────┬───────────────────────────┬─────────────────────────────┘
                │                           │
   Ministry of Education          Ministry of Labour
   ROLES=issuer · DPG: walt.id    ROLES=issuer · DPG: CREDEBL
   did:web:minerd.gob.do          did:web:mt.gob.do
```

### 13 implemented phases

| # | Phase | Description |
|---|-------|-------------|
| 0 | Baseline | CREDEBL, Trust Registry, Prometheus/Grafana, PG/Redis |
| 0.5 | did:web Inji | `ISSUER_DID_DOMAIN` enables did:web across the entire Inji stack automatically |
| 1 | Roles | `VERIFIABLY_ROLES` — conditional module activation per instance |
| 1.5 | DID Resolver + ES256 | Generic `did:web` resolver with 10-min cache; JWT migration to ES256 |
| 4 | Federation Config | `federation.json` as seed; DB as master; state-prefix routing |
| 5 | Trust Registry CRUD | Extended with `ServiceEndpoint`; admin `/admin/federation/members` |
| 2 | Public Portal | `/verify` for citizens — no login, schema picker + QR + trust badge |
| 10 | Status List Cache | Status list cache with ES256 signature verification and fail-closed policy |
| 3 | Schema Federation | Aggregator with 5-min TTL cache — zero added latency on `/verify` |
| 6 | Events Log | `verification_events` in PostgreSQL — no holder PII stored |
| 7 | Analytics API | `GET /api/ecosystem/issuers/{did}/stats` — issuers pull their own stats |
| 8 | Prometheus Federation | Hub aggregates metrics from all members via file_sd hot-reload |
| 9 | Trust Health Monitor | Days-until-expiry + endpoint up/down gauges; 3 Prometheus alert rules |

### Additional components built during production deployment

Discovered and resolved while deploying with MINERD and MT:

- **`verifiably` adapter**: lets the Hub delegate OID4VP verification to another
  verifiably-go instance via API key — without exposing the underlying DPG
- **Full OID4VP template in `/api/v1/verify/request`**: the Hub can send the complete
  template (fields, format, disclosure) to the issuer's verification endpoint
- **Hub admin landing page**: post-login entry screen for Hub operators
- **fix: `VERIFIABLY_API_KEYS` passthrough** — env var was not reaching the Docker container
- **fix: `host.docker.internal` on Linux** — `credebl-oid4vci-rewriter` was resolving to
  `172.17.0.1` (Docker bridge) which cannot reach the Credo agent on the compose network;
  `_credebl_configure_oid4vci_rewriter` now detects the container's actual IP
- **fix: already-provisioned wallet recovery** — CREDEBL returns 409 on re-provision;
  bootstrap now recovers the existing wallet instead of failing
- **i18n on the public portal** — `renderPublicPage` now runs the same translation
  pipeline as the admin portal

---

## 4. Current production status

| Instance | URL | DPG | Status |
|---|---|---|---|
| **Hub** | `verify.cdpi.dev` | — | ✅ live |
| **MINERD** | `verifiably.minerd.credenciales.ysalabs.work` | walt.id | ✅ live |
| **MT** | `verifiably.mt.credenciales.ysalabs.work` | CREDEBL | ✅ live |

**End-to-end flow verified in production:**
1. Citizen visits `verifiably.ysalabs.work`
2. Selects a document type (schemas from MINERD or MT)
3. Scans the QR code with any OID4VC-compatible wallet
4. Wallet fetches the authorization request JWT from the corresponding issuer's agent
5. Citizen presents the credential
6. Hub displays the badge: ✅ **Verified** — with issuer, trust level, and status list source

---

## 5. Privacy and trust design

| Principle | Implementation |
|---|---|
| No holder PII | `verification_events` never writes citizen data |
| No verification correlation | The Hub cannot determine whether two verifications belong to the same holder |
| Status list privacy | Bitstring / Token Status List — the issuer only knows someone fetched the list, not which credential was checked |
| Asymmetric signing | Trust Registry JWT signed ES256; public key at `/.well-known/jwks.json` |
| No vendor lock-in | Any OID4VC-compatible wallet works (tested with Inji Web and CREDEBL wallets) |

---

## 6. Hub infrastructure

```yaml
# docker-compose.yml — hub stack
hub-postgres:     PostgreSQL 16 — Trust Registry, events, API keys
verifiably-go:    Hub app (VERIFIABLY_ROLES=hub)
hub-prometheus:   Self-scrape + federation scrape of all members (file_sd)
hub-grafana:      Ecosystem dashboard — issuance, verification, health
```

**Key Hub environment variables:**

| Variable | Purpose |
|---|---|
| `VERIFIABLY_ROLES=hub` | Enables only hub modules (trust + schemas + portal) |
| `VERIFIABLY_TRUST_SIGNING_KEY` | ES256 PEM private key for signing the Trust Registry JWT |
| `VERIFIABLY_DATABASE_URL` | PostgreSQL DSN — Trust Registry, events, API keys |
| `VERIFIABLY_PUBLIC_URL` | Hub public URL (embedded in the events log) |
| `VERIFIABLY_ADMIN_PASSWORD` | Hub admin password |

---

## 7. Configured monitoring alerts

| Alert | Condition | Severity |
|---|---|---|
| `IssuerAccreditationExpiringSoon` | `days_until_expiry < 30` | warning |
| `IssuerEndpointDown` | `/healthz` endpoint down > 10 min | critical |
| `FederationAllMembersDown` | no federation members scraped | critical |

---

## 8. Open items (long-term)

All critical and high-priority items are complete. What remains are long-term
production infrastructure improvements:

| Item | Priority | Description |
|---|---|---|
| Vault / AWS SSM | P3 | Replace env-var credentials with a secret manager |
| mTLS backends | P3 | Mutual TLS between verifiably-go and DPG backends |
| Volume backup | P3 | Daily backup of the `verifiably-go-state` volume |
| Push revocation | Backlog | Notify the holder when their credential is revoked |
| Docker socket (CREDEBL) | Backlog | `agent-provisioning` requires the Docker socket — privilege risk |
| `VERIFIABLY_MODE=ui\|api` | Backlog | Decouple the REST API from the HTMX frontend |
| did:web Walt.id automation | Post-Phase 5 | Walt.id supports did:web but the compose env var is missing |

---

## 9. Project numbers

| Metric | Value |
|---|---|
| Commits in `federated-issuance` | 99 |
| Federation phases delivered | 13 / 13 (100%) |
| Security / bug items resolved (TODO.md) | 26 / 31 (84%) — 5 remaining are long-tail |
| Supported DPGs | 5 (walt.id, CREDEBL, Inji Certify, Inji Verify, Inji Web) |
| Production instances | 3 (Hub + MINERD + MT) |
| New external dependencies added | 0 (pure Go stdlib throughout) |
