# Federated Emission — Architecture and Progress

**Branch:** `federated-issuance` (already merged into `main` — this document is
the historical development log, no branch checkout is required to use any of
the phases described below)
**Last update:** 2026-05-17 (Phases 2 + 10 + 3 + 6 + 7 + 8 + 9 completed)

---

## Goal

Extend verifiably-go to support a federated ecosystem of verifiable
credential issuers with:

- N independent verifiably-go instances (one per issuing organization)
- A central Hub (CDPI) with a Trust Registry, Schema Registry, and a public
  verification portal (no login)
- Each instance runs only the modules it needs (`VERIFIABLY_ROLES`)
- Any OID4VC-compatible wallet can present credentials from any issuer
- A unified trust framework under a central authority with an upgrade path
  to OpenID Federation 1.0

---

## Actual state of the codebase on `federated-issuance` (base: `add-credebl`)

> Branch created from `add-credebl`, which includes the CREDEBL adapter,
> Trust Registry, Prometheus metrics, Grafana, and admin_metrics. This
> section reflects the reality verified by reading the files directly.

### What already exists

| Component | Location | Notes |
|-----------|-----------|-------|
| Adapter interface | `backend/adapter.go` | Full interface with all methods |
| Registry (fan-out) | `internal/adapters/registry/registry.go` | Multi-adapter, `Register()`, correct fan-out |
| BackendEntry/Config | `internal/adapters/registry/config.go` | Reads `backends.json` |
| SchemaStore | `internal/adapters/registry/schema_store.go` | JSON persistence for custom schemas |
| Factory | `internal/adapters/factory/factory.go` | Builds: waltid, credebl, injicertify, injiverify, injiweb |
| Walt.id adapter | `internal/adapters/waltid/` | Issuer + holder + verifier |
| **CREDEBL adapter** | `internal/adapters/credebl/` | Issuer + verifier (OID4VP + DCQL) |
| Inji Certify adapter | `internal/adapters/injicertify/` | Issuer (auth-code + pre-auth) |
| Inji Verify adapter | `internal/adapters/injiverify/` | Verifier only |
| Inji Web adapter | `internal/adapters/injiweb/` | Holder only |
| LibreTranslate | `internal/adapters/libretranslate/` | Translation |
| Auth OIDC | `internal/auth/` | Providers, registry, user store |
| **Trust Registry** | `internal/trust/` | `registry.go` (interface) + `store.go` (pg + mem) + `jwt.go` |
| **Trust handler** | `internal/handlers/trust.go` | Public `GET /trust-registry` JWT |
| **Prometheus metrics** | `internal/metrics/metrics.go` | Counters + histograms |
| **Admin metrics UI** | `internal/handlers/admin_metrics.go` | `/admin/metrics` |
| **REST API** | `internal/handlers/api.go` | Headless issuance endpoints |
| **PostgreSQL storage** | `internal/storage/pg/` | Sessions, issued_credentials, trusted_issuers |
| **Redis storage** | `internal/storage/redis/` | Optional session cache |
| **Rate limiter** | `internal/handlers/ratelimit.go` | Per API key (60/min) + per IP (20/min, `VERIFIABLY_RATE_IP_RPM`) |
| Handlers | `internal/handlers/` | All current handlers |
| Issuance log | `internal/issuance/log.go` | JSON-backed + pg, with `OwnerKey` scoping |
| Status list stores | `internal/statuslist/` | Bitstring (W3C) + Token (IETF) |
| Domain types | `vctypes/vctypes.go` | Schema, DPG, Credential, OID4VPTemplate |
| Main / router | `cmd/server/main.go` | All routes registered flat, no conditionals |
| DID proxy (Inji) | `internal/handlers/inji_proxy.go` | Inji-specific DID doc proxy — NOT a generic resolver |
| Config | `config/backends.json` | Current adapter config |
| **Grafana dashboard** | `deploy/compose/monitoring/grafana/` | Existing metrics dashboard |
| **Prometheus config** | `deploy/compose/monitoring/prometheus.yml` | Local instance scrape |
| **did:web deploy automation (Inji)** | `deploy/compose/stack/inji/certify/init.sh` | `ISSUER_DID_DOMAIN` → automatic `did:web:{domain}` on postgres init |
| **did:web deploy automation (preauth)** | `deploy/compose/stack/inji/certify/init-preauth.sh` | Same DID as primary in prod; `inji_proxy` merges keys |
| **`ISSUER_DID_DOMAIN` in .env** | `deploy/compose/stack/.env.example` | Single variable to enable did:web across the whole Inji stack |

### What does NOT exist yet (needs to be built)

| Component | Phase | Notes |
|-----------|------|-------|
| `internal/didresolver/` | Phase 1.5 | Generic `did:web` resolver — the Inji proxy doesn't serve this purpose |
| ES256 signing key + JWKS endpoint | Phase 1.5 | Upgrade from HS256 to ES256 in Trust Registry JWT |
| `VERIFIABLY_ROLES` routing | Phase 1 | Conditional module activation |
| Public `/verify` portal | Phase 2 | No login, for citizens |
| Public `/api/schemas` | Phase 3 | CORS + cache TTL, with SourceIssuerDID |
| Schema aggregation cache | Phase 3 | In-memory cache, 5-10 min TTL; without this, N+1 HTTP requests on every `/verify` |
| `config/federation.json` | Phase 4 | Initial Hub seed — DB is master |
| State prefix routing in Registry | Phase 4 | Pending TODO in `FetchPresentationResult` — blocks Phase 2 |
| Issuer admin CRUD | Phase 5 | `/admin/federation/members` |
| `ServiceEndpoint` in TrustedIssuer | Phase 5 | Extension of the existing struct |
| ALTER TABLE `trusted_issuers` | Phase 5 | New columns via `ADD COLUMN IF NOT EXISTS` in `runMigrations()` |
| `verification_events` log | Phase 6 | PostgreSQL from day 1 (not JSON — Hub is the aggregation point) |
| Issuer Analytics API | Phase 7 | `/api/ecosystem/issuers/{did}/stats` |
| Defined API key lifecycle | Phase 7 | One-time display, hashed in DB, rotation via admin UI |
| Prometheus Federation | Phase 8 | Hub aggregates metrics from registered issuers |
| Trust Registry Health monitoring | Phase 9 | Expiry gauges + endpoint health |
| Status List Cache | Phase 10 | Cache with JWT signature verification — must ship with Phase 2 |
| CREDEBL did:web automation | Post-Phase 5 | CREDEBL uses an Aries agent on an Indy ledger; did:web requires manual agent re-provisioning (steps documented in `credebl.env`) |
| Walt.id did:web compose config | Post-Phase 5 | Walt.id supports did:web but there's no env var in the current compose; pending |

---

## Architectural decisions (fixed, not up for debate)

| Decision | Choice |
|----------|----------|
| Deployment model | Separate verifiably-go instances per issuer |
| Trust governance | Single central authority (CDPI) — signed JWT |
| Trust Registry JWT signing algorithm | ES256 (ECDSA P-256) — HS256 is dev baseline only |
| Source of truth for members | DB (`trusted_issuers`) is master; `federation.json` = initial seed and export |
| Trust upgrade path | OpenID Federation 1.0 — `trust.Registry` interface doesn't change |
| Verification portal | Public, no login (`/verify` on the Hub) |
| Target wallets | Any OID4VC-compatible wallet (no lock-in) |
| Required DID method | `did:web` with own domain — accreditation requirement |
| Status list policy | Configurable per schema: `fail-open` or `fail-closed` |
| Schema federation | Activated automatically when an issuer registers (via ServiceEndpoint) |
| Events log backend | PostgreSQL from day 1 (JSON-backed doesn't scale for the Hub) |
| Backwards compat | Without `VERIFIABLY_ROLES` → identical to current behavior |
| `did:web` is an accreditation requirement, not a runtime one | Deployments without `ISSUER_DID_DOMAIN` work with Docker-internal `did:web` (dev) or `did:key`; public `did:web` is only required to join the Hub |
| Single variable for federation-ready Inji | `ISSUER_DID_DOMAIN=domain.gov` enables `did:web` across the whole Inji stack automatically (postgres init + Spring Boot); no other changes needed |
| Primary and preauth DIDs share a domain in prod | In production both Inji instances use `did:web:{ISSUER_DID_DOMAIN}`; `inji_proxy` merges their keys into a single DID Document — no kid collision |
| Volume re-init required when changing domain | The `init.sh` scripts only run on the first PostgreSQL volume initialization; changing `ISSUER_DID_DOMAIN` on an existing deploy requires `docker volume rm certify-db certify-preauth-db` |
| CREDEBL did:web not automated | CREDEBL uses an Aries agent on an Indy/Sovrin ledger; did:web requires manual re-provisioning documented in `credebl.env` — doesn't block the other phases |

---

## Hub prerequisites (verify.cdpi.dev)

Before operating in `hub` mode, the host must have:

1. `did:web:verify.cdpi.dev` resolvable at `https://verify.cdpi.dev/.well-known/did.json`
2. An ECDSA P-256 key pair to sign the Trust Registry JWT (ES256), configured
   in `VERIFIABLY_TRUST_SIGNING_KEY` (private key PEM)
3. `GET /.well-known/jwks.json` — exposes the public key; external verifiers
   use it to validate the JWT without a shared secret

Without these three requirements, external verifiers cannot validate the
Trust Registry JWT and the upgrade path to OpenID Federation 1.0 is not
possible.

---

## Extension to the TrustedIssuer model

```go
// internal/trust/registry.go
type TrustedIssuer struct {
    DID                 string
    DisplayName         string
    Schemas             []string
    ServiceEndpoint     string    // base URL: "https://issuer-a.gov"
    StatusListEndpoints []string  // public URLs of its status lists
    StatusListPolicy    string    // "fail-open" | "fail-closed" (default: "fail-closed")
    AccreditedAt        time.Time
    ValidUntil          time.Time
}
```

---

## Architecture diagram

```
┌──────────────────────────────────────────────────────────┐
│           HUB  (verifiably-go --role=hub)                │
│  verify.cdpi.dev                                         │
│                                                          │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  Trust Registry │  │Schema Registry│  │  /verify   │  │
│  │  /trust-registry│  │  /schemas    │  │  (public)  │  │
│  │  JWT ES256      │  │  (federated) │  │  no login  │  │
│  └─────────────────┘  └──────────────┘  └────────────┘  │
│                                                          │
│  /.well-known/jwks.json → ES256 public key                │
│  Admin: /admin/federation/members (issuer CRUD)          │
│  federation.json → initial seed; DB is master             │
└──────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Issuer A    │    │  Issuer B    │    │  Issuer C    │
│  ROLES=issuer│    │ ROLES=issuer │    │ ROLES=issuer │
│  DPG: walt.id│    │ DPG: CREDEBL │    │  DPG: Inji   │
│  did:web:a…  │    │ did:web:b…   │    │  did:web:c…  │
│              │    │              │    │              │
│  /api/schemas│    │ /api/schemas │    │ /api/schemas │
│  /status-list│    │ /status-list │    │ /status-list │
│  /healthz    │    │ /healthz     │    │ /healthz     │
└──────────────┘    └──────────────┘    └──────────────┘
```

---

## Verification flow on the Hub

```
Citizen visits /verify
    │
    ├── Selects a schema (aggregated cache from all issuers, 5 min TTL)
    │
    ├── Hub generates an OID4VP request via the matching issuer's adapter
    │        (verifier adapter configured in federation.json / DB)
    │        (state prefix identifies the adapter back in FetchPresentationResult)
    │
    ├── Citizen presents with their OID4VC wallet
    │
    ├── Hub receives the presentation → FetchPresentationResult() (routed by state prefix)
    │
    ├── Status list check (Phase 10 — required for Phase 2 to be complete):
    │     → live fetch from issuer.gov/status-list/...  (3s timeout)
    │     → verify JWT signature against the issuer's did:web (generic DID resolver)
    │     → fallback to cache (Redis/JSON)
    │     → policy: fail-closed or fail-open if no cache available
    │
    ├── Trust Registry check: IsTrusted(issuerDID, schemaID)
    │
    └── Result: "Verified by CDPI" badge if TrustStatus == "trusted"
```

---

## Status list flow in a federated ecosystem

```
Credential issued by Issuer A contains:
  "status": {
    "status_list": {
      "uri": "https://issuer-a.gov/status-list/token/v1",  ← embedded URL
      "idx": 42
    }
  }

Hub verifies:
  1. DPG adapter fetches the status list URL (embedded in the credential)
  2. Verifies the status list's JWT signature against did:web:issuer-a.gov
     → internal/didresolver: GET https://issuer-a.gov/.well-known/did.json
     → caches the DIDDocument for 10 min to avoid resolving on every check
  3. Reads the bit at index 42
  4. On failure → uses the Hub's cache → if no cache → applies the policy

Privacy: W3C Bitstring / IETF Token Status List are lists with thousands
of positions → Issuer A only learns that someone fetched the list,
not which specific credential was checked.
```

---

## Metrics per actor

### Issuer A — its own `/admin/metrics`
- Credentials issued (by schema, by date) — already exists in the log
- Active / revoked credentials — already exists in the log
- Verifications of its credentials (by schema) → data from the Hub via
  `GET /api/ecosystem/issuers/{did}/stats`

### Hub / CDPI — `/admin/ecosystem`
- Ecosystem totals: issued, verified, active issuers
- Per issuer: issued, verified, error rate, accreditation status
- Trust Registry health: per-issuer traffic light (days until expiry)
- Status list availability: status list uptime

---

## Accreditation requirements for issuers

To register with the Hub, each issuer MUST have:

1. `did:web:{domain}` — resolvable at `https://{domain}/.well-known/did.json`
   - **For Inji stacks:** set `ISSUER_DID_DOMAIN={domain}` in `.env` before
     the first `docker compose up` (or wipe volumes and restart if the stack
     already exists)
   - **For CREDEBL:** requires manual agent re-provisioning (see `credebl.env`)
   - **For Walt.id:** pending compose automation
2. Public status lists at `{serviceEndpoint}/status-list/{type}/v1`
   - No auth required
   - JWTs signed with the declared DID's key
3. `GET {serviceEndpoint}/api/schemas` — schemas without auth, with CORS
4. `GET {serviceEndpoint}/healthz` — returns HTTP 200
5. `VERIFIABLY_ROLES=issuer` (or roles that include `issuer`)

---

## Runbook — Onboarding a New Issuer to the Hub

This section is the operational, step-by-step counterpart to the
"Accreditation requirements" checklist above. Use it whenever a real DPG
deployment (Inji, walt.id, or CREDEBL) needs to be accredited into a running
Hub. Unlike the phase log below (implementation history), this runbook
reflects the current, verified behavior of the code — update it if a phase
changes any of the mechanics described here.

### Mental model

The Hub is **pull-based, not push-based**: the Hub calls the member (never
the reverse) to request a presentation, and it polls the member's public
endpoints to build the schema cache and Prometheus metrics. There is no
`VERIFIABLY_HUB_URL` or auto-registration handshake — onboarding is an
out-of-band exchange of URLs/keys followed by a manual `POST` (via the admin
UI or API) on the Hub side.

The runtime source of truth is the `trusted_issuers` Postgres table on the
Hub, not `config/federation.json` — that file only seeds the table on the
very first boot when the table is empty (see Phase 4 below). Treat it as a
backup/export format, not something the Hub re-reads on every restart.

Two identifiers must not be confused:
- **DID** (`did:web:...`) — identifies who signs the credentials. Must
  resolve at `https://{domain}/.well-known/did.json`.
- **`service_endpoint`** — the base URL of that member's own `verifiably-go`
  instance (its API: `/healthz`, `/api/schemas`, `/status-list/...`,
  `/api/v1/verify/*`). This is a completely separate field from the DID —
  the `verifiably` adapter (`internal/adapters/verifiably/adapter.go`) never
  derives a URL from the DID, so the DID's domain and the service endpoint's
  domain do not need to match.

### Step 1 — Prepare the member (issuer side)

1. Confirm `VERIFIABLY_ROLES` includes both `issuer` and `schemas` (add
   `verifier` too if the member also verifies locally):
   ```bash
   grep VERIFIABLY_ROLES .env
   # VERIFIABLY_ROLES=issuer,verifier,schemas
   ```
   Without `schemas`, `GET /api/schemas` 404s (the route is only registered
   under `activeRoles.Has(roles.Schemas)` — see Phase 3) even though the rest
   of the member works fine. `hub` is not needed here — that role is for the
   Hub instance itself, and implies `trust`+`schemas` only for that node.

2. Set `VERIFIABLY_API_KEYS=hub:<random-hex>` in the member's `.env`. This
   key is what the Hub will use as Bearer auth when it calls the member's
   `/api/v1/verify/*` (adapter `verifiably`) and `/metrics` (Prometheus
   federation scrape).

3. Enable a public `did:web` for the member — **mechanics differ per DPG**,
   see the per-DPG subsections below.

4. Apply any `.env` change with a full rebuild+recreate, not a bare restart:
   ```bash
   ./deploy.sh run <inji|waltid|credebl>
   ```
   `docker restart` reuses the container's frozen environment from its
   original `docker create` — it will NOT pick up new/changed variables in
   `.env`. Only `deploy.sh run` (which rebuilds the image and recreates the
   container) re-reads `.env`.

5. Verify the four public endpoints the Hub will require at registration
   time:
   ```bash
   curl -sk -o /dev/null -w "%{http_code}\n" https://<did-domain>/.well-known/did.json
   curl -sk -o /dev/null -w "%{http_code}\n" https://<service-endpoint>/healthz
   curl -sk -o /dev/null -w "%{http_code}\n" https://<service-endpoint>/api/schemas
   curl -sk -o /dev/null -w "%{http_code}\n" https://<service-endpoint>/status-list/bitstring/<id>
   ```
   All four must return `200`. `/healthz` is a **hard** registration
   requirement — `RegisterFederationMember` aborts with an error if it
   doesn't respond (see Phase 5).

6. Hand the Hub operator, out of band: the member's `did:web:...`, its
   `service_endpoint` URL, and one `VERIFIABLY_API_KEYS` value (the key part,
   not the name) to use as `verifier_api_key`.

### Step 1a — Inji Certify specifics

`ISSUER_DID_DOMAIN` is the single variable that enables `did:web` across the
whole Inji stack — it does **not** generate new keys, it only changes the
identifier Inji Certify uses to reference the Ed25519 keys it already
manages.

```bash
# in the Inji stack's .env (e.g. deploy/compose/stack/.env)
ISSUER_DID_DOMAIN=inji-certify-authcode.<public-domain>
```

- If the stack already ran once with this unset, the DID was already seeded
  into Postgres by `init.sh`/`init-preauth.sh` (they only run on first volume
  init). Changing the domain later requires:
  ```bash
  ./deploy.sh down inji
  docker volume rm certify-db certify-preauth-db
  ./deploy.sh up inji && ./deploy.sh run inji
  ```
- Primary (auth-code) and pre-auth typically use **different** subdomains
  (e.g. `inji-certify-authcode.<domain>` vs `inji-certify-preauth.<domain>`)
  — each is seeded independently by its own init script and each gets its
  own `did:web`.
- Prefer the domain where Caddy already terminates the auth-code/pre-auth
  subdomain that the `verifiably-go` proxy patches (see next point) over the
  root `service_endpoint` domain — they represent different things (signer
  vs. API), and re-using the `verifiably.<domain>` root for the DID would
  require adding a custom `/.well-known/did.json` handler there, which isn't
  wired by default.
- Critical: confirm nginx routes `did.json` through the Go proxy, which
  patches a `kid` mismatch (Inji Certify v0.14.0 publishes one `kid` in its
  DID document but signs credentials with a different one derived from the
  same key — see `internal/handlers/inji_proxy.go`):
  ```bash
  docker exec certify-nginx cat /etc/nginx/conf.d/default.conf | grep -A6 "well-known/did.json"
  ```
  Expect `proxy_pass http://injiproxy/inji-proxy/.well-known/did.json;` (or
  `.../inji-proxy-preauth/...` for the pre-auth flow). If instead you see a
  direct `proxy_pass` to the Certify backend, the `kid` patch is missing and
  verification may fail against strict verifiers.
- Verify end to end:
  ```bash
  curl -fsSL https://inji-certify-authcode.<domain>/.well-known/did.json | python3 -m json.tool
  ```

### Step 1b — walt.id specifics

walt.id's issuer-api supports `did:web` natively, but there is currently no
wired `.env` variable for it in this repo's compose (unlike Inji's
`ISSUER_DID_DOMAIN`). Treat this as manual/pending automation:
- Confirm the walt.id issuer image's own `did:web` configuration (its own
  key management, outside this repo's compose wiring).
- The Caddy public config (`scripts/gen-caddy.sh`) already knows how to
  serve a static DID document inline for the `walt-issuer` slug (see the
  `walt-issuer.<domain>` block in a generated `Caddyfile.public` — it
  responds to `/.well-known/did.json` with a hand-built DID document using
  `scripts/bootstrap-waltid-did.sh`-generated keys). If walt.id is the DPG
  in play, use that script to generate the key pair and let Caddy serve the
  resulting document, rather than trying to get walt.id itself to serve it.

### Step 1c — CREDEBL specifics

CREDEBL runs on an Aries agent backed by an Indy/Sovrin ledger, and does
**not** automate `did:web` today. Enabling it requires manually
re-provisioning the Aries agent to use `did:web` instead of `did:indy`/
`did:sov` — steps are documented inline in
`deploy/compose/credebl/config/credebl.env`. This is a manual, one-time
operation per CREDEBL deployment; it isn't triggered by any single env var
the way Inji's is.

### Step 2 — Register the member on the Hub

7. Log into `https://<hub-domain>/admin/login`.

8. Go to `/admin/federation/members` and submit the form (or `POST` the
   same fields as JSON) with:
   - `did` — must start with `did:web:` (hard requirement, enforced in
     `RegisterFederationMember`; anything else, including `did:key`, is
     rejected before it ever reaches the DID resolver)
   - `display_name`
   - `service_endpoint` — the member's own `verifiably-go` root URL
   - `verifier_api_key` — the key handed over in step 6
   - `schemas` (optional, CSV) — empty means wildcard (accept all)
   - `status_list_endpoints` (optional, CSV)
   - `status_list_policy` — `fail-closed` (default, recommended) or
     `fail-open`
   - `valid_until` (optional, `YYYY-MM-DD`)

9. On save, the Hub validates the `did:web:` prefix, performs a blocking
   `GET {service_endpoint}/healthz` (hard fail if it doesn't return 200),
   and best-effort resolves the DID document (failure here is a
   warning only, so dev/staging members without a fully public DID doc can
   still be registered). If everything passes, the `verifiably` adapter for
   this member is wired **live** — no Hub restart needed.

10. Optionally issue an analytics API key for the member:
    `POST /admin/federation/members/{did}/api-key`. The plaintext is shown
    once — hand it back to the member so they can query their own stats at
    `GET /api/ecosystem/issuers/{did}/stats`.

11. Regenerate the Prometheus federation scrape config so Grafana picks up
    the new member:
    ```bash
    ./deploy/compose/monitoring/generate-federation-prometheus.sh
    ```
    This reads directly from `trusted_issuers`, rewrites
    `prometheus-hub.yml` with one `job_name` per member (each with its own
    Bearer token), and reloads Prometheus via `--web.enable-lifecycle`
    without a restart. Re-run it any time a member is added, edited, or
    removed via the admin UI — it is not automatic on its own.

12. (Backup) If you want this registration to survive a from-scratch DB
    rebuild, mirror the same entry into `config/federation.json` manually —
    the Hub does not re-read that file once `trusted_issuers` has rows.

### Verification checklist

```bash
# DID resolves publicly
curl -fsSL https://<did-domain>/.well-known/did.json

# Member appears healthy from the Hub's perspective
curl -fsSL https://<hub-domain>/admin/federation/members   # (requires admin session)

# Prometheus picked up the new scrape target
curl -s https://<hub-domain-internal>:9090/api/v1/targets | grep <member-did>
```

---

## Implementation phases

### ✅ Phase 0 — Baseline (existing since `add-credebl`)

CREDEBL adapter, Trust Registry (JWT + pg + mem), Prometheus metrics,
admin_metrics UI, Grafana dashboard, PostgreSQL/Redis storage, headless
REST API. No changes required — this is the starting point.

---

### ✅ Phase 0.5 — DID:web Deployment Automation (Inji Certify)

**Goal:** Let any Inji Certify deployment use a public `did:web` to be
eligible for the Hub's Trust Registry, with a single environment variable.

**Design decisions made:**
- `did:web` is an **accreditation** requirement (Hub membership), not a
  runtime one
- Without `ISSUER_DID_DOMAIN`: the stack keeps working with
  `did:web:certify-nginx` (Docker-internal, dev only) — zero regression
- With `ISSUER_DID_DOMAIN=issuer.gov`: both Inji instances (primary +
  preauth) use `did:web:issuer.gov`; `inji_proxy` already merges their keys
  into the DID Document
- The init scripts only run on the very first volume initialization —
  changing domains requires `docker volume rm certify-db certify-preauth-db`

**Files created/modified:**
- [x] `deploy/compose/stack/inji/certify/init.sh` — initializes
  certify-postgres with the correct DID
- [x] `deploy/compose/stack/inji/certify/init-preauth.sh` — same for
  preauth; bash logic for shared domain in prod vs. separate hostnames in dev
- [x] `deploy/compose/stack/.env.example` — `ISSUER_DID_DOMAIN=` with full
  documentation
- [x] `deploy/compose/stack/inji/certify/certify-csvdp-farmer.properties` —
  `${CERTIFY_ISSUER_DID:did:web:certify-nginx}` (Spring Boot resolves from env)
- [x] `deploy/compose/stack/inji/certify/certify-csvdp-farmer-preauth.properties`
  — same, with `did:web:certify-preauth-nginx` fallback
- [x] `deploy/compose/stack/docker-compose.yml` — 4 services updated:
  volumes + `CERTIFY_ISSUER_DID` env var on inji-certify and
  inji-certify-preauth-backend
- [x] `deploy/compose/credebl/config/credebl.env` — documented steps for
  manual did:web (CREDEBL requires Aries agent re-provisioning)

**Pending (doesn't block other phases):**
- Walt.id did:web in compose (supported by the DPG, missing env var in compose)
- CREDEBL did:web automation (requires agent provisioning refactor)

---

### ✅ Phase 1 — Deployment Roles

**Goal:** Enable/disable modules per instance with `VERIFIABLY_ROLES`.

**Files created/modified:**
- [x] `internal/roles/roles.go` — new package: `Set` type, `Parse()`,
  `FromEnv()`, `Has()`, `Log()`
- [x] `cmd/server/main.go` — imports `roles`, calls `roles.FromEnv()` +
  `activeRoles.Log()` at startup; routes reorganized into labeled blocks
  guarded by `activeRoles.Has(...)`
- [x] Conditional routing logic implemented:
  - `issuer`: `/issuer/*`, `/status-list/*`, `/api/v1/credentials/*`, `/api/v1/bulk/*`
  - `holder`: `/holder/*`
  - `verifier`: `/verifier/*`, `/api/v1/verify/*`
  - `trust`: `GET /trust-registry`, `/admin/trust/*` (hub implies trust automatically)
  - `schemas`: placeholder — routes added in Phase 3
  - `hub`: `/verify/*` placeholder — routes added in Phase 2; `hub` implies
    `trust` + `schemas` in `Parse()`
- [x] Startup log: `slog.Info("roles activos", "roles", activeRoles.names())`
- [x] Core routes (healthz, auth, static, lang, docs) always active — zero regression

**Design decisions:**
- `nil` Set = all roles active (env var absent → identical to current behavior)
- `hub` implies `trust` and `schemas` in `Parse()` — no need to set them separately
- Shared admin (`/admin/auth-providers`, `/admin/metrics`) gated by `issuer || verifier`
- Inji proxy routes always registered (backward compat — no adapter check)

**Verified success criteria:**
- `VERIFIABLY_ROLES=issuer` → only issuance routes active
- `VERIFIABLY_ROLES=hub` → only `/trust-registry` (+ `/verify/*` in Phase 2)
- No variable → everything active (regression-free)

---

### ✅ Phase 1.5 — DID Resolver + Trust Registry Key Upgrade

**Goal:** Enable signature verification for arbitrary `did:web` identifiers
and migrate the Trust Registry JWT to ES256 with a public JWKS endpoint.

**Files created/modified:**
- [x] `internal/didresolver/resolver.go` — `Resolver` interface,
  `DIDDocument`, `VerificationMethod` types
- [x] `internal/didresolver/web.go` — `WebResolver`: parses
  `did:web:{domain}[:{path}]`, HTTPS GET, in-memory cache with 10 min TTL,
  thread-safe with sync.Mutex
- [x] `internal/trust/jwt.go` — added `BuildJWTES256` (ECDSA P-256, R||S
  32-byte padding), `PublicKeyToJWK`; `BuildJWT` (HS256) kept for dev/fallback
- [x] `internal/handlers/trust.go` — `ServeTrustRegistry` uses ES256 when
  `TrustSigningKey != nil`, HS256 as fallback; added `ServeJWKS` →
  `GET /.well-known/jwks.json`
- [x] `internal/handlers/handlers.go` — H struct:
  `TrustSigningKey *ecdsa.PrivateKey`, `DIDResolver didresolver.Resolver`
- [x] `cmd/server/main.go` — `loadTrustSigningKey()`: loads PEM (SEC1 or
  PKCS8), generates an ephemeral key with a warning if absent; `trustAlg()`
  for logging; `h.DIDResolver = didresolver.NewWebResolver()`; registers
  `GET /.well-known/jwks.json` in the trust block

**Design decisions:**
- Without `VERIFIABLY_TRUST_SIGNING_KEY` → an ephemeral ES256 key is
  generated at startup (dev safe, public key changes on restart)
- `did:web:example.com` → `https://example.com/.well-known/did.json`;
  `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
- `FillBytes` for R||S padding in the ES256 JWT (P-256 = 32 bytes per component)
- PKCS8 fallback in `loadTrustSigningKey` for keys generated with
  `openssl genpkey`

**Success criteria:**
- `GET /.well-known/jwks.json` returns a JWK set `{kty:EC, crv:P-256, alg:ES256}`
- Trust Registry JWT uses ES256, verifiable without a shared secret
- `Resolve("did:web:issuer-a.gov")` returns a DIDDocument with `VerificationMethods`
- A second call to the same DID doesn't make an HTTP request (cache hit)

---

### ✅ Phase 2 — Hub: Public Verification Portal

**Goal:** No-login `/verify` portal for citizens.

**Files created/modified:**
- [x] `internal/handlers/public_verify.go` — auth-free handlers:
  - `GET /verify` → `ShowPublicVerify` — lists the adapter's custom schemas
  - `POST /verify/request` → `PublicVerifyRequest` — generates an OID4VP
    request; IP rate-limited via the `"public-verify"` key; returns
    `fragment_public_qr` with the QR + polling setup
  - `GET /verify/result/{state}` → `PublicVerifyResult` — HTMX polling every
    3s; attaches `TrustStatus` + `StatusListSource`; returns
    `fragment_public_result`
  - `checkStatusListAvailability()` helper: queries TrustRegistry +
    StatusListCache to determine the Source
  - `renderPublicPage()` helper: uses `layout_public` without the auth nav
- [x] `templates/public/layout_public.html` — minimal layout: CDPI header +
  main + footer, no role-based nav
- [x] `templates/public/verify.html` — `content_public_verify` (schema
  picker grid) + `fragment_public_qr` (QR + polling bootstrap) +
  `fragment_public_result` (✅/❌ badge with TrustStatus, StatusListSource,
  DisclosedFields)
- [x] `internal/handlers/handlers.go` — H struct: added
  `StatusListCache statuslistcache.Cache`
- [x] `backend/adapter.go` — `VerificationResult` extended with
  `StatusListSource string` and `StatusListCachedAt *time.Time`
- [x] `cmd/server/main.go` — routes `/verify`, `/verify/request`,
  `/verify/result/{state}` under `activeRoles.Has(roles.Hub)`

**Design decisions:**
- HTMX polling every 3s (same pattern as the operator verifier) — SSE is a
  future improvement
- `resolveFields()` not invoked in the public portal (default pre-filling is
  not needed for a VP request)
- DPG selector: first available verifier DPG (Phase 3 adds
  `SourceIssuerDID` for schema→issuer routing)
- IP rate limit uses `"public-verify"` as the bucket key (60 req/min global
  + 20/min per IP)
- `StatusListSource` fallback: if the cache has no data but
  `res.CheckedRevocation=true`, it's reported as "live" (the adapter checked it)

**Success criteria:**
- A citizen visits `/verify`, picks a schema, scans the QR, sees the CDPI
  badge
- The badge shows TrustStatus, issuer, StatusListSource
- The result shows `StatusListSource: "live" | "cached" | "unknown"` to the citizen

---

### ✅ Phase 3 — Schema Federation

**Goal:** Each issuer publicly exposes its schemas; the Hub aggregates them
with caching.

> **Note:** Without caching, every `/verify` page load on the Hub makes N
> HTTP requests to the issuers (one per ecosystem member). A single issuer
> going down blocks the load. The cache is an integral part of this phase,
> not optional.

**Files created/modified:**
- [x] `vctypes/vctypes.go` — added to `Schema`:
  ```go
  SourceIssuerDID  string `json:"sourceIssuerDid,omitempty"`
  SourceDeployment string `json:"sourceDeployment,omitempty"`
  ```
- [x] `internal/schemacache/aggregator.go` — new package:
  - `Aggregator` struct: in-memory `map[string]issuerEntry` keyed by DID +
    `memberIDs` (DID→adapterKey)
  - `NewAggregator(ttl time.Duration, memberIDs map[string]string) *Aggregator`
  - `Start(ctx, trust.Registry)`: goroutine — immediate poll at startup +
    ticker every TTL
  - `Schemas() []vctypes.Schema`: returns a merge of all cached entries
    (fast read)
  - `refresh()`: iterates `TrustedIssuers()`, calls `fetchIssuer()` for each
    issuer with a `ServiceEndpoint`
  - `fetchIssuer()`: GET `{ServiceEndpoint}/api/schemas` (5s timeout, 1 MiB
    cap); preserves cache on failure; overrides `SourceIssuerDID` +
    `SourceDeployment` with values known to the Hub
- [x] `internal/handlers/public_schemas.go` — new:
  - `ServePublicSchemas`: `GET /api/schemas` — CORS, returns custom schemas
    with `SourceIssuerDID` from `VERIFIABLY_ISSUER_DID` and
    `SourceDeployment` from `VERIFIABLY_PUBLIC_URL`
  - `ServeHubSchemas`: `GET /schemas` — CORS, returns
    `h.SchemaCache.Schemas()` (Hub mode)
  - `setCORSHeaders()`: helper for `Access-Control-Allow-Origin: *`
- [x] `internal/handlers/handlers.go` — H struct: added
  `SchemaCache *schemacache.Aggregator`
- [x] `internal/handlers/public_verify.go`:
  - `ShowPublicVerify`: uses `h.SchemaCache.Schemas()` when available;
    falls back to the local adapter
  - `PublicVerifyRequest`: uses `picked.SourceDeployment` as `dpgKey` for
    correct routing; falls back to the first verifier if there's no match
- [x] `cmd/server/main.go`:
  - Imports `schemacache`
  - Under `activeRoles.Has(roles.Schemas)`: `GET /api/schemas` +
    `OPTIONS /api/schemas`
  - Under `activeRoles.Has(roles.Hub)`: wires up the aggregator (reads
    `federation.json` for the DID→memberID map), `agg.Start(shutCtx,
    h.TrustRegistry)`, `GET /schemas` + `OPTIONS /schemas`

**Design decisions:**
- 5 min TTL: balances freshness against load on issuers; background refresh
  for zero-latency reads
- The Hub overrides `SourceIssuerDID` + `SourceDeployment` from its own
  trust registry — it doesn't trust the values the issuer self-reports
- `SourceDeployment` = `member.ID` from `federation.json` = the adapter's
  key in the Registry → direct routing without extra joins
- `OPTIONS` registered explicitly (Go 1.22 mux matches by method)
- `nil` schemas → `[]vctypes.Schema{}` (empty JSON array, never `null`)

**Success criteria:**
- Issuer A at `https://issuer-a.gov/api/schemas` returns its schemas
- The Hub's `/schemas` returns schemas from all registered issuers
- A second `/verify` load (within the TTL) makes no HTTP calls to issuers
- If Issuer B goes down, the Hub keeps showing its schemas from cache

---

### ✅ Phase 4 — Federation Config

**Goal:** The Hub keeps `config/federation.json` as an initial seed and
builds the Registry dynamically from the DB at startup.

**Note:** State prefix routing for `FetchPresentationResult` was already
implemented in `registry.go` (format `"dpg:<vendor>:<inner-state>"`). No
changes were required — the phase confirmed the blocker was already resolved.

**Files created/modified:**
- [x] `internal/federation/config.go` — new package: `Config`,
  `EcosystemInfo`, `Member`
- [x] `config/federation.json` — example file with one member (`issuer-a` →
  `did:web:issuer-a.gov`)
- [x] `internal/federation/loader.go` — `LoadConfig(path string)` +
  `(*Config).ToBackendEntries()`, which converts members into
  `registry.BackendEntry` (verifier-only, vendor=member.ID)
- [x] `cmd/server/main.go` — `bootstrapHub()` function + call in `main()`
  under `activeRoles.Has(roles.Hub)`:
  1. Loads `config/federation.json` (or `VERIFIABLY_FEDERATION_CONFIG`)
  2. Registers a verifier adapter for each member with `VerifierBackendType`
  3. Seeds the trust registry from `federation.json` only if the DB is empty

**Design decisions:**
- The `federation.json` seed is idempotent: if the DB already has entries,
  it doesn't re-seed
- Members without `verifierBackendType` are skipped in
  `ToBackendEntries()` — they only participate as issuers
- The `VERIFIABLY_FEDERATION_CONFIG` env var allows overriding the path
- `bootstrapHub` is a silent no-op if `federation.json` doesn't exist —
  zero regression on deployments without a hub

**Success criteria:**
- A Hub with members in federation.json → the Registry has a verifier
  adapter per member
- `FetchPresentationResult` correctly routes by state prefix (already worked)
- The trust registry auto-seeds on the first boot of an empty hub

---

### ✅ Phase 5 — Trust Registry Extension + Issuer Registration CRUD

**Goal:** Extend the existing Trust Registry with `ServiceEndpoint` and
build the Hub's issuer admin CRUD.

> The Trust Registry already exists in `internal/trust/` with a complete
> interface (`IsTrusted`, `TrustedIssuers`, `Add`, `Remove`), PostgreSQL +
> memStore backends, and the `GET /trust-registry` JWT endpoint. It only
> needs to be extended.

**Files created/modified:**
- [x] `internal/trust/registry.go` — `TrustedIssuer` extended with
  `ServiceEndpoint`, `StatusListEndpoints`, `StatusListPolicy`
- [x] `internal/trust/store.go` — `pgStore.Add()` and `pgStore.refresh()`
  updated for the 3 new fields
- [x] `internal/storage/pg/db.go` — `runMigrations()` adds:
  ```sql
  ALTER TABLE trusted_issuers
    ADD COLUMN IF NOT EXISTS service_endpoint      TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS status_list_endpoints TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS status_list_policy    TEXT   NOT NULL DEFAULT 'fail-closed';
  ```
- [x] `internal/trust/jwt.go` — no changes needed: `BuildJWTES256`
  marshals the full `[]TrustedIssuer` slice via JSON; the new fields appear
  automatically in the payload
- [x] `internal/handlers/admin_federation.go` — new:
  - `GET /admin/federation/members` → `ShowFederationMembers`
  - `POST /admin/federation/members` → `RegisterFederationMember` (JSON or form)
  - `POST /admin/federation/members/{did}/delete` → `DeleteFederationMember`
  - Validations: DID must be `did:web:*`; healthz check if
    `service_endpoint` is present; DID resolution is warn-only (non-blocking)
  - HTMX: re-renders `fragment_federation_list` instead of redirecting
- [x] `templates/pages/admin_federation.html` — table with inline form +
  `fragment_federation_list`
- [x] `cmd/server/main.go` — routes under `activeRoles.Has(roles.Hub)`

**Design decisions:**
- The existing `trust.Registry` is reused as the backend — no new table
- DID resolution at registration time is warn-only (dev environments don't
  have a public DID doc)
- The healthz check is a hard failure only if `service_endpoint` is present
- `jwt.go` needed no changes — the new fields flow through automatic JSON
  marshaling
- The form lives on the same page (not a separate one) — an HTMX swap
  replaces the list

**Success criteria:**
- `GET /trust-registry` returns an ES256 JWT with `service_endpoint`,
  `status_list_endpoints`, `status_list_policy` per issuer
- The admin can add/view/delete issuers from `/admin/federation/members`
- Idempotent migration: `ADD COLUMN IF NOT EXISTS` doesn't break an
  existing DB

---

### ✅ Phase 6 — Verification Events Log

**Goal:** Persist every completed verification for analytics.

> **PostgreSQL from day 1.** The Hub is the aggregation point for the whole
> ecosystem. The JSON-backed pattern from `issuance/log.go` works fine for a
> single issuer, but on the Hub every event from every schema and issuer
> converges here. JSON with a mutex is a bottleneck under concurrent load
> and doesn't support efficient queries for
> `/api/ecosystem/issuers/{did}/stats`. The `pg/` pattern already exists.

**Files created/modified:**
- [x] `internal/verification/events.go` — new package: `Event` struct,
  `Log` interface, `NewID()`
- [x] `internal/verification/pg_log.go` — PostgreSQL-backed: `NewPGLog(pool)`,
  `Append()` (ON CONFLICT DO NOTHING), `QueryByIssuer()` (uses
  ve_issuer_did_idx)
- [x] `internal/storage/pg/db.go` — DDL added to `runMigrations()`:
  ```sql
  CREATE TABLE IF NOT EXISTS verification_events (...)
  CREATE INDEX IF NOT EXISTS ve_issuer_did_idx ON verification_events (issuer_did, verified_at DESC);
  ```
- [x] `internal/handlers/handlers.go` — H struct: `VerificationLog verification.Log`
- [x] `internal/handlers/public_verify.go` — `PublicVerifyResult`:
  fire-and-forget goroutine after a terminal result; emits
  `Event{IssuerDID, SchemaName, Status, TrustStatus, StatusListSrc}`
- [x] `internal/handlers/verifier.go` — `SimulateResponse`: fire-and-forget
  goroutine; emits `Event{IssuerDID, SchemaID, SchemaName, VerifierDPG,
  Status, TrustStatus}`
- [x] `cmd/server/main.go` — `verification.NewPGLog(pgPool)` wired when
  `pgPool != nil`; nil on deployments without a DB (feature silently disabled)

**Design decisions:**
- PostgreSQL-only: there's no JSON-backed implementation —
  `h.VerificationLog = nil` on deployments without a DB, feature disabled
  with zero regression
- Fire-and-forget goroutine with a `context.WithTimeout(5s)` per event — the
  HTTP response never waits on the DB
- `ON CONFLICT (id) DO NOTHING` in Append: idempotent if the goroutine retries
- No PII: `Event` has no holder field; `DisclosedFields` is never written
- `DeploymentID = VERIFIABLY_PUBLIC_URL` for cross-instance correlation

**Success criteria:**
- Every completed verification produces a PostgreSQL record
- No holder PII in any record
- `QueryByIssuer` returns results in <100ms with the index

---

### ✅ Phase 7 — Issuer Analytics API

**Goal:** Each issuer can see stats on its verified credentials.

**Files created/modified:**
- [x] `internal/trust/apikeys.go` — new package:
  - `APIKeyStore` interface: `Issue`, `Validate`, `Revoke`, `HasKey`
  - `pgAPIKeyStore`: UPSERT on Issue (atomic rotation), SHA-256 on
    Validate, DELETE on Revoke
  - `NewPGAPIKeyStore(pool)` + `ErrInvalidAPIKey` sentinel error
- [x] `internal/storage/pg/db.go` — DDL added to `runMigrations()`:
  ```sql
  CREATE TABLE IF NOT EXISTS issuer_api_keys (
      did        TEXT        PRIMARY KEY,
      key_hash   TEXT        NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  ```
- [x] `internal/handlers/ecosystem_api.go` — new handler:
  - `GET /api/ecosystem/issuers/{did}/stats` with `Authorization: Bearer`
  - Validates the key → DID; checks the DID matches `{did}` in the path
    (401/403)
  - Aggregates `verification_events` from the last 30 days:
    total/valid/invalid/bySchema
  - JSON response: `{issuer_did, period_days,
    verified:{total,valid,invalid,by_schema}}`
- [x] `internal/handlers/handlers.go` — H struct: `IssuerAPIKeyStore trust.APIKeyStore`
- [x] `internal/handlers/admin_federation.go`:
  - `IssueAPIKey`: `POST /admin/federation/members/{did}/api-key` —
    generates a key, renders `fragment_api_key_display` with the plaintext
    visible once
  - `RevokeAPIKey`: `POST /admin/federation/members/{did}/api-key/revoke` —
    revokes it, re-renders the member list
  - `memberKeyMap()`: helper that builds a `map[DID]bool` for the template
  - `ShowFederationMembers`, `RegisterFederationMember`,
    `DeleteFederationMember` — updated to pass `MemberKeys` and
    `HasAPIKeyStore`
- [x] `templates/pages/admin_federation.html`:
  - Empty `#api-key-display` slot, filled via HTMX with
    `fragment_api_key_display`
  - `fragment_api_key_display`: shows the token, a copy-to-clipboard
    button; empty slot when there's no key
  - `fragment_federation_list`: "API key" column with an `active/none` pill
    + Generate/Rotate/Revoke buttons (only when `HasAPIKeyStore`)
- [x] `cmd/server/main.go`:
  - `trust.NewPGAPIKeyStore(pgPool)` wired when `pgPool != nil`
  - Routes under Hub: `POST .../api-key`, `POST .../api-key/revoke`,
    `GET /api/ecosystem/issuers/{did}/stats`

**Design decisions:**
- One-time display: plaintext is never stored; SHA-256 of the token in the
  DB; UPSERT on Issue (rotation atomically invalidates the previous one)
- `HasKey` for the template: N SELECT EXISTS per member in
  ShowFederationMembers (acceptable: a few dozen members)
- Verifications only (no issuance): the Hub doesn't issue credentials — the
  analytics API only exposes data from the Hub's `verification_events`
- `ErrInvalidAPIKey` sentinel: the caller distinguishes "bad key" from an
  I/O error without inspecting strings

**Success criteria:**
- Issuer A calls `/api/ecosystem/issuers/{did}/stats` with its API key →
  breakdown of verifications by schema over 30 days
- Invalid key → 401; another DID's key → 403
- The admin generates a key from `/admin/federation/members` → it's shown
  once with a "Copy" button
- The admin revokes a key → the list updates live, "none" pill

---

### ✅ Phase 8 — Prometheus Federation on the Hub

**Goal:** The Hub aggregates metrics from all issuers.

**Files created:**
- [x] `deploy/compose/monitoring/prometheus-hub.yml` — Hub-specific
  Prometheus config:
  - `verifiably-hub` job: scrapes the Hub's own `/metrics` (15s)
  - `verifiably-federation` job: one `job_name` block per member, generated
    directly from `trusted_issuers` (see the updated script below)
  - Preserves the `issuer_did` and `issuer_name` labels from the targets
- [x] `deploy/compose/monitoring/generate-federation-prometheus.sh` — bash
  script:
  - Queries the Hub's `trusted_issuers` table directly (via
    `docker compose exec postgres psql`) — the DB is the single source of
    truth; members managed through the admin UI at
    `/admin/federation/members` are picked up the next time this script runs
  - Rewrites `prometheus-hub.yml` in place from
    `prometheus-hub.template.yml`, adding one scrape job per member (each
    with its own Bearer token)
  - Reloads Prometheus via `--web.enable-lifecycle` without a restart
- [x] `deploy/compose/monitoring/grafana/dashboards/verifiably-ecosystem-v1.json`:
  - **Ecosystem Totals row**: 5 stat panels — Active Issuers, Issued (24h),
    Verified at Hub, Valid Rate, Unreachable Issuers
  - **Verification Trends row**: 2 time series — Verification Rate by
    Issuer + Issuance Rate by Member
  - **Per-Issuer Breakdown row**: table with issued/verified/valid/status
    per issuer (merge + organize transformations)
  - **Trust Registry Health row**: days-until-expiry bar gauge (30/90 day
    thresholds), 2 stat panels, health table — all waiting on Phase 9 metrics
  - Template variables: `$issuer` (multi-select from label_values) +
    `$interval`
- [x] `deploy/compose/hub/docker-compose.yml` — standalone Hub stack:
  - Services: postgres, verifiably-go (ROLES=hub), prometheus (uses
    prometheus-hub.yml), grafana
  - Grafana: home dashboard = ecosystem overview
- [x] `deploy/compose/hub/.env.example` — required variables documented

**Design decisions:**
- The generate script queries the DB directly and rewrites the full
  scrape-jobs section — the DB is the single source of truth, so there's no
  separate targets file to keep in sync
- `honor_labels: true` on the federation job: preserves the issuer's labels
  without colliding with the Hub's own labels
- The dashboard includes Phase 9 panels (Trust Registry Health) as
  placeholders — they show no data until Phase 9 emits the gauges
- `$__range` for totals over the selected period; `$interval` for rates

**Operational workflow:**
```bash
# 1. Add/edit/remove members via the Hub admin UI
#    (or config/federation.json for the initial seed)
# 2. Regenerate the Prometheus federation scrape config:
./deploy/compose/monitoring/generate-federation-prometheus.sh
# 3. Prometheus reloads automatically (--web.enable-lifecycle, no restart needed)
# 4. Verify targets at http://localhost:9090/targets
```

**Success criteria:**
- `GET http://localhost:9090/targets` shows every federation member
- Grafana at `http://localhost:3100` opens the Ecosystem Overview dashboard
  by default
- Issuance panels (scraped from issuers) and verification panels (Hub) show
  real data
- Trust Registry Health panels show "no data" until Phase 9

---

### ✅ Phase 9 — Trust Registry Health Monitoring

**Goal:** Proactively detect issuers whose accreditation is expiring or
that are down.

**Files created/modified:**
- [x] `internal/metrics/metrics.go` — extended with a gauge type:
  - `gge` struct: `{name, ls string, val atomic.Int64}`
  - `gauges map[string]*gge` on `registry`; initialized in `newRegistry()`
  - `SetGauge(name string, v int64, labels ...string)`: upsert under lock
  - `DeleteGauge(name string, labels ...string)`: removes an entry under
    lock (stale cleanup)
  - `snapshot()` updated to a 3-value return `([]*ctr, []*histo, []*gge)`
  - `writeTo()` emits gauges with a `# TYPE xxx gauge` header, sorted by
    name+ls
  - Package-level `SetGauge` / `DeleteGauge` functions added
- [x] `internal/trust/health.go` — new package:
  - `EndpointStatus{Up, Checked bool, At time.Time}` — in-memory state, no DB
  - `Monitor` struct: `status map[string]EndpointStatus`, `knownDIDs
    map[string]struct{}`, `http.Client` (5s timeout)
  - `NewMonitor()`: initializes with a 5s client
  - `Start(ctx, Registry)`: launches 2 goroutines — `runExpiry()` +
    `runEndpoint()`
  - `runExpiry()`: hourly ticker → `emitExpiry()` — gauge
    `trusted_issuer_days_until_expiry{did,name}`; cleans up gauges for
    removed DIDs via a `knownDIDs` diff
  - `runEndpoint()`: 5 min ticker → `probeEndpoints()` — GET
    `{ServiceEndpoint}/healthz`, gauge
    `trusted_issuer_endpoint_up{did,name}` (1/0), updates the `status` map
  - `EndpointStatus(did string)`: thread-safe read of the in-memory status
- [x] `deploy/compose/monitoring/alerts.yml` — 3 alert rules:
  - `IssuerAccreditationExpiringSoon`:
    `trusted_issuer_days_until_expiry < 30`, severity: warning, for: 0m
  - `IssuerEndpointDown`: `trusted_issuer_endpoint_up == 0`, severity:
    critical, for: 10m
  - `FederationAllMembersDown`:
    `count(up{job="verifiably-federation"} == 1) == 0`, severity:
    critical, for: 15m
- [x] `deploy/compose/monitoring/prometheus-hub.yml` — `rule_files` uncommented:
  ```yaml
  rule_files:
    - /etc/prometheus/alerts.yml
  ```
- [x] `internal/handlers/handlers.go` — H struct: `TrustHealthMonitor *trust.Monitor`
- [x] `internal/handlers/admin_federation.go`:
  - `memberHealthMap(members)`: builds a `map[DID]trust.EndpointStatus`
    from `TrustHealthMonitor`
  - Every fragment render updated to include `MemberHealth`
- [x] `templates/pages/admin_federation.html` — "Health" column with a
  traffic-light dot:
  - Gray: `not $health.Checked` (not probed yet)
  - Red: endpoint down (`not $health.Up`) OR expired OR `< 30 days`
  - Yellow: 30–90 days
  - Green: `>= 90 days` or no expiration
  - Uses the `daysUntil` template function (sentinel 99999 for no-expiry →
    always green)
- [x] `cmd/server/main.go`:
  - Monitor wired under `activeRoles.Has(roles.Hub) && h.TrustRegistry != nil`
  - `daysUntil` added to `funcMap`: returns
    `int(time.Until(t).Hours()/24)`; `t.IsZero()` → `99999`

**Design decisions:**
- In-memory gauges with `atomic.Int64`: no external dependencies,
  thread-safe, compatible with the existing stdlib-only metrics.go
- `knownDIDs` for stale gauge cleanup: when an issuer is removed from the
  trust registry, its gauge disappears from `/metrics` on the next ticker
  round (no restart)
- `EndpointStatus` in memory (no DB): it's ephemeral state — doesn't need
  persistence; recalculated on every probe cycle; only serves to render the
  traffic light in the admin UI
- `99999` sentinel in `daysUntil` for `ValidUntil.IsZero()`: the template
  uses direct numeric comparisons (`lt $days 30`, `lt $days 90`) with no
  special branch for "no expiration"

**Success criteria:**
- `GET /metrics` exposes `trusted_issuer_days_until_expiry` and
  `trusted_issuer_endpoint_up` per issuer
- The `IssuerAccreditationExpiringSoon` alert fires when an issuer has <30 days left
- The `IssuerEndpointDown` alert fires after 10 min of the endpoint being down
- The `/admin/federation/members` admin panel shows a live per-issuer
  health traffic light
- Removing an issuer clears its gauge on the next ticker cycle (doesn't
  persist in `/metrics`)

---

### ✅ Phase 10 — Status List Cache with Signature Verification

**Goal:** The Hub keeps cached copies of status lists for availability and integrity.

**Files created:**
- [x] `internal/statuslistcache/cache.go` — `Cache` interface + `Result{RawJWT, Source, CachedAt, ExpiresAt}`
- [x] `internal/statuslistcache/json_cache.go` — `jsonStore`: in-memory map
  + disk (`state/status-list-cache/{sha256(url)[:16]}.json`); thread-safe
  with `sync.RWMutex`
- [x] `internal/statuslistcache/fetcher.go` — `Fetcher` implements `Cache`:
  1. `fetchLive()`: GET with a 3s timeout; supports raw JWT and JSON with
     `token`/`jwt`/`verifiableCredential`
  2. `verifyJWT()`: extracts `iss` from the payload → resolves the DID →
     ES256-verifies against the DID doc's `publicKeyJWK`; resolution
     failure is warn-only; a signature mismatch returns an error
  3. `verifyES256JWT()`: pure stdlib (ecdsa, elliptic, sha256, big.Int) — no
     external dependencies
  4. Falls back to `jsonStore.load()` if the fetch fails; `Source:
     "unknown"` if there's no cache either
  5. Default TTL: 6 hours per entry
- [x] `internal/statuslistcache/poller.go` — `Poller`: goroutine; immediate
  poll on `Start()` + hourly ticker; iterates `TrustedIssuers()` +
  `StatusListEndpoints`
- [x] `backend/adapter.go` — `VerificationResult` extended with
  `StatusListSource string`, `StatusListCachedAt *time.Time`
- [x] `cmd/server/main.go` — `statuslistcache.NewFetcher()` wired in all
  roles; `NewPoller().Start()` only in Hub mode

**Design decisions:**
- 6 hour TTL: balances freshness against availability (an issuer down for
  < 6h → cache still valid)
- Pure stdlib ES256 verification: no `golang.org/x/crypto` or
  `lestrrat-go/jwx`; the curve is P-256 (the same algorithm as the Hub's own
  Trust Registry JWT)
- JWK as `map[string]any` (the type used by the existing resolver's
  DIDDocument)
- Fail-closed on DID resolution: if the resolver fails, the cache isn't
  blocked (warn-only) — this prevents a temporarily unresolvable DID from
  making the endpoint unavailable

**Success criteria:**
- If Issuer A goes down, the Hub uses the cache and shows
  `StatusListSource: "cached"`
- A status list with an invalid ES256 signature → `Source: "unknown"` +
  error returned
- The poller warms the cache at startup and every hour

---

## Design constraints (non-negotiable)

1. **100% backwards-compatible**: without `VERIFIABLY_ROLES` → identical to
   current behavior
2. **Stable `trust.Registry` interface**: `IsTrusted`, `TrustedIssuers`,
   `Add`, `Remove` don't change once created (upgrade path to OpenID
   Federation without interface changes)
3. **Existing adapters left unmodified**: changes only in the server layer
   and new packages
4. **No new external dependencies** without explicit justification
5. **No PII in analytics tables**: `verification_events` never stores
   holder data
6. **No verification correlation**: don't store fields that would let two
   verifications be linked to the same holder
7. **Asymmetric signing mandatory in production**: HS256 is for dev/local
   testing only; production requires `VERIFIABLY_TRUST_SIGNING_KEY` to be
   configured

---

## Recommended implementation sequence

```
Phase 1 (Roles) → Phase 1.5 (DID Resolver + ES256) → Phase 4 (Federation Config)
      ↓
Phase 5 (Trust Registry + CRUD)
      ↓
Phase 2 (Hub Public Portal) + Phase 10 (Status List Cache)  ← ship together
      ↓
Phase 3 (Schema Federation with cache)
      ↓
Phase 6 (Verification Events Log — PostgreSQL)
      ↓
Phase 7 (Issuer Analytics API) → Phase 8 (Prometheus Federation)
      ↓
Phase 9 (Trust Registry Health)
```

Phases 1, 1.5, 4, 5 are the core of federation.
Phases 2 + 10 are the public portal (always together).
Phases 6–9 are the observability plane.

---

## Key reference files

```
backend/adapter.go                           ← main interface + VerificationResult
internal/adapters/registry/registry.go       ← fan-out, Register(), AllAdapters()
internal/adapters/registry/config.go         ← BackendEntry, LoadConfig()
internal/adapters/factory/factory.go         ← builds adapters from config
internal/handlers/handlers.go                ← H struct, render(), pageData()
internal/handlers/verifier.go                ← current verification flow
internal/handlers/trust.go                   ← GET /trust-registry handler
internal/handlers/ratelimit.go               ← rate limiter (IP + API key, already implemented)
internal/trust/registry.go                   ← interface + TrustedIssuer
internal/trust/jwt.go                        ← BuildJWT (HS256 → ES256 in Phase 1.5)
internal/issuance/log.go                     ← audit log pattern (follow for events)
internal/statuslist/store.go                 ← status list store pattern
internal/storage/pg/db.go                    ← runMigrations() — ALTER TABLEs go here
cmd/server/main.go                           ← startup, wiring, route registration
config/backends.json                         ← adapter config format
vctypes/vctypes.go                           ← domain types
```

---

## Overall progress

- [x] Phase 0 — Baseline (add-credebl)
- [x] Phase 0.5 — DID:web Deployment Automation (Inji Certify)
- [x] Phase 1 — Deployment Roles (`VERIFIABLY_ROLES`)
- [x] Phase 1.5 — DID Resolver + Trust Registry Key Upgrade (ES256 + JWKS)
- [x] Phase 4 — Federation Config (`federation.json` + hub bootstrap + state
  prefix routing confirmed)
- [x] Phase 5 — Trust Registry Extension + Federation Member CRUD Admin
- [x] Phase 2 — Hub Public Portal (citizen `/verify` + HTMX polling)
- [x] Phase 10 — Status List Cache (fetcher + JSON store + poller + ES256 verify)
- [x] Phase 3 — Schema Federation
- [x] Phase 6 — Verification Events Log
- [x] Phase 7 — Issuer Analytics API
- [x] Phase 8 — Prometheus Federation
- [x] Phase 9 — Trust Registry Health Monitoring
