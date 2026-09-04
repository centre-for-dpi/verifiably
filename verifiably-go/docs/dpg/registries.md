# Registries & data sources — implementation guide

> **Adapter type:** none — registries are **data sources**, not `backend.Adapter` DPGs. verifiably
> **reads** identities/claims from them via the bulk engine (`internal/handlers/bulk.go`) and writes
> the results into the certify-internal registries.
> **Roles it serves:** issuer bulk-provision (`vc_subject`) and registrar bulk-enrol
> (`identity_registry`).

In the MOSIP/eSignet model a citizen cannot self-mint an identity — identities originate from an
**authoritative source** run by a separate entity. This guide covers those sources (Sunbird RC and
the federated agency registries), how verifiably pulls from them, the registry-admin console, and
the certify-internal registries they feed.

---

## 1. The model — verifiably reads, never owns

verifiably is a **consumer** of external registries. It offers four pluggable connectors and two
sinks:

```
 CSV file ─┐
 secured API (X-Road / REST) ─┤   column→field     ┌─→ certify.vc_subject        (issuance claims)
 PostgreSQL SELECT ───────────┤──  mapping  ──────→ │
 Sunbird RC entity search ────┘                     └─→ certify.identity_registry (enrolled identities)
```

The **connectors** are the same for both flows (`internal/handlers/bulk.go`): `parseCSVRows`,
`fetchJSONRows` (secured API), `queryDBRows` (Postgres SELECT), `searchRegistryAll` /
`sunbirdSchemas` (Sunbird). The **sink** differs: issuer bulk-provision → `runBulkProvision` →
`vc_subject`; registrar bulk-enrol → `runBulkIdentity` → `identity_registry`.

---

## 2. Sunbird RC — the registry of record ("the DPG")

Sunbird RC is a standalone **registry + credentialing chain** (vault + identity + credential-schema
+ credential services) — the authoritative citizen registry the demo treats as the ID repository.

- **Where it runs:** a **separate stack** (the workshop infra, not the verifiably-go compose),
  reachable from verifiably at `http://156.67.105.185:18091` (its registry API) and publicly at
  `sunbird-rc.in-labs.cdpi.dev`. Port remaps avoid the verifiably stack (registry 18091, DB 15432,
  keycloak 18080, nginx 11080).
- **How verifiably reaches it:** the `VERIFIABLY_REGISTRIES` env (a JSON array). Live value:
  ```json
  [{"id":"sunbird","label":"Sunbird RC (all entities, auto-discover)",
    "url":"http://156.67.105.185:18091","discover":true,"searchField":"individualId"}]
  ```
  `discover:true` lets the registrar/issuer console list the entities the registry actually holds
  (`sunbirdSchemas` → `GET /api/docs/swagger.json`-derived entity list); `searchField` is the
  record column holding each holder's eSignet `individualId`.
- **Read path:** `POST /api/v1/<entity>/search` returns every record of an entity; each record is one
  row to provision/enrol. Columns are mapped to credential/identity fields in the console's
  next step (they need not match names).

Sunbird RC is documented in depth in the workshop infra runbook (`infra/REBUILD.md` §2); this guide
covers only verifiably's **read** integration.

---

## 3. Federated agency registries (DAD / GN / Business)

Three standalone FastAPI sources-of-truth — the "data exchange without VCs" path — each its own
SQLite + OpenAPI/Swagger, published at `*.registry.in-labs.cdpi.dev` (e.g.
`dad.registry.in-labs.cdpi.dev`). They live in `infra/registries/` in the workshop repo (seeded
DAD 60 / GN 60 / Business 52 rows) and are consumed by verifiably's bulk engine the same way as any
**secured API** source (`fetchJSONRows` against `…/<entity>/issuance`, a schema-shaped export).

---

## 4. The registry-admin console

A separate container that lets a registrar populate a Sunbird RC entity from a simple UI (single
record / CSV / API / DB / registry), mirroring the bulk picker.

| | |
|---|---|
| Image / container | `registry-admin:local` / `registry-admin` |
| Port | `${REGISTRY_ADMIN_HOST_PORT:-18095}:8000`, public at `registry-admin.<domain>` |
| `SUNBIRD_URL` | `http://156.67.105.185:18091` (the registry it writes to) |
| `VERIFIABLY_SCHEMAS_URL` | `http://verifiably-go:8080/api/registry-credentials` (reads the active Inji credential list to pre-fill entity names) |

verifiably links to it via `VERIFIABLY_REGISTRY_ADMIN_URL=https://registry-admin.in-labs.cdpi.dev`.
Source: `deploy/registry-admin/app.py` (FastAPI + httpx + psycopg).

---

## 5. The certify-internal registries (the sinks)

Both live in the auth-code `inji_certify` DB (`certify` schema) — see
[inji-certify-authcode.md](./inji-certify-authcode.md):

| Table | Written by | Read by |
|---|---|---|
| `identity_registry` | registrar bulk-enrol (`runBulkIdentity` → `UpsertIdentity`) | `/holder/register` activation gate (`GetIdentity`) + `createMockIdentity`. Keyed by raw individualId. |
| `vc_subject` | issuer bulk-provision + activation (`ProvisionSubject`) | Certify's Postgres data-provider (via `vc_subject_<slug>` views), keyed by the eSignet subject id. |

**Demo Postgres source:** `citizens-postgres` (`postgres:16.4-alpine`, DB `citizens`, host port
`5435`) is the sample database the "Bulk from PostgreSQL" connector demonstrates `queryDBRows`
against.

---

## 6. Environment variables

| Var | Where | Meaning |
|---|---|---|
| `VERIFIABLY_REGISTRIES` | `scripts/start-container.sh` | JSON array of configured registries (`id/label/url/path/entity/searchField/discover` + optional `tokenUrl/clientId/clientSecret/scope` for an OAuth2 client_credentials grant and `insecureSkipVerify` for demo hosts — see `.env.example`). Drives the registry dropdown, the "Bulk from API" picker and auto-discover. |
| `VERIFIABLY_REGISTRY_ADMIN_URL` | `scripts/start-container.sh` | Link to the registry-admin console. |
| `INJI_CERTIFY_DATABASE_URL` | `scripts/start-container.sh` | The `inji_certify` DSN — where both sinks live. |

---

## 7. APIs & handlers

**verifiably surface:** registrar — `/registrar/identities`, `POST /registrar/identities/{source,preview,apply,registry-entities}`;
issuer bulk-provision — the Inji bulk source picker on `/issuer/issue`; `POST /api/v1/subjects`
(single-subject provision); `GET /api/registry-credentials` (active credential list for the console).
**Connectors:** `internal/handlers/bulk.go` (`queryDBRows`, `searchRegistryAll`, `sunbirdSchemas`,
`discoverEntities`, `runBulkProvision`), `internal/handlers/bulk_api.go` (`fetchGETRows`, `fetchSunbirdRows`,
`fetchJSONRows`, `BulkAPIEntities`), `internal/handlers/inji_schema.go` (`registryClient`, `registryAuthHeader`,
`swaggerEntities`), `internal/handlers/identity.go` (`runBulkIdentity`,
identity source options), `internal/storage/pg/subjects.go` (`UpsertIdentity`, `GetIdentity`,
`ProvisionSubject`).

---

## 8. Gotchas

- **Sunbird RC + federated registries are external** — they are not brought up by
  `deploy.sh up`; they live in the workshop infra. verifiably only needs `VERIFIABLY_REGISTRIES`
  pointed at reachable URLs. If the registry dropdown is empty, check that env + the registry's
  reachability from the verifiably-go container.
- **`searchField` must be the individualId column.** The provisioned/enrolled row is keyed by it;
  a wrong `searchField` yields identities eSignet can't match at claim time.
- **Registry data ≠ credentials.** These registries hold source records; issuance/enrolment turns
  them into `vc_subject`/`identity_registry` rows. Sunbird's own credentialing chain (native
  PDF+QR) is a separate "registry-as-record" path verified via [Inji Verify](./inji-verify.md).

See also: [inji-certify-authcode.md](./inji-certify-authcode.md) (the sinks + activation) ·
[../deploy.md](../deploy.md) · [../architecture.md](../architecture.md).

---

## 9. Using a registry through "Bulk from API" (any DPG)

The `registry` chip is Inji-only (it feeds `vc_subject`). Every other DPG — walt.id in particular —
reaches a Sunbird RC registry through the **Bulk from secured API** chip, because registry access
is just API access. The api mini-form (`templates/pages/issuer_issue.html`, handler
`BulkPreview` → `bulk_api.go`) has:

| Field | Meaning |
|---|---|
| Request style `api_mode` | `get` (default — GET a JSON array, unchanged legacy behaviour) or `sunbird` (`POST <url>/api/v1/<entity>/search {"filters":{}}`) |
| Configured registry `api_pick` | one `VERIFIABLY_REGISTRIES` entry; pre-fills URL, entity, search field, and — **server-side only** — the token settings and TLS flag |
| `api_url` | base URL (sunbird) or full URL (get) |
| `api_entity` + **Discover entities** | entity to pull; discovery tries `POST /api/v1/Schema/search`, then the registry's Swagger/OpenAPI `paths` (`/api/docs/swagger.json`, `/swagger.json`) — "listed from Swagger" when the Schema entity is locked down |
| `api_search` | record column copied into `individualId` when the record lacks one (default `individualId`) |
| Authentication | a static `Authorization` header (`api_auth`) **or** an OAuth2 client_credentials grant (`api_token_url`, `api_client_id`, `api_client_secret`, `api_scope`) — the fetched token overrides the header |
| `api_insecure` | skip TLS verification (demo hosts with expired certs); refused when `VERIFIABLY_ENV=production` |
| `api_limit` | row cap (0 = all) |

**Entity precedence:** a picked registry's configured entity wins over the form's schema-ID prefill;
a name you type yourself wins over both. Rows are flattened (Sunbird `osid`/`osOwner`/`_os*` metadata
dropped), then mapped column→field exactly like CSV/DB rows and issued through the DPG's normal
bulk sink (`Adapter.IssueBulk` for walt.id).

**Failure messages:** `Fetch failed: HTTP 404: Schema 'X' not found` (Sunbird's own `params.errmsg`
is surfaced), `Fetch failed: entity 'X' has no records`, `Entity is required for Sunbird RC search.`
A failed token grant is logged and the request proceeds unauthenticated, so the registry's 401 is
what you see.

**Example deployment configuration** (a staging registry behind an OAuth2 client_credentials
IdP whose certificate is self-signed — *illustrative only; nothing in the code knows any registry*):

```
VERIFIABLY_REGISTRIES='[{"id":"national-registry","label":"National Population Registry (staging)","url":"https://registry.example.org","entity":"Person","searchField":"individualId","tokenUrl":"https://idp.example.org/oauth2/token","clientId":"<client id>","clientSecret":"<client secret>","insecureSkipVerify":true}]'
```

In the UI: issuer → walt.id → schema → Bulk → **Bulk from secured API** → request style *Sunbird RC
search* → pick the registry (entity becomes `Person`) → *Discover entities* → *Preview & map*
→ map columns → *Issue N credentials*.
