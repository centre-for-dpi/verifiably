# CREDEBL — implementation guide

> **Version:** CREDEBL **v2.x** (all service images `ghcr.io/credebl/*:latest`, unpinned; Credo-TS
> agent via `ghcr.io/credebl/credo-controller:latest`).
> **Adapter type:** `credebl` → `internal/adapters/credebl`.
> **Roles:** issuer · verifier (holder delegated to an external OID4VCI wallet).

CREDEBL is the heaviest DPG — a ~23-service microservice platform (Aries/Credo agent, NestJS
services over NATS, its own Keycloak realm, MinIO, Redis, Postgres). verifiably fronts it as a
single credentialing surface.

---

## 1. What it is

A full SSI platform. Services split into infrastructure, the NestJS microservice mesh (routed via
one api-gateway over NATS), the Credo (Aries) agent, and a set of one-shot bootstrap containers.
OID4VCI **pre-authorized code** issuance (`dc+sd-jwt` / `vc+sd-jwt`) and OID4VP verification (DCQL).

---

## 2. The role verifiably plays — **proxy + auth broker + schema store**

- **Reverse-proxies** the api-gateway (which routes internally to the microservices).
- **Auth broker.** Signs in as the CREDEBL platform admin (password encrypted on-wire, CryptoJS
  AES) and caches the Bearer token for subsequent calls.
- **Schema store.** Custom schemas are POSTed into CREDEBL's template/schema system.
- **OID4VCI/OID4VP orchestrator.** Translates between verifiably's schema model and CREDEBL's
  agent/offer/presentation model; rewrites offer URIs from the internal agent address to the public
  host so external wallets can reach them.

The holder is **not** built in — CREDEBL issues offers that any external OID4VCI wallet (Inji Web,
Credo mobile, etc.) claims.

---

## 3. Services (compose — `deploy/compose/credebl/docker-compose.yml`)

All carry `profiles: ["credebl"]` **except** `credebl-oid4vci-rewriter` (always up for public
hairpin routing). `deploy.sh` auto-passes `--profile credebl` when the scenario needs it.

**Infrastructure**
| Service | Image | Role |
|---|---|---|
| `credebl-postgres` | `postgres:16.4-alpine` | Platform DB `credebl`. |
| `credebl-redis` | `redis:7.4-alpine` | Cache/queues. |
| `credebl-nats` | `nats:2.10-alpine` | Inter-service message bus. |
| `credebl-minio` (+ `credebl-minio-setup`) | `minio/minio:latest`, `minio/mc:latest` | S3 (schema files, OOB). Public at `credebl-minio.<domain>`. |
| `credebl-mailpit` | `axllent/mailpit:latest` | Dev SMTP capture. |
| `credebl-schema-file-server` | `ghcr.io/credebl/schema-file-server:latest` | Hosts schema JSON. |
| `credebl-oob-redirector` | `python:3.12-alpine` | Out-of-band URL redirects. |
| `credebl-oid4vci-rewriter` | `nginx:1.27-alpine` | Rewrites internal agent URLs → public host; the public OID4VCI/OID4VP/did.json entrypoint. |

**Bootstrap (one-shot)**: `credebl-seed` (`ghcr.io/credebl/seed:latest`),
`credebl-platform-admin-bootstrap` (`postgres:16.4-alpine`, runs `bootstrap-platform-admin.sh`).

**Microservice mesh** (all `ghcr.io/credebl/<name>:latest`, over NATS): `api-gateway` (`:5000`,
the only HTTP ingress), `user`, `utility`, `connection`, `issuance`, `ledger`, `organization`,
`verification`, `cloud-wallet`, `oid4vc-issuance`, `oid4vc-verification`, `ecosystem`.

**Credo agent**: `credebl-agent-provisioning` (spawns per-org Credo agents on ports 9200+, mounts
`/var/run/docker.sock`) + `credebl-agent-service` (`ghcr.io/credebl/agent-service:latest`,
`AFJ_VERSION=ghcr.io/credebl/credo-controller:latest`).

Service array: `CREDEBL_SERVICES` in `scripts/common.sh`.

---

## 4. Environment variables

**Adapter** (`internal/adapters/credebl/config.go` — env overrides `backends.json`):

| Var | `backends.json` key | Meaning |
|---|---|---|
| `CREDEBL_API_URL` | (baseURL) | api-gateway public URL, `https://credebl.in-labs.cdpi.dev`. |
| `CREDEBL_EMAIL` | `email` | Platform-admin email. |
| `CREDEBL_PASSWORD` | — | Plaintext (AES-encrypted on-wire). **Secret.** |
| `CREDEBL_CRYPTO_PRIVATE_KEY` | `cryptoPrivateKey` | Key for the password encryption. **Secret.** |
| `CREDEBL_ORG_ID` | `orgId` | Pre-provisioned org UUID (`6463b259-…`). |
| `CREDEBL_ISSUER_ID` | `issuerId` | OID4VCI issuer id (`43cdb080-…`). |
| `CREDEBL_VERIFIER_ID` | `verifierId` | OID4VP verifier id (auto-provisioned if empty). |

Passed through by `scripts/start-container.sh` (`${CREDEBL_*:+-e …}`). Platform-service env
(DB/Redis/NATS URLs, secrets) lives in the generated `credebl.env` (see §5).

---

## 5. Runtime / generated configs

`deploy/compose/credebl/config/`:
| File | Committed? | Role |
|---|---|---|
| `credebl.env` | **generated** by `ensure_credebl_env()` (bootstrap-credebl.sh) | Service env + auto-generated secrets (Postgres/MinIO passwords, agent api-key, schema-file-server crypto key). Re-read on subsequent runs. |
| `keycloak-realm.json` | committed | CREDEBL's Keycloak realm (imported into the shared Keycloak). |
| `postgres-init.sql` | committed | DB init. |
| `credebl-master-table.json` | committed | Seed data (countries, etc.). |
| `aws/config` | committed | S3 client config for the utility service. |

Plus **deploy-generated** under `${CREDEBL_COMPOSE_DIR}/.agent-runtime/` (by
`write_credebl_agent_runtime_env()`): `nginx-oid4vci.conf` (the `sub_filter` rewrite rules for the
oid4vci-rewriter), `agent.env`, and the per-agent config/token/endpoints.

---

## 6. Caddy

```caddy
credebl.in-labs.cdpi.dev {
	handle /oid4vci/*      { reverse_proxy credebl-oid4vci-rewriter:80 }
	handle /oid4vp/*       { reverse_proxy credebl-oid4vci-rewriter:80 }
	handle /openid4vc/*    { reverse_proxy credebl-oid4vci-rewriter:80 }
	handle /.well-known/did.json { reverse_proxy credebl-oid4vci-rewriter:80 }
	reverse_proxy credebl-api-gateway:5000
}

credebl-minio.in-labs.cdpi.dev {
	reverse_proxy credebl-minio:9000
}
```

The OID4VCI/OID4VP/did.json paths go through the nginx rewriter (which rewrites the Credo agent's
internal URLs to the public host); everything else hits the api-gateway. In localhost mode the
stack Caddyfile routes `/oid4vci/*` to `host.docker.internal:${CREDEBL_AGENT_API_PORT:-8001}`.

---

## 7. Databases & APIs

**Database `credebl`** (`credebl-postgres`) — the platform DB (users, orgs, schemas, credential
records, agent wallets). Credo agent wallets are stored here too
(`WALLET_STORAGE_HOST=172.17.0.1`).

**Upstream API (verifiably → api-gateway):** `POST /v1/auth/login`,
`POST /v1/orgs/{orgId}/oid4vc/{issuers,verifiers}`,
`POST /v1/orgs/{orgId}/oid4vc/{issuerId}/create-offer`,
`GET /v1/orgs/{orgId}/oid4vc/{issuerId}/template`,
`POST /v1/orgs/{orgId}/verifier/{verifierId}/verify-request`,
`GET …/verify-presentation/verify?requestId=…`, `POST /v1/orgs/{orgId}/schemas/import`.
**Adapter files:** `internal/adapters/credebl/` (`config.go`, `adapter.go`, `auth.go`,
`issuer.go`, `verifier.go`).

---

## 8. Deploy + verify

```bash
ssh <your-deploy-host> 'cd /path/to/verifiably-go && ./deploy.sh up credebl'   # or: up all
```

Sequence (`scripts/bootstrap-credebl.sh`): `ensure_credebl_env` (write `credebl.env` + secrets) →
bring up Keycloak + `bootstrap_credebl_keycloak_realm` (import realm) → compose up `--profile credebl`
→ `write_credebl_agent_runtime_env` (nginx + agent.env, restart the rewriter) →
`bootstrap_credebl_seed_and_platform_admin` + `ensure_credebl_platform_admin_shared_agent`. Several
`_credebl_patch_*` helpers patch the upstream api-gateway/Credo images at runtime (context
validator, credential/proof events, issuance schema/context URLs, OOB save) for OID4VCI compliance.

**Smoke:** issue a `dc+sd-jwt` credential (pre-auth offer) → claim in an external wallet → verify.

---

## 9. Gotchas

- **`--profile credebl` is mandatory.** Without it none of the 23 services start (only the
  always-on rewriter). `deploy.sh` adds it automatically per scenario.
- **Keycloak realm + scopes.** CREDEBL routes login via `credebl-realm`/`credebl-client`; a seed
  re-import can reset the client's default scopes to openid-only (breaks profile/email). The
  bootstrap re-attaches them (`ensure_credebl_keycloak_login_scopes`).
- **Unpinned `:latest` images.** CREDEBL follows upstream `:latest`, so a `docker pull` can shift
  behaviour — the `_credebl_patch_*` helpers exist to re-apply compliance fixes after image moves.
- **`backends.json` fields.** `orgId`/`issuerId` are pre-provisioned; `verifierId` auto-provisions
  on first verify. See [../deploy.md](../deploy.md) "CREDEBL backends.json fields".

See also: [../architecture.md](../architecture.md) · [../deploy.md](../deploy.md) ·
[../dpg-matrix.md](../dpg-matrix.md).
