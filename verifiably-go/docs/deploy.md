# Deployment

`deploy.sh` is the single entrypoint. It wraps `docker compose` around
`deploy/compose/stack/docker-compose.yml` (the vendored MOSIP + walt.id
service definitions), layers a verifiably-go-specific override
(`deploy/docker-compose.injiweb-fix.yml`), and then runs the verifiably-go
image as a separate container on the same docker network.

`deploy/compose/` is self-contained — everything the compose file
needs (Caddyfile, Keycloak realm JSON, WSO2IS certs, Inji Certify data
CSVs, Mimoto bootstrap, oidc-ui nginx, seed scripts) lives there. The
tree preserves the sibling `stack/` + `injiweb/` layout the compose file
and seed scripts expect via relative paths.

> **Per-DPG deploy detail** (each DPG's containers, env, Caddy, runtime configs,
> databases) is in [`docs/dpg/`](dpg/README.md). This doc covers the shared
> mechanics; the guides cover each DPG end-to-end.

## Prerequisites

- **Docker Engine 20.10+** with the **Compose v2** plugin (`docker compose`, not the
  legacy `docker-compose`). The compose file is Compose-spec (`name:`, not `version:`).
- **git**, **bash**, **curl**, **openssl** on PATH (openssl generates the hub signing
  key + CREDEBL secrets; a missing openssl fails late with a mount error).
- RAM: ~**8 GiB** for `all`, ~**6 GiB** for `inji`, ~**4 GiB** for `waltid`.
- Ports: localhost/port mode exposes one port per service (e.g. 3001-3005, 7001-7003,
  8082, 8091-8094, 5001); per-subdomain mode needs **80 + 443** open instead.

## First deploy (any host)

1. `git clone <repo> && cd verifiably-go`
2. `cp .env.example .env`  (or `./deploy.sh setup` for an interactive wizard).
3. Set **`VERIFIABLY_PUBLIC_HOST`** in `.env` — the one required knob, the address
   browsers *and* sibling containers use to reach this host:
   - localhost dev → `localhost`
   - a VPS/EC2 reached by IP → that public IP
   - a public domain (per-subdomain mode) → ALSO set `VERIFIABLY_HOSTS_PATTERN=https://%s.<domain>`,
     `VERIFIABLY_PUBLIC_DOMAIN=<domain>`, `VERIFIABLY_LE_EMAIL=<email>`, and create
     `*.<domain>` DNS A records pointing here (with 80/443 open for Let's Encrypt).
4. `./deploy.sh up <all|waltid|inji|credebl>` — starts the scenario's DPG services and
   bootstraps their OIDC clients + secrets (idempotent; safe to re-run).
5. `./deploy.sh run <same scenario>` — builds + starts the verifiably-go container.
6. Verify — see [Verifying a deploy](#verifying-a-deploy).

**Generated / bootstrapped files — do NOT hand-edit** (regenerated on each `up`/`run`):
`config/backends.json`, `config/auth-providers*.json`, `deploy/compose/stack/wso2-deployment.toml`,
`deploy/compose/stack/Caddyfile.public`, `config/docker-compose.injiweb-fix.rendered.yml`.
Secrets are auto-generated and persisted so re-runs are stable: `config/wso2is.env` (WSO2
DCR), `deploy/compose/credebl/config/credebl.env` (CREDEBL), `config/trust-signing-key.pem`
(hub). The demo IdP/TLS keystores under `deploy/compose/**/certs*/` are committed demo
material — replace them for any non-demo use.

## Subcommands

| Command                                             | Does                                                                  |
|------------------------------------------------------|------------------------------------------------------------------------|
| `./deploy.sh up <all\|waltid\|inji\|credebl> [--role <roles>]` | Brings up every DPG container the scenario (and role, if given) needs + seeds clients |
| `./deploy.sh run <all\|waltid\|inji\|credebl>`      | Builds + starts the verifiably-go container (run after `up`)          |
| `./deploy.sh down <all\|waltid\|inji\|credebl>`     | Stops the verifiably-go container and the scenario's DPG services    |
| `./deploy.sh status`                                | Lists running compose services + verifiably-go container state       |
| `./deploy.sh config <all\|waltid\|inji\|credebl>`   | Regenerates `config/backends.json` + prints it (no container touched)|

Typical first run: `./deploy.sh up all && ./deploy.sh run all`.

## Scenarios

| Scenario | DPG services                                                                  | IdPs (always both) | Translator |
|----------|-------------------------------------------------------------------------------|--------------------|------------|
| `all`    | walt.id (issuer/wallet/verifier) + Inji Certify + Inji Certify Preauth + Inji Verify + Inji Web + Mimoto + eSignet + mock-identity + certify-nginx + certify-preauth-nginx + CREDEBL | Keycloak + WSO2IS | Yes |
| `waltid` | walt.id only                                                                  | Keycloak + WSO2IS  | Yes        |
| `inji`   | Inji Certify + Inji Verify + Inji Web + Mimoto + eSignet + mock-identity + certify-nginx + certify-preauth-nginx | Keycloak + WSO2IS  | Yes        |
| `credebl`| CREDEBL platform (also bundled into `all`)                                     | Keycloak + WSO2IS  | Yes        |
| `hub`    | Trust Registry + portal — a separate deployment (`deploy/compose/hub/`, its own `.env`) | n/a       | n/a        |

`backends.json` is rendered per scenario so the UI never offers a DPG
whose backend isn't running. **Auth providers are not scoped**: every
scenario brings up both Keycloak and WSO2 Identity Server, and the
sign-in page always offers both. The scenario only decides which DPG
cards the user can pick from after auth. The WSO2IS OIDC client is
bootstrapped via `scripts/bootstrap-wso2is.sh` on every `deploy.sh up`,
regardless of scenario.

## Verifying a deploy

- `./deploy.sh status` — every service the scenario needs, plus the `verifiably-go`
  container, should be **Up**.
- `deploy.sh up` runs a built-in OIDC discovery smoke gate per provider (you'll see
  `discovery gate: '<idp>' OK` in the log). Set `VERIFIABLY_STRICT_VERIFY=1` to make a
  failed gate abort the deploy instead of just warning.
- Open `http://<host>:<port>` (localhost mode) or `https://<domain>` (subdomain mode),
  pick a role, and confirm the `/auth` page shows the Keycloak + WSO2 (+ eSignet) tiles.
- Logs: `docker compose -p waltid logs -f <service>` and `docker logs -f verifiably-go`.
- Destructive reset (wipes volumes — DB + keystores): `./deploy.sh reset <scenario>`.

## Compose override pipeline

`deploy/docker-compose.injiweb-fix.yml` holds our additive compose
overlay. Relative paths inside an override get resolved against the
**primary** compose's directory, not the override's, so paths there use a
`{{VERIFIABLY_GO_DIR}}` placeholder that `deploy.sh` substitutes with the
absolute repo root at render time. The rendered file lands in
`config/docker-compose.injiweb-fix.rendered.yml`.

The override mounts:

- `deploy/injiweb-overrides/mimoto-bootstrap.properties` → `/home/mosip/mimoto-bootstrap.properties`
  Fixes a Mimoto crash loop: upstream points `spring.cloud.config.uri` at
  the Inji Web SPA (not a config server); Spring parses HTML, fails, and
  exits 1. The patched bootstrap disables Spring Cloud Config.

- `deploy/injiweb-overrides/mimoto-issuers-config.json` → both
  `injiweb-ui:/home/mosip/mimoto-issuers-config.json` and
  `certify-nginx:/config/server/mimoto-issuers-config.json`
  Fixes two upstream issues: the `wellknown_endpoint` pointed at a 404
  path, and Mimoto's `IssuerConfigUtil.getIssuerWellknown()` ignores the
  field entirely and instead appends a string to `credential_issuer_host`
  — so both fields need to contain `/v1/certify`.

- `deploy/injiweb-overrides/certify-nginx.conf` → `/etc/nginx/conf.d/default.conf`
  Routes `/.well-known/did.json` and `/v1/certify/credentials/status-list/`
  through the verifiably-go inji-proxy so we can patch kid fragments the
  upstream did.json misses. See
  [architecture.md § Inji-proxy](architecture.md#inji-proxy-didweb-resolver--credential-forwarder)
  for the why.

- `deploy/injiweb-overrides/inji-verify-config.json` → `/usr/share/nginx/html/assets/config.json`
  Inji Verify v0.16.0 ships without this render-order config; its UI
  `JSON.parse`s the fallthrough HTML, gets an empty object, and crashes
  with "Cannot read properties of undefined" on every successful
  verification.

## Seed scripts + repair helpers

After `docker compose up` completes, `cmd_up` runs:

- `deploy/compose/injiweb/seed-esignet-client.sh` — extracts the
  `wallet-demo-client` public key from its p12 keystore, converts to JWK,
  and POSTs to eSignet's client-mgmt API. Idempotent; re-runs return
  `duplicate_client_id` and exit 0.

- `deploy/compose/injiweb/seed-mock-identity.sh` — stuffs an identity
  (individualId `8267411072`, PIN `111111`) into mock-identity so the
  OTP login screen has something to authenticate.

- `scripts/bootstrap-wso2is.sh` — registers verifiably-go's OIDC client
  via DCR; writes `config/wso2is.env` so `backends_for_docker` can pick
  up the client_secret.

- `repair_injiweb_client_redirect_uri` (in deploy.sh) — ensures the
  eSignet client's `redirect_uris` list contains
  `http://${PUBLIC_HOST}:3004/redirect`. Needed because the seed script
  registers the client ONCE and treats duplicates as success; if a
  previous deploy used a different PUBLIC_HOST, eSignet rejects
  /authorize with `invalid_redirect_uri`. Repairs the DB row in place
  and deletes the Redis `clientdetails::wallet-demo-client` cache entry.

- `recover_injiweb` (before compose up) — force-removes any eSignet /
  mock-identity containers that might be stuck in a restart loop from a
  previous run's entrypoint + writable-layer state pollution.

- **certify-nginx reload** (`scripts/start-container.sh`, after verifiably-go
  starts) — verifiably-go is recreated with a fresh IP on every `up`/`run`;
  `certify-nginx` fronts the Inji auth-code well-known/credential routes through
  the `injiproxy` upstream (`verifiably-go:8080`). The nginx conf uses a
  `resolver` + variable upstream to re-resolve per request (≤30s), and
  start-container.sh additionally `nginx -s reload`s certify-nginx so there is no
  502 window. **Symptom if missing:** "selected schema missing" on `/issuer/issue`
  right after building an Inji schema (the vendor's schemas get skipped on a 502).

**Catalog reset.** `scripts/reset-authcode-catalog.sh [--yes]` wipes the Inji
auth-code catalog back to empty (deletes `credential_config` + `vc_credential_owner`
rows, drops the `vc_subject_*` extraction views, restores the scope `.properties`
to their committed baseline, restarts `inji-certify` + `injiweb-esignet`) — for a
fresh issuance test. Keeps `vc_subject` (base table) and `identity_registry`.

## Environment variables

Every knob lives in a single file — `verifiably-go/.env` — which
`deploy.sh` sources at startup and passes to `docker compose` via
`--env-file`. Copy the template on first use:

```bash
cp verifiably-go/.env.example verifiably-go/.env
```

The template has every variable documented with sensible laptop defaults.
The key ones:

| Variable                       | Default       | Purpose                                                                   |
|--------------------------------|---------------|----------------------------------------------------------------------------|
| `VERIFIABLY_PUBLIC_HOST`       | `172.24.0.1`  | **The one knob to flip for single-host deployments.** Host the browser uses for every service. Leave at default for laptop; set to your EC2 hostname / VPS IP / LAN address for remote |
| `PUBLIC_HOST`                  | `${VERIFIABLY_PUBLIC_HOST}` | Alias read by the compose file + seed scripts           |
| `VERIFIABLY_HOSTS_PATTERN`     | _(empty)_     | **Optional per-subdomain mode.** When set, every service URL is `printf "$VERIFIABLY_HOSTS_PATTERN" "<slug>"`. See [Per-subdomain deployment](#per-subdomain-deployment) below |
| `VERIFIABLY_HOST_PORT`         | `8080`        | Host port mapped to the verifiably-go container                            |
| `VERIFIABLY_PUBLIC_URL`        | `http://${VERIFIABLY_PUBLIC_HOST}:${VERIFIABLY_HOST_PORT}` | Shown on `deploy.sh run` |
| `VERIFIABLY_IMAGE`             | `verifiably-go:local` | Image tag for the build                                          |
| `VERIFIABLY_CONTAINER`         | `verifiably-go` | docker container name                                                  |
| `WALTID_{ISSUER,WALLET,VERIFIER}_PORT` | `7001/7002/7003` | Host ports for walt.id                                       |
| `CERTIFY_NGINX_PORT`           | `8091`        | Inji Certify nginx (auth-code flow)                                        |
| `CERTIFY_PREAUTH_PORT`         | `8094`        | Inji Certify pre-auth stanza                                               |
| `INJI_VERIFY_{UI,SERVICE}_PORT`| `3001/8082`   | Inji Verify                                                                |
| `INJIWEB_UI_PUBLIC_PORT`       | `3004`        | Inji Web SPA                                                               |
| `ESIGNET_PUBLIC_PORT`          | `3005`        | eSignet oidc-ui                                                            |
| `MIMOTO_PORT`                  | `8099`        | Mimoto BFF                                                                 |
| `KEYCLOAK_{PORT,REALM,CLIENT_ID}` | `8180/vcplatform/vcplatform` | Keycloak OIDC wiring                            |
| `WSO2_{PORT,CLIENT_ID,CLIENT_SECRET}` | `9443/verifiably_go_client/<generated>` | WSO2IS OIDC. `CLIENT_SECRET` populated by `scripts/bootstrap-wso2is.sh` on first up |
| `INJIWEB_P12_PASSWORD`         | `xy4gh6swa2i` | Matches the p12 in `deploy/compose/injiweb/config/certs/`                  |
| `INJI_PROXY_EXTRA_KIDS`        | _(empty)_     | Pre-seed kids for the PRIMARY (auth-code) inji-proxy did.json handler      |
| `INJI_PROXY_PREAUTH_EXTRA_KIDS`| _(empty)_     | Pre-seed kids for the PRE-AUTH inji-proxy did.json handler                 |
| `VERIFIABLY_DEBUG_MOCK_MARKERS`| `0`           | Show `[mock]` pills on surfaces still mock-backed                          |
| `VERIFIABLY_STATE_DIR`         | `state`       | Path (inside the container) for session files and status-list bitmap. Mapped to a Docker named volume (`verifiably-go-state`) by `deploy.sh` |
| `VERIFIABLY_SESSION_SECRET`    | _(auto-generated)_ | AES-256-GCM key (any string; SHA-256'd internally) for encrypting session files. Auto-generated on first start and stored at `$VERIFIABLY_STATE_DIR/session.key`. Override here to keep sessions across full stack teardowns |
| `CREDEBL_LEDGER_URL`           | `http://test.bcovrin.vonx.io` | AnonCreds ledger HTTP URL for the CREDEBL agent                |
| `CREDEBL_GENESIS_URL`          | `http://test.bcovrin.vonx.io/genesis` | AnonCreds genesis file URL                              |
| `CREDEBL_TAILS_FILE_SERVER`    | `https://tails.vonx.io` | Tails file server for AnonCreds revocation                        |
| `CREDEBL_SESSION_LIMIT`        | `500`         | Max concurrent Credo agent sessions (also controls `INMEMORY_LRU_CACHE_LIMIT`) |
| `CREDEBL_NGINX_RATE_LIMIT`     | `10r/s`       | nginx rate-limit for `/oid4vci`, `/oid4vp`, `/openid4vc` paths             |
| `CREDEBL_NGINX_RATE_BURST`     | `30`          | nginx burst allowance above `CREDEBL_NGINX_RATE_LIMIT` before HTTP 429     |

### Inji auth-code: public issuer, activation, registries

These drive the Inji auth-code path (see
[dpg/inji-certify-authcode.md](dpg/inji-certify-authcode.md)). Most are **derived**
by `deploy.sh cmd_up` in subdomain mode — pin them in `.env` only to override.

| Variable | Default / source | Purpose |
|---|---|---|
| `AUTHCODE_PUBLIC_URL` | derived (`url_for inji-certify-authcode`) | Public `mosip_certify_domain_url` for the auth-code Certify → public `credential_issuer` + status-list URL. |
| `ISSUER_DID_DOMAIN` | derived (host of `AUTHCODE_PUBLIC_URL`) | Auth-code issuer DID = `did:web:${ISSUER_DID_DOMAIN}`. Unset ⇒ `certify-nginx` (dev). |
| `AUTHCODE_ALLOWED_AUD` | `http://certify-nginx:80/v1/certify/issuance/credential` | Pins certify's `authn.allowed-audiences` to the **internal** endpoint (eSignet issues the access token with the internal aud). **Without it every claim 401s once `domain_url` is public.** |
| `PREAUTH_PUBLIC_URL` | derived (`url_for inji-certify-preauth`) | Public `domain_url` for the pre-auth instance. |
| `PREAUTH_DID_DOMAIN` | derived (host of `PREAUTH_PUBLIC_URL`) | Pre-auth issuer DID, decoupled from `ISSUER_DID_DOMAIN`. |
| `INJI_AUTHCODE_CLIENT_ID` | `wallet-demo-client` | OIDC client for the auth-code claim (also derives the PSU-token). |
| `INJI_AUTHCODE_CLIENT_KID` | `wallet-demo-client-kid` | `kid` in the `client_assertion`. |
| `INJI_AUTHCODE_SCOPE` | `mock_identity_vc_ldp` | Default credential scope. |
| `ESIGNET_BASE_URL` | derived (`url_for esignet`) | eSignet authorize/token/JWKS base. **Must be set when recreating inji-certify** — else it falls back to a firewalled `:3005` and claiming hangs 133s (use `deploy.sh up`, not a bare recreate). |
| `SMTP_HOST/PORT/USER/PASSWORD/FROM/FROM_NAME` | `.env` | Real email-OTP for registry-gated activation. `SMTP_PASSWORD` is a **secret** (e.g. a Gmail app password) — never commit it. |
| `VERIFIABLY_REGISTRIES` | `.env` (JSON array) | Configured external registries (Sunbird RC + federated agency registries) the bulk engine reads from. See [dpg/registries.md](dpg/registries.md). |
| `VERIFIABLY_REGISTRY_ADMIN_URL` | `.env` | Link to the registry-admin console. |

`INJI_AUTHCODE_CLIENT_KEY_PEM` (the RSA key signing the `client_assertion`) is
extracted from `oidckeystore.p12` by `scripts/start-container.sh` — a runtime
secret, never in the repo.

**Caddy hairpin aliases (required).** In subdomain mode, `caddy-public` must alias
`inji-certify-authcode.<domain>`, `inji-certify-preauth.<domain>`, `esignet.<domain>`,
and `walt-*.<domain>` on the compose network, so in-cluster containers (Inji Verify
resolving an issuer did.json, certify reaching the eSignet JWKS, the wallet resolving
an offer) route internally instead of hairpinning the box's blocked `:443`. Missing
the `inji-certify-authcode` alias makes external verification of a claimed VC fail
with `DidWebPublicKeyResolver: Connection timeout`.

### CREDEBL `backends.json` fields

The CREDEBL adapter also reads per-adapter fields from `config/backends.json`
(generated by `deploy.sh`). These are set inside the `"config"` object of the
CREDEBL entry:

| Field                   | Default | Purpose                                                                   |
|-------------------------|---------|---------------------------------------------------------------------------|
| `pollTimeoutSeconds`    | `120`   | How long `FetchPresentationResult` polls for a holder presentation before returning `Pending`. Increase for slow network paths or manual testing. |

Command-line override: set `VERIFIABLY_ENV_FILE=/path/to/other.env
./deploy.sh ...` to swap the entire file for one invocation (e.g. keep
`.env` pinned to laptop, ship `.env.ec2` for a staging run).

## mDL / mdoc issuance (`issuer-api2`)

ISO/IEC 18013-5 mdoc credentials (mDL, Photo ID) are issued through a
second, separate walt.id instance — `issuer-api2` — because the legacy
`issuer-api` cannot type-map CBOR correctly for mdoc (see
`docs/superpowers/adr/2026-08-20-mdl-cbor-type-limits.md`). This section is
what an operator running `./deploy.sh up waltid` needs to know that isn't
covered by the general walt.id wiring above.

### What a fresh deploy does for you, automatically

`scripts/gen-caddy.sh`'s `provision_issuer2_certificates()` runs on every
`up` and is idempotent (`mdl-pki-gen: dsc.pem already exists — keeping it`
on the second and later runs):

- Generates a self-signed **IACA root** (CA:TRUE) and a **Document Signer
  (DSC)** cert it issues, both P-256, EKU `1.0.18013.5.1.2` (the mDL DS
  OID), DSC validity capped at 457 days (ISO/IEC 18013-5 Annex B). Written
  to `deploy/k8s/config/issuer2/certs/{iaca,dsc}.pem`.
- Wires the DSC's key coordinates into `issuer2-profiles.conf`'s
  `defaultIssuerKey`/`defaultIssuerX5chain` — **but only while the
  committed baseline's example certificate is still in place**, so an
  operator's own real cert (see below) is never silently overwritten by a
  redeploy.
- Publishes the IACA over HTTP for wallets to fetch dynamically — see
  "Wallet trust anchors" below. **This never happens automatically for
  `dsc.pem`** — that file carries private-key-bearing material and is
  never served by anything, by design.
- Seeds `issuer2-profiles.conf` and `credential-issuer-metadata.conf` from
  their tracked `*.baseline.conf` counterparts (`cp -n`, no-clobber — see
  "Baseline/runtime config split" below).

The DN says what it is: `O=POC-DO-NOT-TRUST`. This is demo PKI, not a
production certificate authority. Real certificate provisioning is a
separate concern tracked in
`docs/superpowers/specs/2026-07-23-issuer-key-rotation-design.md`.

### Wallet trust anchors — POC endpoint now, VICAL is the production path

A wallet verifying an mdoc's signature needs to trust the IACA above. Since
every fresh deploy (or any deploy that starts without an existing
`dsc.pem`) generates a **new** IACA, a wallet that only trusts a
hardcoded/compiled-in certificate breaks on every such redeploy with
`"No trusted certificate was found"`.

`verifiably-go` solves this for the POC by publishing the current IACA
over HTTP:

```
GET https://<walt-issuer2 subdomain>/trust/mdoc-anchors
```

returning `{ "anchors": ["-----BEGIN CERTIFICATE-----..."], "poc": true }`.
A companion wallet (see `cdpi-wallet`'s `src/agent/mdocTrustAnchors.ts`)
fetches this from the exact origin it resolved the credential offer's
`credential_issuer` from, unions it with a compiled-in fallback so
previously issued credentials keep verifying after a rotation, and falls
back to stale-cache-or-static on any fetch error.

**This endpoint is deliberately unsigned**, and that is documented as a
POC ceiling, not an oversight: an issuer signing its own anchor response
adds no security an attacker forging the response couldn't also forge the
signature over. See the header comment in
`internal/handlers/mdoc_anchors.go` and
`docs/superpowers/adr/2026-08-23-mdl-trust-anchor-distribution.md` for the
full reasoning.

**The documented production replacement is a VICAL-shaped list signed by
the Hub** — an authority distinct from any single issuer, so a compromised
issuer cannot self-certify. This extends the Hub's existing
`internal/trust/registry.go` `TrustedIssuer` model (today DID-only) with an
X.509 field, served from the Hub's already-signed `GET /trust-registry`.
Not implemented yet; tracked in the ADR above.

**Caddy routing note (subdomain mode only):** the endpoint lives on the
`verifiably-go` container, but the wallet fetches it from the
`walt-issuer2` origin (the `credential_issuer` it resolved the offer from —
a different container). `scripts/gen-caddy.sh`'s `walt-issuer2` block
allowlists only `/openid4vci/*`, `/.well-known/*`, and
`/trust/mdoc-anchors`, returning 404 for everything else — deliberately
narrow, because `issuer-api2` ships zero authentication on its own
management API (`POST /issuer2/credential-offers` mints arbitrary signed
credentials; `GET /issuer2/sessions` leaks issuer private key material).
If a wallet reports "No trusted certificate was found" after this endpoint
was confirmed working, check first whether it 200s **from the
`walt-issuer2` origin specifically** — a 404 there with a 200 on
`verifiably-go`'s own domain is exactly this routing gap, not a code bug.

### Baseline/runtime config split — survives `git pull`

`deploy/k8s/config/issuer2/issuer2-profiles.conf` and
`credential-issuer-metadata.conf` hold generated (DSC/IACA x5chain) and
operator-authored (custom mdoc schema display names) content, so they are
**gitignored runtime files**, seeded on first deploy from tracked
`issuer2-profiles.baseline.conf` / `credential-issuer-metadata.baseline.conf`
via `cp -n` (no-clobber — a fresh clone gets the seed; an existing
deployment's real cert and schema names are never touched by a later
`git pull`). See
`docs/mdl-issuance-manual-checklist.md`'s "One-time migration" section if
you are updating a deployment created before this split existed.

### `.env` quoting for the issuer2 JSON key variables

`VERIFIABLY_ISSUER2_CI_TOKEN_KEY` and `VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY`
hold JSON values. **Wrap them in single quotes in `.env`:**

```bash
VERIFIABLY_ISSUER2_CI_TOKEN_KEY='{"type":"jwk","jwk":{"kty":"EC",...}}'
```

`deploy.sh`/`common.sh` load `.env` via `set -o allexport; source .env`.
Sourced this way, bash **silently strips the double quotes from an
unquoted value on export** — `VAR={"a":"b"}` (no shell quoting) becomes
`{a:b}` once exported, which then fails walt.id's HOCON/Hoplite decode with
a misleading `Expected quotation mark '"', but had 't' instead` error that
looks unrelated to quoting at all. Reproduce it yourself if in doubt:

```bash
echo 'X={"a":"b"}' > e1.env; bash -c 'set -o allexport; source e1.env; echo $X'   # => {a:b}  (broken)
echo "X='{\"a\":\"b\"}'" > e2.env; bash -c "set -o allexport; source e2.env; echo \$X"  # => {"a":"b"}  (correct)
```

If you fix `.env` after hitting this, fixing the file alone is not
enough — the already-rendered `issuer-service.conf` on disk still has the
broken value baked in. Re-run `./deploy.sh up waltid` (which re-renders the
`.conf` from `.env` and recreates the container) rather than `docker
restart`, which does not reread `--env-file` at all.

## Secrets to regenerate per deployment

Every country deployment must generate its own secrets. Do not reuse values from another deployment or from this repo's example files. The commands below produce cryptographically random values.

Run these once, before the first `./deploy.sh up hub`, and keep the results in a secure vault (Bitwarden, 1Password, AWS Secrets Manager, etc.).

### Hub — `deploy/compose/hub/.env`

```bash
# 1. PostgreSQL password
openssl rand -hex 32

# 2. Session encryption key (AES-256-GCM)
openssl rand -hex 32

# 3. Admin panel password
openssl rand -base64 18

# 4. Grafana password
openssl rand -base64 18
```

Paste each output into the corresponding field in `hub/.env`:

| Field | Command above |
|---|---|
| `POSTGRES_PASSWORD` | #1 |
| `VERIFIABLY_SESSION_SECRET` | #2 |
| `VERIFIABLY_ADMIN_PASSWORD` | #3 |
| `GRAFANA_PASSWORD` | #4 |

### Hub — trust registry signing key

The Hub signs its trust registry JWT with an ES256 P-256 private key. Without a persistent key the Hub generates an ephemeral one on every restart — all previously-issued trust tokens become invalid.

Generate and save the key **once per deployment**:

```bash
# Generate a P-256 key in PKCS8 format (the format the Hub expects)
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/trust-key.pem
openssl pkcs8 -topk8 -nocrypt -in /tmp/trust-key.pem -out config/trust-signing-key.pem
rm /tmp/trust-key.pem

# Verify it loaded correctly (optional smoke-test)
openssl pkey -in config/trust-signing-key.pem -noout -text | grep "Private-Key"
```

The file `config/trust-signing-key.pem` is already git-ignored and already mounted as `/app/config/trust-signing-key.pem` inside the Hub container via the `../../../config:/app/config:ro` volume in `deploy/compose/hub/docker-compose.yml`. No `.env` change needed — the Hub reads it automatically when `VERIFIABLY_TRUST_SIGNING_KEY` is empty.

### Hub — independent verifier (`hub-verifier-api`)

The Hub can run its own Walt ID verifier so it can verify credentials
without depending on federated nodes having a verifier of their own.
It's opt-in via the `verifier` Docker Compose profile:

```bash
docker compose -f deploy/compose/hub/docker-compose.yml --env-file deploy/compose/hub/.env --profile verifier up -d
```

Config in `deploy/compose/hub/.env`:

| Variable | Default | Purpose |
|---|---|---|
| `VERIFIABLY_ROLES` | `verifier` | Hub's own Go-app role — the hub rarely needs to also issue or be a holder |
| `HUB_VERIFIER_PORT` | `7053` | Host port for the Walt ID verifier-api container (bind to `127.0.0.1:7053` in production — no public exposure needed when behind Caddy) |
| `HUB_VERIFIER_BASE_URL` | `http://localhost:7053` | Base URL the verifier-api advertises in `presentation_definition_uri`/`request_uri`. Must be browser-reachable — in TLS mode set to `https://<VERIFIABLY_PUBLIC_DOMAIN>/verifier-api` |
| `WALTID_VERSION` | `0.18.2` | Image tag for `waltid/verifier-api` — pin to match the rest of your Walt ID deployment |

Caddy exposes it at `/verifier-api/*` (via `handle_path`, which strips the
prefix before proxying) — deliberately **not** `/verify*`, which is already
routed to the Hub's own citizen-facing public verification portal served by
`verifiably-go:8080` itself. Routing `/verify*` to the raw verifier container
would silently break that portal.

Verify it's up:

```bash
curl -s http://localhost:7053/openapi | grep -q verifier && echo "hub-verifier-api OK"
```

> **Do not commit this file.** It is private — possession equals the ability to sign arbitrary trust registry JWTs as your federation authority.

### CREDEBL — `deploy/compose/credebl/config/credebl.env`

Most CREDEBL secrets (PostgreSQL, MinIO, Keycloak, JWT, NextAuth) are auto-generated by `scripts/bootstrap-credebl.sh` on first run. One field is **not** auto-generated and must be changed manually:

```bash
# CRYPTO_PRIVATE_KEY — AES passphrase used by CREDEBL to encrypt
# the platform admin wallet password before sending it to the Credo agent.
# Must be ≥ 32 characters. Any random string works.
openssl rand -hex 20
```

Set the output as `CRYPTO_PRIVATE_KEY=<value>` in `credebl.env` before running the CREDEBL bootstrap for the first time. Changing it after bootstrap requires re-encrypting the stored wallet password — change it before, not after.

### Quick checklist before going live

```
[ ] hub/.env — POSTGRES_PASSWORD             (openssl rand -hex 32)
[ ] hub/.env — VERIFIABLY_SESSION_SECRET     (openssl rand -hex 32)
[ ] hub/.env — VERIFIABLY_ADMIN_PASSWORD     (openssl rand -base64 18)
[ ] hub/.env — GRAFANA_PASSWORD              (openssl rand -base64 18)
[ ] config/trust-signing-key.pem             (openssl ecparam + pkcs8, see above)
[ ] credebl.env — CRYPTO_PRIVATE_KEY         (openssl rand -hex 20)
```

## Migrating to a remote host (EC2, dev VM, LAN)

One-variable flip:

```bash
# edit verifiably-go/.env
VERIFIABLY_PUBLIC_HOST=ec2-1-2-3-4.compute-1.amazonaws.com
```

That's it. The same `.env` drives every service — backends.json / auth-providers.json stanzas, the compose file's `${PUBLIC_HOST}` references (eSignet redirect, Mimoto's MIMOTO_URL injection, the patched Inji Web issuer catalog), and the eSignet client-redirect-URI repair helper.

Caveats:

- **TLS**: browsers reaching WSO2IS on `:9443` self-signed will need cert trust. Keycloak on `:8180` is HTTP so unaffected. For a public-facing EC2 you'd typically drop a Caddy / ALB in front and re-point `VERIFIABLY_PUBLIC_HOST` plus the port vars at your TLS terminator.
- **Firewall**: open `VERIFIABLY_HOST_PORT`, `KEYCLOAK_PORT`, `WSO2_PORT`, `CERTIFY_NGINX_PORT`, `INJIWEB_UI_PUBLIC_PORT`, `ESIGNET_PUBLIC_PORT`, `INJI_VERIFY_UI_PORT` on the instance — every one is visited from the browser.
- **Re-run `./deploy.sh up <scenario>`** after flipping PUBLIC_HOST so the `repair_injiweb_client_redirect_uri` helper re-registers the eSignet client's redirect URI on the new host. The helper is idempotent and only writes when the list diverges.

## Per-subdomain deployment

If you'd rather run each service on its own subdomain (`walt-issuer.example.com`, `inji-certify.example.com`, ...) instead of one host with eleven different ports, set `VERIFIABLY_HOSTS_PATTERN` in `.env`:

```bash
VERIFIABLY_HOSTS_PATTERN=https://%s.example.com
```

The `%s` is the per-service slug. `deploy.sh` substitutes it for each service when it generates `backends.json` and `auth-providers.json`, so a single env var rewires every URL. Empty (default) preserves the legacy `${VERIFIABLY_PUBLIC_HOST}:${PORT}` form, so localhost dev keeps working unchanged.

### What `%s` becomes

deploy.sh writes URLs for these slugs (one per service the stack runs):

| Slug                   | What it is                                  |
|------------------------|---------------------------------------------|
| `walt-issuer`          | walt.id issuer-api                          |
| `walt-wallet`          | walt.id wallet-api                          |
| `walt-verifier`        | walt.id verifier-api                        |
| `inji-certify`         | Inji Certify (auth-code stanza, via nginx)  |
| `inji-certify-preauth` | Inji Certify (pre-auth stanza, via nginx)   |
| `inji-verify`          | Inji Verify backend                         |
| `inji-verify-ui`       | Inji Verify SPA                             |
| `inji-web`             | Inji Web wallet SPA                         |
| `mimoto`               | Mimoto BFF                                  |
| `esignet`              | eSignet OIDC UI                             |
| `keycloak`             | Keycloak IdP                                |
| `wso2`                 | WSO2 IS IdP                                 |
| `verifiably`           | verifiably-go itself                        |

So `VERIFIABLY_HOSTS_PATTERN=https://%s.example.com` yields `https://walt-issuer.example.com`, `https://inji-certify.example.com`, and so on for all thirteen.

### What you need to wire (one-time, on the host)

A working Caddy reverse proxy ships in the repo — you don't need to write your own. Three things to do on the host:

#### 1. DNS

Point either:

- **A wildcard `A` record** `*.example.com → <host-ip>` (one entry covers every service), or
- **One `A` record per slug** — `walt-issuer.example.com`, `walt-wallet.example.com`, ... thirteen total. Use this if your DNS provider charges per record-type or you prefer explicit per-service control.

Verify with `dig walt-issuer.example.com +short` from anywhere — should resolve to your host's public IP.

#### 2. Caddyfile (already written for you)

The repo ships a complete Caddyfile at:

```
verifiably-go/deploy/compose/stack/Caddyfile.public
```

It declares one block per slug pointing at the right container + internal port — including the WSO2-on-self-signed-HTTPS upstream and Inji Verify's quirky port-8000 SPA. Don't edit unless you want a different subdomain scheme; the `{$VERIFIABLY_PUBLIC_DOMAIN}` placeholder is filled in from `.env` at container start.

The matching `caddy-public` service is registered in `docker-compose.yml` behind the `subdomain` profile. `deploy.sh` automatically passes `--profile subdomain` to compose when `VERIFIABLY_HOSTS_PATTERN` is non-empty, so you don't run anything new — `./deploy.sh up <scenario>` brings Caddy up alongside the rest.

##### Hairpin NAT (container → public subdomain)

A container that calls a service by its **public** name (e.g. the walt.id `wallet-api`
resolving an OID4VCI `credential_offer_uri` at `walt-issuer.<domain>`, or an OID4VP
`request_uri` at `walt-verifier.<domain>`) would otherwise route to the box's own
public IP `:443` and time out — most cloud hosts don't hairpin traffic from the docker
bridge back to themselves. Two mechanisms keep those calls on the docker network:

- **`verifiably-go`** is started with `--add-host <slug>.<domain> → caddy-public-ip`
  for **every** public slug (`compute_host_aliases` in `scripts/start-container.sh`).
- **compose-managed services** rely on **`caddy-public` network aliases** — the
  `caddy-public` service answers to each public FQDN on the docker network
  (`inji-certify-preauth`, `esignet`, `walt-issuer`, `walt-verifier`, `walt-wallet`),
  so Docker's embedded DNS resolves them to Caddy's internal IP, where TLS terminates
  and the request is proxied to the backend. Add more FQDNs to that `aliases:` list in
  `docker-compose.yml` if a new internal container starts calling a public name.

Set these in `.env`:

```bash
VERIFIABLY_HOSTS_PATTERN=https://%s.example.com
VERIFIABLY_PUBLIC_DOMAIN=example.com          # apex must match the pattern
VERIFIABLY_LE_EMAIL=ops@example.com           # Let's Encrypt account email
```

If `VERIFIABLY_LE_EMAIL` is left empty Caddy falls back to an internal CA — fine for local-dev with `/etc/hosts` overrides, but browsers will reject the cert on a public deploy.

#### 3. Firewall

Caddy needs ports 80 + 443 reachable from the public internet. Per-service container ports stay internal — they're not bound to the host in subdomain mode.

**Ubuntu/Debian (UFW)**:

```bash
sudo ufw allow 80/tcp        # ACME HTTP-01 challenge + redirect to 443
sudo ufw allow 443/tcp       # HTTPS
sudo ufw allow 443/udp       # HTTP/3 (QUIC) — Caddy serves it by default
sudo ufw allow 22/tcp        # SSH (don't forget this BEFORE enabling the firewall)
sudo ufw enable
sudo ufw status numbered
```

**RHEL/CentOS/Fedora (firewalld)**:

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --reload
```

**Cloud-provider firewall (EC2, DigitalOcean, etc.)**: open inbound 80, 443/tcp, 443/udp from `0.0.0.0/0`. The host-level UFW/firewalld step is still recommended as defense-in-depth.

**Check from outside the host** (a different machine):

```bash
curl -fsSL https://walt-issuer.example.com/.well-known/openid-credential-issuer | head
```

Returns the walt.id metadata document → routing works. Fails with a TLS error → Let's Encrypt didn't complete (usually port 80 unreachable, DNS not propagated, or a rate-limit hit on Let's Encrypt — see `docker logs caddy-public` for specifics).

#### Using a different reverse proxy

If you'd rather use nginx, Traefik, AWS ALB, Cloudflare Tunnel, etc.: skip the `subdomain` profile (just don't set `VERIFIABLY_HOSTS_PATTERN`'s companion `VERIFIABLY_PUBLIC_DOMAIN` and add `--profile=""`) and route from your own proxy to the per-service container ports. The full upstream map is in `Caddyfile.public` if you need a reference for what each subdomain should target.

### Picking your subdomain scheme

The pattern is printf-style, so you have full control over what each subdomain looks like:

| Pattern                                      | Example URL                                        |
|----------------------------------------------|----------------------------------------------------|
| `https://%s.example.com`                     | `https://walt-issuer.example.com`                  |
| `https://%s.demo.example.com`                | `https://walt-issuer.demo.example.com`             |
| `https://verifiably-%s.example.com`          | `https://verifiably-walt-issuer.example.com`       |
| `http://%s.localdev:8080`                    | `http://walt-issuer.localdev:8080`                 |

All work. Just make sure your DNS + reverse-proxy match the pattern.

### Caveats specific to this mode

- **Verifiably-go itself stays backend-agnostic.** The same binary runs in either mode; the URL choice happens at deploy-time when `backends.json` + `auth-providers.json` are generated.
- **OIDC redirect URIs auto-configure.** `bootstrap-keycloak.sh` and `bootstrap-wso2is.sh` consume `VERIFIABLY_CALLBACK_URL` (set automatically by `deploy.sh` via `url_for`), so the pattern-mode callback (`https://verifiably.<your-domain>/auth/callback`) lands in both clients' allow-lists alongside the legacy localhost entries. Re-running `./deploy.sh up <scenario>` after a domain change is enough — both bootstraps are idempotent and additive (set-union, not replace), so a host change doesn't strand stale entries.
- **eSignet redirect URI.** `repair_injiweb_client_redirect_uri` in `deploy.sh` injects `http://${PUBLIC_HOST}:3004/redirect` into the `wallet-demo-client` row in eSignet's postgres — still pattern-unaware. After first deploy in pattern mode, manually run:
  ```sql
  UPDATE client_detail
  SET redirect_uris = redirect_uris || ARRAY['https://inji-web.<your-domain>/redirect']
  WHERE id = 'wallet-demo-client';
  ```
  inside `injiweb-postgres`, or fall back to `VERIFIABLY_PUBLIC_HOST` mode for the eSignet-fronted Inji Web flow specifically.

## Full reset

To start from a fully clean slate (wipe all keys, all registered clients,
all issued VCs):

```bash
./deploy.sh down all

docker compose -p waltid --profile injiweb \
  -f deploy/compose/stack/docker-compose.yml \
  rm -f -v certify-postgres inji-certify \
              certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy \
              certify-nginx certify-preauth-nginx \
              injeweb-postgres injiweb-esignet \
              injiweb-mimoto injiweb-ui injiweb-oidc-ui \
              injiweb-mock-identity injiweb-datashare injiweb-minio \
              injiweb-redis

docker volume rm waltid_certify-db waltid_certify-pkcs12 \
                 waltid_certify-preauth-db waltid_certify-preauth-pkcs12 \
                 waltid_injiweb-db waltid_injiweb-esignet-keystore \
                 waltid_injiweb-mockid-keystore waltid_injiweb-minio

./deploy.sh up all && ./deploy.sh run all
```

This is what you want when Inji Certify's keys drift out of sync with
already-issued status-list credentials (see [dpg-matrix.md § Inji Certify](dpg-matrix.md#inji-certify-v0140)).

## Kubernetes / Helm

Every runtime piece already ships as a container, so porting to Helm is
mostly mechanical:

- The `host.docker.internal:host-gateway` trick the inji-proxy depends on
  becomes a proper Kubernetes `Service` DNS name — certify-nginx's
  upstream stanza points at `verifiably-go.<namespace>.svc` instead.
- Persistent docker volumes become `PersistentVolumeClaim`s.
- Seed scripts become `Job`s or `initContainer`s that gate the main
  services' readiness probes.
- Secrets (the `wallet-demo-client` p12 password, OIDC client secrets)
  move into `Secret` resources.
- The translator cache can stay inside the verifiably-go pod or move to
  a shared PVC if you scale horizontally.
