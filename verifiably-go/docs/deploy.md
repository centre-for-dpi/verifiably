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

| Command                                    | Does                                                                  |
|--------------------------------------------|------------------------------------------------------------------------|
| `./deploy.sh up <all\|waltid\|inji>`       | Brings up every DPG container the scenario needs + seeds clients     |
| `./deploy.sh run <all\|waltid\|inji>`      | Builds + starts the verifiably-go container (run after `up`)          |
| `./deploy.sh down <all\|waltid\|inji>`     | Stops the verifiably-go container and the scenario's DPG services    |
| `./deploy.sh status`                       | Lists running compose services + verifiably-go container state       |
| `./deploy.sh config <all\|waltid\|inji>`   | Regenerates `config/backends.json` + prints it (no container touched)|

Typical first run: `./deploy.sh up all && ./deploy.sh run all`.

## Scenarios

| Scenario | DPG services                                                                  | IdPs (always both) | Translator |
|----------|-------------------------------------------------------------------------------|--------------------|------------|
| `all`    | walt.id (issuer/wallet/verifier) + Inji Certify + Inji Certify Preauth + Inji Verify + Inji Web + Mimoto + eSignet + mock-identity + certify-nginx + certify-preauth-nginx | Keycloak + WSO2IS | Yes |
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
