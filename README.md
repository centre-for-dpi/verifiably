# verifiably

A thin, backend-agnostic Go + HTMX UI for issuing, holding, and verifying
W3C Verifiable Credentials against real DPG (Digital Public Goods) stacks.
One interface (`backend.Adapter`) drives every screen; swap implementations
to point at a different vendor without touching the UI.

The app and its deploy tooling live under [`verifiably-go/`](verifiably-go/).
Everything below refers to that subtree — run the commands from there.

Supported DPGs out of the box:

- **walt.id Community Stack** v0.18.2 — issuer / holder / verifier via walt.id's issuer-api, wallet-api, verifier-api
- **Inji Certify** v0.14.0 — issuer, both OID4VCI pre-authorised code and authorization code flows
- **Inji Web Wallet** v0.16.0 — holder via the MOSIP Inji Web SPA + Mimoto BFF
- **Inji Verify** v0.16.0 — verifier via Inji Verify's QR-upload and OID4VP endpoints
- **CREDEBL** — issuer (OID4VCI pre-auth) + verifier (OID4VP) via CREDEBL's 18-service stack;
  bootstrapped automatically including Keycloak realm, platform-admin, DID, and credential template

Plus OIDC sign-in via **Keycloak** or **WSO2 Identity Server**, and
app-wide translation via **LibreTranslate** (English / French / Spanish).

## Prerequisites

Before the quickstart will succeed on a fresh machine:

| requirement | why it matters |
|---|---|
| **Docker Engine 24+** with Compose v2 (`docker compose`, not `docker-compose`) | Every DPG + IdP + translator runs as a container; the compose file uses v2-only features. |
| **Non-root Docker access** — your user is in the `docker` group | `deploy.sh` invokes `docker` without `sudo`. `sudo usermod -aG docker "$USER" && newgrp docker` once. Verify with `docker ps` (no sudo). |
| **~8 GB RAM free** for `waltid` or `inji` scenarios; **~12 GB** for `all` (includes CREDEBL's 18 microservices) | Check `free -h` before starting. On a low-RAM VPS, add swap: `fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile`. |
| **Ports free** on the host: 80, 443, 3001, 3004, 3005, 5432–5437, 7001–7003, 8080, 8090–8099, 8180, 8182, 9443 | Compose publishes each DPG on its canonical port. Check `sudo ss -ltn` before starting; `lsof -i :8080` to find who holds any conflict. |
| **`envsubst`** (part of `gettext`) in your `$PATH` | `deploy.sh` renders `wso2-deployment.toml` from a template with it. Most Linux distros have it preinstalled; on macOS: `brew install gettext` + `brew link --force gettext`. |
| **Go 1.25+** *(optional)* | Only needed if you want to run `verifiably-go` outside docker via `go run ./cmd/server`. `./deploy.sh up` builds its own container image. |
| **`curl`, `jq`, `python3`** | `deploy.sh` and the bootstrap scripts (Keycloak, WSO2IS, CREDEBL) use them for seeding OIDC clients, rendering configs, and patching CREDEBL containers. |

Docker Hub has the two first-party images the stack pulls:

- [`adammwaniki/inji-preauth-poc`](https://hub.docker.com/r/adammwaniki/inji-preauth-poc) — a tiny reverse proxy that patches two Inji Certify pre-auth OID4VCI endpoints so wallets outside the container network work. Source: [`verifiably-go/cmd/inji-preauth-proxy`](verifiably-go/cmd/inji-preauth-proxy).
- [`adammwaniki/verification-adapter`](https://hub.docker.com/r/adammwaniki/verification-adapter) — standalone backend-agnostic verifier showcase on port 8085; referenced by the `inji` / `all` scenarios as a parallel demo (verifiably-go itself doesn't call it).

All other containers pull from their vendors' official Docker Hub repos.

## Quickstart

Clone, run the setup wizard, bring the stack up:

```bash
git clone https://github.com/centre-for-dpi/demo-daas-3-0.git
cd demo-daas-3-0/verifiably-go

./deploy.sh setup    # interactive wizard — writes .env with your IP / domain
                     # (auto-runs on first 'up' if .env is missing)

./deploy.sh up all   # pull images + start every DPG container +
                     # build & launch the verifiably-go container
```

First `up all` takes 15–30 minutes on a fast connection (CREDEBL pulls ~46 images
and its bootstrap provisions a Keycloak realm, DID, issuer, and credential template).
Subsequent runs are seconds. When it's done, point a browser at:

```
http://localhost:8080          # if you chose localhost in setup
https://verifiably.<domain>   # if you enabled Let's Encrypt in setup
```

You should see the role-picker landing page. Click **Issuer**, log in as
`holder` / `holder` via the Keycloak button, and you're in.

### Deploying somewhere other than localhost (EC2, bare-metal demo box, …)

Run the setup wizard — it asks for your server's IP, whether to enable
Let's Encrypt subdomains, Keycloak admin password, and CREDEBL admin email,
then writes `verifiably-go/.env`:

```bash
./deploy.sh setup
```

The key variable it sets is `VERIFIABLY_PUBLIC_HOST` (the IP the browser
reaches services on). Everything downstream — `backends.json` browser-facing
URLs, Mimoto's OIDC redirect_uris, Keycloak/WSO2IS issuer URLs, eSignet
redirects, the WSO2 `hostname` in `wso2-deployment.toml` — is derived by
substituting `${VERIFIABLY_PUBLIC_HOST}` inside `deploy.sh`. Nothing needs
hand-editing.

You can also set it manually in `.env` before running `up`:

```ini
# Laptop / localhost (default):
VERIFIABLY_PUBLIC_HOST=172.24.0.1

# EC2 / remote host:
VERIFIABLY_PUBLIC_HOST=ec2-1-2-3-4.compute-1.amazonaws.com
```

Then `./deploy.sh up all` stands the stack up at
`http://${VERIFIABLY_PUBLIC_HOST}:8080`. Full variable reference + TLS /
proxy notes in
[`verifiably-go/docs/deploy.md`](verifiably-go/docs/deploy.md).

### Deploying with your own domain (TLS subdomains)

When you want real URLs instead of `<ip>:<port>` — e.g. so external
wallets can hit a public OIDC discovery endpoint, or so you can hand
out tidy links to demo participants — switch the stack into subdomain
mode. Caddy fronts every container on its own subdomain, terminates
TLS via Let's Encrypt, and reverse-proxies to the docker-internal
upstream. The setup runs in seven steps.

**1. Pick a domain you control.** A bare apex like `vc.example.com`.
You don't need a separate domain per service — every service is a
subdomain underneath this one. Examples below use `example.com` as
the RFC-2606-reserved placeholder; replace it with your own domain
everywhere it appears.

**2. Point DNS at the host.** At your domain registrar (Cloudflare,
Route 53, Namecheap, GoDaddy, Squarespace …), add an **A record** — the standard
DNS row that maps a hostname to an IPv4 address. Each row has three
fields:

| Field | What it means | What to put |
| --- | --- | --- |
| Type / Record | DNS record kind | `A` |
| Name / Host | The subdomain (registrar appends the apex) | `walt-issuer` (or `*` for a wildcard) |
| Value / IP | The IPv4 address it resolves to | Your host's public IP (`curl ifconfig.me` on the host) |

Either a single wildcard (simplest — one row, matches every
subdomain):

```
*.example.com    A    <public IP>
```

Or one row per subdomain you'll route (better with locked-down DNS
providers, or when you want explicit control over which names
resolve):

```
walt-issuer.example.com   A   <IP>
walt-wallet.example.com   A   <IP>
walt-verifier.example.com A   <IP>
credebl.example.com       A   <IP>
inji-certify.example.com  A   <IP>
…
```

DNS propagation takes a minute or two. Verify before continuing:

```bash
dig +short walt-issuer.example.com
# expected: <your public IP>
```

If `dig` returns nothing, propagation hasn't finished yet — Caddy's
Let's Encrypt cert request in step 6 will fail with a "no DNS
resolution" error until it does.

**3. Open ports 80 and 443 on the host's firewall / cloud security
group.** Let's Encrypt's HTTP-01 challenge needs port 80 to issue
certs; production HTTPS uses 443. The legacy per-service ports
(7001-7003, 8180, 9443, 3001, 3004, …) can stay closed — nothing
external talks to them when subdomains are in play.

**4. Run setup and choose "Yes" to Let's Encrypt:**

```bash
./deploy.sh setup
# → Enable HTTPS via Let's Encrypt? Y
# → Base domain: example.com
# → Let's Encrypt email: you@example.com
# → CREDEBL platform admin email: admin@example.com
```

This writes `VERIFIABLY_PUBLIC_DOMAIN`, `VERIFIABLY_HOSTS_PATTERN`, and
`VERIFIABLY_LE_EMAIL` to your `.env`. You can also set them manually:

```ini
VERIFIABLY_PUBLIC_DOMAIN=example.com
VERIFIABLY_HOSTS_PATTERN=https://%s.example.com
VERIFIABLY_LE_EMAIL=you@example.com
```

The `%s` is a `printf` placeholder — `deploy.sh` substitutes each
service's slug into it.

**5. (Optional) Customise the subdomain labels.** Defaults are listed
below. Override any of them by setting `VERIFIABLY_SLUG_<NAME>` in
`.env`. Set the value to empty to skip a service entirely (no Caddy
block, not exposed):

| Default subdomain | What's behind it | Override env var |
| --- | --- | --- |
| `verifiably.<domain>` | The verifiably-go UI itself | `VERIFIABLY_SLUG_VERIFIABLY` |
| `walt-issuer.<domain>` | walt.id `issuer-api` (OID4VCI wellknown) | `VERIFIABLY_SLUG_WALT_ISSUER` |
| `walt-wallet.<domain>` | walt.id `wallet-api` | `VERIFIABLY_SLUG_WALT_WALLET` |
| `walt-verifier.<domain>` | walt.id `verifier-api` (OID4VP) | `VERIFIABLY_SLUG_WALT_VERIFIER` |
| `credebl.<domain>` | CREDEBL API gateway + Credo agent | `VERIFIABLY_SLUG_CREDEBL` |
| `keycloak.<domain>` | Keycloak demo IdP | `VERIFIABLY_SLUG_KEYCLOAK` |
| `wso2.<domain>` | WSO2 IS demo IdP | `VERIFIABLY_SLUG_WSO2` |
| `inji-certify.<domain>` | Inji Certify (auth-code flow) | `VERIFIABLY_SLUG_INJI_CERTIFY` |
| `inji-certify-preauth.<domain>` | Inji Certify (pre-auth flow) | `VERIFIABLY_SLUG_INJI_CERTIFY_PREAUTH` |
| `inji-verify.<domain>` | Inji Verify backend | `VERIFIABLY_SLUG_INJI_VERIFY` |
| `inji-verify-ui.<domain>` | Inji Verify UI | `VERIFIABLY_SLUG_INJI_VERIFY_UI` |
| `inji-web.<domain>` | Inji Web SPA | `VERIFIABLY_SLUG_INJI_WEB` |
| `mimoto.<domain>` | Mimoto wallet BFF | `VERIFIABLY_SLUG_MIMOTO` |
| `esignet.<domain>` | eSignet OIDC UI | `VERIFIABLY_SLUG_ESIGNET` |

**6. Deploy:**

```bash
./deploy.sh up all
```

First run, expect ~30 seconds of extra startup while Caddy negotiates
TLS with Let's Encrypt for each subdomain in `Caddyfile.public`. Certs
land in the `caddy-public-data` named volume — they survive restarts
and renew automatically. Browse to `https://verifiably.<your-domain>`.

**7. Verify it's actually subdomain-routing:**

```bash
curl -sI https://walt-issuer.<your-domain>/draft13/.well-known/openid-credential-issuer | head -2
# HTTP/2 200
# server: Caddy
```

If you get a cert error or `502 Bad Gateway`, the usual culprits are:

- DNS hasn't propagated yet (give it 1-2 minutes for fresh records).
- Port 80 isn't open → LE challenge fails → cert never issues. Fix the
  firewall and `docker restart caddy-public`.
- `VERIFIABLY_HOSTS_PATTERN` was unset on `./deploy.sh up all` (only
  the domain vars in `.env` had it) → walt.id's `SERVICE_HOST` advertises
  the wrong URL inside the wellknown. Put both subdomain vars in `.env`
  so every invocation sees them.

To switch **back** to legacy `<host>:<port>` mode, comment out
`VERIFIABLY_HOSTS_PATTERN` and `VERIFIABLY_PUBLIC_DOMAIN` and re-run
`./deploy.sh up all`. The `caddy-public` container won't start
(its `subdomain` compose profile is gated on the env var), and every
URL falls back to the `http://<host>:<port>` form served by the
always-on internal Caddy on 7001/7002/7003.

```bash
# if necessary to your use case, remember to run deploy script as 
`VERIFIABLY_NO_DEFAULT_IDPS=1 ./deploy.sh up all` 
```

### Scenarios

`deploy.sh` supports four scenarios so you don't have to boot
everything when you only care about one stack. Every scenario includes
Keycloak so the sign-in page always offers an OIDC provider; the
scenario gates which DPG backends come up.

| Scenario | DPG services | IdPs | RAM |
|---|---|---|---|
| `all` | walt.id + Inji Certify + Inji Web + Inji Verify + CREDEBL | Keycloak + WSO2IS | ~12 GB |
| `waltid` | walt.id Community Stack | Keycloak | ~2 GB |
| `inji` | Inji Certify + Inji Web + Inji Verify | WSO2IS | ~5 GB |
| `credebl` | CREDEBL (18 microservices) | Keycloak + WSO2IS | ~4 GB |

Usage is the same pattern: `./deploy.sh <up|run|down|status|config> <scenario>`.

The `run` subcommand rebuilds and restarts **only** the verifiably-go
container without touching compose — useful when the DPG stack is already
up and you just changed verifiably-go's code or config.

### Credentials for demo flows

Pre-seeded for every fresh `./deploy.sh up`:

| provider | username | password | lives in |
|---|---|---|---|
| Keycloak realm `vcplatform` | `holder` | `holder` | `deploy/compose/stack/keycloak-realm.json` |
| Keycloak realm `vcplatform` | `issuer` | `issuer` | same |
| Keycloak realm `vcplatform` | `admin`  | `admin`  | same |
| WSO2IS master (admin console at `https://<host>:9443/console`) | `admin` | `admin` | WSO2IS stock defaults |
| eSignet mock-identity (Inji Web holder flow only) | Individual ID `8267411072` | PIN/OTP `111111` | `deploy/compose/injiweb/` mock-identity seed |
| CREDEBL platform admin | *(set in setup wizard)* | *(auto-generated if blank)* | `verifiably-go/.env` → `CREDEBL_ADMIN_EMAIL` / `CREDEBL_PASSWORD` |

WSO2IS doesn't seed app users automatically — for the WSO2IS login
button you either register a user at `https://<host>:9443/console` or
stick with Keycloak, which does come pre-seeded.

CREDEBL credentials are generated on first `./deploy.sh up credebl|all` and
written to `.env`. Re-running `up` is idempotent — existing credentials are
reused and CREDEBL's bootstrap steps are skipped if the platform-admin and
issuer already exist.

### Bring your own OIDC provider

You don't have to keep Keycloak / WSO2IS — sign-in providers come from
three places and get merged at startup:

| Source | What it is | Survives `./deploy.sh up all`? |
|---|---|---|
| `config/auth-providers.system.json` | Demo defaults (Keycloak + WSO2IS) written by `deploy.sh`. | No — rewritten every run. |
| `config/auth-providers.user.json`   | Whatever you add via the admin UI. | Yes. |
| `VERIFIABLY_OIDC_PROVIDERS` env     | A JSON array that replaces both files for that boot. | Yes (it's an env var). |

If both files have a provider with the same `id`, the user file wins.
That's how you "edit" a demo provider — re-add it via the UI with the
same id and your version takes over.

**To skip the demo IdPs entirely on a fresh install**, set
`VERIFIABLY_NO_DEFAULT_IDPS=1` before running `deploy.sh` as illustrated below. The system
file ends up empty, so the next visit to `/auth` shows a one-time setup
form where you can register your own provider before signing in:

```bash
VERIFIABLY_NO_DEFAULT_IDPS=1 ./deploy.sh up all
# browse to /auth → "First-run setup" form
```

**To manage providers after install**, click the **Admin** link
(top-right). The admin sign-in is a single shared account, separate
from the issuer / holder / verifier OIDC sessions, with no
self-registration — defaults to `admin` / `admin`, override with
`VERIFIABLY_ADMIN_USER` / `VERIFIABLY_ADMIN_PASSWORD` before starting
the container. From the admin page you can delete any registered
provider. New providers are added from the regular sign-in page (the
form below the provider tiles), not from the admin page — so the
admin role is purely curation.

Demo defaults deleted from the admin UI
come back on the next `./deploy.sh up all`; use
`VERIFIABLY_NO_DEFAULT_IDPS=1` to ensure they remain retired properly.

```bash
VERIFIABLY_NO_DEFAULT_IDPS=1 ./deploy.sh up all
# only your custom providers will remain
```

**To control the surface**, set `VERIFIABLY_AUTH_ADMIN` before
starting the container:

| Value | Admin page | "+ Add OIDC provider" form on `/auth` | Persistence |
|---|---|---|---|
| `rw` *(default)* | Visible (login, list, delete) | Visible | Works |
| `ro`             | Visible (login, list, delete) | **Hidden** — only the admin curates the list | Works |
| `off`            | **Hidden** (404, no nav link, no admin login) | **Hidden** | Works (env / system file only) |

`off` locks the UI down entirely — no admin layer, no user self-add. The
provider list comes only from the sources the operator controls outside
the UI: `VERIFIABLY_OIDC_PROVIDERS` (env JSON), `auth-providers.system.json`
(deploy.sh-managed), or per-field env overrides. `ro` is the right
choice when an admin curates a fixed list from inside the UI and end
users should pick from it without adding their own. `rw` is full surface.

Persistence is independent of the mode — providers added via the sign-in
form (rw + first-run only) persist to `auth-providers.user.json` and
survive `./deploy.sh up all`. A fresh install with no providers
configured anywhere bypasses the `off`/`ro` lockdown for the bootstrap
form on `/auth` so you can't accidentally lock yourself out.

```bash
VERIFIABLY_NO_DEFAULT_IDPS=1 ./deploy.sh up all
# run this after setting the VERIFIABLY_AUTH_ADMIN variable in .env
# and then refresh your browser for updated UI
```

Custom credential schemas built via the issuer schema-builder persist
similarly: walt.id's HOCON catalog (`credential-issuer-metadata.conf`)
keeps the type definitions, and a sibling `config/custom-schemas.user.json`
mirror keeps the verifiably-go-specific metadata (issuer attribution,
per-OIDC-subject scoping, the Custom flag) that walt.id's wellknown
can't carry. Both are bind-mounted into the container; both survive
`./deploy.sh up all`. Holders' wallets persist on the Postgres named
volume `wallet-db` and the `wallet-api-data` named volume — those only
go away on `./deploy.sh reset`.

OIDC discovery is required — your server must serve
`/.well-known/openid-configuration`. Plain OAuth2, SAML, and LDAP need
a different integration.

### Stopping

```bash
./deploy.sh down all
```

### Clearing persistent data after stopping

```bash
./deploy.sh reset
# follow the instructions that will show up as-is for case sensitivity
```
This will help clear persistent volumes e.g.,:

```bash
# terminal output after running the reset script

 Volume waltid_injiweb-minio  Removed
 Volume waltid_vc-adapter-cache  Removed
 Volume waltid_citizens-data  Removed
 Volume waltid_inji-verify-db  Removed
 Volume waltid_injiweb-mockid-keystore  Removed
 Volume waltid_certify-pkcs12  Removed
 Volume waltid_wallet-db  Removed
 Volume waltid_injiweb-db  Removed
 Volume waltid_injiweb-esignet-keystore  Removed
 Volume waltid_certify-preauth-pkcs12  Removed
 Volume waltid_credebl_postgres_data  Removed
 Volume waltid_credebl_redis_data  Removed
 Volume waltid_credebl_nats_data  Removed
 Volume waltid_credebl_minio_data  Removed
```

Persistent docker volumes (eSignet DB, Inji Certify keystore, walt.id
wallet DB, CREDEBL Postgres/Redis/NATS/MinIO) are preserved between runs
and may persist after running the reset script.

To start from a fully clean slate, remove the project volumes with
`docker volume rm waltid_<name>` — see
[verifiably-go/docs/deploy.md](verifiably-go/docs/deploy.md#full-reset)
for the exact list.

## Troubleshooting

Common things that trip up a first deploy:

**`pull access denied for verification-adapter-adapter` / `pull access denied for inji-preauth-proxy`**

You're on an older checkout that still references image tags that only
exist locally on a contributor's laptop. `git pull` to the latest `main`
and re-run `./deploy.sh up <scenario>`. The current `docker-compose.yml`
pulls from `adammwaniki/verification-adapter` and `adammwaniki/inji-preauth-poc`
on Docker Hub, both public.

**Keycloak redirects with "Invalid parameter: redirect_uri"**

The realm JSON accepts localhost, `172.24.0.1`, any `*.amazonaws.com`
host, and any `http://*:8080/*` — enough to cover the laptop + EC2
cases. If you're deploying to a custom domain, add it to
`deploy/compose/stack/keycloak-realm.json` under `clients[0].redirectUris`
and `docker compose up -d --force-recreate keycloak`.

**WSO2 redirects to `localhost:9443/authenticationendpoint/login.do`
(and the browser can't resolve localhost)**

WSO2's `deployment.toml` is templated from `.template` using
`VERIFIABLY_PUBLIC_HOST`. If you edited `.env` *after* the first
`./deploy.sh up`, re-run `./deploy.sh up all` — it'll regenerate the toml
and recreate the wso2is container. Confirm with:

```bash
curl -sk https://<your-host>:9443/oauth2/token/.well-known/openid-configuration \
  | jq .issuer
# should echo your host, NOT "localhost"
```

**Inji Certify / Inji Certify Preauth container is `unhealthy`, schema page empty, `/issuer/schema` 502s on the well-known metadata**

Symptom in `docker logs inji-certify` (or `inji-certify-preauth-backend`):
```
io.mosip.kernel.core.keymanager.exception.NoSuchSecurityProviderException:
  KER-KMA-004 --> No such alias: <uuid>
Application run failed
```
This is a **keystore / DB desync**: a previous run wrote key aliases
into the postgres DB, the keystore PKCS12 got regenerated on a later
run, and the alias the DB still references no longer exists in the
keystore. The named volumes (`waltid_certify-db`, `waltid_certify-pkcs12`,
`waltid_certify-preauth-db`, `waltid_certify-preauth-pkcs12`) are hardcoded
to the `waltid` project prefix, so they persist across `docker compose
down` AND across cwd moves (e.g. running from a fresh clone in `/tmp`
inherits volumes from your usual workspace).

Fix:
```bash
./deploy.sh reset       # wipes every waltid_* volume; asks for 'RESET' to confirm
./deploy.sh up <scenario>
```

If you want to wipe just the Inji Certify halves without touching
walt.id / Inji Web / citizens DBs:
```bash
docker compose -f deploy/compose/stack/docker-compose.yml rm -fs certify-postgres inji-certify certify-preauth-postgres inji-certify-preauth-backend
docker volume rm waltid_certify-db waltid_certify-pkcs12 waltid_certify-preauth-db waltid_certify-preauth-pkcs12
./deploy.sh up <scenario>
```

**CREDEBL bootstrap fails or "OID4VCI rewriter config failed" warning**

CREDEBL's bootstrap provisions a Keycloak realm, platform-admin account,
DID, OID4VCI issuer, and credential template on first `up`. If a step
fails partway through (e.g. Keycloak wasn't ready yet), re-running
`./deploy.sh up credebl` or `./deploy.sh up all` is idempotent — each
bootstrap step checks whether the resource already exists before creating it.

If you see `OID4VCI rewriter config failed — credential offer downloads will 502`
in the startup log, the nginx sidecar that rewrites CREDEBL credential offer
URLs couldn't determine the Credo agent's dynamic admin port. This resolves
automatically on the next `up` once CREDEBL's agent-provisioning service has
written its port config.

**`./deploy.sh` calls `docker` and gets "permission denied"**

Your user isn't in the `docker` group. Fix once:
```bash
sudo usermod -aG docker "$USER"
newgrp docker     # activate in current shell, or log out and back in
docker ps         # should work without sudo
```

**Port conflicts**

`sudo ss -ltn` lists listening ports. Common collisions:
- 5432 (Postgres) — another postgres on the host
- 8080 — any other web app
- 8099 — Tomcat default on some Linux distros

Either stop the conflicting service or change the port in `.env` (e.g.
`VERIFIABLY_HOST_PORT=8081`). Ports 80/443 are only needed if you bring
up the Caddy TLS reverse proxy; skip it for localhost dev.

## What this app does

Each of the three core roles has a dedicated flow:

**Issuer** — pick a DPG (capability-aware cards so you only see what
that vendor can do) → pick or build a schema → pick flow mode (auth-code
vs pre-authorized-code for Inji; pre-auth for walt.id and CREDEBL) → enter
one subject or upload a bulk CSV → get back a real OID4VCI offer URI +
QR code, or for Inji a printable PDF with an embedded status-list-ready
QR. Bulk issuance runs as an async job (HTTP 202 + SSE progress stream)
so large CSVs don't block the UI.

**Holder** — pick a wallet DPG → scan, paste, or select an example
offer → review the pending offer → accept it into the wallet → present
it to a verifier via QR, OID4VP link, or direct upload.

**Verifier** — pick a verifier DPG → either request an OID4VP
presentation from a template (signed request JWT + QR for cross-device)
or upload a VC directly (paste JSON-LD, paste SD-JWT compact, or upload
a QR image). Get back signature verification, DID resolution, revocation
status, and the fields actually disclosed.

All user-facing text is translated on the fly when you switch language
in the top bar — both the static template strings and dynamic text
coming from DPG responses.

## Where to look next

- **[verifiably-go/docs/architecture.md](verifiably-go/docs/architecture.md)**
  — package layout, adapter interface, registry routing, HTMX patterns,
  translation middleware, and the inji-proxy that bridges walt.id / Mimoto /
  Inji Verify quirks.

- **[verifiably-go/docs/deploy.md](verifiably-go/docs/deploy.md)** —
  deploy.sh walkthrough per scenario, compose overrides, seed scripts,
  database-repair helpers, environment variables, and migrating from
  localhost to an EC2 instance.

- **[verifiably-go/docs/dpg-matrix.md](verifiably-go/docs/dpg-matrix.md)**
  — per-DPG capability matrix, known upstream bugs we work around (Inji
  Certify kid mismatch, Inji Verify UI render-order config, Inji Web
  PUBLIC_HOST coupling), version-compatibility caveats.

- **[verifiably-go/docs/spec-versions.md](verifiably-go/docs/spec-versions.md)**
  — pinned OID4VCI / OID4VP / SD-JWT VC / W3C VC 2.0 draft versions
  implemented by each adapter, known wire-format gaps, and update instructions.

- **[verifiably-go/docs/haip-conformance.md](verifiably-go/docs/haip-conformance.md)**
  — HAIP (High Assurance Interop Profile) gap analysis: which requirements
  each adapter meets (✅), partially meets (⚠️), or is missing (❌), with a
  prioritised closure plan.

- **[verifiably-go/docs/integration.md](verifiably-go/docs/integration.md)**
  — adapter-to-endpoint mapping per DPG, how to swap `MockAdapter` for a
  real implementation, how authenticated requests flow through the OIDC
  providers.

- **[verifiably-go/testdata/bulk-issuance/README.md](verifiably-go/testdata/bulk-issuance/README.md)**
  — copy-paste recipes for the bulk-issuance feature (CSV fixtures,
  SELECT queries against the seeded `citizens` postgres, and a dockerized
  "ministry registry" scenario to exercise the Secured-API bulk source).

- **[verifiably-go/TODO.md](verifiably-go/TODO.md)**
  — resolved security and reliability items (P0–P3) from the 2026-05-16
  review, plus the long-tail architectural backlog (Vault/SSM, mTLS, push
  revocation, VERIFIABLY_MODE).

## License

See repository root.
