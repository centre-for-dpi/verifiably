# verifiably

A thin, backend-agnostic Go + HTMX UI for issuing, holding, and verifying
W3C Verifiable Credentials against real DPG (Digital Public Goods) stacks.
One interface (`backend.Adapter`) drives every screen; swap implementations
to point at a different vendor without touching the UI.

The app and its deploy tooling live under [`verifiably-go/`](verifiably-go/).
Everything below refers to that subtree — run the commands from there.

Supported DPGs out of the box:

- **walt.id Community Stack** v0.18.2 — issuer / holder / verifier via walt.id's issuer-api, wallet-api, verifier-api
- **Inji Certify** v0.14.0 — issuer, both OID4VCI pre-authorised code and authorization code flows. The auth-code flow has an **in-app multi-format schema builder** (create a credential live — W3C VCDM 1.1/2.0 as `ldp_vc` or IETF SD-JWT VC as `vc+sd-jwt` — which writes the Certify config + registry extraction view + eSignet scope and restarts the services in place)
- **Inji Web Wallet** v0.16.0 — holder via the MOSIP Inji Web SPA + Mimoto BFF, **or** claim Inji Certify auth-code credentials **in-app via eSignet** (no external redirect)
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
| **`curl`, `jq`, `python3`, `openssl`** | `deploy.sh` and the bootstrap scripts (Keycloak, WSO2IS, CREDEBL) use them for seeding OIDC clients, rendering configs, patching CREDEBL containers, and generating secrets + the hub signing key. |

Docker Hub has the two first-party images the stack pulls:

- [`adammwaniki/inji-preauth-poc`](https://hub.docker.com/r/adammwaniki/inji-preauth-poc) — a tiny reverse proxy that patches two Inji Certify pre-auth OID4VCI endpoints so wallets outside the container network work. Source: [`verifiably-go/cmd/inji-preauth-proxy`](verifiably-go/cmd/inji-preauth-proxy).
- [`adammwaniki/verification-adapter`](https://hub.docker.com/r/adammwaniki/verification-adapter) — standalone backend-agnostic verifier showcase on port 8085; referenced by the `inji` / `all` scenarios as a parallel demo (verifiably-go itself doesn't call it).

All other containers pull from their vendors' official Docker Hub repos.

## Running unit tests

Go is not required on the host — the test suite runs inside a Docker container:

```bash
cd verifiably-go

# Run all unit tests (requires Docker):
docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  -e GOTOOLCHAIN=auto \
  -e GOFLAGS="-mod=mod" \
  golang:1.24 \
  go test ./...
```

Expected output — every package should print `ok`:

```
ok  github.com/verifiably/verifiably-go/internal/roles        0.018s
ok  github.com/verifiably/verifiably-go/internal/trust        0.024s
ok  github.com/verifiably/verifiably-go/internal/metrics      0.013s
ok  github.com/verifiably/verifiably-go/internal/didresolver  0.013s
ok  github.com/verifiably/verifiably-go/internal/verification 0.013s
ok  github.com/verifiably/verifiably-go/internal/federation   0.015s
ok  github.com/verifiably/verifiably-go/internal/handlers     0.045s
```

To run a single package with verbose output:

```bash
docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  -e GOTOOLCHAIN=auto \
  -e GOFLAGS="-mod=mod" \
  golang:1.24 \
  go test -v ./internal/trust/...
```

If Go 1.25+ is in your `$PATH`, you can skip Docker and run `go test ./...` directly.

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
| `credebl` | CREDEBL (18 microservices) | Keycloak | ~6 GB |

Usage is the same pattern: `./deploy.sh <up|run|down|status|config> <scenario>`.

To bring up only the CREDEBL stack (useful for dedicated issuer/verifier nodes):

```bash
./deploy.sh up credebl
```

First run pulls ~46 images and runs the full CREDEBL bootstrap (Keycloak realm,
platform-admin account, DID, OID4VCI issuer, credential template). Expect
8–15 minutes. Subsequent runs are idempotent — each bootstrap step checks
whether the resource already exists and skips it.

The `run` subcommand rebuilds and restarts **only** the verifiably-go
container without touching compose — useful when the DPG stack is already
up and you just changed verifiably-go's code or config.

---

## Federated Ecosystem (Hub mode)

The `federated-issuance` branch extends verifiably-go into a multi-organisation
ecosystem: N independent issuer instances plus a central **Hub** that runs the
Trust Registry, Schema Registry, and a public verification portal for citizens.

```
┌──────────────────────── HUB (verify.cdpi.dev) ──────────────────────────┐
│  Trust Registry  (/trust-registry, JWT ES256)                           │
│  Schema Registry (/api/schemas — aggregated + cached from issuers)      │
│  Public verify   (/verify — no login, citizen-facing)                   │
│  Admin           (/admin/federation/members — CRUD, API key lifecycle)  │
│  Monitoring      (Prometheus + Grafana — federation-wide scrape)        │
└────────────┬──────────────────┬──────────────────┬───────────────────── ┘
             │                  │                  │
     Emisor A (walt.id)  Emisor B (CREDEBL)  Emisor C (Inji)
     ROLES=issuer         ROLES=issuer        ROLES=issuer
     did:web:a.gov        did:web:b.gov       did:web:c.gov
```

### Hub from scratch

Follow these steps once on a fresh machine to get the Hub running end-to-end.

**1. Check out the branch and enter the subtree:**

```bash
git clone https://github.com/centre-for-dpi/demo-daas-3-0.git
cd demo-daas-3-0/verifiably-go
git checkout federated-issuance   # branch with federation code
```

**2. Generate the ES256 signing key for the Trust Registry JWT:**

```bash
# Create the config directory if it doesn't exist
mkdir -p config

# Generate a PKCS8 PEM key (compatible with both openssl versions):
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ec-raw.pem
openssl pkcs8 -topk8 -nocrypt -in /tmp/ec-raw.pem -out config/trust-signing-key.pem
rm /tmp/ec-raw.pem

# Verify it looks right:
head -2 config/trust-signing-key.pem
# -----BEGIN PRIVATE KEY-----
```

If you leave `VERIFIABLY_TRUST_SIGNING_KEY` empty the Hub uses an ephemeral
key — fine for local dev but the public key changes on every restart, breaking
external JWT verification.

**3. Create the `.env` file:**

```bash
cp deploy/compose/hub/.env.example deploy/compose/hub/.env
```

Open `deploy/compose/hub/.env` and set the required fields (marked `# *`):

| Variable | Example / Notes |
|---|---|
| `POSTGRES_PASSWORD` | Any random string — e.g. `openssl rand -hex 16` |
| `VERIFIABLY_PUBLIC_URL` | `http://localhost:8080` (dev) or `https://verify.cdpi.dev` (prod) |
| `VERIFIABLY_SESSION_SECRET` | 32 random hex bytes — `openssl rand -hex 32` |
| `VERIFIABLY_ADMIN_PASSWORD` | Your hub admin password |
| `GRAFANA_PASSWORD` | Your Grafana admin password |
| `VERIFIABLY_TRUST_SIGNING_KEY` | Leave blank to use the PEM file at `config/trust-signing-key.pem` (mounted read-only into the container). |

**4. Configure the federation:**

`config/federation.json` declares which issuer organisations belong to the
ecosystem. The repo ships a single example member. Edit it to reflect your actual
issuers:

```json
{
  "ecosystem": {
    "name": "CDPI Ecosystem",
    "trustRegistryURL": "https://verify.cdpi.dev/trust-registry",
    "hubURL": "https://verify.cdpi.dev"
  },
  "members": [
    {
      "id": "issuer-a",
      "name": "Ministerio de Educación",
      "did": "did:web:issuer-a.gov",
      "deploymentURL": "https://verifiably.issuer-a.gov",
      "roles": ["issuer"],
      "verifierBackendType": "walt_community",
      "verifierConfig": { "verifierBaseUrl": "https://issuer-a.gov/verifier", "standardVersion": "draft13" },
      "statusListEndpoints": ["https://issuer-a.gov/status-list/bitstring/v1"],
      "statusListPolicy": "fail-closed"
    },
    {
      "id": "issuer-b",
      "name": "Ministerio de Trabajo",
      "did": "did:web:issuer-b.gov",
      "deploymentURL": "https://verifiably.issuer-b.gov",
      "roles": ["issuer"],
      "verifierBackendType": "verifiably",
      "verifierConfig": {
        "serviceEndpoint": "https://verifiably.issuer-b.gov",
        "apiKey": "<hub key from issuer-b VERIFIABLY_API_KEYS>"
      },
      "statusListEndpoints": ["https://verifiably.issuer-b.gov/status-list/bitstring/v1"],
      "statusListPolicy": "fail-closed"
    }
  ]
}
```

Supported `verifierBackendType` values:

| Value | Backend | `verifierConfig` fields |
|---|---|---|
| `walt_community` | walt.id Community Stack verifier-api | `verifierBaseUrl`, `standardVersion` (`draft13` or `draft20`) |
| `verifiably` | Another verifiably-go instance (OID4VP via API key) | `serviceEndpoint`, `apiKey` |
| `credebl` | CREDEBL OID4VP endpoint | `orgId`, `apiUrl`, `email`, `password` |

> **`deploymentURL`** is the base URL of the member's verifiably-go instance.
> The Hub schema aggregator appends `/api/schemas` to this URL to fetch that
> member's credential types for the public `/verify` portal. It must be
> reachable from the Hub container.

> **API key wiring (backend type `verifiably`):** the `apiKey` value in
> `verifierConfig` must exactly match the key half (after the colon) of one
> entry in the issuer node's `VERIFIABLY_API_KEYS` env var.
> For example, if issuer-b runs with:
> ```
> VERIFIABLY_API_KEYS=hub:d0517ce8d93a907390cee0c9e7895e929d9a85fdffb30dd9d8920553fbc3e778
> ```
> then `federation.json` must have:
> ```json
> "apiKey": "d0517ce8d93a907390cee0c9e7895e929d9a85fdffb30dd9d8920553fbc3e778"
> ```
> A mismatch causes a silent `401` on the public `/verify` portal — the
> "generate presentation" button appears to do nothing. After correcting the
> key, restart the Hub so `bootstrapHub` re-registers the verifier adapter:
> `docker restart hub-verifiably-go`.

For dev/local testing the `members` array can be empty — the Hub boots fine with
no registered members.

**5. Generate the Prometheus federation scrape targets:**

```bash
bash deploy/compose/monitoring/generate-federation-prometheus.sh \
     config/federation.json \
     deploy/compose/hub/federation-targets.json
```

This creates the `file_sd` targets file Prometheus needs to scrape each
member's `/metrics` endpoint. Re-run this whenever you add or remove members,
then trigger a live reload:

```bash
docker compose -f deploy/compose/hub/docker-compose.yml exec prometheus \
  curl -sX POST http://localhost:9090/-/reload
```

**6. Build the verifiably-go image:**

```bash
docker build -t verifiably/verifiably-go:latest .
```

Or override `VERIFIABLY_IMAGE` in `.env` to point at a registry image and skip
the local build.

**7. Start the Hub stack:**

```bash
docker compose -f deploy/compose/hub/docker-compose.yml --env-file deploy/compose/hub/.env up -d
```

This brings up four containers:

| Container | Port | What it is |
|---|---|---|
| `hub-postgres` | — (internal) | PostgreSQL 16 — Trust Registry, verification events, API keys |
| `verifiably-go` | 8080 | Hub app (`VERIFIABLY_ROLES=hub`) |
| `hub-prometheus` | 9090 | Prometheus with federation scrape + alert rules |
| `hub-grafana` | 3100 | Grafana with the ecosystem overview dashboard |

**8. Verify everything is healthy:**

```bash
# Hub health check
curl -s http://localhost:8080/healthz
# {"status":"ok"}

# Public verify portal (citizen-facing, no login required)
# The hub root / now redirects here — not the role-picker
curl -sI http://localhost:8080/verify

# Trust Registry JWT
curl -s http://localhost:8080/trust-registry | cut -c1-60

# JWKS endpoint (public key for JWT verification)
curl -s http://localhost:8080/.well-known/jwks.json | python3 -m json.tool

# Prometheus targets
curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool | grep health

# Grafana
open http://localhost:3100   # login: admin / <GRAFANA_PASSWORD>
```

> **Note:** In hub mode the root path `/` serves the citizen-facing public
> verification portal (`/verify`). The admin UI lives at `/admin/login`.

**9. (Optional) Register an issuer from the admin UI:**

Browse to `http://localhost:8080/admin/login` → log in with `admin` /
`<VERIFIABLY_ADMIN_PASSWORD>`. After login you land on the **Hub Overview**
page; navigate to **Federation Members** → fill in the DID, service endpoint,
and status list URLs → **Register**.

Members added through the admin UI are immediately included in the schema
aggregator — no restart required. From the same page you can generate an API
key for each issuer so they can call `GET /api/ecosystem/issuers/{did}/stats`
to pull their verification stats.

**Stopping the Hub stack:**

```bash
docker compose -f deploy/compose/hub/docker-compose.yml down
```

**Full reset (destroys data volumes):**

```bash
docker compose -f deploy/compose/hub/docker-compose.yml down -v
```

### Running an issuer node

An individual ministry runs verifiably-go with `VERIFIABLY_ROLES=issuer`
pointing at their DPG backend. The existing `./deploy.sh up <scenario>` flow
is unchanged — add `VERIFIABLY_ROLES=issuer` to the container environment
to restrict it to issuer routes only. Issuer nodes do not need a PostgreSQL
instance (the standard JSON-backed log works) unless you want verification
events analytics.

**Required roles for Hub integration:**

| Role | Why it is needed |
|---|---|
| `issuer` | Core issuance routes (OID4VCI, schema builder, bulk issuance). |
| `verifier` | OID4VP presentation request endpoint — called by the Hub when a citizen scans a QR on the public portal. |
| `schemas` | Exposes `GET /api/schemas` so the Hub's schema aggregator can pull this member's credential types. Without this role, the Hub's public `/verify` portal shows no schemas for the member. |

Minimum recommended value for a node that participates in the federation:

```
VERIFIABLY_ROLES=issuer,verifier,schemas
```

**API key for Hub-to-node calls (backend type `verifiably`):**

The Hub authenticates to the issuer node's verifier endpoint using the
`apiKey` from `federation.json`. The issuer node validates incoming requests
against its `VERIFIABLY_API_KEYS` env var (format: `name:hex-secret`, multiple
entries comma-separated).

On the issuer node, generate and set the key once:

```bash
# Generate a random key
KEY=$(openssl rand -hex 32)
echo "hub:$KEY"
# → add  VERIFIABLY_API_KEYS=hub:<KEY>  to the node's environment
```

Then copy the `<KEY>` part into `federation.json` under
`verifierConfig.apiKey` for that member. The `hub:` prefix is just a
human-readable label — the Hub only sends the raw key in the
`Authorization: Bearer` header.

### Environment variables added by the federation branch

| Variable | Default | Purpose |
|---|---|---|
| `VERIFIABLY_ROLES` | *(all roles)* | Comma/space-separated list: `issuer`, `holder`, `verifier`, `trust`, `schemas`, `hub`. `hub` implies `trust` + `schemas`. Omit for legacy all-roles mode. |
| `VERIFIABLY_TRUST_SIGNING_KEY` | *(ephemeral)* | PEM (SEC1 or PKCS8) of the ECDSA P-256 private key used to sign Trust Registry JWTs. Ephemeral key on every restart if unset. |
| `VERIFIABLY_FEDERATION_CONFIG` | `config/federation.json` | Path to the federation members JSON file. |
| `VERIFIABLY_ISSUER_DID` | *(empty)* | `did:web:` of this deployment — embedded as `sourceIssuerDid` in `/api/schemas` responses so the Hub knows which issuer owns each schema. |
| `VERIFIABLY_DATABASE_URL` | *(empty)* | PostgreSQL DSN. Required for Trust Registry persistence, verification events, and API keys. JSON-backed fallback if unset. |
| `ISSUER_DID_DOMAIN` | *(empty)* | Inji-specific: domain for `did:web` — sets `CERTIFY_ISSUER_DID` in Inji's postgres init scripts. Must be set before first `docker compose up` (or after deleting Inji volumes). |

---

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

> **Back up `deploy/compose/credebl/config/credebl.env` before any destructive
> operation.** This file holds the auto-generated secrets (Postgres password,
> agent API key, JWT secret, wallet password, …). Docker volumes are keyed to
> these values — if the file is lost while volumes are still intact, Postgres
> will refuse connections with "password authentication failed" and the stack
> will not start. Copy it somewhere safe; if you need to rebuild from scratch,
> delete both the file and the volumes together (`./deploy.sh reset` followed by
> `docker volume rm` for the `cdpi-credebl_*` volumes).

**CREDEBL `did:web` (subdomain mode only)**

When `VERIFIABLY_PUBLIC_DOMAIN` is set, the bootstrap automatically uses
`did:web` for the CREDEBL agent — no extra configuration required. The DID is
`did:web:credebl.<your-domain>` and the bootstrap writes the DID document to
`deploy/compose/credebl/.agent-runtime/did/did.json`, served by the nginx
sidecar at `/.well-known/did.json`.

Verify after the first `deploy.sh up credebl`:

```bash
curl https://credebl.<your-domain>/.well-known/did.json
# Expected: JSON with "id": "did:web:credebl.<your-domain>" and a verificationMethod
```

The DID is provisioned once and stored in Postgres. Re-running `deploy.sh up`
will not change it. If you need to rotate the DID (e.g. key compromise), you
must delete the CREDEBL volumes and re-provision from scratch — the `orgDid`
field in `org_agents` is the source of truth.

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

### Updating a running deployment

When new commits land on the branch, apply them without losing data:

```bash
cd /path/to/demo-daas-3-0
git pull --ff-only
cd verifiably-go
./deploy.sh up credebl   # or 'all', 'waltid', etc. — same scenario as before
```

`deploy.sh up` is **idempotent**: it re-reads `credebl.env`, re-applies all
runtime patches to the CREDEBL containers, and skips any bootstrap step whose
resource already exists in Postgres. Docker volumes and Postgres data are
untouched.

After `git pull`, restart Caddy so it picks up the new `Caddyfile.public`
(see the inode note in Troubleshooting below):

```bash
docker compose -f deploy/compose/stack/docker-compose.yml restart caddy-public
```

If you only changed verifiably-go's own code (not the DPG stack), use `run`
instead of `up` — it rebuilds and restarts just the verifiably-go container
without touching any DPG service:

```bash
./deploy.sh run credebl
```

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

## REST API

verifiably-go exposes a machine-to-machine REST API for issuing, revoking,
and verifying credentials programmatically — no browser session required.

### Authentication

Set the `VERIFIABLY_API_KEYS` environment variable before starting the
container (`name1:key1,name2:key2`, multiple entries comma-separated).
Each key is owner-scoped: credentials issued by key A are never visible to
key B.

```bash
# Generate a key
KEY=$(openssl rand -hex 32)
# Add to your .env or docker-compose env:
# VERIFIABLY_API_KEYS=myapp:$KEY
```

Pass the key in every request:

```http
Authorization: Bearer <key>
```

Rate limiting: 60 requests/minute per key. Requests that exceed the limit
return HTTP 429 with `Retry-After: 60`.

### Interactive docs

When the app is running, browse to `/api/docs` for the Scalar interactive
documentation (includes a "Try it" panel for every endpoint). The raw
OpenAPI 3.0 spec is at `/api/openapi.yaml`.

### Endpoint reference

**Issuance** (requires `VERIFIABLY_ROLES=issuer`):

| Endpoint | Description |
|---|---|
| `POST /api/v1/credentials/issue` | Issue one credential — returns the `offer_uri` the holder scans with their wallet |
| `POST /api/v1/credentials/issue/bulk` | Issue N credentials synchronously — returns per-row outcomes in one response |
| `POST /api/v1/credentials/issue/bulk/async` | Submit an async batch job (HTTP 202) — returns `job_id` immediately; workers process in the background |
| `GET /api/v1/bulk/{jobID}` | Poll async job status (`pending` → `running` → `done` / `error`) |
| `GET /api/v1/bulk/{jobID}/events` | Server-Sent Events stream of job progress — useful for real-time dashboards |
| `GET /api/v1/credentials` | List credentials issued under this API key (supports `?q=`, `?state=`, `?std=`, `?format=` filters) |
| `GET /api/v1/credentials/{id}` | Get one issuance record |
| `POST /api/v1/credentials/{id}/revoke` | Revoke a credential (flips its status list bit; idempotent) |
| `POST /api/v1/credentials/{id}/reinstate` | Un-revoke a credential |

**Verification** (requires `VERIFIABLY_ROLES=verifier`):

| Endpoint | Description |
|---|---|
| `POST /api/v1/verify/request` | Create an OID4VP presentation request — returns `request_uri` (deep link / QR content) and `state` token |
| `GET /api/v1/verify/result/{state}` | Poll for verification result; returns `pending` until the holder responds, then `verified` or `failed` with disclosed fields |

**Ecosystem analytics** (Hub only — `VERIFIABLY_ROLES=hub`):

| Endpoint | Description |
|---|---|
| `GET /api/ecosystem/issuers/{did}/stats` | 30-day verification statistics for an issuer; Bearer key must be scoped to that DID |

### Quick example — issue one credential

```bash
BASE_URL=https://verifiably.example.gov
API_KEY=your-key-here

curl -s -X POST "$BASE_URL/api/v1/credentials/issue" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_id": "nationalId",
    "subject_data": {
      "given_name": "Jane",
      "family_name": "Doe",
      "nationalIdentifier": "123456789"
    }
  }' | jq .
# {
#   "credential_id": "vc-...",
#   "offer_uri": "openid-credential-offer://...",
#   "flow": "pre_auth"
# }
```

### Quick example — async bulk issuance

```bash
# Submit the batch (HTTP 202 — returns immediately)
JOB=$(curl -s -X POST "$BASE_URL/api/v1/credentials/issue/bulk/async" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_id": "nationalId",
    "rows": [
      {"given_name": "Alice", "family_name": "Smith"},
      {"given_name": "Bob",   "family_name": "Jones"}
    ]
  }' | jq -r .job_id)

# Poll status
curl -s "$BASE_URL/api/v1/bulk/$JOB" \
  -H "Authorization: Bearer $API_KEY" | jq .

# Or stream progress via Server-Sent Events
curl -s "$BASE_URL/api/v1/bulk/$JOB/events" \
  -H "Authorization: Bearer $API_KEY"
```

### Quick example — OID4VP verification

```bash
# Create a presentation request
STATE=$(curl -s -X POST "$BASE_URL/api/v1/verify/request" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"schema_id": "nationalId", "fields": ["given_name", "family_name"]}' \
  | jq -r .state)

REQUEST_URI=$(curl -s -X POST "$BASE_URL/api/v1/verify/request" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"schema_id": "nationalId", "fields": ["given_name", "family_name"]}' \
  | jq -r .request_uri)

# Display request_uri as a QR code for the holder to scan, then poll:
until [ "$(curl -s "$BASE_URL/api/v1/verify/result/$STATE" \
  -H "Authorization: Bearer $API_KEY" | jq -r .status)" != "pending" ]; do
  sleep 1
done

curl -s "$BASE_URL/api/v1/verify/result/$STATE" \
  -H "Authorization: Bearer $API_KEY" | jq .
```

---

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

**Hub public `/verify` shows no schemas (schema list is empty)**

The Hub aggregates credential schemas by calling `GET /api/schemas` on each
member's `deploymentURL`. If a member's schema list is empty, check two things:

1. **`schemas` role missing on the issuer node.** The issuer node must include
   `schemas` in `VERIFIABLY_ROLES`. Without it, `/api/schemas` returns 404 and
   the hub logs a warning like `schema cache: fetch failed` for that member.
   Fix: add `schemas` to the node's `VERIFIABLY_ROLES` and restart it.

2. **`deploymentURL` wrong or unreachable.** The Hub container must be able to
   reach `<deploymentURL>/api/schemas`. Confirm with:
   ```bash
   curl -s <deploymentURL>/api/schemas | python3 -m json.tool | head -20
   ```
   If you get a 404 or connection error, fix `deploymentURL` in
   `federation.json` and restart the Hub.

After fixing either issue, the schema cache refreshes within 5 minutes (or
restart the Hub to force an immediate refresh).

**Hub `/verify` portal: "El servicio de verificación del emisor no está disponible" (silent — no QR appears)**

This error fires when the Hub's `RequestPresentation` call to the member's
verifier returns a non-200 status. Check the Hub logs for the exact cause:

```bash
docker logs hub-verifiably-go --tail 50 2>&1 | grep "RequestPresentation\|public verify"
```

Common causes:

| Log message | Cause | Fix |
|---|---|---|
| `returned 401: {"error":"invalid or missing API key"}` | `apiKey` in `federation.json` doesn't match `VERIFIABLY_API_KEYS` on the issuer node | Update `federation.json` with the correct key (key half after the colon in `VERIFIABLY_API_KEYS`), then `docker restart hub-verifiably-go` |
| `returned 502: ... "Agent details not found"` | CREDEBL agent on the member node is down or not provisioned | Restart CREDEBL on that node; if on Linux run `_credebl_configure_oid4vci_rewriter` after restart |
| `returned 503` | Member's verifiably-go or DPG backend is down | Check the member node's container status |
| `No verifiers available` | Member not registered in the Hub's verifier registry | Confirm the member entry exists in `federation.json` and the Hub was restarted after any change |

**Hub: OID4VP authorization request returns 504 on Linux**

Wallet scans a QR code from the public `/verify` portal, loads for a long
time, then reports "presentation request expired". Fetching the
`request_uri` URL directly returns `504 Gateway Timeout`.

Root cause: the `credebl-oid4vci-rewriter` nginx sidecar proxies wallet
requests to the Credo agent. On Linux, `host.docker.internal` resolves to
`172.17.0.1` (Docker's default bridge), but the Credo Platform-admin container
lives on the compose project network (`172.24.x.x`), so the port is unreachable
from the bridge IP.

`deploy.sh up credebl` fixes this automatically by detecting the container's
actual Docker network IP and patching `nginx-oid4vci.conf`. The fix persists as
long as the agent container keeps the same IP (i.e. across restarts of the
stack, since Docker preserves container IPs within a named network).

If you restart the Credo agent container **outside** of `deploy.sh` (e.g.
`docker restart <agent-container>`) and it gets a new IP, re-run manually:

```bash
cd /path/to/demo-daas-3-0/verifiably-go
source .env
source scripts/common.sh
source scripts/bootstrap-credebl.sh
_credebl_configure_oid4vci_rewriter
```

This is idempotent — safe to re-run at any time. This issue does not affect
Docker Desktop (Mac/Windows) where `host.docker.internal` routes through the VM
correctly.

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

**Caddy still returns 404 for a route that exists in `Caddyfile.public` (after `git pull`)**

When `git pull` updates `deploy/compose/stack/Caddyfile.public`, the running
Caddy container does not see the change automatically. On Linux, `git pull`
replaces the file atomically (rename into place), which changes the inode.
Docker's bind mount was attached to the old inode — `caddy reload` reads the
file through that stale mount and silently keeps the old config.

Fix: restart the Caddy container so it re-opens the bind mount against the
current inode:

```bash
docker compose -f deploy/compose/stack/docker-compose.yml restart caddy-public
```

Verify that the new route is live by grepping the config inside the container:

```bash
docker exec waltid-caddy-public-1 grep 'well-known' /etc/caddy/Caddyfile
```

This only affects deployments where Caddy was already running before the pull.
A fresh `deploy.sh up` is not affected because Caddy starts against the current
file from the beginning.

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

**Inji pre-auth credential won't hold in the walt.id wallet (`invalid_proof`
/ `proof_header_ambiguous_key`)** — use an external OID4VCI wallet with **SD-JWT**

The bundled walt.id Community Stack wallet-api (**v0.18.2**) cannot receive an
Inji Certify pre-authorized-code credential, for two reasons that both live
inside the walt.id image and are not fixable on the issuer side:

1. **Non-conformant proof.** walt.id's `useOfferRequest` builds the OID4VCI
   proof JWT with a header carrying **both** a top-level `kid` *and* a `jwk`.
   OID4VCI requires exactly one key reference, so Inji's `JwtProofValidator`
   rejects it with `proof_header_ambiguous_key` → `400 invalid_proof`. (Proven:
   a clean `jwk`-only proof issues `200`; adding a top-level `kid` flips it to
   the same 400.)
2. **No ldp_vc presentation.** Even if received, walt.id v0.18.2 can only
   *present* compact-JWT formats (`jwt_vc_json`, `vc+sd-jwt`) — its VP path
   throws on `ldp_vc` (JSON-LD).

A holder-side adapter that exports a wallet-managed key (`keys/{id}/load`
returns the private JWK), signs a conformant proof itself, redeems the
credential, and stores it back is **also blocked**: wallet-api v0.18.2's
`PUT /credentials` ("Store credential") returns `500 NotImplementedError`, so
there is no way to inject an externally-fetched credential into the wallet.
walt.id's only ingest path is its own (broken-proof) exchange.

The **issuer side is fully conformant** — a clean, `jwk`-bound
`openid4vci-proof+jwt` issues `200` through the entire public chain. So the
working path is to scan/paste the offer into an **external OID4VCI wallet**
(e.g. a Credo-based mobile wallet) and issue the schema as **SD-JWT
(`sd_jwt_vc (IETF)`)**, which holds end-to-end. ldp_vc (W3C) holds in wallets
with proper JSON-LD + Data Integrity support; SD-JWT is the most broadly
compatible. Making the walt.id *holder* work would require a walt.id wallet-api
version that emits a conformant proof (and implements credential import).

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
it to a verifier via QR, OID4VP link, or direct upload. *(For the Inji
auth-code path — the Inji Web Wallet DPG — the holder instead browses an
in-app credential catalog, signs in with eSignet, and receives the VC
right here in verifiably, with no external Inji Web redirect.)*

**Verifier** — pick a verifier DPG → either request an OID4VP
presentation from a template (signed request JWT + QR for cross-device)
or upload a VC directly (paste JSON-LD, paste SD-JWT compact, or upload
a QR image). Get back signature verification, DID resolution, revocation
status, and the fields actually disclosed.

All user-facing text is translated on the fly when you switch language
in the top bar — both the static template strings and dynamic text
coming from DPG responses.

## Credential delivery models

A credential can reach its subject two fundamentally different ways. They are
**not interchangeable** — different trust models, different consumers, different
failure modes. Picking the wrong one is behind most "why won't this work in a
wallet?" confusion.

|          | Bearer / QR-on-PDF | Wallet / OID4VCI |
| -------- | ------------------ | ---------------- |
| **Binding**  | bound to a **server-held key the recipient never receives** → bearer (holding the QR = holding the credential) | bound to the **wallet's own key** (holder proves possession) |
| **Consumer** | a **verifier** scans it (Inji Verify) | the **holder** holds + presents it (OID4VP) |
| **Good for** | paper / offline / kiosk verification | digital wallet, selective disclosure, presentation |

**Bearer / QR-on-PDF.** The Inji Certify pre-auth *"issue as PDF"* path mints
the credential entirely server-side: verifiably-go generates a proof-signing
key, builds a conformant OID4VCI proof, redeems the signed VC, and embeds it
(PixelPass-encoded) as a QR on a printable A4 page. The credential is bound to
that server-held key, which the subject **never receives** — so the subject
cannot perform a holder-bound presentation. A verifier (Inji Verify) trusts it
by checking the issuer's signature against its `did:web`, not by challenging the
holder. Possession of the QR *is* the credential, exactly like a paper
certificate. This is **not** a wallet onboarding mechanism: scanning the QR
into an OID4VCI wallet does nothing, because the QR is a finished credential,
not an `openid-credential-offer://`.

**Wallet / OID4VCI.** The subject's wallet generates its own key, signs the
OID4VCI proof-of-possession, and receives a credential bound to that key. Only
the wallet can present it (OID4VP) because only it can prove possession of the
bound key. This is the holder-bound model that enables selective disclosure and
verifiable presentation — and the one whose cross-stack interop quirks are
covered under Troubleshooting (walt.id's non-conformant proof + missing import,
the mobile wallet's `ldp_vc` handling, SD-JWT as the most portable format).

### A middle path: server-custodied keys (hosted wallet)

The bearer model's server-held key does **not** have to be thrown away. If the
operator *retained* that key in a (web) wallet **on the holder's behalf** — a
**custodial / hosted wallet** — the credential becomes fully presentable: the
custodian holds the binding key and builds the OID4VP presentation *for* the
holder, who only logs in to a web wallet. This blends the two columns above —
holder-bound crypto, but no device wallet to install. It is worth considering
because:

- **Zero-install onboarding** — the holder needs only a browser login, not a
  mobile wallet that may mishandle the issuer's formats.
- **The custodian signs *conformant* proofs and presentations** — it controls
  key generation and the OID4VCI/OID4VP crypto, sidestepping the external-wallet
  interop bugs (e.g. walt.id's `kid`+`jwk` proof rejection, or a wallet that
  can't present `ldp_vc`).
- **It is already how walt.id's `wallet-api` works** — it custodies keys
  server-side (its `keys/{id}/load` even returns the private JWK), so a hosted
  model is a natural extension of the existing holder service rather than a new
  component.

The trade-off is **custody**: a hosted wallet is *not* self-sovereign — the
holder trusts the operator to hold their keys, and portability/recovery become
the operator's responsibility. It is the classic custodial-vs-self-custody
choice every wallet ecosystem makes; for workshops, onboarding demos, or
low-assurance credentials the custodial convenience often wins, while
high-assurance / long-lived credentials favour a self-custody device wallet.

### Inji Certify pre-auth: which formats work where

The pre-auth issuer mints two credential formats — **`ldp_vc`** (W3C JSON-LD,
`Ed25519Signature2020`; both VCDM 1.1 and 2.0) and **`vc+sd-jwt`** (IETF SD-JWT
VC, signed with an `x5c` certificate chain). It does **not** mint `mso_mdoc` on
this path. Inji issues both as *valid* credentials — the limitations below are
all **consumer-side**: how each wallet / verifier handles the format.

| Format | OID4VCI → mobile (Credo) | OID4VCI → walt.id holder | OID4VP (present) | PDF (bearer QR) |
| ------ | ------------------------ | ------------------------ | ---------------- | --------------- |
| **`ldp_vc`** (W3C, Ed25519Signature2020) | ✗ wallet's Inji path is compact-JWT-only — a JSON-LD object crashes it | ✗ proof rejected (`kid`+`jwk`); v0.18.2 also can't store/present `ldp_vc` | ✗ walt.id VP path handles only compact-JWT | ✓ minted server-side, PixelPass QR, verified by Inji Verify |
| **`vc+sd-jwt`** (IETF, `x5c`) | ✓ compact JWT — holds end-to-end | ✗ proof rejected (`kid`+`jwk`) at issuance | ⚠️ presentable by a Credo wallet to an `x5c`-aware verifier (Inji Verify); the walt.id verifier rejects it (*"Only DIDs are supported as issuer IDs"*) | ✗ PixelPass expects CBOR-able JSON-LD; a compact SD-JWT is storage-only, no usable QR |

Why each limitation exists (all detailed in Troubleshooting):

- **mobile `ldp_vc` crash** — the wallet flags `/v1/certify/` as a legacy
  endpoint and runs a compact-JWT-only path; a JSON-LD object hits
  `String.split` → "undefined is not a function".
- **walt.id proof rejection** — `wallet-api` builds a proof header carrying both
  `kid` and `jwk`; OID4VCI requires exactly one, so Inji returns
  `proof_header_ambiguous_key`. (Format-agnostic — blocks both formats.)
- **walt.id can't present `ldp_vc`** — its OID4VP path calls `.jsonPrimitive` on
  the vpToken, which throws for a JSON-LD object (only compact-JWT works).
- **SD-JWT verifier mismatch** — Inji signs SD-JWT under an `x5c` certificate,
  but the walt.id verifier only resolves **DID** issuers for W3C credentials.
- **SD-JWT has no PDF QR** — the PixelPass pipeline (CBOR → zlib → base45) is
  built for structured JSON-LD; a compact SD-JWT string isn't a scannable
  credential QR.

**Net, today:** for a wallet use **`vc+sd-jwt` → a Credo-based mobile wallet**;
for offline / paper use **`ldp_vc` → PDF + Inji Verify**. None of these are Inji
issuance bugs — Inji emits standards-valid credentials in both formats.

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

- **[verifiably-go/federated-emission.md](verifiably-go/federated-emission.md)**
  — federation architecture plan: all 13 implementation phases (Fase 0–9 + 10),
  architectural decisions, DID:web deployment automation, hub compose topology,
  and the criteria used to verify each phase.

- **[verifiably-go/deploy/compose/hub/docker-compose.yml](verifiably-go/deploy/compose/hub/docker-compose.yml)**
  — Hub compose stack: verifiably-go (hub mode) + PostgreSQL + Prometheus + Grafana.
  Copy `deploy/compose/hub/.env.example` to `.env` and fill in the required fields
  before running `docker compose up`.

## License

See repository root.
