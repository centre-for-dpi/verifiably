# Repeatable deployment after a total docker nuke

This documents whether wiping all Docker state and re-deploying reproduces a working
verifiably system, what you must supply, and how to reproduce the demo data behind the
screenshots. It covers a public VPS/EC2 (subdomain + TLS) and localhost (legacy host:port).

## TL;DR — what a nuke + `./deploy.sh up all` reproduces

A "total docker nuke" wipes everything:

```bash
docker rm -f $(docker ps -aq) 2>/dev/null
docker rmi -f $(docker images -aq) 2>/dev/null
docker volume rm $(docker volume ls -q) 2>/dev/null
docker network rm $(docker network ls -q --filter type=custom) 2>/dev/null
docker system prune -a --volumes -f
```

After that, `git clone` → edit `.env` → `./deploy.sh up all` **reconstructs all surfaces and
base plumbing** but **not the demo data**:

| Reproduced by deploy (code/scripts) | NOT reproduced (runtime state in wiped volumes) |
|---|---|
| Every UI surface (issuer/holder/verifier, registry consoles, `/admin/esignet`, `identity.registry`/`admin.registry`) | Enrolled National ID registry rows (`certify.identity_registry`) |
| IdP base users: Keycloak `holder`/`issuer`/`admin`, WSO2 `admin` | Provisioned claims (`certify.vc_subject`) |
| eSignet `wallet-demo-client`, one mock identity `8267411072`/PIN `111111` | UI-built schemas (Business Registration / Director / Testa\* / Fresh\*) |
| Base `VerifiablePersonCredential` catalog entry, 200 mock citizens | Issued/revoked ledger + AUTHORISED/DENIED verdicts |
| walt.id / CREDEBL DIDs, all host-coupled config (regenerated from `.env`) | The narrowed eSignet login-factor config; demo IdP users `adamk`/`adamw` |

So the **application** comes back identically; the **demo dataset** (identities, schemas,
provisioned claims, and therefore the AUTHORISED/DENIED verdicts) is created by the e2e
harness under `e2e/demo/` — see "Reproduce the demo" below.

## What you must supply for a fresh host

Copy `.env.example` → `.env` and set:

1. **Host + domain** (subdomain mode): `VERIFIABLY_PUBLIC_HOST` (IPv4), `PUBLIC_HOST`,
   `VERIFIABLY_PUBLIC_DOMAIN`, `VERIFIABLY_HOSTS_PATTERN=https://%s.<domain>`,
   `VERIFIABLY_LE_EMAIL`. (`./deploy.sh setup` writes host/domain/LE for you; it does NOT
   write the secrets below — set those by hand and don't re-run the wizard after, it
   rewrites `.env`.)
2. **Secrets** (now listed as concrete lines in `.env.example`): `VERIFIABLY_API_KEYS`
   (change the demo secret), `SMTP_*` (only if you want email-OTP holder activation),
   `VERIFIABLY_REGISTRIES` (optional). Demo defaults elsewhere are safe for a demo, rotate
   for production (`WALLET_ENCRYPTION_KEY`, DB passwords, admin passwords).
3. **DNS** (subdomain mode, operator's manual step): wildcard `*.<domain>` **and**
   `*.registry.<domain>` → the host IP (the two-label `identity.registry.<domain>` /
   `admin.registry.<domain>` need the second wildcard). Open ports 80 + 443 for Let's Encrypt.

Then `./deploy.sh up all` (or `make up-all`).

### localhost / legacy mode
Leave `VERIFIABLY_HOSTS_PATTERN=` empty. URLs become `http://<host>:<port>`, the main Caddy
binds `:80`, and Let's Encrypt is skipped — no public DNS needed. `./deploy.sh up all` works
on localhost. (The walt.id service confs now render `http://<host>:<port>` in legacy mode, so
this path is unblocked.)

## Deployment granularity

- Whole stack: `./deploy.sh up all`
- Per DPG: `./deploy.sh up waltid | inji | credebl`
- Teardown: `./deploy.sh down <scenario>`; wipe volumes: `./deploy.sh reset`
- A Makefile wraps these (`make up-all`, `make waltid-up`, `make inji-up`, `make credebl-up`,
  `make nuke`, `make reset`). See `make help`.

## Reproduce the demo (identities, schemas, verdicts)

The demo data is created by the committed e2e harness (`e2e/demo/`), run headless against a
running deploy. Prerequisites: the stack is up (`up all`), `VERIFIABLY_API_KEYS` is set, and
the Playwright image is available. Each script's header documents its holder UIN/PINs.

```bash
# from a host with docker + the running stack:
docker run --rm --network host \
  -v "$PWD/e2e/demo":/pv -v /tmp/e2e-out:/root/e2e-out \
  -e BASE=https://verifiably.<domain> \
  mcr.microsoft.com/playwright:v1.55.0-noble \
  node /pv/demo-inji-director.mjs        # Inji auth-code delegated pair → AUTHORISED → revoke → DENIED
# demo-director-full.mjs = the walt.id delegated pair (issuer Keycloak, holder WSO2)
```

These recreate the enrolled identities, the Business Registration + Company Director schemas,
the provisioned claims, and drive claim → present → revoke to reproduce the AUTHORISED then
DENIED verdicts shown in the PR screenshots.

## Known re-deploy gotchas (handled)

- **walt.id service confs** render host-correctly in both subdomain and legacy mode.
- **Hairpin sidecars** (`deploy/compose/credebl/jwks-hairpin.sh`,
  `deploy/compose/verifier-status-hairpin.sh`) derive their alias from `VERIFIABLY_PUBLIC_DOMAIN`
  (no hardcoded host); they no-op in legacy mode. Run them after `up` in subdomain mode if you
  use CREDEBL issuance or the walt.id verifier "Status" policy.
- **Auth-code scope files** (`inji/certify/certify-postgres-dataprovider.properties`,
  `inji/esignet/credential-scopes.properties`): the committed baseline advertises only the
  base scope, matching a fresh certify volume. Do NOT commit the runtime-accumulated scopes a
  running box adds (schemas re-add their own scopes when rebuilt). If a box's working tree has
  drifted and you wipe the certify volume, restore the baseline first:
  `scripts/reset-authcode-catalog.sh --yes`.
- **Don't commit deploy-generated config** (`Caddyfile.public`, `backends*.json`,
  `wso2-deployment.toml`, the rendered `*-service.conf`) — all regenerate from `.env` on every `up`.
