# walt.id Community Stack — implementation guide

> **Version:** walt.id Community Stack **v0.18.2** (issuer-api, verifier-api, wallet-api).
> **Adapter type:** `walt_community` → `internal/adapters/waltid`.
> **Roles:** issuer · holder · verifier (the only DPG that ships a full built-in wallet).

This guide documents exactly what makes the walt.id DPG work inside verifiably, down to the
containers, env vars, Caddy blocks, HOCON configs, and database — and the role verifiably plays.

---

## 1. What it is

walt.id is an open-source, API-driven credentialing stack. Three standalone HTTP services:

| Service | Image | Internal port | Role |
|---|---|---|---|
| `issuer-api` | `waltid/issuer-api:0.18.2` | 7002 | Onboards signing keys/DIDs, mints OID4VCI offers, hosts issuer metadata. |
| `verifier-api` | `waltid/verifier-api:0.18.2` | 7003 | Runs OID4VP sessions, evaluates presentations. |
| `wallet-api` | `waltid/wallet-api:0.18.2` | 7001 | A hosted holder wallet: accounts, key/DID management, claim + present. |

Backing store: one shared PostgreSQL (`postgres:16.4-alpine`, DB `waltid`). An in-cluster
`caddy:2.8` fronts the three APIs in localhost mode; in subdomain mode the shared `caddy-public`
terminates TLS (see §6).

Credential formats it can issue: `w3c_vcdm_2` (VCDM 2.0 as JWT), `sd_jwt_vc (IETF)`, `mso_mdoc`
(ISO 18013-5). OID4VCI draft-13 (pre-authorized **and** authorization code); OID4VP verify via
Presentation Exchange 2.0.

---

## 2. The role verifiably plays — **orchestrator + proxy + schema registry**

verifiably-go does **not** reimplement walt.id; it drives the three APIs through the
`backend.Adapter` interface and unifies them under one UX:

- **Issuer.** Builds OID4VCI offers by calling issuer-api; onboards a `did:web` signing key at
  deploy (see §9). Bulk issuance fans out one offer per row.
- **Holder.** Proxies the hosted wallet-api — walt.id **is** verifiably's walt.id-holder persona
  (register/login → list wallets → `exchange/{resolveCredentialOffer,useOfferRequest,usePresentationRequest}`
  → list credentials).
- **Verifier.** Builds a Presentation Exchange request via verifier-api and polls the session.
  (v0.18.2 has no direct-credential-verify endpoint, so `VerifyDirect()` returns
  `backend.ErrNotSupported` for this DPG — use Inji Verify for paste/scan verification.)
- **Schema registry.** Custom schemas built in verifiably's UI are persisted into walt.id's
  **HOCON catalog** (`credential-issuer-metadata.conf`) and verifiably **restarts issuer-api** so
  it reloads its `credential_configurations_supported` map. This is the one place verifiably
  reaches into a walt.id config file + the docker socket.

---

## 3. The flows

**Issue → wallet (pre-auth):**
1. Operator picks a schema + "issue to wallet" in verifiably.
2. Adapter → `POST issuer-api/openid4vc/{jwt|sdjwt|mdoc}/issue` → offer URI (`openid-credential-offer://`).
3. Holder opens the offer in the wallet-api persona → `exchange/resolveCredentialOffer` →
   `exchange/useOfferRequest` → credential stored in the wallet DB.

**Verify (OID4VP):**
1. Verifier picks a template → adapter maps fields to a Presentation Definition →
   `POST verifier-api/openid4vc/verify` → OID4VP request + session id.
2. verifiably renders the `openid4vp://` QR; wallet responds.
3. Adapter polls `GET verifier-api/openid4vc/session/{id}` until terminal → verdict.

**Custom schema save:**
1. Operator builds a schema → verifiably writes the config into the mounted
   `credential-issuer-metadata.conf` → restarts `issuer-api` (docker socket) → schema becomes
   issuable.

---

## 4. Services (compose)

All in `deploy/compose/stack/docker-compose.yml`, default profile (no `--profile` needed):

```
postgres        postgres:16.4-alpine   ${POSTGRES_PORT:-5432}:5432   DB/user/pass = waltid
caddy           caddy:2.8              ${CADDY_HTTP_PORT:-80}:80     localhost-mode API fronting
issuer-api      waltid/issuer-api:0.18.2     7002   mount ../../k8s/config/issuer  (ro)
verifier-api    waltid/verifier-api:0.18.2   7003   mount ../../k8s/config/verifier (ro)
wallet-api      waltid/wallet-api:0.18.2     7001   mount ../../k8s/config/wallet   (ro) + wallet-api-data vol
```

`wallet-api` `depends_on` postgres (healthy) + caddy. Service array `WALTID_SERVICES` in
`scripts/common.sh`: `postgres caddy issuer-api verifier-api wallet-api`. Keycloak
(`quay.io/keycloak/keycloak:25.0`) and LibreTranslate ride along in every scenario but walt.id's
wallet OIDC login is **off** by default (see §7).

---

## 5. Environment variables

**Adapter side** (read by `internal/adapters/waltid/config.go`; may also come from the
`backends.json` `config` block, which takes precedence when present):

| Var | Meaning |
|---|---|
| `WALTID_CATALOG_PATH` | Path to `credential-issuer-metadata.conf` **as seen by verifiably-go** (e.g. `/app/issuer-api-config/credential-issuer-metadata.conf`). Empty ⇒ custom schemas use an in-memory borrow instead of persisting. Set in `scripts/start-container.sh`. |
| `WALTID_ISSUER_SERVICE` | Compose service name of issuer-api to restart after a catalog write (default `issuer-api`). |

The `backends.json` `config` block pins the public upstreams:
```json
"issuerBaseUrl":   "https://walt-issuer.in-labs.cdpi.dev",
"verifierBaseUrl": "https://walt-verifier.in-labs.cdpi.dev",
"walletBaseUrl":   "https://walt-wallet.in-labs.cdpi.dev",
"standardVersion": "draft13",
"demoAccount": { "name": "Verifiably Demo", "email": "verifiably-demo@example.org", "password": "<demo>" }
```

**wallet-api container** (compose): `SERVICE_HOST`, `WALLET_BACKEND_PORT=7001`,
`DB_NAME/DB_USERNAME/DB_PASSWORD=waltid`, `POSTGRES_DB_HOST=postgres`, and the crypto material
`WALLET_ENCRYPTION_KEY` / `WALLET_SIGN_KEY` (demo defaults — **rotate before any non-demo deploy**),
`WALLET_TOKEN_LIFETIME_DAYS=30`. OIDC login vars (`WALLET_OIDC_*`) are present so `oidc.conf`
parses, but login is disabled unless you re-enable it in `logins.conf`.

---

## 6. Caddy (subdomain mode)

`deploy/compose/stack/Caddyfile.public` — verbatim:

```caddy
walt-issuer.in-labs.cdpi.dev {
	handle /.well-known/did.json {
		header Content-Type "application/json"
		header Access-Control-Allow-Origin "*"
		respond `{"@context": [...], "id": "did:web:walt-issuer.in-labs.cdpi.dev",
		         "verificationMethod": [{ "type": "JsonWebKey2020", ... "publicKeyJwk": {"kty":"EC","crv":"P-256", ...}}],
		         "assertionMethod": [...], "authentication": [...]}` 200
	}
	reverse_proxy issuer-api:7002
}

walt-wallet.in-labs.cdpi.dev {
	reverse_proxy wallet-api:7001
}

walt-verifier.in-labs.cdpi.dev {
	reverse_proxy verifier-api:7003
}
```

The `did:web:walt-issuer.<domain>` document is served **by Caddy** as a static `respond` (the
issuer's onboarded P-256 JWK), so external verifiers can resolve the issuer DID.

**Hairpin aliases** — `caddy-public` carries `walt-issuer` / `walt-verifier` / `walt-wallet`.`<domain>`
as network aliases so in-cluster clients (the wallet resolving an offer URI whose host is the
public issuer, a status-list fetch, etc.) reach caddy's internal IP instead of hairpinning the
box's blocked :443.

---

## 7. Runtime configs (HOCON)

All under `deploy/k8s/config/` (shared by compose + Helm; walt.id resolves `${ENV}` substitutions
at container start — **not** regenerated at deploy):

| File | Role |
|---|---|
| `issuer/credential-issuer-metadata.conf` | The **catalog** — `credential_configurations_supported`. verifiably rewrites this on custom-schema save + restarts issuer-api. |
| `issuer/credential-issuer-metadata.baseline.conf` | Pristine catalog seeded with the demo/workshop schemas so issuance works on first boot. |
| `issuer/issuer-service.conf`, `issuer/web.conf` | issuer-api service + web binding (`${SERVICE_HOST}`, `${ISSUER_API_PORT}`). |
| `verifier/verifier-service.conf`, `verifier/web.conf` | verifier-api service + binding. |
| `wallet/{auth,logins,web,db,oidc,trust,_features,registration-defaults,rejectionreason}.conf` | wallet-api config. `logins.conf` controls enabled login methods (OIDC off by default); `db.conf` reads the `waltid` DSN; `web.conf` binds `${WALLET_BACKEND_PORT}`. |

---

## 8. Databases & APIs

**Database:** `waltid` on the shared `postgres` container (host port `${POSTGRES_PORT:-5432}`).
Holds wallet-api accounts, keys, DIDs, and stored credentials. issuer/verifier are largely
stateless (keys onboarded at deploy).

**Upstream APIs verifiably calls:**
- issuer-api `:7002` — `POST /onboard/issuer`, `POST /openid4vc/{format}/issue`,
  `GET /{version}/.well-known/openid-credential-issuer`, `POST /schemas/import`, `GET /schemas/{id}`.
- verifier-api `:7003` — `POST /openid4vc/verify`, `GET /openid4vc/session/{id}`.
- wallet-api `:7001` — `POST /wallet-api/auth/{register,login}`,
  `GET /wallet-api/wallet/accounts/wallets`,
  `POST /wallet-api/wallet/{walletId}/exchange/{resolveCredentialOffer,useOfferRequest,usePresentationRequest}`,
  `GET /wallet-api/wallet/{walletId}/credentials`.

**verifiably adapter files:** `internal/adapters/waltid/` — `config.go` (env + config),
`adapter.go` (interface glue), `issuer.go` (issuance), `verifier.go` (OID4VP), `wallet.go`
(holder/wallet). Reached only through the Registry fan-out (`internal/adapters/registry`); handlers
never import it directly.

---

## 9. Deploy + verify

```bash
ssh colombo 'cd /root/verifiably/verifiably-go && ./deploy.sh up waltid'   # or: up all
```

`deploy.sh` brings up `WALTID_SERVICES` + the IdPs + translator, then runs
`bootstrap_waltid_did_web` (`scripts/bootstrap-waltid-did.sh`): calls issuer-api `/onboard/issuer`
to create the `did:web` signing key (falls back to `did:key` if it fails). It waits on ports
7001–7003 (+ 8180 Keycloak, 5000 LibreTranslate) and runs the OIDC discovery gate.

**Smoke:** build/issue a schema → offer appears; the walt.id wallet persona claims it without a
ConnectTimeout; saving a custom schema restarts issuer-api and the schema becomes issuable. e2e:
`e2e/esignet-wallet.mjs` and the walt.id flow scripts in `e2e/`.

---

## 10. Gotchas

- **Custom-schema Save → "restart issuer-api: docker.sock permission denied."** verifiably-go
  (uid 65532) must be in the docker group; `scripts/start-container.sh` runs it with
  `--group-add <docker_gid>`. Never hand-recreate the container without that flag.
- **Wallet OIDC login timeouts / disabled.** OIDC is intentionally off (`logins.conf`); the
  `WALLET_OIDC_*` env exist only so `oidc.conf` parses. Re-enabling requires real values + adding
  `oidc` back to the enabled methods.
- **`VerifyDirect` unsupported.** walt.id v0.18.2 exposes no paste/scan verify endpoint; the
  adapter returns `backend.ErrNotSupported`. Route direct verification through Inji Verify.
- **Demo crypto keys.** `WALLET_ENCRYPTION_KEY` / `WALLET_SIGN_KEY` default to upstream demo
  values — rotate for anything real.

> **Looking for mdoc/mDL (ISO 18013-5) issuance?** That's a separate walt.id
> instance, `issuer-api2`, not covered by this guide — see
> [deploy.md's "mDL / mdoc issuance (issuer-api2)"](../deploy.md#mdl-mdoc-issuance-issuer-api2)
> section for its certs, trust-anchor endpoint, and config split.

See also: [architecture.md](../architecture.md) · [deploy.md](../deploy.md) ·
[dpg-matrix.md](../dpg-matrix.md) · [integration.md](../integration.md).
