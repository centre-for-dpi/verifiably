# Inji Certify (Auth-Code) + eSignet + the in-app Inji wallet — implementation guide

> **Versions:** Inji Certify **v0.14.0** (`injistack/inji-certify-with-plugins:0.14.0`),
> eSignet **1.5.1** (`mosipid/esignet-with-plugins:1.5.1`), OIDC-UI **1.5.1**, mock-identity-system
> **0.10.1** (`mosipid/mock-identity-system:0.10.1`).
> **Adapter type:** `inji_certify_authcode` → `internal/adapters/injicertify` (+ handlers).
> **Roles:** issuer · holder (verifiably owns the in-app wallet).

This is the largest DPG in verifiably. It is the MOSIP/eSignet **authoritative-identity** model:
an issuer defines credentials; a registrar enrols citizens into an identity registry; a holder
**authenticates** (does not self-mint) via eSignet and pulls the credential into an in-app wallet.

---

## 1. What it is

The **authorization_code** OID4VCI flow. Certify signs credentials from claims held in
`certify.vc_subject`, keyed by the eSignet subject (PSU-token). eSignet is the OIDC IdP that
authenticates the holder against `mock-identity-system` (the dev stand-in for MOSIP's ID
Repository / IDA). verifiably provides the wallet UI, orchestrates the whole OID4VCI dance, and is
its own **public did:web issuer** (`did:web:inji-certify-authcode.<domain>`), separate from the
pre-auth instance.

It is a **separate stack** from [Inji Certify Pre-Auth](./inji-certify-preauth.md): distinct
containers, DB, DID, and public host.

---

## 2. The role verifiably plays — **issuer control-plane + wallet owner + DID/metadata proxy**

- **Owns the wallet UI** at `/holder/wallet/inji` — no redirect to the external Inji Web app.
- **Orchestrates the auth-code claim** end to end (PKCE authorize → token via `private_key_jwt`
  → holder-proof JWT → credential request).
- **Is the public issuer.** Certify's `mosip_certify_domain_url` is the public host, so the VC's
  `credential_issuer` + `credentialStatus` URLs are publicly resolvable; the issuer DID is
  `did:web:inji-certify-authcode.<domain>`.
- **Patches did.json.** Certify v0.14 publishes one kid but may sign with another; verifiably's
  `InjiProxyPrimaryDidJSON` (`internal/handlers/inji_proxy.go`) serves a did.json patched with
  every observed signing kid. certify-nginx routes `/.well-known/*` and the credential endpoint
  back through verifiably-go (`inji-proxy`).
- **Provisions claims + identities.** Registrar bulk-enrols into `certify.identity_registry`;
  activation writes `certify.vc_subject`; schema-create writes `certify.credential_config` + the
  eSignet/Certify scope files.

---

## 3. The flows

**A. Issuer creates a schema** (`/issuer/schema/build` → save):
`internal/handlers/inji_schema.go applyAuthcodeSchema` →
`SubjectStore.ApplyAuthcodeSchema` (`internal/storage/pg/subjects.go`) inserts a
`certify.credential_config` row + a per-cred `certify.vc_subject_<slug>` extraction VIEW + a
`vc_credential_owner` row; appends the scope to `certify-postgres-dataprovider.properties`
(scope-query-mapping) and `credential-scopes.properties` (eSignet); restarts `inji-certify` +
`injiweb-esignet`. **`did_url` is derived live** from certify's did.json `id` (`certifyIssuerDID`)
so the signed VC's `proof.verificationMethod` matches the issuer.

**B. Registrar enrols citizens** (`/registrar/identities`, admin-gated):
bulk source (CSV / API / PostgreSQL / Sunbird) → column→field mapping → `runBulkIdentity` →
`SubjectStore.UpsertIdentity` into `certify.identity_registry` (keyed by raw individualId). See
[registries.md](./registries.md).

**C. Holder activates** (`/holder/register`, 2-step, registry-gated):
step 1 individualId → `GetIdentity` (refused if not enrolled) → real email-OTP; step 2 OTP+PIN →
`createMockIdentity` from registry demographics (POST to mock-identity-system) → auto-provision
claims into `certify.vc_subject`. (`internal/handlers/onboard.go`, `otp.go`, `internal/mailer`.)

**D. Holder claims** (`internal/handlers/inji_holder.go`):
1. `GET /holder/wallet/inji/start?cred=<key>` → `StartInjiClaim` builds the eSignet authorize URL
   (PKCE, per-credential scope, `acr_values=mosip:idp:acr:static-code` = PIN login).
2. eSignet PIN login → redirect to `/holder/wallet/inji/callback?code=…`.
3. `InjiClaimCallback` → `POST esignet/oauth/v2/token` (`grant_type=authorization_code`,
   `code_verifier`, `client_assertion` = RS256 JWT signed with `INJI_AUTHCODE_CLIENT_KEY_PEM`).
4. Holder-proof JWT (ES256, ephemeral P-256 `did:jwk`) with `aud` = certify's `credential_issuer`
   (read live from the well-known).
5. `POST certify/issuance/credential` (through certify-nginx → inji-proxy → certify) → signed VC.
6. VC stored on the session (`InjiClaimedVCs`, persisted); shown at
   `/holder/wallet/inji/credentials`.

**E. Download QR-on-PDF** (`GET /holder/wallet/inji/credentials/{id}/pdf`,
`internal/handlers/inji_wallet_pdf.go`): reuses the pre-auth path's PixelPass encoder + gofpdf
(`injicertify.EncodePixelPassQR` / `RenderCredentialPDF`) — a one-page A4 with the claims + a
PixelPass QR scannable by [Inji Verify](./inji-verify.md).

---

## 4. Services (compose)

| Service | Image | Port | Role |
|---|---|---|---|
| `inji-certify` | `injistack/inji-certify-with-plugins:0.14.0` | `8090:8090` | The auth-code Certify issuer. Profiles `default,postgres-dataprovider`. |
| `certify-nginx` | `nginx:1.27` | `8091:80` | Fronts certify; routes `/.well-known/*` + credential endpoint back through verifiably-go (inji-proxy). |
| `certify-postgres` | `postgres:15` | `5433:5432` | DB `inji_certify` (auth-code). |
| `injiweb-esignet` | `mosipid/esignet-with-plugins:1.5.1` | `8088:8088` | OIDC IdP (authorize/token/JWKS). File-based scopes. |
| `injiweb-oidc-ui` | `mosipid/oidc-ui:1.5.1` | `${ESIGNET_PUBLIC_PORT:-3005}:3000` | eSignet's browser login UI (served at `esignet.<domain>`). |
| `injiweb-mock-identity` | `mosipid/mock-identity-system:0.10.1` | `8083:8082` | Identity store eSignet authenticates against. |
| `injiweb-postgres` | `postgres:15` | — | DBs `mosip_mockidentitysystem`, `mosip_esignet`, `inji_mimoto`. |
| `injiweb-redis` | `redis:7.4-alpine` | — | eSignet/mimoto cache. |

(`injiweb-*` services are in the `injiweb` profile; the mimoto / inji-web-ui / datashare / minio
containers belong to the external Inji Web wallet path, not the in-app wallet.)

---

## 5. Environment variables

**verifiably-go** (`scripts/start-container.sh`, `-e` flags):

| Var | Value / source | Meaning |
|---|---|---|
| `INJI_CERTIFY_UPSTREAM_URL` | `http://inji-certify:8090` | Direct upstream for metadata + the credential request (bypasses certify-nginx). |
| `INJI_CERTIFY_DATABASE_URL` | `postgres://postgres:postgres@certify-postgres:5432/inji_certify?sslmode=disable` | Subject/identity/credential_config provisioning. |
| `INJI_AUTHCODE_CLIENT_KEY_PEM` | extracted from `oidckeystore.p12` | RSA key signing the `client_assertion` (private_key_jwt). **Secret.** |
| `INJI_AUTHCODE_CLIENT_ID` | `wallet-demo-client` | OIDC client id (also feeds the PSU-token derivation). |
| `INJI_AUTHCODE_CLIENT_KID` | `wallet-demo-client-kid` | `kid` in the client_assertion header. |
| `INJI_AUTHCODE_SCOPE` | `mock_identity_vc_ldp` | Default scope (overridden per-credential from `credential_config.scope`). |
| `ESIGNET_BASE_URL` | `https://esignet.in-labs.cdpi.dev` | eSignet authorize/token/JWKS base (derived by `url_for esignet`). |
| `SMTP_HOST/PORT/USER/PASSWORD/FROM/FROM_NAME` | `.env` (gitignored) | Real email-OTP for activation. `SMTP_PASSWORD` is a **secret** (Gmail app password). |
| `VERIFIABLY_PUBLIC_URL` | `https://verifiably.in-labs.cdpi.dev` | Callback base for the claim redirect. |

**Certify container** (compose, auth-code instance):

| Var | Value | Meaning |
|---|---|---|
| `active_profile_env` | `default,postgres-dataprovider` | Loads `certify-default.properties` then `certify-postgres-dataprovider.properties`. |
| `CERTIFY_ISSUER_DID` | `did:web:${ISSUER_DID_DOMAIN:-certify-nginx}` | Issuer DID embedded in VCs + did.json id. |
| `mosip_certify_domain_url` | `${AUTHCODE_PUBLIC_URL:-http://certify-nginx:80}` | **PUBLIC** — drives `credential_issuer`, the status-list URL, and `identifier`. |
| `AUTHCODE_ALLOWED_AUD` | `http://certify-nginx:80/v1/certify/issuance/credential` | Pins the `aud` certify's `authn.allowed-audiences` requires (see Gotchas). |

**Derived in `deploy.sh cmd_up`:** `AUTHCODE_PUBLIC_URL` (`url_for inji-certify-authcode`) →
`ISSUER_DID_DOMAIN` (host part). Unset host ⇒ falls back to `certify-nginx` (dev).

---

## 6. Caddy

```caddy
inji-certify-authcode.in-labs.cdpi.dev {
	handle /.well-known/did.json {
		rewrite * /inji-proxy/.well-known/did.json
		reverse_proxy verifiably-go:8080
	}
	reverse_proxy certify-nginx:80
}
```

did.json is served by verifiably-go (patched with observed kids); everything else proxies to
certify-nginx. `esignet.<domain>` → `injiweb-oidc-ui:3000`. **Hairpin:** `caddy-public` aliases
`inji-certify-authcode.<domain>` and `esignet.<domain>` so sibling containers (Inji Verify
resolving the issuer did.json; certify reaching the eSignet JWKS) route internally — **required**,
else external verification of a claimed VC fails with `DidWebPublicKeyResolver: Connection timeout`.

**certify-nginx internals** (`inji/certify-nginx/nginx.conf`): uses `resolver 127.0.0.11` +
variable upstreams (`$certify_backend inji-certify:8090`, `$injiproxy_backend verifiably-go:8080`)
for per-request DNS. `location = /v1/certify/issuance/credential` and
`/.well-known/openid-credential-issuer` proxy to `verifiably-go/inji-proxy/*`; the rest to certify.

---

## 7. Runtime configs

`deploy/compose/stack/inji/certify/`:
- **`certify-default.properties`** (shared with pre-auth). Key line:
  `mosip.certify.authn.allowed-audiences={ '${AUTHCODE_ALLOWED_AUD:${mosip.certify.domain.url}${server.servlet.path}/issuance/credential}' }`
  — reads `AUTHCODE_ALLOWED_AUD` when set (auth-code), else the public `domain.url` (pre-auth).
  Also `mosip.certify.identifier=${mosip.certify.domain.url}`,
  `mosip.certify.data-provider-plugin.did-url=${CERTIFY_ISSUER_DID:…}`.
- **`certify-postgres-dataprovider.properties`** (auth-code only, `postgres-dataprovider` profile).
  `mosip.certify.data-provider-plugin.postgres.scope-query-mapping={ '<scope>':'select … from certify.vc_subject_<slug> where individual_id=:id', … }` — appended per schema.
- **`init-authcode.sql`** seeds `certify.credential_config` (the `VerifiablePersonCredential` row)
  + the extraction views on a fresh volume.

`deploy/compose/stack/inji/esignet/credential-scopes.properties` (file-based, authoritative):
`mosip.esignet.supported.credential.scopes={ '<scope>', … }` and
`mosip.esignet.credential.scope-resource-mapping={ '<scope>':'http://certify-nginx:80/v1/certify/issuance/credential', … }`
— the **internal** aud eSignet stamps into the access token (matches `AUTHCODE_ALLOWED_AUD`).

---

## 8. Databases & APIs

**Database `inji_certify`** (container `certify-postgres`, `certify` schema) — key tables:

| Table | Role |
|---|---|
| `credential_config` | One row per issuable credential (the OID4VCI catalog). `did_url` = the issuer DID. |
| `vc_subject` | Holder claims (`claims` jsonb) keyed by the eSignet subject id. The data-provider reads it via `vc_subject_<slug>` VIEWs. |
| `vc_credential_owner` | Issuer ownership (owner-scopes the schema browser + delete). |
| `identity_registry` | Authoritative enrolled identities (registrar-written; the activation gate). |
| `status_list_credential`, `status_list_available_indices`, `credential_status_transaction`, `ledger` | Revocation status list (BitstringStatusList). Signed under the issuer DID. |
| `key_alias`, `key_store`, `key_policy_def`, `ca_cert_store` | Certify's key manager. |

**verifiably API surface** (auth-code-related): `POST /api/v1/subjects` (provision vc_subject),
`GET /api/registry-credentials`, `GET/POST /holder/register`, `/holder/wallet/inji/*`,
`/registrar/identities/*`, `/issuer/schema/*`. Adapter/handler files: `internal/adapters/injicertify/`
(`adapter.go`, `issuer.go`, `db.go`, `pdf.go`, `pixelpass.go`, `export.go`),
`internal/handlers/` (`inji_holder.go`, `inji_schema.go`, `inji_proxy.go`, `inji_wallet_pdf.go`,
`qr_decode.go`, `onboard.go`, `identity.go`, `otp.go`), `internal/storage/pg/subjects.go`,
`internal/injidid/observed.go`, `internal/mailer`.

---

## 9. Deploy + verify

```bash
ssh colombo 'cd /root/verifiably/verifiably-go && ./deploy.sh up inji'   # cmd_up: derives AUTHCODE_PUBLIC_URL etc.
```

Use `up` (not `run`) when changing certify env/DID/domain — `up` derives the full env and recreates
inji-certify safely. A bare `docker compose up --force-recreate inji-certify` with only `.env`
sourced risks a 133s JWKS hang (unset `ESIGNET_BASE_URL`). To wipe the catalog for a fresh test:
`scripts/reset-authcode-catalog.sh --yes`.

**Smoke (proven e2e):** provision `vc_subject` for a UIN → claim via eSignet PIN
(`e2e/person-claim.mjs`, `e2e/claim-public-check.mjs`) → VC `issuer`/`proof.verificationMethod`/
`credentialStatus` are all the public host → Download PDF → Inji Verify returns SUCCESS.

---

## 10. Gotchas (all live-diagnosed)

- **Public issuer needs the audience decoupled.** Making `mosip_certify_domain_url` public also
  moves `authn.allowed-audiences`, but eSignet issues the access token with the **internal** aud
  (its scope-resource-mapping stays internal) → every claim 401s `invalid_token`. Fix:
  `AUTHCODE_ALLOWED_AUD` pins the validator to the internal endpoint (auth-code only; pre-auth
  keeps the `${domain.url}` default). **Note:** this is `authn.allowed-audiences`, *not*
  `oauth.access-token.audience`.
- **`did_url` must equal the issuer DID.** UI-created creds used to hardcode
  `did:web:certify-nginx`, so a claimed VC's `proof.verificationMethod` was unresolvable →
  INVALID. Now derived live from certify's did.json id.
- **Stale status-list credential.** A status list signed before the DID went public makes
  verification fail (`PublicKeyResolutionFailedException`). Regenerate: clear
  `status_list_credential` / `status_list_available_indices` / `credential_status_transaction` /
  `ledger`, restart certify, re-claim.
- **"selected schema missing" on `/issuer/issue`.** certify-nginx cached a stale verifiably-go IP
  (the `injiproxy` upstream) → 502 on the well-known the schema list reads → the Inji vendor's
  schemas get skipped. Mitigated by the nginx `resolver`+variable upstream (auto-recovers ≤30s)
  and by `start-container.sh` reloading certify-nginx after every verifiably-go (re)start.
- **Never recreate certify with only `.env`.** Use `deploy.sh up`; otherwise `ESIGNET_BASE_URL`
  falls back to a firewalled `:3005` and claiming hangs 133s.

See also: [Inji Certify Pre-Auth](./inji-certify-preauth.md) · [Inji Verify](./inji-verify.md) ·
[registries.md](./registries.md) · [../architecture.md](../architecture.md) · [../deploy.md](../deploy.md).
