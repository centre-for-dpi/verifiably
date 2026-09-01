# Inji Certify (Pre-Auth) — direct-to-PDF implementation guide

> **Version:** Inji Certify **v0.14.0** (`injistack/inji-certify-with-plugins:0.14.0`);
> `inji-preauth-proxy` **v0.1.0** (`adammwaniki/inji-preauth-poc:v0.1.0`, built from
> `cmd/inji-preauth-proxy/`).
> **Adapter type:** `inji_certify_preauth` → `internal/adapters/injicertify`.
> **Role:** issuer only (no holder wallet — the PDF *is* the credential).

The pre-auth path is the "registry-as-record / paper QR" model: an operator enters (or CSV-loads)
claims, verifiably runs the whole OID4VCI **pre-authorized_code** dance server-side, and hands back
a printable PDF whose QR embeds a signed VC. The subject walks away with paper, not a wallet
credential. It is a **completely separate stack** from
[Inji Certify Auth-Code](./inji-certify-authcode.md) — its own containers, DB, DID, and public host,
so the two issuers' keys never cross.

---

## 1. What it is

A second Inji Certify instance running the **`csvdp-farmer`** (CSV/pre-auth data-provider) profile.
Certify itself is its own OAuth authorization server here (it mints the pre-auth token — no
eSignet). verifiably drives it, encodes the resulting VC as a MOSIP PixelPass QR, and renders a
one-page PDF.

Formats: `ldp_vc` (Ed25519Signature2020). `DirectPDF: true`.

---

## 2. The role verifiably plays — **server-side OID4VCI client + PDF renderer**

verifiably runs the entire pre-auth dance in `internal/adapters/injicertify/pdf.go`
(`issueAsPDFPreAuth`) — the subject types nothing and holds no wallet:

1. `POST /v1/certify/pre-authorized-data` (stage the offer with the claims).
2. Extract the pre-authorized code from the offer JSON.
3. `POST /v1/certify/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`)
   → access token + `c_nonce`.
4. Build an **adapter-held** ES256 proof JWT (P-256, header `{typ,alg,jwk}`, **no `kid`/`iss`** per
   OID4VCI §7.2.1.1 anonymous pre-auth; `aud` = the offer's `credential_issuer`).
5. `POST /v1/certify/issuance/credential` → signed VC.
6. `encodePixelPass(vc)` → base45(zlib(CBOR(json))); `renderCredentialPDF` lays out claims + a
   high-recovery QR; bytes stashed on the adapter, served at `GET /issuer/issue/pdf/{id}`.

verifiably also **observes signing kids** (`injidid.Preauth.Remember`) and serves the pre-auth
did.json patched with them, independent of the primary instance.

---

## 3. Services (compose)

| Service | Image | Port | Role |
|---|---|---|---|
| `inji-preauth-proxy` (container `inji-certify-preauth`) | `adammwaniki/inji-preauth-poc:v0.1.0` | `8094:8090` | Transparent proxy at Inji's network identity — see §7. |
| `inji-certify-preauth-backend` | `injistack/inji-certify-with-plugins:0.14.0` | — | The Certify pre-auth issuer. Profile `default,csvdp-farmer`. |
| `certify-preauth-nginx` | `nginx:1.27` | `8095:80` | Fronts the pre-auth backend; routes credential + well-known through verifiably-go (`inji-proxy-preauth`). |
| `certify-preauth-postgres` | `postgres:15` | `5436:5432` | DB `inji_certify` (isolated from the auth-code DB). |

The pre-auth data provider stashes claims in Certify's own cache during the
`pre-authorized-data` POST — it does **not** use `vc_subject` or `identity_registry`.

---

## 4. Environment variables

`inji-certify-preauth-backend` (compose):

| Var | Value | Meaning |
|---|---|---|
| `active_profile_env` | `default,csvdp-farmer` | Loads `certify-default.properties` + `certify-csvdp-farmer-preauth.properties`. |
| `CERTIFY_ISSUER_DID` | `did:web:${PREAUTH_DID_DOMAIN:-${ISSUER_DID_DOMAIN:-certify-preauth-nginx}}` | Pre-auth issuer DID, decoupled from the auth-code instance. |
| `mosip_certify_domain_url` | `${PREAUTH_PUBLIC_URL:-http://inji-certify-preauth:8090}` | Public — so `credential_issuer`/`credential_endpoint` in offers + the DID are externally resolvable. |
| `MOSIP_CERTIFY_AUTHN_JWK_SET_URI` | `${PREAUTH_JWKS_URI:-http://inji-certify-preauth:8090/…/jwks.json}` | JWKS stays **internal** (cluster-local). |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://certify-preauth-postgres:5432/inji_certify` | Isolated DB. |

**Derived in `deploy.sh cmd_up`:** `PREAUTH_PUBLIC_URL` (`url_for inji-certify-preauth`, port 8094)
→ `PREAUTH_DID_DOMAIN` (host part). Unset host ⇒ `certify-preauth-nginx` (dev). These are
**deliberately separate** from `AUTHCODE_PUBLIC_URL`/`ISSUER_DID_DOMAIN` — re-pointing the shared
var would move the auth-code issuer onto the pre-auth did.json (which carries only the pre-auth
key) and break auth-code verification.

**Adapter config** (`backends.json`): `baseUrl` / `publicBaseUrl` =
`https://inji-certify-preauth.in-labs.cdpi.dev`, `internalBaseUrl` / `offerIssuerUrl` =
`http://inji-certify-preauth:8090`.

---

## 5. Caddy

```caddy
inji-certify-preauth.in-labs.cdpi.dev {
	reverse_proxy certify-preauth-nginx:80
}
```

A plain reverse proxy — no did.json interception here (the pre-auth instance's did.json is served
through its own nginx → verifiably-go `inji-proxy-preauth`). **Hairpin:** `caddy-public` aliases
`inji-certify-preauth.<domain>` so the wallet-api (walt.id) can resolve a pre-auth
`credential_offer_uri` whose host is the public pre-auth name without hairpinning the box IP.

---

## 6. Runtime configs

- `deploy/compose/stack/inji/certify/certify-default.properties` — shared with auth-code; the
  pre-auth instance leaves `AUTHCODE_ALLOWED_AUD` unset, so `authn.allowed-audiences` keeps the
  `${mosip.certify.domain.url}` default (certify's own token, aud = its public host).
- `deploy/compose/stack/inji/certify/certify-csvdp-farmer-preauth.properties` — the pre-auth /
  CSV data-provider plugin config.
- `deploy/compose/stack/inji/certify-preauth-nginx/nginx.conf` — same resolver+variable pattern as
  certify-nginx; routes the credential endpoint + well-known through
  `verifiably-go/inji-proxy-preauth/*`.
- `deploy/compose/stack/inji/certify/init-preauth.sql` + `init-preauth.sh` — seed the isolated DB.

---

## 7. The `inji-preauth-proxy` (why it exists)

Strict OID4VCI wallets (walt.id, Sphereon) follow the issuer identifier verbatim. Inji advertises
`credential_issuer: http://inji-certify-preauth:8090` but serves metadata under
`/v1/certify/issuance/.well-known/…`, not at the root — so strict wallets 404. The proxy
(`cmd/inji-preauth-proxy/main.go`) sits at Inji's network identity and:
1. answers `GET /.well-known/openid-credential-issuer` at the root, proxying to Inji's real
   metadata URL and rewriting the payload (strips null optionals, empty `credential_definition`,
   walt.id-incompatible `display`) so strict JSON parsers accept it;
2. forwards the credential request through.

This is what let **SD-JWT → an external Credo mobile wallet** work for pre-auth; walt.id's own
holder cannot claim pre-auth (v0.18.2 emits a non-conformant proof) — use an external wallet + PDF.

---

## 8. Databases & APIs

**Database `inji_certify`** on `certify-preauth-postgres` (isolated). Uses `credential_config`
(custom schemas created via the issuer builder); **not** `vc_subject`/`identity_registry` (the
pre-auth data-provider caches claims itself).

**Upstream API (via the proxy/nginx):** `/v1/certify/pre-authorized-data`,
`/v1/certify/oauth/token`, `/v1/certify/issuance/credential`,
`/v1/certify/issuance/.well-known/openid-credential-issuer`.
**verifiably surface:** `POST /issuer/issue` (mode = "As a PDF"), `GET /issuer/issue/pdf/{id}`,
plus the delegated-access pre-auth APIs `/api/v1/delegation/inji/preauth/{issue,claim}`.
**Adapter files:** `internal/adapters/injicertify/pdf.go`, `pixelpass.go`, `export.go`;
`internal/handlers/pdf_download.go`; `internal/injidid/observed.go` (`Preauth`).

---

## 9. mso_mdoc (mDL / Photo ID) issuance

Since 2026-08-25, this instance also issues **mso_mdoc** (ISO/IEC 18013-5 mDL and
ISO/IEC 23220-1 Photo ID) — a second, independent production emitter alongside
walt.id/issuer-api2 (see [`../deploy.md`](../deploy.md#mdl-mdoc-issuance-issuer-api2)
for that path). Same "verifiably mediates, the DPG issues" rule applies: Inji
Certify holds the signing key and produces the CBOR/COSE structure; verifiably-go
only builds the request and translates shapes.

**How an operator gets here:** create a custom schema in the issuer builder with
Std = `mso_mdoc` while the active DPG is this Pre-Auth instance — no separate UI
path, the same builder used for every other format. `saveMdocSchema`
(`internal/adapters/injicertify/db.go`) writes a real `credential_config` row;
`driving_privileges` is validated for docType count (1–4 categories, mDL only —
`internal/adapters/injicertify/issuer.go`, gated on `ModePreAuth` AND the
resolved docType being `mdoc.MDLDocType` specifically, so Photo ID — which has no
`driving_privileges` element — is never wrongly rejected).

**What makes this different from the SD-JWT/LDP paths above:** claims must be
nested under the docType's real ISO namespace before the Velocity template
substitutes them (`org.iso.18013.5.1` for mDL, `org.iso.23220.1` for Photo ID —
resolved via `mdoc.NamespaceForDocType`, the same allowlist walt.id/issuer2.go
uses, NOT derived by string-stripping the docType), and `driving_privileges`
rides as a raw, unquoted JSON array marker in the template so Velocity's
`toJsonMap` produces a real CBOR array rather than a quoted string.

**Known limitation (upstream, not fixable here):** Inji Certify's own mdoc
conversion does not bstr-encode `portrait` correctly — it stays a text string
where ISO 18013-5 requires a CBOR byte string. This is a defect in Inji
Certify's `MDocProcessor` bytecode itself, confirmed against the shipped image
(not something any config in this repo controls); mitigated on the reader side
in `cdpi-wallet`, not here.

**Trust anchor:** this instance's mock-HSM signs with a self-signed root
distinct from both walt.id's IACA and the Auth-Code instance's own root —
`GET /trust/mdoc-anchors` (proxied per-instance the same way `.well-known/did.json`
is, see §5) serves all of them so a wallet resolving from any of this
deployment's mso_mdoc origins gets the right anchor. Extracted automatically on
deploy by `provision_inji_root_anchors` (`deploy.sh`) — no manual step.

---

## 10. Deploy + verify

```bash
ssh colombo 'cd /root/verifiably/verifiably-go && ./deploy.sh up inji'   # brings up both certify instances
```

`inji-preauth-proxy` is built from source on first `up` (image `adammwaniki/inji-preauth-poc:v0.1.0`).
**Smoke:** `/issuer/issue` with an Inji Pre-Auth DPG + "As a PDF" → a PDF downloads; rasterize the
QR and upload to [Inji Verify](./inji-verify.md) → SUCCESS.

---

## 11. Gotchas

- **Keep it separate from auth-code.** Distinct DB (`certify-preauth-postgres`), DID
  (`did:web:inji-certify-preauth.<domain>`), and did.json (only the pre-auth key). Never point
  `ISSUER_DID_DOMAIN` at the pre-auth host.
- **JWKS is internal on purpose.** `MOSIP_CERTIFY_AUTHN_JWK_SET_URI` stays cluster-local; only the
  domain_url (issuer/offer URLs) goes public.
- **walt.id holder can't claim pre-auth.** v0.18.2 emits a non-conformant proof (kid+jwk) and
  `PUT /credentials` is NotImplemented — use an external wallet + SD-JWT, or the PDF path.

See also: [Inji Certify Auth-Code](./inji-certify-authcode.md) · [Inji Verify](./inji-verify.md) ·
[../architecture.md](../architecture.md) · [../deploy.md](../deploy.md).
