# Inji Verify — implementation guide

> **Version:** Inji Verify **v0.16.0** (`mosipid/inji-verify-service:0.16.0`,
> `mosipid/inji-verify-ui:0.16.0`).
> **Adapter type:** `inji_verify` → `internal/adapters/injiverify`.
> **Role:** verifier only.

Inji Verify is the DPG verifiably uses for **direct** credential verification (paste / scan / QR
upload) and MOSIP-style **OID4VP** presentation requests. It is the verifier behind
`/verifier/verify` when the Inji Verify DPG is selected.

---

## 1. What it is

Two containers + a Postgres:

| Service | Image | Port | Role |
|---|---|---|---|
| `inji-verify-service` | `mosipid/inji-verify-service:0.16.0` | `8082:8080` | The REST verify **backend** (`/v1/verify/*`). |
| `inji-verify-ui` | `mosipid/inji-verify-ui:0.16.0` | `3001:8000` | The browser **UI** (scan/upload). |
| `inji-verify-postgres` | `postgres:13` | `5434:5432` | DB `inji_verify` (schema `verify`). |

> **Host trap:** `inji-verify.<domain>` is the **backend** (`/` returns a Tomcat 404); the **UI**
> lives at `inji-verify-ui.<domain>`. Point browser flows at the UI host.

Formats it verifies: `ldp_vc` (JSON-LD, Data Integrity) and `vc+sd-jwt`.

---

## 2. The role verifiably plays — **OID4VP request builder + result adjudicator**

- **Builds the Presentation Definition** from a schema/template (`RequestPresentation`) and creates
  the OID4VP session via `POST /v1/verify/vp-request`, then renders the `openid4vp://` QR.
- **Polls + adjudicates** the result (`FetchPresentationResult`), applying the **INJIVER-1131
  guard**: even if the service reports `SUCCESS`, verifiably re-checks that at least one returned
  VC actually carries a claim matching the requested template fields — otherwise it demotes the
  verdict to invalid. (Upstream cross-device OID4VP can report success for a wrong VC.)
- **Direct verification** (`VerifyDirect`) for paste/scan/upload: dispatches by format —
  **JSON-LD → `/v1/verify/vc-verification`** (synchronous), **JWT/SD-JWT → `/v1/verify/vc-submission`**
  (returns a `transactionId`, then poll `/v1/verify/vp-result/{txid}`).
- **Decodes PixelPass QR uploads** before verifying: an uploaded QR from a wallet PDF carries the
  VC as base45(zlib(CBOR(json))), not the VC itself. `decodeUploadedQR`
  (`internal/handlers/qr_decode.go`) PixelPass-decodes it (via `injicertify.DecodePixelPassQR`) so a
  JSON-LD VC routes to the working `vc-verification` endpoint.

---

## 3. The flows

**Direct verify (paste/scan/upload):** `POST /verifier/verify/direct` → `decodeUploadedQR`
(PixelPass-decode if applicable) → `VerifyDirect`:
- JSON-LD VC → `POST /v1/verify/vc-verification` (Content-Type `application/ld+json`) →
  `{ "verificationStatus": "SUCCESS" | "INVALID" }`.
- JWT/SD-JWT VC → `POST /v1/verify/vc-submission` → `transactionId` → poll
  `GET /v1/verify/vp-result/{txid}`.

**OID4VP presentation:** template → PD → `POST /v1/verify/vp-request` → render QR
(`openid4vp://…?request_uri=…`) → wallet responds → poll `GET /v1/verify/vp-result/{txid}` →
INJIVER-1131 guard → verdict card.

---

## 4. Environment variables

**`inji-verify-service`** (compose) — Spring env, no file-based config:

| Var | Value | Meaning |
|---|---|---|
| `DATABASE_HOST/NAME/SCHEMA/USERNAME/PASSWORD` | `inji-verify-postgres` / `inji_verify` / `verify` / `postgres` / `postgres` | Backend DB. |
| `INJI_VP_SUBMISSION_BASE_URL` | `https://inji-verify.in-labs.cdpi.dev` | Base URL in VP-submission + status responses. |
| `INJI_DID_VERIFY_URI` | `did:web:inji-verify.in-labs.cdpi.dev:v1:verify` | The verifier's DID (OID4VP `client_id`). |
| `INJI_DID_VERIFY_PUBLIC_KEY_URI` | `…/v1/verify/.well-known/did.json#key-0` | Verifier public-key ref. |

The service also imports the certify + certify-preauth self-signed certs into the Java trust store
at startup (via `keytool`) so its did:web resolver can fetch those DID documents over HTTPS.
`INJI_VP_SUBMISSION_BASE_URL` / `INJI_DID_VERIFY_*` are derived by `deploy.sh cmd_up`
(`url_for inji-verify`).

**Adapter config** (`backends.json`): `baseUrl=https://inji-verify.in-labs.cdpi.dev`,
`internalBaseUrl=http://inji-verify-service:8080` (used for all server-to-server calls),
`clientId=did:web:inji-verify.in-labs.cdpi.dev:v1:verify`.

---

## 5. Caddy

```caddy
inji-verify.in-labs.cdpi.dev {
	handle /v1/verify/.well-known/did.json {
		header Content-Type "application/did+ld+json"
		header Access-Control-Allow-Origin "*"
		respond `{"@context": [...], "id": "did:web:inji-verify.in-labs.cdpi.dev:v1:verify",
		         "verificationMethod": [{ "type": "Ed25519VerificationKey2020",
		           "publicKeyMultibase": "z6Mkkzru…" }], "authentication": [...]}` 200
	}
	reverse_proxy inji-verify-service:8080
}

inji-verify-ui.in-labs.cdpi.dev {
	reverse_proxy inji-verify-ui:8000
}
```

The verifier's own did:web document is a static Caddy `respond`. **Status-list hairpin:** to verify
an auth-code VC's revocation status, `inji-verify-service` must fetch
`https://inji-certify-authcode.<domain>/…/status-list/…` and resolve the issuer did.json — this
works only because `caddy-public` aliases `inji-certify-authcode.<domain>` (see
[inji-certify-authcode.md](./inji-certify-authcode.md) §6).

---

## 6. Databases & APIs

**Database `inji_verify`** (`verify` schema). verify-service 0.16.0 runs
`spring.jpa.hibernate.ddl-auto=none` and ships **no Flyway/Liquibase migrations**, so the
`verify` schema must be created out-of-band. We provision it from the canonical
mosip/inji-verify v0.16.0 DDL, committed at **`deploy/compose/stack/inji/verify/init.sql`**
(schema `verify` + four tables: `authorization_request_details`, `presentation_definition`,
`vp_submission`, `vc_submission`). It is **mounted into `inji-verify-postgres`'s
`/docker-entrypoint-initdb.d`** (runs on a fresh volume) and **applied idempotently by
`deploy.sh` (`apply_inji_verify_schema`, gated `all|inji`)** for existing volumes.
Without it, the stateful `vc-submission` and **OID4VP `vp-request`/`vp-submission`** paths 500
(`relation "authorization_request_details" does not exist`); only the stateless
`vc-verification` (JSON-LD paste/upload) path works. With the schema present, cross-device
OID4VP online-sharing (external wallet presents an SD-JWT → `vp-result` `SUCCESS`) works.

Two more requirements for cross-device OID4VP to reach an external wallet:
- The `inji_verify` backend's **`config.baseUrl` must stay PUBLIC** (it is the wallet-facing
  `request_uri` host). `scripts/start-container.sh`'s docker-config rewriter preserves it
  (`type == "inji_verify"` skips `baseUrl`); only `internalBaseUrl` is rewritten to the
  docker-internal host.
- The service entrypoint imports `certify-nginx.crt` + `certify-preauth-nginx.crt` into the JVM
  `cacerts` so its did:web issuer resolver can fetch the Inji issuer's DID doc over TLS.

**Upstream API (verifiably → service):** `POST /v1/verify/vc-verification`,
`POST /v1/verify/vc-submission`, `GET /v1/verify/vp-result/{txid}`, `POST /v1/verify/vp-request`,
`GET /v1/verify/vp-request/{id}/status`.
**verifiably surface:** `/verifier/verify`, `POST /verifier/verify/direct`,
`POST /verifier/verify/request`, `POST /verifier/verify/response`.
**Adapter files:** `internal/adapters/injiverify/` (`config.go`, `adapter.go`, `normalize.go`),
`internal/handlers/verifier.go`, `internal/handlers/qr_decode.go`.

---

## 7. Deploy + verify

```bash
ssh colombo 'cd /root/verifiably/verifiably-go && ./deploy.sh up inji'
```

**Smoke (proven live):** upload a wallet QR-on-PDF's QR to `inji-verify-ui.<domain>` (or POST it to
`/verifier/verify/direct`) → `{"verificationStatus":"SUCCESS"}`. Scripts: `e2e/inji-verdict.mjs`,
`e2e/inji-verify-mine.mjs`, `e2e/verifier-qr-direct.mjs`.

---

## 8. Gotchas (live-diagnosed)

- **Uploaded QR must be PixelPass-decoded.** Before the fix, `decodeUploadedQR` returned the raw
  base45 payload, so the adapter treated it as non-JSON-LD and routed to `vc-submission` → 500
  (`relation "vc_submission" does not exist`). Now it decodes to the VC and routes JSON-LD to
  `vc-verification`.
- **QR crops need a quiet zone.** A too-tight crop makes Inji Verify report "No QRCode found";
  keep a white margin around the QR.
- **`STATUS_RETRIEVAL_ERROR … certify-nginx: Name does not resolve`** = the VC's status-list URL is
  internal, or certify-nginx was mid-restart. The fix is the public auth-code issuer + the
  `inji-certify-authcode` caddy alias (see the auth-code guide).
- **`DidWebPublicKeyResolver: Connection timeout`** = the service can't hairpin to the public issuer
  host — requires the caddy-public alias for that host.
- **UI vs backend host** — `inji-verify.<domain>` 404s in a browser; use `inji-verify-ui.<domain>`.

See also: [Inji Certify Auth-Code](./inji-certify-authcode.md) ·
[Inji Certify Pre-Auth](./inji-certify-preauth.md) · [../architecture.md](../architecture.md) ·
[../integration.md](../integration.md).
