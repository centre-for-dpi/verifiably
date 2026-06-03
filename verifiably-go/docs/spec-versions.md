# Spec versions implemented by each adapter

> Last updated: 2026-05-16.  
> **Purpose:** reference for deciding whether an upstream change can break wire-format compatibility.  
> Update this table on every CREDEBL / walt.id / Inji version bump.

---

## Quick-reference table

| Adapter | Component version | Protocol | Role | Spec / draft | Credential format |
|---|---|---|---|---|---|
| CREDEBL | v1.x (Credo-TS 0.5.x) | OID4VCI | Issuer | OpenID for Verifiable Credential Issuance draft-13 (pre-authorized code flow only) | `dc+sd-jwt` / `vc+sd-jwt` (SD-JWT VC) |
| CREDEBL | v1.x (Credo-TS 0.5.x) | OID4VP | Verifier | OpenID for Verifiable Presentations draft-20 (cross-device; DCQL query) | `dc+sd-jwt` / `vc+sd-jwt` |
| walt.id | Community Stack v0.18.2 | OID4VCI | Issuer | OpenID for Verifiable Credential Issuance draft-13 (pre-authorized + authorization code) | `jwt_vc_json`, `vc+sd-jwt`, `mso_mdoc` |
| walt.id | Community Stack v0.18.2 | OID4VP | Verifier | OpenID for Verifiable Presentations draft-18 (Presentation Exchange 2.0 path) | `jwt_vc_json`, `vc+sd-jwt` |
| Inji Certify | v0.14.0 | OID4VCI | Issuer | OpenID for Verifiable Credential Issuance draft-13 (pre-authorized + authorization code) | `ldp_vc` (Ed25519Signature2020), `vc+sd-jwt` |
| Inji Verify | v0.16.0 | OID4VP | Verifier | OpenID for Verifiable Presentations draft-20 (cross-device QR) | `ldp_vc`, `vc+sd-jwt` |
| Inji Web | v0.16.0 | OID4VCI (holder) | Wallet | OpenID for Verifiable Credential Issuance draft-13 (authorization code, Mimoto-mediated) | `ldp_vc`, `vc+sd-jwt` |

---

## Credential format names

| Wire name | Standard | Notes |
|---|---|---|
| `dc+sd-jwt` | IETF SD-JWT VC draft-05+ | Newer MIME type; preferred by CREDEBL ≥ v1. |
| `vc+sd-jwt` | IETF SD-JWT VC draft-01–04 | Older MIME type; still accepted by both CREDEBL and walt.id adapters. |
| `jwt_vc_json` | W3C VCDM 1.1 + JWT | Primary format for walt.id → walt.id round-trips. |
| `jwt_vc_json-ld` | W3C VCDM 1.1 + JWT-LD | Walt.id can issue; no tested wallet claim/present pipeline. |
| `ldp_vc` | W3C VCDM 1.1 / 2.0 + Data Integrity | Ed25519Signature2020; Inji Certify. LDP verify broken in Mimoto v0.16.0 (vc-verifier canonicalization bug). |
| `mso_mdoc` | ISO 18013-5 | Walt.id can issue; Inji Certify is mock-only at v0.14.0. No verifier adapter in this stack. |

---

## CREDEBL adapter

**Source files:** `internal/adapters/credebl/`  
**Backend version:** CREDEBL v1.x, Credo-TS (AnonCreds + SD-JWT) 0.5.x

### OID4VCI — Issuer

| Item | Value |
|---|---|
| Flow | Pre-authorized code only |
| Offer endpoint | `POST /v1/orgs/{orgId}/oid4vc/{issuerId}/create-offer` |
| Template endpoint | `GET /v1/orgs/{orgId}/oid4vc/{issuerId}/template` |
| Grant type | `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| Credential format | `dc+sd-jwt` (adapter also accepts `vc+sd-jwt` as alias) |
| Spec draft | OID4VCI draft-13 |

**Notes:**  
- Authorization code flow is not implemented — CREDEBL's issuer API creates offers directly without an authorization server round-trip.  
- The offer URI scheme is `openid-credential-offer://`; the host portion is rewritten by the adapter from the Docker-internal address to `CREDEBL_PUBLIC_URL` so wallets can reach it from outside the container network.

### OID4VP — Verifier

| Item | Value |
|---|---|
| Query language | DCQL (Digital Credentials Query Language) |
| Request endpoint | `POST /v1/orgs/{orgId}/oid4vp/presentation?verifierId={id}` |
| Result endpoint | `GET /v1/orgs/{orgId}/oid4vp/verifier-presentation?id={state}` |
| Presentation format | `dc+sd-jwt` |
| Spec draft | OID4VP draft-20 + DCQL |
| `vp_token` wire formats | Array-of-objects `{"credentials":{"vc-1":"<compact-sd-jwt>"}}` (Credo ≥ 0.5) or bare string (older Credo) — both handled in `extractDisclosedFieldsFromVpToken` |

**Notes:**  
- No direct-verify endpoint; all verification goes through the OID4VP cross-device flow.  
- A verifier is auto-provisioned on first use when `VerifierID` is absent from `backends.json`.

---

## walt.id adapter

**Source files:** `internal/adapters/waltid/`  
**Backend version:** Community Stack v0.18.2 (`issuer-api`, `wallet-api`, `verifier-api`, `web-portal`)

### OID4VCI — Issuer

| Item | Value |
|---|---|
| Flows | Pre-authorized code + authorization code |
| Credential formats | `jwt_vc_json`, `vc+sd-jwt` (tested E2E); `jwt_vc_json-ld`, `ldp_vc` (issuer-only — no wallet claim pipeline) |
| Spec draft | OID4VCI draft-13 |
| Credential offer scheme | `openid-credential-offer://` |

**Format selection logic:**  
`formatRank` in `internal/adapters/waltid/catalog.go` prefers `jwt_vc_json` for W3C VCDM schemas and `vc+sd-jwt` for SD-JWT schemas, matching walt.id's own E2E test fixtures. The catalog deduplicates by `(Name, Std)` to avoid presenting duplicate credentials to the wallet.

### OID4VP — Verifier

| Item | Value |
|---|---|
| Query language | Presentation Exchange 2.0 (`presentation_definition`) |
| Spec draft | OID4VP draft-18 (PE 2.0 path — `/openid4vc/v1/*` endpoints not yet used) |
| Tested format pairs | `jwt_vc_json` + `type` field in PD; `vc+sd-jwt` + `vct` field in PD |

**Notes:**  
- OID4VP v1.0 (`/openid4vc/v1/*`) endpoints are landing in v0.18.x; the adapter has not been migrated yet.  
- Format/type mismatch between issued credential and PD causes a Kotlin `JsonArray is not a JsonPrimitive` 400 error in the wallet. The adapter's `buildRequestCredentials` function avoids this by matching the PD's field key (`type` vs `vct`) to the credential's format.

---

## Inji Certify adapter

**Source files:** `internal/adapters/injicertify/`  
**Backend version:** v0.14.0

### OID4VCI — Issuer

| Item | Value |
|---|---|
| Flows | Pre-authorized code (demo/staging) + authorization code (production via eSignet) |
| Credential formats | `ldp_vc` (Ed25519Signature2020, W3C VCDM 2.0), `vc+sd-jwt` |
| Signing | Ed25519; keys managed by MOSIP keymanagerservice |
| Spec draft | OID4VCI draft-13 |

**Known compatibility gaps:**  
- `ldp_vc` verify round-trip broken in Inji Web v0.16.0 (Mimoto ships vc-verifier with URDNA2015 canonicalization bug; see [dpg-matrix.md § Inji Web](dpg-matrix.md#inji-web-wallet-v0160)).  
- `mso_mdoc` is mock-only at v0.14.0.  
- Tested matrix per MOSIP: Inji Certify v0.14.0 ↔ Inji Web v0.17.0 (we run v0.16.0).

---

## Inji Verify adapter

**Source files:** `internal/adapters/injiverify/`  
**Backend version:** v0.16.0

### OID4VP — Verifier

| Item | Value |
|---|---|
| Flow | Cross-device QR (Inji Verify SPA + `inji-verify-service`) |
| Submission endpoint | `POST /vc-submission` |
| Result endpoint | `GET /vp-result/{transactionId}` |
| Direct upload | `POST /v1/verify/vc-verification` (JSON-LD VCs) |
| Credential formats | `ldp_vc`, `vc+sd-jwt` |
| Spec draft | OID4VP draft-20 |

**Caveats:**  
- INJIVER-1131: Inji Verify v0.16.0 may return SUCCESS for a VP that doesn't satisfy all requested fields. The adapter re-validates disclosed claims against the requested field set and downgrades the verdict if there is a mismatch.  
- Tested matrix per MOSIP: Inji Verify v0.16.0 ↔ Inji Certify v0.13.1 (we run v0.14.0).

---

## SD-JWT VC spec reference

Both CREDEBL and walt.id implement **IETF SD-JWT VC** (Selective Disclosure for JWTs):

- **Active draft**: `draft-ietf-oauth-sd-jwt-vc-05` (as of 2025-Q4)
- **Key fields**: `vct` (credential type URI), `_sd` (selective disclosures), `~` separator in compact serialization
- **Compact serialization**: `<issuer-jwt>~<disclosure-1>~...~[<kb-jwt>]`

The `extractDisclosedFieldsFromVpToken` function in `internal/adapters/credebl/verifier.go` handles both:
- **Array format** (Credo-TS ≥ 0.5): `{"credentials":{"vc-1":"<compact-sd-jwt>"}}`
- **String format** (older Credo-TS): bare compact SD-JWT string

---

## How to update this file

1. **On a CREDEBL version bump**: check the Credo-TS release notes for OID4VCI/OID4VP draft changes; update the draft number and `vp_token` format table if the wire format changes.
2. **On a walt.id Community Stack bump**: check the `waltid-services` changelog for PE version changes or new `/openid4vc/v1/*` endpoints; update the OID4VP draft row and the format-selection notes.
3. **On an Inji bump**: cross-reference against MOSIP's tested-compatibility matrix in the release notes; update the version column and the known-gaps section.
