# OID4VC High Assurance Interoperability Profile (HAIP) — Conformance Audit

**Spec:** [openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)  
**Audited:** 2026-05-16 (original audit, against walt.id 0.18.2)  
**Gap 1 re-audited:** 2026-08-24 (see note below) — the other findings below have
**not** been re-audited and may also be stale; only Gap 1 was checked.  
**Scope:** verifiably-go as orchestrator (not issuer/verifier DPG); walt.id
0.23.1 is the version actually deployed today (`deploy/compose/stack/docker-compose.yml`).

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Conformant |
| ⚠️ | Partial / conditional |
| ❌ | Gap — action required |
| N/A | Not applicable to this component |

---

## 1. Credential Format

| Requirement | Status | Notes |
|-------------|--------|-------|
| SD-JWT VC (`vc+sd-jwt`) MUST be supported | ✅ | wired via `sd_jwt_vc (IETF)` in schema catalog |
| mdoc (`mso_mdoc`) SHOULD be supported | ⚠️ | format recognized, no revocation support |
| W3C VCDM 2.0 (`ldp_vc`) is out of scope for HAIP | N/A | still supported for non-HAIP flows |

---

## 2. Issuance (OID4VCI)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Authorization Code Flow | ✅ | delegated to walt.id |
| Pre-authorized Code Flow | ✅ | used in single / bulk issuance |
| `credential_offer` URI via QR | ✅ | `offerURI` returned and surfaced to operator |
| `issuer_state` binding | ✅ | handled by walt.id |
| Proof-of-possession (DPoP / key-binding) | ⚠️ | enforced by walt.id; verifiably-go doesn't inspect proof |
| Issuer metadata at `/.well-known/openid-credential-issuer` | ⚠️ | served by walt.id; verifiably-go proxies the offer, not the metadata |
| `credential_identifier` in offer | ✅ | schema-id mapped to credential config |
| Batch issuance (`/batch_credential`) | ⚠️ | bulk.go issues N single credentials; no true batch endpoint |
| Display metadata for credentials | ⚠️ | SchemaName propagated; `display` array not surfaced |

---

## 3. Presentation (OID4VP)

| Requirement | Status | Notes |
|-------------|--------|-------|
| `vp_token` returned via `response_mode=direct_post` | ✅ | verified in `internal/adapters/waltid/verifier.go` |
| `response_mode=direct_post.jwt` (HAIP REQUIRED) | ❌ | **Gap moved, not closed** (re-verified 2026-08-24): walt.id `verifier-api:0.23.1` genuinely implements JARM — a live `POST /openid4vc/verify` with `responseMode: direct_post.jwt` returns a real encrypted request (`client_metadata.jwks.keys[0]` EC P-256 `use:enc`/`alg:ECDH-ES`, `authorization_encrypted_response_enc:"A256GCM"`), confirmed via a real container, not source reading. But `internal/adapters/waltid/verifier.go`'s `verifyBody` struct has no `response_mode`/`responseMode` field at all (grepped — zero matches) and never sends one, so **verifiably-go doesn't request it even though the backend can now serve it**. The gap is in this repo's adapter code, not in walt.id. |
| `client_id_scheme=x509_san_dns` (HAIP REQUIRED) | ❌ | **Gap**: walt.id uses `redirect_uri` as `client_id`; x509 cert not provisioned |
| `client_id_scheme=did` | ✅ | current default in walt.id |
| Presentation exchange (DIF PE) | ✅ | `presentation_definition` wired via OID4VP template |
| `nonce` freshness | ✅ | session state enforces one-time use |
| SD-JWT selective disclosure | ✅ | disclosed fields extracted and stored in `DisclosedFields` |
| `vp_token` as SD-JWT (not LD-Proof) | ✅ | verified by regression tests in `vp_token_regression_test.go` |

---

## 4. Key Binding & Wallet Attestation

| Requirement | Status | Notes |
|-------------|--------|-------|
| `wallet_attestation` JWT in token request | ❌ | **Gap**: HAIP §6 requires wallets to present a wallet attestation signed by the wallet provider; not enforced in verifiably-go (would require verifier-side attestation validation) |
| Holder key binding proof (`cnf` claim) | ⚠️ | enforced by walt.id wallet-api; verifiably-go doesn't verify `cnf` independently |
| Key binding JWT (`kb-jwt`) over `vp_token` | ⚠️ | present in SD-JWT VC wire format; verifiably-go extracts claims without re-verifying `kb-jwt` signature |

---

## 5. Security

| Requirement | Status | Notes |
|-------------|--------|-------|
| TLS for all endpoints (HAIP §4.1) | ✅ | enforced by Caddy in subdomain mode; localhost mode exempt per spec |
| Authorization Code PKCE | ✅ | `PendingPKCE` stored in session, passed through OIDC flow |
| DPoP token binding (HAIP RECOMMENDED) | ⚠️ | not enforced by verifiably-go; delegated to walt.id |
| `iss` claim validation in responses | ⚠️ | verified by walt.id; verifiably-go trusts the adapter's success/error |
| Status list revocation (HAIP §7.2) | ✅ | W3C BSL 2023 + IETF Token Status List both implemented |
| Credential expiry (`exp` claim) | ⚠️ | set by walt.id; not enforced by verifiably-go on fetch |

---

## 6. Identified Gaps — Priority Order

### ❌ Gap 1: `response_mode=direct_post.jwt` (JARM)
**Requirement:** HAIP §5.5 — response MUST be JWT-encrypted to the verifier's public key.  
**Current state (re-verified 2026-08-24 against a real `waltid/verifier-api:0.23.1`
container):** the walt.id upstream support this gap used to be blocked on **now
exists** — `POST /openid4vc/verify` with `responseMode: direct_post.jwt` returns
a genuinely JARM-encrypted authorization request (real `jwks.keys`, ECDH-ES /
A256GCM). But `verifiably-go` itself never asks for it:
`internal/adapters/waltid/verifier.go`'s `verifyBody` struct has no
`response_mode` field, so every request this repo sends still gets plain
`direct_post`. The gap moved from "walt.id doesn't support this" to "this
repo's adapter doesn't request it."  
**Risk:** Credential claims in transit are visible to redirect intermediaries.  
**Fix path:**
1. Add a `ResponseMode string \`json:"responseMode,omitempty"\`` (or the exact
   casing walt.id's `VerifierApi.kt` expects — confirm against a live call
   before shipping, don't assume the casing matches the OID4VP spec's
   snake_case) field to `verifyBody` in `internal/adapters/waltid/verifier.go`,
   set to `"direct_post.jwt"`.
2. Provision the verifier's encryption key and confirm it's the one walt.id
   echoes back in `client_metadata.jwks` (it was auto-generated in the
   container tested here — confirm whether that's stable across restarts or
   needs explicit provisioning for a real deployment).
3. Update the OID4VP consumer side (any wallet this ecosystem talks to) to
   decrypt a JARM response — this is no longer walt.id-blocked, so it's the
   next real blocker once the adapter change above ships.

**Effort:** S–M — no longer blocked on walt.id; is now a real, scoped adapter
change plus wallet-side decrypt support.

### ❌ Gap 2: `client_id_scheme=x509_san_dns`
**Requirement:** HAIP §4.3 — verifiers in high-assurance flows MUST authenticate with an X.509 certificate whose SAN DNS matches the client_id.  
**Current state:** `client_id` is the verifier's `redirect_uri` (scheme `redirect_uri`).  
**Risk:** Wallet cannot distinguish a legitimate verifier from a phishing site without a certificate.  
**Fix path:**
1. Issue a TLS certificate for the verifier subdomain (already done via Caddy/Let's Encrypt in subdomain mode).
2. Configure walt.id verifier-api `client_id_scheme = "x509_san_dns"` and point to the cert.
3. verifiably-go passes `client_id` through the `OID4VPTemplate`; add `ClientIDScheme` field to the template type.

**Effort:** M — config change in walt.id + schema extension in verifiably-go.

### ❌ Gap 3: `wallet_attestation`
**Requirement:** HAIP §6 — issuer MUST validate wallet attestation JWT before issuing.  
**Current state:** attestation not required or validated.  
**Risk:** Any OAuth client that has the authorization code can impersonate a conformant wallet.  
**Fix path:**
1. Add `wallet_attestation` validation to the issuance flow in `APIIssue` / walt.id adapter.
2. Trust anchor (wallet provider public key) must be fetched from a trusted registry or pinned.

**Effort:** L–XL (depends on whether a public wallet attestation registry exists for the target wallets).

---

## 7. What's Already HAIP-Compliant

- SD-JWT VC credential format end-to-end (issue → present → verify disclosed fields)
- OID4VCI Pre-auth + Authorization Code flows via walt.id
- OID4VP with DIF PE `presentation_definition`
- W3C BSL 2023 + IETF Token Status List revocation
- PKCE in OIDC authorization flows
- TLS termination via Caddy in production mode
- Nonce freshness (one-time use enforced via session state)
- Per-issuer credential scoping (`OwnerKey`)

---

## 8. Recommended Closure Plan

| Priority | Item | Version target |
|----------|------|---------------|
| P1 | Add `response_mode: direct_post.jwt` to `verifyBody` in the walt.id adapter — walt.id 0.23.1 already supports JARM, verifiably-go just isn't asking for it (re-verified 2026-08-24) | verifiably-go sprint, no walt.id upgrade needed |
| P1 | Configure `client_id_scheme=x509_san_dns` in verifier-api — **not re-audited against 0.23.1**, may also have changed | Same release cycle |
| P2 | Add `ClientIDScheme` field to `OID4VPTemplate` and thread it through `RequestPresentation` | verifiably-go sprint |
| P3 | Research wallet attestation registry for target wallets (EUDI, inji) | Architecture spike |
| P3 | Add `kb-jwt` signature verification in verifier adapter | After trust anchor decision |
