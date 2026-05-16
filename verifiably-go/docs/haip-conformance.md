# OID4VC High Assurance Interoperability Profile (HAIP) — Conformance Audit

**Spec:** [openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)  
**Audited:** 2026-05-16  
**Scope:** verifiably-go as orchestrator (not issuer/verifier DPG); walt.id 0.18.2 as primary DPG.

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
| `response_mode=direct_post.jwt` (HAIP REQUIRED) | ❌ | **Gap**: HAIP mandates JARM-encrypted response; walt.id 0.18.2 supports `direct_post` only |
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
**Current state:** `direct_post` (plain JSON body, no encryption).  
**Risk:** Credential claims in transit are visible to redirect intermediaries.  
**Fix path:**
1. Upgrade walt.id to a version that supports JARM (check release notes for `direct_post.jwt`).
2. Provision the verifier's encryption key (ECDH-ES+A256KW) and register it in the verifier metadata.
3. verifiably-go passes the `response_mode` parameter through to `RequestPresentation` — no code change needed once walt.id supports it.

**Effort:** M — depends on walt.id upstream support.

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
| P1 | Upgrade walt.id to a release with `direct_post.jwt` support | Next walt.id release after 0.18.2 |
| P1 | Configure `client_id_scheme=x509_san_dns` in verifier-api | Same release cycle |
| P2 | Add `ClientIDScheme` field to `OID4VPTemplate` and thread it through `RequestPresentation` | verifiably-go sprint |
| P3 | Research wallet attestation registry for target wallets (EUDI, inji) | Architecture spike |
| P3 | Add `kb-jwt` signature verification in verifier adapter | After trust anchor decision |
