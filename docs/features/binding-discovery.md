# Credential Discovery with Citizen Binding

## Overview

This document describes the **binding-discovery** feature branch, which extends the verifiably-go federation hub and the cdpi-wallet to support a self-service credential issuance flow where a citizen can discover and obtain verifiable credentials directly from their verified national identity, without any operator-mediated step.

The core insight is that certain credentials — those whose claims map 1:1 to what a national identity provider (IdP) already attests — can be issued immediately after the citizen authenticates. No separate enrollment, no back-office check: the citizen's `national_id` (or equivalent) is the binding anchor that makes this possible.

---

## Problem Statement

Prior to this work:
- The discovery catalog (`GET /api/v1/discovery/credentials`) returned **all** credentials the federation offers, including those that require issuer-gated data (e.g., academic degrees, employment status) that cannot be derived from a national identity token alone.
- There was no client-side gate: a citizen without a `national_id` claim in their token would see the discovery tab, tap "Obtener", and receive a cryptic 403 error from the issuer.
- The eligibility endpoint (`POST /api/v1/credentials/eligible`) required an API key, making it unusable from the wallet directly.
- The self-issue endpoint (`POST /api/v1/credentials/self-issue`) only accepted an `id_token`; Keycloak does not always return a new `id_token` in token refresh responses, causing stale-token failures.

---

## Architecture

```
[Citizen's Phone]                  [Federation Hub]              [Member Issuer]
  cdpi-wallet
       │
       │ 1. GET /api/v1/discovery/credentials
       │────────────────────────────────────────► filterCitizenBindingCredentials()
       │                                            └─ only national_id-bearing creds
       │◄────────────────────────────────────────
       │
       │ 2. POST /api/v1/credentials/eligible
       │    body: { access_token: "..." }           ──────────────────────────────►
       │                                            verifyCitizenToken()  (JWKS)
       │                                            evaluateEligibility()
       │◄───────────────────────────────────────────────────────────────────────────
       │
       │ 3. POST /api/v1/credentials/self-issue
       │    body: { access_token: "...", credential_configuration_id: "..." }
       │                                            ──────────────────────────────►
       │                                            verifyCitizenToken()
       │                                            BuildOffer() → OID4VCI offer
       │◄───────────────────────────────────────────────────────────────────────────
       │
       │ 4. OID4VCI flow (existing cdpi-wallet receive screen)
       │    openid-credential-offer://... → /receive
```

---

## Server-side Changes (`verifiably-go`)

### 1. Discovery Catalog Filter — `internal/handlers/discovery.go`

**New functions:**

```go
func filterCitizenBindingCredentials(issuers []backend.IssuerCatalogEntry) []backend.IssuerCatalogEntry
```

(plus the package-level `mockCitizenIdentity` claim set)

**What they do:**  
Before encoding the catalog response, every credential is tested against `mockCitizenIdentity` — a synthetic claim set representing the maximum information a national-ID OIDC token can provide (covering every alias in `identityAliases`) — using `evaluateEligibility`, the **same** function the citizen eligibility and self-issue checks use. A credential passes only when **every** declared claim is coverable (`Available == true`, i.e. zero missing claims). A credential mixing identity claims with issuer-gated data — e.g. `[national_id, degree]` — is **stripped**, because `"degree"` is not coverable from any identity token and self-issue would 403 on it. (The earlier "passes if *any* claim resolves" logic over-admitted exactly these credentials, leaving dead "Obtener" buttons.) Issuers with no remaining credentials are removed entirely.

**Alias matching:**  
`resolveClaim` normalises claim names (strips non-alphanumeric, lowercases) and checks against `identityAliases` in `identity_prefill.go`. The following field names are treated as equivalent:

| Field name (raw) | Normalised | Maps to |
|---|---|---|
| `national_id` | `nationalid` | nationalid |
| `NationalId` | `nationalid` | nationalid |
| `cedula` | `cedula` | nationalid |
| `dni` | `dni` | nationalid |
| `documentnumber` | `documentnumber` | nationalid |

**Why a mock token?**  
The catalog filter runs at serving time, not per-citizen. It answers "could _any_ citizen obtain this credential from their national identity alone?" — a structural property of the credential schema, not a per-citizen eligibility check. Using a mock token with `nationalid` present lets `resolveClaim` answer that question without a real token.

**Standalone issuer mode:**  
Previously `ServeCredentialCatalog` only worked when a `CredentialCache` (hub) was present. Now, when `CredentialCache` is `nil`, the handler falls back to calling `cachedIssuerMetadata` and returns a single-entry catalog for this member itself — same endpoint, same wallet code, no hub required. The standalone route is registered in `cmd/server/main.go` on the issuer role when the hub role is not co-located.

**Tests added** (`discovery_test.go`):
- `TestServeCredentialCatalog_StandaloneIssuer` — non-hub deployment returns its own catalog
- `TestServeCredentialCatalog_FiltersNonCitizenCredentials` — diploma filtered out, RuralId passes
- `TestServeCredentialCatalog_ExcludesIssuerWithNoEligibleCredentials` — issuer with only non-national-id creds excluded entirely
- `TestServeCredentialCatalog_AliasedNationalIDClaims` — `cedula` and `documentnumber` pass via alias

---

### 2. Eligibility Endpoint — `internal/handlers/eligibility.go`

**New citizen self-check path:**

```
POST /api/v1/credentials/eligible
Content-Type: application/json

{ "access_token": "<citizen's OIDC access_token>" }
```

No API key required. The handler detects the citizen path when:
1. The request body contains `access_token` or `id_token`, AND
2. No valid API key is present in the `Authorization` header.

The token is verified against all configured JWKS providers via `verifyCitizenToken`. On success, eligibility is evaluated against the **full unscoped catalog** (all schemas this member issues), not scoped to a particular API key. This gives the citizen a complete picture of what they can obtain.

**Operator path unchanged:**  
When a valid API key is present, the existing flow runs: the API key scopes the issuer metadata, and raw `claims` (or `id_token`) in the body provide the identity. Both paths coexist; the citizen path is tried first.

**CORS added:**  
`setCORSHeaders` and OPTIONS preflight handling were added so the wallet can call this endpoint cross-origin (needed for federation members running on different domains from the hub).

**Improved diagnostics:**  
`verifyCitizenToken` now logs a structured `slog.Warn` when each provider rejects a token, making debugging failed verifications feasible without enabling debug-level logging globally.

**Tests added** (`eligibility_test.go`):
- `TestAPICheckEligibility_CitizenAccessToken` — citizen path returns correct eligibility without API key
- `TestAPICheckEligibility_CitizenBadTokenRejected` — bad signature returns 401

---

### 3. Self-Issue Endpoint — `internal/handlers/self_issue.go`

**`access_token` added alongside `id_token`:**

```go
type selfIssueRequest struct {
    IDToken     string `json:"id_token,omitempty"`      // legacy, kept for compat
    AccessToken string `json:"access_token,omitempty"`  // preferred
    CredentialConfigurationID string `json:"credential_configuration_id"`
}
```

The handler picks `access_token` first; if absent, falls back to `id_token`. Both are verified identically by `verifyCitizenToken`. The distinction matters because Keycloak does not always include a new `id_token` in refresh responses — only the `access_token` is reliably fresh. Sending an expired `id_token` was causing 401 errors even when the session was still valid.

**Error logging improved:**  
When a citizen is denied due to missing claims, a structured `slog.Warn` is emitted with the credential configuration ID and the list of missing claims. This replaces a silent 403 that was hard to correlate in logs.

**Tests added** (`self_issue_test.go`):
- `TestAPISelfIssue_AccessToken` — wallet sends `access_token`; endpoint issues credential correctly

---

### 4. Registry — `internal/adapters/registry/registry.go`

**`GetIssuerMetadata` simplified:**

The previous implementation aggregated credentials from both vendor adapter instances and custom schemas, deduplicating by `id+format`. This made the public discovery catalog inherit entries that were never registered by an authenticated identity.

New behaviour:
- Only custom schemas with a non-`session-` `OwnerKey` are included.
- `session-<hex>` schemas are temporary test/demo artifacts created by anonymous users via the schema builder UI. They must not appear in the public catalog.
- Schemas with an empty `OwnerKey` (created via admin CLI or API) are always included.
- Vendor adapter entries (`metaStub` / HOCON templates) are never included.

**Why this matters:**  
Without this filter, a developer testing the schema builder would accidentally populate the federation's public catalog with demo schemas. The catalog should only contain schemas deliberately registered by authenticated operators.

**Tests updated** (`registry_test.go`):
- `TestRegistry_GetIssuerMetadata_OnlyCustomSchemas` — covers all four rules: keycloak-owned included, session-owned excluded, admin included, vendor excluded.

---

### 5. OIDC Audience Validation — `internal/auth/oidc/jwks.go`

**Documentation clarified:**  
The `checkTemporalAudience` comment was rewritten to cite RFC 7519 §4.1.3 and OIDC Core §3.1.3.7, and to document that Keycloak `access_token`s need an **Audience** client-scope mapper configured so the `clientId` appears in the `aud` claim. Without this, the server rejects otherwise valid Keycloak access tokens with an audience error.

**Test updated** (`jwks_test.go`):  
The multi-audience test case was updated from `["x", "client"]` to `["account", "client"]` — the realistic array Keycloak produces when the Audience mapper is configured. This makes the test serve as executable documentation of the expected token shape.

---

### 6. Server Routing — `cmd/server/main.go`

The discovery catalog route (`GET /api/v1/discovery/credentials`) is now registered when the **issuer role** is active and the **hub role** is not co-located:

```go
if !activeRoles.Has(roles.Hub) {
    mux.HandleFunc("GET /api/v1/discovery/credentials", h.ServeCredentialCatalog)
    mux.HandleFunc("OPTIONS /api/v1/discovery/credentials", h.ServeCredentialCatalog)
}
```

When both roles are active in the same process, the hub block registers these routes with a `CredentialCache` wired in. Registering them again would cause a duplicate pattern panic.

---

## Wallet-side Changes (`cdpi-wallet`)

### 1. Discover Tab — `app/(tabs)/discover.tsx`

#### Token freshness management

```typescript
const JWT_EXPIRY_BUFFER_MS = 60_000; // 60-second proactive refresh window
```

The wallet decodes the JWT locally (no signature verification — structural only) to determine if a token is within 60 seconds of expiry. This ensures the access_token sent to the issuer never expires in transit. If the token is near-expiry, the wallet calls `refreshUser(force: true)` to hit the IdP unconditionally, bypassing the stored expiry timestamp.

#### `tokenHasNationalId(token: string): boolean`

Decodes the JWT payload and checks for the presence of any of: `national_id`, `nationalId`, `cedula`, `dni`. This mirrors the server-side alias table so the client-side gate and the server-side eligibility check stay in sync. Returns `false` on malformed tokens (fail-open — let the server decide).

#### Three-state load flow

```
refreshUser() → read token
  │
  ├─ near-expiry OR no national_id → refreshUser(force=true) → re-read token
  │
  ├─ no token OR no national_id → setState('no_national_id')  [show identity gate]
  │
  ├─ token still expired after force-refresh → setState('error')  [session truly gone]
  │
  └─ valid token with national_id → fetch catalog → check eligibility → setState('ready')
```

#### Eligibility filter

After fetching the catalog, the wallet calls `POST /api/v1/credentials/eligible` on each issuer's `service_endpoint` with `{ access_token: token }`. The response is a `Set<"endpoint|credId">` used to filter which "Obtener" buttons are rendered. Failures are non-fatal: if the eligibility check for one issuer fails, other issuers are still shown. The server enforces eligibility at issuance time regardless.

#### Fallback: `access_token ?? id_token`

Every token read uses `getOidcAccessToken() ?? getOidcIdToken()` as a fallback chain. The `id_token` is used as a last resort for wallets logged in before the Keycloak Audience mapper was configured.

#### UI states

| State | Trigger | Displayed |
|---|---|---|
| `loading` | Initial load | Activity indicator |
| `no_national_id` | Token lacks national ID claim | 🪪 "Identity verification required" screen |
| `error` | Network failure or expired session | 📡 Error screen with Retry button |
| `!user` | No OIDC session at all | 🔐 Login required screen |
| `ready` | Normal flow | Scrollable catalog filtered by eligibility |

---

### 2. Settings Tab — `app/(tabs)/settings.tsx`

When the user is not signed in with an OIDC account (`!user && oidcConfig.enabled`), the Session section now shows a sign-in card instead of hiding entirely.

The same PKCE flow used in the unlock screen (`useAuthRequest` + `promptAsync`) is embedded directly in the settings component. After a successful login:
1. Tokens are saved via `saveOidcTokens`.
2. User info is fetched from the IdP's `userinfo` endpoint.
3. `setUser()` updates the context, causing the component to re-render and show the user card immediately — no navigation required.

This solves a UX gap where a user who had never connected an OIDC account (or who logged out and then wanted to log back in) had to close the app and reopen it to reach the unlock screen's login button.

**Key difference from unlock screen:**  
On the unlock screen, `exchangeCode` calls `unlockWithKey()` to navigate to the credentials tab after login. In settings, there is no navigation — the user stays on the settings screen and sees their account information appear.

---

### 3. Token Refresh — `src/auth/UserContext.tsx`

`refreshUser` was extended with a `force?: boolean` parameter:

```typescript
refreshUser: (force?: boolean) => Promise<boolean>
```

When `force = true`, the stored expiry check is skipped and the IdP is always contacted. This is used by the discover tab when:
- The stored token is near-expiry (within 60 s).
- The token lacks a `national_id` claim (may be a pre-mapper token that needs to be refreshed to pick up newly configured claims).

---

### 4. Internationalisation

Three locale files (`en.ts`, `es.ts`, `fr.ts`) were updated with:

**Discover namespace:**
- `no_national_id_title` — heading for the identity gate screen
- `no_national_id_body` — body explaining what to do
- `session_expired` — message when refresh_token is also gone

**Settings namespace:**
- `sign_in` — label for the sign-in button on the Session card
- `not_signed_in` — description text when no OIDC account is linked

---

## End-to-End Flow

1. **Citizen opens Discover tab** while authenticated.  
   - Wallet checks token freshness and `national_id` presence.  
   - If missing, shows "Identity verification required" and stops.

2. **Wallet fetches the catalog** from the hub: `GET /api/v1/discovery/credentials`.  
   - The hub filters the response to only national-ID-bearing credentials.  
   - Result: only credentials the citizen can _structurally_ obtain.

3. **Wallet checks eligibility** per issuer: `POST /api/v1/credentials/eligible` with the access_token.  
   - Issuer verifies the token against its JWKS, evaluates claim coverage.  
   - Only credentials where all required claims are present in the token return `available: true`.

4. **Citizen taps "Obtener".**  
   - Wallet calls `POST /api/v1/credentials/self-issue` with `access_token` + `credential_configuration_id`.  
   - Issuer verifies the token, confirms eligibility, builds an OID4VCI pre-auth offer.  
   - Returns `{ offer_uri: "openid-credential-offer://..." }`.

5. **Wallet navigates to `/receive`** with the offer URI — the existing OID4VCI flow completes the issuance.

---

## Security Notes

- **No claim trust from the wallet:** The server never trusts claims sent raw from the wallet. All claims are extracted from the verified OIDC token. The wallet sends the token; the server verifies it.  
- **Eligibility ≠ authorisation:** The eligibility check at step 3 is a UX filter (hide buttons the citizen can't use). The self-issue endpoint at step 4 performs its own independent verification and eligibility check. A citizen cannot bypass eligibility by calling self-issue directly.  
- **Audience validation:** The access_token must include the server's `clientId` in its `aud` claim (Keycloak requires an Audience mapper for this). Tokens minted for a different relying party are rejected.  
- **No PII logged:** Token bodies and claim maps are never written to logs. Error messages reference token position (`"token expired"`) not claim content.  
- **Session-owned schemas excluded:** Anonymous test schemas created via the schema builder UI are not served in the public catalog, preventing accidental data leakage or misleading catalog entries.

---

## Keycloak Configuration Required

For the full flow to work, the Keycloak realm must have:

1. **User attribute `national_id`** stored on each citizen's profile.  
2. **User Attribute mapper** on the client (or a shared client scope): maps `national_id` → token claim `national_id` for both the `access_token` and `id_token`.  
3. **Audience mapper** on the client: adds the `clientId` to the `aud` claim of the `access_token`. Without this, the server rejects the token with an audience error even though the signature is valid.

---

## Testing Coverage

| Layer | File | Tests added / modified |
|---|---|---|
| Go handlers | `discovery_test.go` | 4 new (standalone, filter, exclusion, aliases) |
| Go handlers | `eligibility_test.go` | 2 new (citizen access_token, bad token 401) |
| Go handlers | `self_issue_test.go` | 1 new (access_token path) |
| Go registry | `registry_test.go` | 1 rewritten (session exclusion, vendor exclusion) |
| Go OIDC | `jwks_test.go` | 1 test comment + realistic aud array updated |

All Go tests pass. TypeScript type-checking passes (the `useAutoDiscovery` null-arg pattern follows the pre-existing pattern already in `unlock.tsx`).

---

## Files Changed

### `demo-daas-3-0` (verifiably-go)

| File | Change |
|---|---|
| `cmd/server/main.go` | Register discovery route on standalone issuer |
| `internal/adapters/registry/registry.go` | Filter session-owned schemas from GetIssuerMetadata |
| `internal/adapters/registry/registry_test.go` | Rewrite test for new filtering rules |
| `internal/auth/oidc/jwks.go` | Clarify audience validation comment |
| `internal/auth/oidc/jwks_test.go` | Update aud array to realistic Keycloak shape |
| `internal/handlers/discovery.go` | Standalone mode + citizen-binding filter |
| `internal/handlers/discovery_test.go` | 4 new tests |
| `internal/handlers/eligibility.go` | Citizen self-check path + CORS |
| `internal/handlers/eligibility_test.go` | 2 new tests |
| `internal/handlers/self_issue.go` | Accept access_token; improved error logging |
| `internal/handlers/self_issue_test.go` | 1 new test |
| `.gitignore` | Ignore `verifiably-go/.agent-runtime/` |

### `cdpi-wallet`

| File | Change |
|---|---|
| `app/(tabs)/discover.tsx` | Token freshness, national_id gate, eligibility filter, 3-state load |
| `app/(tabs)/settings.tsx` | OIDC sign-in button for unauthenticated users |
| `src/auth/UserContext.tsx` | `force` parameter on `refreshUser` |
| `src/i18n/locales/en.ts` | `no_national_id_*`, `session_expired`, `sign_in`, `not_signed_in` |
| `src/i18n/locales/es.ts` | Same (Spanish) |
| `src/i18n/locales/fr.ts` | Same (French) |
| `src/utils/storage.ts` | Token storage utilities used by discover/settings |

---

## Future Work

- **Additional binding anchors:** email (verified OTP) and phone (SMS OTP) as alternative binding anchors for credentials that don't require a national ID. Architecture documented separately.
- **Multi-credential presentation:** OID4VP flow for presenting multiple credentials from different issuers in a single request. Already supported natively by cdpi-wallet; federation-side integration pending.
- **Pluggable signer (PKI/HSM/KMS):** Abstract the signing layer to support PKCS#11 tokens, X.509 national PKI, and cloud KMS. Architecture designed, implementation pending.
