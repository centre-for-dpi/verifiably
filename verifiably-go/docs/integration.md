# Backend integration

Everything the UI shows comes from **one interface**: `backend.Adapter`
in `backend/adapter.go`. To point verifiably-go at a different DPG, you
implement that interface and register your adapter in
`cmd/server/adapter.go`. No handler code or template changes are needed.

> For the concrete, per-DPG wiring (env, Caddy, configs, DBs) behind each adapter,
> see the guides in [`docs/dpg/`](dpg/README.md).

## The Adapter contract

```go
type Adapter interface {
    // Discovery
    ListIssuerDpgs(ctx context.Context) (map[string]vctypes.DPG, error)
    ListHolderDpgs(ctx context.Context) (map[string]vctypes.DPG, error)
    ListVerifierDpgs(ctx context.Context) (map[string]vctypes.DPG, error)

    // Schemas (issuer)
    ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error)
    ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error)
    SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error
    DeleteCustomSchema(ctx context.Context, id string) error

    // Prefill (issuer)
    PrefillSubjectFields(ctx context.Context, schema vctypes.Schema) (map[string]string, error)

    // Issuance
    IssueToWallet(ctx context.Context, req IssueRequest) (IssueToWalletResult, error)
    IssueAsPDF(ctx context.Context, req IssueRequest) (IssueAsPDFResult, error)
    IssueBulk(ctx context.Context, req IssueBulkRequest) (IssueBulkResult, error)

    // Wallet (holder)
    ListWalletCredentials(ctx context.Context) ([]vctypes.Credential, error)
    ListExampleOffers(ctx context.Context) ([]string, error)
    BootstrapOffers(ctx context.Context) ([]string, error)
    ParseOffer(ctx context.Context, offerURI string) (vctypes.Credential, error)
    ClaimCredential(ctx context.Context, cred vctypes.Credential) (vctypes.Credential, error)
    PresentCredential(ctx context.Context, req PresentCredentialRequest) (PresentCredentialResult, error)

    // OID4VP (verifier)
    ListOID4VPTemplates(ctx context.Context) (map[string]vctypes.OID4VPTemplate, error)
    RequestPresentation(ctx context.Context, req PresentationRequest) (PresentationRequestResult, error)
    FetchPresentationResult(ctx context.Context, state, templateKey string) (VerificationResult, error)
    VerifyDirect(ctx context.Context, req DirectVerifyRequest) (VerificationResult, error)
}
```

The request/response types are defined alongside in `backend/adapter.go`.
All fields are plain Go structs — no tags or reflection magic.

## Swap checklist

1. Create a new package under `internal/adapters/yourdpg/` with a type
   that satisfies `backend.Adapter`.
2. Add a case to `internal/adapters/factory/factory.go` so a
   `config/backends.json` entry with `"type": "your_dpg"` builds your
   adapter.
3. Declare your DPG in a stanza inside `deploy.sh`'s `backends_for`
   helper so the UI knows what vendor, capabilities, and config URLs to
   advertise.
4. Rebuild: `./deploy.sh run all`.

The Registry (which handlers actually hold) will auto-route per-request
calls to your adapter based on the DPG selected in the session.

## Adapter-to-endpoint mapping

The bundled adapters already map onto the four DPGs listed in
[dpg-matrix.md](dpg-matrix.md). The table below is your cheat sheet if
you're writing a new one or porting to a different vendor.

| Adapter method                 | walt.id Community Stack v0.18.2                                  | Inji Certify v0.14.0 (auth-code)                                     | Inji Certify v0.14.0 (pre-auth)                                      | Inji Verify v0.16.0                                              |
|--------------------------------|------------------------------------------------------------------|----------------------------------------------------------------------|----------------------------------------------------------------------|------------------------------------------------------------------|
| `ListSchemas(issuerDpg)`       | `GET {ISSUER}/credentialConfigurations`                          | `GET {CERTIFY}/v1/certify/credential-configuration`                  | Same — shared metadata                                               | —                                                                |
| `PrefillSubjectFields`         | Operator types (no prefill)                                      | MOSIP Identity Plugin: `GET {CERTIFY}/v1/certify/issuance/data-provider/{plugin}?key={uin}` | Operator types (no prefill)                                          | —                                                                |
| `IssueToWallet` (auth-code)    | `POST {ISSUER}/openid4vc/jwt/issue` (or `/sdjwt/issue`) → offer URI | `POST {CERTIFY}/v1/certify/issuance/credential-offer` → OID4VCI offer URI | —                                                                    | —                                                                |
| `IssueToWallet` (pre-auth)     | `POST {ISSUER}/openid4vc/jwt/issue` with `preAuthorizedCode`     | —                                                                    | `POST {CERTIFY}/v1/certify/pre-authorized-data` → staged offer URI   | —                                                                |
| `IssueAsPDF`                   | **Not supported** at v0.18.2                                     | `POST {CERTIFY}/v1/certify/issuance/credential` + pixelpass QR embed | Same                                                                 | —                                                                |
| `IssueBulk`                    | `POST {ISSUER}/openid4vc/batchIssue`                             | Per-row re-issue via `issueToWallet` (bulk endpoint varies)          | Same                                                                 | —                                                                |
| `ParseOffer`                   | `POST {WALLET}/wallet-api/wallet/{id}/exchange/resolveCredentialOffer` | — (Inji Web is redirect-only)                                        | —                                                                    | —                                                                |
| `ClaimCredential`              | `POST {WALLET}/wallet-api/wallet/{id}/exchange/useOfferRequest`  | —                                                                    | —                                                                    | —                                                                |
| `ListWalletCredentials`        | `GET {WALLET}/wallet-api/wallet/{id}/credentials`                | —                                                                    | —                                                                    | —                                                                |
| `PresentCredential`            | `POST {WALLET}/wallet-api/wallet/{id}/exchange/usePresentationRequest` | —                                                                    | —                                                                    | —                                                                |
| `RequestPresentation`          | `POST {VERIFIER}/openid4vc/verify` → request URI + state         | —                                                                    | —                                                                    | `POST {VERIFY}/v1/verify/start-vp` → request URI + state         |
| `FetchPresentationResult`      | `GET {VERIFIER}/openid4vc/session/{state}`                        | —                                                                    | —                                                                    | `GET {VERIFY}/v1/verify/vp-result/{state}`                       |
| `VerifyDirect` (W3C VCDM)      | `POST {VERIFIER}/openid4vc/verify/credential`                     | —                                                                    | —                                                                    | `POST {VERIFY}/v1/verify/vc-verification`                        |
| `VerifyDirect` (SD-JWT VC)     | `POST {VERIFIER}/openid4vc/verify/credential` with `format: sd_jwt_vc` | —                                                                    | —                                                                    | `POST {VERIFY}/v1/verify/vc-submission` + `GET /vp-result/{id}` |

Inji Web Wallet's "adapter" is a stub — the external wallet is browser-hosted,
so verifiably-go hands off via a redirect link rather than calling an API.
The stub reports capabilities so the holder DPG card renders correctly
but every adapter method returns a "not supported" result or empty list.
(The Inji **auth-code** holder wallet is different: it is served **in-app** by
`internal/handlers/inji_holder.go`, not by an adapter — see
[dpg/inji-certify-authcode.md](dpg/inji-certify-authcode.md).)

## Beyond `backend.Adapter`: the auxiliary interfaces

Two capabilities sit **outside** `backend.Adapter` because they are data-plane
concerns, not DPG-abstraction concerns:

- **`SubjectProvisioner`** (`internal/handlers/api_subjects.go`) — the contract for
  the Inji auth-code data plane: `ProvisionSubject` (write `certify.vc_subject`),
  `UpsertIdentity` / `GetIdentity` (`certify.identity_registry`),
  `ApplyAuthcodeSchema` / `ListCredentials` / `DeleteCredential`
  (`certify.credential_config`). Implemented by `internal/storage/pg`
  (`*pg.SubjectStore`); `nil` when `INJI_CERTIFY_DATABASE_URL` is unset. Backs
  `POST /api/v1/subjects`, the Inji schema builder, and the registry-gated
  activation. `did_url` for a new credential is derived live from certify's
  did.json id so the signed VC's `proof.verificationMethod` matches its issuer.

- **The bulk engine** (`internal/handlers/bulk.go`) — four data-source connectors
  (`parseCSVRows`, `fetchJSONRows`, `queryDBRows`, `searchRegistryAll`) feeding
  either issuance (`vc_subject`) or registrar enrolment (`identity_registry`).
  Not part of the adapter; shared by every DPG that provisions subjects. See
  [dpg/registries.md](dpg/registries.md).

**Delegated access** adds a parallel set of REST endpoints (issue/verify a
subject-identity + delegation credential pair, evaluate linkage/invocation/
capability/revocation) under `/api/v1/delegation/*`, backed by
`internal/delegation`. It composes with any DPG's issuance; see
[delegated-access.md](delegated-access.md).

## Auth token propagation

When a user signs in via Keycloak or WSO2IS, the callback handler
(`/auth/callback`) stores the returned access token on the session.
Before every adapter call, handlers wrap the request context with
`httpx.WithToken(ctx, tok)`. The bundled adapters' HTTP clients read the
token back via `httpx.TokenFromContext(ctx)` and attach
`Authorization: Bearer <tok>` to outbound requests.

If your adapter uses something other than bearer auth (mTLS, signed
requests, API keys), add it to your own HTTP client and ignore the
context token — the handler side doesn't care how you authenticate
downstream.

## Per-request holder DPG

Four adapter methods don't take a DPG in their request struct:
`ParseOffer`, `ClaimCredential`, `ListWalletCredentials`, and
`BootstrapOffers`. These use the request context via
`backend.WithHolderDpg(ctx, vendor)` — handlers always wrap; the
Registry reads the DPG back with `backend.HolderDpgFromContext(ctx)` to
pick the right adapter. A single-DPG scenario falls through to the
single registered holder automatically; multi-DPG scenarios fail with
`ErrUnknownDPG` if the context isn't wrapped.

## Error surfaces

Adapter errors bubble up to handlers, which turn them into either:

- **Inline error banners** on the wallet / schema / issue pages
  (`sess.LastWalletError`, etc.) — useful for "last attempt failed"
  context that should persist.
- **HX-Trigger toasts** — quick, auto-fading notifications.
- **Redirect loops** with `h.errorToast` for unrecoverable failures
  (DPG unavailable, backend down).

Return `backend.ErrUnknownDPG` specifically to get the Registry's
"DPG not configured" handling. Everything else flows through as-is,
so keep error messages concise and user-facing — they'll appear in the
UI verbatim.

## Testing your adapter

Write puppeteer tests under `e2e/<yourvendor>-test.mjs` following the
pattern in `e2e/waltid-test.mjs`. The test harness doesn't require
anything specific — spin up your backend, hit the verifiably-go UI via
puppeteer, assert on the rendered HTML. Headless Chromium via
`puppeteer-core` with `CHROME_PATH=/usr/bin/google-chrome`.

For pure-Go unit tests, see `internal/adapters/registry/holder_routing_test.go`
for an example that exercises the Registry without booting HTTP.
