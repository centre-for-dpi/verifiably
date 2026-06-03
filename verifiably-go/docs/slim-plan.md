# Verifiably-Go — Full-Reality Implementation Plan

This plan replaces every simulated/mock path in the verifiably-go UI with live
calls against the DPG stack in `docker/stack/docker-compose.yml`:

- walt.id Community Stack v0.18.2 — issuer-api (`:7002`), verifier-api
  (`:7003`), wallet-api (`:7001`).
- Inji Certify v0.14.0 — primary Auth-Code instance (via certify-nginx `:8091`,
  tokens signed by eSignet) and Pre-Auth instance (`:8094`, tokens signed by
  its own JWKS).
- Inji Web Wallet v0.16.0 — injiweb-ui (`:3004`), mimoto (`:8099`), eSignet
  (`:3005`).
- Inji Verify v0.16.0 — inji-verify-service (`:8082`), inji-verify-ui (`:3001`).
- WSO2IS v7.0.0 (`:9443`) and Keycloak latest (`:8180`) as OIDC IDPs.
- LibreTranslate (`:5000`) for en-GB / fr-FR / es-ES UI translation.

## Guarantees this plan makes explicit

**G1. No simulation remains.** Every current stub — scan, upload, paste,
example-offer cycling, holder presentation, bulk issuance preview, PDF
issuance, auth — resolves to a live call. The word "simulate" and the
`flakyOutcome()` helper both leave the production codepaths.

**G2. Two Inji Certify cards.** The catalog exposes
`inji_certify_authcode` and `inji_certify_preauth` as separate DPG entries.
Downstream screens (schema, mode, issue form, result) reflect each one's
actual capabilities, not a shared abstraction.

**G3. Hard agnosticism line.** CI rule:
`grep -rE 'waltid|inji_|keycloak|wso2is|mimoto|esignet' internal/handlers templates vctypes backend cmd`
must return zero matches. Vendor names live only in `internal/adapters/*`,
`internal/auth/*`, and `backends.json`.

## Full "simulate → real" inventory

| Current stub | Lives at | Replacement |
|---|---|---|
| `flakyOutcome()` random 75/25 split | `mock/adapter.go:276` | Deleted. All `VerificationResult` comes from a real verifier call. |
| `SimulateResponse` → mock `FetchPresentationResult` | `verifier.go:55` | Handler renamed to `FetchResponse`; adapter polls real verifier session until terminal (walt.id `/openid4vc/session/{state}`, inji-verify `/vp-result/{transactionId}`). |
| `VerifyDirect` method=scan | `verifier.go:72` | Front-end adds `getUserMedia` + `jsQR`. Decoded QR text POSTs as `CredentialData`. |
| `VerifyDirect` method=upload | `verifier.go:72` | Multipart upload accepted. Server-side QR extraction via `gozxing` or pixelpass-compatible decoder. |
| `SimulatePresent` | `handlers.go` + `holder_present.html` | New adapter method `PresentCredential(ctx, credID, requestURI)` drives the real OID4VP response path. |
| `ListExampleOffers` 3 hardcoded fixtures | `mock/data.go:181` | Replaced with `BootstrapOffers(ctx)` — adapter issues a canned credential against its live backend at startup. |
| `PrefillSubjectFields` mock values | `mock/data.go:132` | walt.id → empty; Inji Auth-Code → MOSIP Identity Plugin; Inji Pre-Auth → CSV data-provider. |
| `ListWalletCredentials` seed | `mock/data.go:226` | walt.id → `GET /wallet/{id}/credentials`; Inji Web → Mimoto session-scoped list. Walletbag JSON persistence on top. |
| `IssueBulk` hardcoded 247/2 | `mock/adapter.go:152` | Adapter iterates real CSV rows and aggregates real per-row outcomes. |
| `IssueAsPDF` walt.id | `mock/adapter.go:138` | `ErrNotSupported` (UI hides via `DPG.DirectPDF=false`). |
| `IssueAsPDF` Inji Certify Auth-Code | — | Real call via Claim-169 QR/pixelpass path. |
| `CompleteAuth` stub | `handlers.go:162` | Real OIDC callback against whichever provider the user picked. |
| Inji Web "redirect only" | previous plan | Real: OAuth-style handshake with Mimoto; token stored on session; credentials readable via `GET /v1/mimoto/wallet-credentials`. |
| Inji Verify cross-device | previous plan | Real: `POST /vc-submission`, poll `/vp-result/{id}`. No browser-tab hand-off. |
| Top-bar language selector | not implemented | LibreTranslate, offline-cached via pre-extracted `locales/{fr,es}.json`. |

## Two Inji Certify cards — downstream capability redesign

### Card A — Inji Certify · Authorization Code (via eSignet)

- Tag: `Auth-Code · via eSignet`
- Tagline: "The holder logs into eSignet, which issues an OIDC access token
  that Inji Certify accepts as a resource server."
- Capabilities:
  - Flow: holder is redirected to eSignet for interactive login (mock-identity UIN).
  - Data: claims populate from MOSIP Identity Plugin via UIN lookup.
  - Wallet: compatible with Inji Web Wallet; also any OID4VCI wallet supporting Auth-Code.
  - Token: Bearer is eSignet-signed; Inji Certify validates via JWKS.
  - Limitation: requires eSignet running; JWKS endpoint reachable.

### Card B — Inji Certify · Pre-Authorized Code

- Tag: `Pre-Auth · operator-driven`
- Tagline: "The operator stages claims directly on the certify instance; the
  wallet exchanges a pre-authorized code with certify's own token endpoint —
  no user login."
- Capabilities:
  - Flow: operator POSTs claims to `/pre-authorized-data`; offer URI carries pre-auth code.
  - Data: operator-entered or CSV row via Pre-Auth data-provider plugin.
  - Wallet: paste-based in-process wallets, walt.id wallet (pre-auth), PDF destination. **Not** compatible with Inji Web Wallet.
  - Token: certify-signed by this isolated instance's own JWKS.
  - Limitation: no user consent screen; demo scenarios only.

### Downstream screen branching

- **Schema picker** — live per-DPG `GET /v1/certify/credential-configuration`.
  The UI renders whatever each instance reports (no shared schema list).
- **Mode picker** — branches on `dpg.Capabilities`:
  - Card A enables `wallet` (redirect flow), `inji_web`. Disables `pdf` unless MOSIP Identity Plugin + pixelpass are configured.
  - Card B enables `wallet (paste)`, `pdf`. Disables `inji_web`.
- **Issue form** — source picker branches:
  - Card A: *Manual entry*, *MOSIP Identity Plugin (UIN lookup)*.
  - Card B: *Manual entry*, *CSV row (farmer_identity_data.csv)*.
- **Result panel** — shows the actual downstream endpoint/mechanism:
  - Card A: eSignet authorization URL + expected JWKS source.
  - Card B: pre-auth code inside offer URI + certify token endpoint.

All branchings are driven by `dpg.Capabilities` keys (`flow.auth_code`,
`flow.pre_auth`, `token.source`, `wallet.compatible_with`). No
`if vendor == …` anywhere in handlers.

## Architecture changes

1. `vctypes.DPG` gains `Capabilities []Capability{Title, Body, Kind}`.
2. Two Inji Certify adapters, one client — `Client{baseURL, flow, authMode,
   jwksURL}` parameterised twice by the registry.
3. New adapter method `PresentCredential(ctx, credID, requestURI)`.
4. New adapter method `BootstrapOffers(ctx)` — live example offers at startup.
5. `IssueBulkRequest.RowCount int` → `Rows []map[string]string`. Real CSV.
6. Front-end `static/scanner.js` (jsQR), server-side PDF QR extractor.
7. Walletbag JSON persistence (ported from ui-demo commit 9e9c169).
8. Inji Web linking flow: `GET /holder/link/injiweb` + callback.
9. Inji Verify polling lives inside the injiverify adapter — UI contract unchanged.

## Packages

```
internal/
  adapters/
    registry/        # dispatcher; reads backends.json
    waltid/          # issuer + verifier + wallet HTTP client
    injicertify/     # parameterised twice (authcode + preauth)
    injiweb/         # mimoto + esignet client + linking flow
    injiverify/      # vc-verification + vc-submission + vp-result
    libretranslate/  # translation client
  auth/
    keycloak/        # OIDC PKCE
    wso2is/          # OIDC PKCE
    session.go
  store/
    walletbag/       # JSON persistence
    schemas/         # custom-schema persistence
  httpx/             # shared transport: auth, retries, timeouts, errors
config/
  backends.json
```

## Milestones (simulation-free)

1. Scaffolding + CI agnosticism rule. Registry, `httpx`, env toggle, grep rule in CI.
2. walt.id end-to-end. All three roles. Bootstrap offers work. Walletbag populated from live wallet-api.
3. Inji Certify — two cards. Catalog entries, capability-driven downstream screens, both flows real end-to-end.
4. Inji Verify. `vc-verification` + `vc-submission`/`vp-result`, INJIVER-1131 guard, real polling.
5. Inji Web account linking. OAuth handshake; credentials readable; holder can present.
6. Scan + upload on verifier. Camera path + PDF QR extraction; adapter paste/scan/upload paths live.
7. Holder presentation (`PresentCredential`). New adapter method; real OID4VP response.
8. Bulk issuance real CSV path.
9. Auth (Keycloak + WSO2IS). Real OIDC login, token injection, refresh.
10. i18n (LibreTranslate). Extractor, locale files, selector in top bar.
11. Compose service + live e2e. Dockerfile, service entry, full test matrix.

## Definition of done

- `grep -RE 'simulate|mock|Flaky|Example(Offer|Credential)s' cmd internal/handlers templates` returns zero matches in production paths.
- Agnosticism grep rule passes.
- Two Inji Certify cards render distinct capability lists; their mode-picker and issue-form options differ.
- Every handler path that previously called a mock function now has an integration test hitting a real container.
- Walletbag survives `docker compose down && up`.
- Scan, upload, paste, and present exchange real data end-to-end.
- Language selector drives real LibreTranslate translations.
