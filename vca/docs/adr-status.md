# ADR status

This page records the state of every decision in the architecture
decision records. The root record set is [ADR.md](../../ADR.md). It
holds ADR-001 to ADR-031. The records from ADR-032 on are files in
[adr](adr), listed in the [index](adr.md). The page covers ADR-001 to
ADR-079, one row per decision.

The status values are:

- `Done`: the tree holds the code, the document, or the workflow that the
  decision asks for.
- `Partial`: a part of the decision works. The note names the gap.
- `Deferred`: the decision waits for an event outside this branch.
- `Not started`: no work exists yet.

The "where" column names the file or the package that holds the proof.
A row that is not `Done` carries a note.

## ADR-001: Rebrand and redefined purpose

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-001 | 1 Rename to VCA with a new module path | Done | `vca/go.mod` | |
| ADR-001 | 2 Product is a set of adapters | Done | `vca/README.md` | |
| ADR-001 | 3 The adapter mediates, the DPG signs | Done | `vca/services/dpg-adapter-*` | |
| ADR-001 | 4 Vendor names stay inside adapter packages | Partial | `vca/internal/cli`, `vca/core/pixelpass` | The CLI flags and one core comment name vendors. No CI job checks the rule. |
| ADR-001 | 5 Four target audiences | Done | `vca/docs` | |
| ADR-001 | 6 One adapter deploys alone | Done | `deploy/vca/compose.yaml` | |

## ADR-002: Decompose the monolith into microservices

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-002 | 1 One service per route group | Done | `vca/services` | |
| ADR-002 | 2 Small backend services with a Capabilities RPC | Done | `vca/proto/vca/backend/v1` | |
| ADR-002 | 3 Each service owns its data | Partial | `vca/services/internal/store` | Each service owns its key space. A PostgreSQL backend and migration files are a follow-up. |
| ADR-002 | 4 No writes into DPG databases or the Docker socket | Done | `vca/services/dpg-adapter-*` | |
| ADR-002 | 5 Connect calls with mutual service identity | Done | `vca/internal/peerauth`, `vca/internal/cli/peer.go` | ADR-075: each service signs its calls with an identity of the deployment, and each internal Connect service checks its callers. The callee proves itself only by its address on the network. |
| ADR-002 | 6 Trace Context through the OpenTelemetry SDK | Partial | `vca/services/internal/serve/trace` | The code passes `traceparent` by hand. The build network blocks the SDK module. |
| ADR-002 | 7 One shared library of pure functions | Done | `vca/core` | |

## ADR-003: Protocol buffers as the canonical contract

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-003 | 1 Every API in proto3 | Done | `vca/proto/vca` | |
| ADR-003 | 2 Connect protocol per service | Done | `vca/gen/vca/*/v1/*connect` | |
| ADR-003 | 3 OpenAPI 3.1 from the proto files | Partial | `vca/hack/openapi.sh` | The plugin needs a networked machine. The script skips the step and passes. |
| ADR-003 | 4 buf lint and buf breaking in CI | Done | `.github/workflows/vca-ci.yml` | |
| ADR-003 | 5 Field rules with protovalidate | Not started | `vca/proto` | Each service checks its fields in Go code. The module is not in the tree. |
| ADR-003 | 6 Opaque payload plus a format enum | Done | `vca/proto/vca/common/v1/common.proto` | |
| ADR-003 | 7 Standard HTTP endpoints stay plain | Done | `vca/services/*/internal/httpapi` | |

## ADR-004: Test-driven development and code standard

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-004 | 1 Each RPC starts with a test | Done | `vca/services/*/internal` | |
| ADR-004 | 2 Coverage gate at 90 percent, core at 100 | Done | `vca/hack/coverage.sh` | |
| ADR-004 | 3 Functional style, no package state | Done | `vca/core`, `vca/.golangci.yml` | |
| ADR-004 | 4 Contract tests with fixtures and a nightly run | Done | `vca/hack/contract-tests.sh` | |
| ADR-004 | 5 Property and fuzz tests for decoders | Done | `vca/core/ingest/fuzz_test.go` | |
| ADR-004 | 6 Playwright end to end tests on each PR | Partial | `vca/services/walkthrough`, `.github/workflows/vca-ci.yml` | Two Go walkthroughs run each service of a walt.id and a CREDEBL deployment as processes in every test run. The job "wallet.js in Chromium" runs Playwright on each PR. `TestWalletScriptInChromium` claims and presents through `wallet.js` against the walt.id walkthrough. Test doubles stand in for the DPG and the identity provider. No run against the compose stack exists. |
| ADR-004 | 7 Flaky tests go to quarantine in one day | Not started | `vca/docs/ci.md` | No page names the quarantine rule and no CI job tracks it. |
| ADR-004 | 8 Accessibility tests with axe-core | Not started | `vca/ui/a11ytest` | Go tests check the structure, and the walkthroughs check each page they open. The Playwright test opens the wallet pages in Chromium. The axe-core package is not in the offline toolchain of the build machine, so no axe run exists yet. |

## ADR-005: One container image per service

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-005 | 1 Static binary on distroless nonroot | Done | `vca/services/*/Dockerfile` | |
| ADR-005 | 2 Nonroot, read-only root, no capabilities | Done | `deploy/vca/compose.yaml`, `deploy/vca/helm` | |
| ADR-005 | 3 No image mounts the Docker socket | Done | `deploy/vca/compose.yaml` | |
| ADR-005 | 4 OCI labels on every image | Done | `.github/workflows/vca-release.yml` | |
| ADR-005 | 5 Keyless cosign signature and an SBOM | Done | `.github/workflows/vca-release.yml` | |
| ADR-005 | 6 One port, health probes, healthcheck flag | Done | `vca/services/internal/serve` | |
| ADR-005 | 7 Images hold all web assets | Done | `vca/ui/static`, `vca/ui/fonts` | |

## ADR-006: CI and CD with a version tag per release

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-006 | 1 SemVer versions and image tags | Done | `.github/workflows/vca-release.yml` | |
| ADR-006 | 2 Conventional Commits checked in CI | Done | `vca/hack/check-commits.sh` | |
| ADR-006 | 3 Release workflow on a `v*` tag | Done | `.github/workflows/vca-release.yml` | |
| ADR-006 | 4 One version for all services | Done | `.github/workflows/vca-release.yml` | |
| ADR-006 | 5 PR workflow with the full check list | Partial | `.github/workflows/vca-ci.yml` | The workflow has no browser test job and no axe job. Linter fixes run on another branch. |
| ADR-006 | 6 Workflows at the repository root | Done | `.github/workflows` | |
| ADR-006 | 7 Nightly contract tests and a kind deploy | Done | `.github/workflows/vca-nightly.yml` | |

## ADR-007: Interactive setup CLI

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-007 | 1 A Go CLI replaces the bash wizard | Done | `vca/cmd/vca`, `vca/internal/cli` | |
| ADR-007 | 2 Questions per role and per DPG | Done | `vca/internal/cli/setup.go` | |
| ADR-007 | 3 Prefill from a dotenv file | Done | `vca/internal/cli/dotenv.go` | |
| ADR-007 | 4 Precedence from flag to default | Done | `vca/internal/cli/resolve.go` | |
| ADR-007 | 5 One env file per role and DPG, mode 0600 | Done | `vca/internal/cli/secrets.go` | |
| ADR-007 | 6 Every variable in a proto Config message | Done | `vca/proto/vca/config/v1` | |
| ADR-007 | 7 One run for all roles | Done | `vca/internal/cli/setup.go` | |

## ADR-008: One-click deploy

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-008 | 1 Deploy with compose profiles | Done | `vca/internal/cli/compose.go` | |
| ADR-008 | 2 Deploy all roles in one run | Done | `vca/internal/cli/deploy.go` | |
| ADR-008 | 3 DPG stacks in pinned compose files | Done | `deploy/vca/dpg` | |
| ADR-008 | 4 DPG post-boot steps as Go subcommands | Done | `vca/internal/cli/dpgconfig.go` | |
| ADR-008 | 5 One Helm chart per service and an umbrella | Done | `deploy/vca/helm` | ADR-074 moves the role switches under `global.roles`. |
| ADR-008 | 6 Dry run, status, and down | Done | `vca/internal/cli/deploy.go` | |
| ADR-008 | 7 One role stays under 4 GB of memory | Done | `vca/docs/deploy.md` | |

## ADR-009: Super admin CLI and portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-009 | 1 Admin operations are RPCs | Done | `vca/proto/vca/admin/v1` | |
| ADR-009 | 2 Cobra command tree with man pages | Done | `vca/internal/cli/command.go` | |
| ADR-009 | 3 Portal help page from the same source | Done | `vca/services/admin/internal/portal` | |
| ADR-009 | 4 A description option on every RPC | Done | `vca/proto/vca/admin/v1/admin.proto` | |
| ADR-009 | 5 OIDC replaces the shared password | Done | `vca/services/admin/internal/login` | |
| ADR-009 | 6 Append-only audit log | Done | `vca/services/internal/auditlog` | The admin service and the auth services share the store. |

## ADR-010: Super admin OIDC onboarding

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-010 | 1 OIDC with discovery | Done | `vca/core/oidc` | |
| ADR-010 | 2 Code flow with PKCE, exact redirect | Done | `vca/services/internal/oidcflow` | |
| ADR-010 | 3 CLI onboarding with client registration | Done | `vca/services/admin/internal/onboard` | |
| ADR-010 | 4 One-time bootstrap token for the first admin | Done | `vca/internal/cli/bootstrap.go` | |
| ADR-010 | 5 The portal runs the same wizard | Done | `vca/services/admin/internal/portal` | |
| ADR-010 | 6 Device code or loopback login | Done | `vca/services/admin/internal/login/cli.go` | |
| ADR-010 | 7 CSRF tokens on browser posts | Done | `vca/services/admin/internal/app` | |

## ADR-011: Signed trust registry

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-011 | 1 Canonical entry with pluggable publishers | Done | `vca/services/trust-registry/internal/entry` | |
| ADR-011 | 2 ETSI list of trusted entities | Done | `vca/services/trust-registry/internal/etsi` | |
| ADR-011 | 3 DeDi directory files and index | Done | `vca/services/trust-registry/internal/dedi` | |
| ADR-011 | 4 Both methods per deployment | Done | `vca/services/trust-registry/internal/publish` | |
| ADR-011 | 5 ES256 or Ed25519 keys, no HS256 | Done | `vca/core/jose` | |
| ADR-011 | 6 Entities named by DID or x509 subject | Done | `vca/core/did`, `vca/services/trust-registry/internal/service` | A DID that `core/did` does not resolve, such as `did:indy`, needs the document of a stack (`ResolveDid`, `FEATURE_DID_RESOLVE`) or the confirmation of an admin. `TestLedgerDidNeedsTheStackOrAConfirmation` pins it. |
| ADR-011 | 7 One cached trust lookup for the policy service | Done | `vca/services/verifier-policy/internal/ports` | |

## ADR-012: Issuer OIDC auth flows

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-012 | 1 Lift the OIDC provider set | Done | `vca/services/issuer-auth/internal/service` | |
| ADR-012 | 2 ES256 session tokens with JWKS | Done | `vca/services/issuer-auth/internal/service/token.go` | |
| ADR-012 | 3 Roles from a claim path | Done | `vca/services/issuer-auth/internal/roles` | |
| ADR-012 | 4 Machine access with client credentials | Done | `vca/services/issuer-auth/internal/service/token.go` | |
| ADR-012 | 5 Providers come from the admin service | Done | `vca/services/admin/internal/service` | |
| ADR-012 | 6 Internal and public URL rewriting | Done | `vca/services/issuer-auth/internal/config` | |

## ADR-013: Issuer schema management portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-013 | 1 JSON Schema 2020-12 documents | Done | `vca/core/jsonschema` | |
| ADR-013 | 2 Immutable versions and a life cycle | Done | `vca/services/schema-registry/internal/record` | |
| ADR-013 | 3 Schema sync as an adapter RPC | Done | `vca/services/dpg-adapter-*/internal/service` | Each adapter serves `RegisterCredentialConfiguration`: walt.id records the setup, Inji writes the configuration API of Certify (P6-I1), and CREDEBL writes a schema and a template. `TestRegisterCreatesConfiguration` and `TestRegisterCredentialConfigurationStoresTheSchemaAndTheTemplate` pin it. |
| ADR-013 | 4 Public read and issuer metadata | Done | `vca/services/schema-registry/internal/httpapi` | |
| ADR-013 | 5 Type metadata per schema | Done | `vca/services/schema-registry/internal/metadata` | |
| ADR-013 | 6 Portal pages for the life cycle | Done | `vca/services/schema-registry/internal/portal` | |

## ADR-014: Issuer schema builder

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-014 | 1 Preview from a pure function | Done | `vca/core/preview` | |
| ADR-014 | 2 Builder edits give a JSON Schema | Done | `vca/services/schema-builder-ui/internal/draft` | |
| ADR-014 | 3 Three preview tabs | Done | `vca/services/schema-builder-ui/internal/pages` | |
| ADR-014 | 4 Keyboard use and a live region | Done | `vca/services/schema-builder-ui/internal/pages` | |
| ADR-014 | 5 Save writes a draft version | Done | `vca/services/schema-builder-ui/internal/service` | |
| ADR-014 | 6 Import from a schema or a DPG catalogue | Done | `vca/services/schema-builder-ui/internal/service` | |

## ADR-015: Issuer data sourcing portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-015 | 1 CSV, HTTP, and SQL sources | Done | `vca/services/data-source/internal/source` | |
| ADR-015 | 2 Credentials as a secret reference | Done | `vca/services/data-source/internal/secrets` | |
| ADR-015 | 3 Role-scoped access per source | Done | `vca/services/data-source/internal/service` | |
| ADR-015 | 4 Field and row preview RPCs | Done | `vca/proto/vca/datasource/v1` | |
| ADR-015 | 5 Stored field map with pure transforms | Done | `vca/core/mapping` | |
| ADR-015 | 6 Allowlist and SSRF guard on HTTP sources | Partial | `vca/services/data-source/internal/httpsrc/guard.go` | The service holds its own guard. The shared `core/fetchguard` package does not serve it yet. |
| ADR-015 | 7 Bulk jobs stream their progress | Done | `vca/services/issuance/internal/service/batch.go` | |

## ADR-016: Issuer multi-format issuance

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-016 | 1 OID4VCI with both grant types | Done | `vca/services/issuance/internal/service` | |
| ADR-016 | 2 SD-JWT VC, VCDM 2.0, and mdoc formats | Done | `vca/proto/vca/common/v1/common.proto` | |
| ADR-016 | 3 PDF channel for every DPG | Done | `vca/core/pdf` | |
| ADR-016 | 4 Claim 169 QR or an offer URI | Done | `vca/core/qr`, `vca/core/ingest/claim169.go` | |
| ADR-016 | 5 Delivery channels and batch issuance | Done | `vca/services/issuance/internal/delivery` | |
| ADR-016 | 6 Each adapter declares its formats | Done | `vca/services/dpg-adapter-*/internal/service` | |

## ADR-017: Issuer issued-credentials portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-017 | 1 One record per issuance in a hash chain | Partial | `vca/core/hashchain`, `vca/services/issued-credentials/internal/record` | The chain runs on the shared store. The move to PostgreSQL waits for the store backend. |
| ADR-017 | 2 A salted subject reference, no personal data | Done | `vca/services/issued-credentials/internal/record` | |
| ADR-017 | 3 Portal with revoke and reinstate | Done | `vca/services/issued-credentials/internal/pages`, `vca/services/issued-credentials/internal/service` | List, search, filters, detail, history, suspend, revoke, reinstate with a reason, and CSV and JSON export. A revoke goes through the stack when its adapter lists `FEATURE_REVOCATION`. |
| ADR-017 | 4 A signed chain head each day | Done | `vca/services/issued-credentials/internal/head` | |
| ADR-017 | 5 Retention per schema with a prune job | Done | `vca/services/issued-credentials/internal/retention` | |

## ADR-018: Bitstring Status List

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-018 | 1 W3C Bitstring Status List v1.0 | Done | `vca/core/statuslist/bitstring` | |
| ADR-018 | 2 Data Integrity or JOSE proofs | Partial | `vca/services/status-bitstring/internal/securer` | The JOSE method works. The `eddsa-rdfc-2022` method needs RDF canonicalisation, so the service refuses it. |
| ADR-018 | 3 Three purposes and the minimum size | Done | `vca/core/statuslist/bitstring` | |
| ADR-018 | 4 Random index allocation | Done | `vca/services/internal/status/lists` | |
| ADR-018 | 5 Cache headers, ETag, stored signature | Done | `vca/services/internal/status/httpapi` | |
| ADR-018 | 6 Per issuer keys with rotation | Done | `vca/services/status-bitstring/internal/config` | |

## ADR-019: Token Status List

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-019 | 1 IETF Token Status List | Done | `vca/core/statuslist/token` | |
| ADR-019 | 2 JWT and CWT representations | Done | `vca/core/statuslist/token/cwt.go` | |
| ADR-019 | 3 Status sizes of 1, 2, 4, and 8 bits | Done | `vca/core/statuslist/token` | |
| ADR-019 | 4 Shared allocation and key code | Done | `vca/services/internal/store` | |
| ADR-019 | 5 Test vectors pinned to the draft | Done | `vca/services/status-token/testdata/vectors` | |

## ADR-020: Wallet OIDC auth flows

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-020 | 1 Citizen login with OIDC and PKCE | Done | `vca/services/wallet-auth/internal/service` | |
| ADR-020 | 2 Short-lived session tokens, no personal data | Done | `vca/services/wallet-auth/internal/service` | |
| ADR-020 | 3 The IdP token as the issuance grant | Done | `vca/services/wallet-auth/internal/service` | |
| ADR-020 | 4 Holder key binding in the browser or the DPG | Done | `vca/services/wallet-portal/internal/blobs`, `vca/services/wallet-portal/internal/portal/holderkey.go`, `vca/services/wallet-auth/internal/service/holderkey.go` | Since 2026-10-04 `wallet.js` binds its signing key once after the browser makes it. `RegisterHolderKey` answers a session token that names the key. `TestTheBrowserBindsItsKeyToTheWallet`, `TestTheBrowserBindsItsKeyOnce`, `TestRegisterHolderKeyRenewsTheSession`, both walkthroughs and `TestWalletScriptInChromium` pin it. |
| ADR-020 | 5 Logout revokes the session | Done | `vca/services/wallet-auth/internal/service` | |
| ADR-020 | 6 Redis-backed rate limit and OTP | Partial | `vca/services/wallet-auth/internal/limits` | The in-process limiter works. The Redis limiter is a stub, because the build network blocks the client. |

## ADR-021: Wallet credentials portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-021 | 1 Discovery page from the aggregated catalogue | Done | `vca/services/wallet-portal/internal/portal` | |
| ADR-021 | 2 Claimable page with a yes or no check | Done | `vca/services/wallet-portal/internal/service` | |
| ADR-021 | 3 Claim, scan, paste, accept, reject | Done | `vca/proto/vca/walletportal/v1` | |
| ADR-021 | 4 DPG wallet storage or browser storage | Done | `vca/services/wallet-portal/internal/blobs` | |
| ADR-021 | 5 OID4VP with a consent screen | Done | `vca/services/wallet-portal/internal/portal` | |
| ADR-021 | 6 Each card shows trust and status | Done | `vca/core/summary` | |

## ADR-022: Verifier schema discovery portal

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-022 | 1 Crawl trusted issuers and cache them | Done | `vca/services/verifier-discovery/internal/crawl` | |
| ADR-022 | 2 Browse issuers, types, and fields | Done | `vca/services/verifier-discovery/internal/portal` | |
| ADR-022 | 3 Templates in DCQL, with PE when needed | Done | `vca/core/dcql` | |
| ADR-022 | 4 Versioned and reusable templates | Done | `vca/services/verifier-discovery/internal/template` | |
| ADR-022 | 5 The catalogue is open to wallets | Done | `vca/proto/vca/discovery/v1` | |

## ADR-023: Verifier multi-format ingestion

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-023 | 1 All listed carriers | Done | `vca/services/verifier-ingest/internal/service` | |
| ADR-023 | 2 One normalised message from pure decoders | Done | `vca/core/ingest` | |
| ADR-023 | 3 QR, Claim 169, and PixelPass decoding | Done | `vca/core/qr`, `vca/core/pixelpass` | |
| ADR-023 | 4 XML ingestion through a configured path | Done | `vca/core/ingest/ingest.go` | |
| ADR-023 | 5 Allowlist and size cap on request fetches | Done | `vca/services/verifier-ingest/internal/oid4vp` | |
| ADR-023 | 6 Camera scanning stays in the browser | Done | `vca/services/verifier-ingest/internal/scanner` | |

## ADR-024: Verifier policy checklist

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-024 | 1 Named checks as pure functions | Done | `vca/core/policy` | |
| ADR-024 | 2 VCA runs the mandatory checks itself | Done | `vca/core/policy`, `vca/services/verifier-ingest/internal/service` | A stack that picks its own nonce returns it in `CreateRequestResponse.nonce`, and `GetResultResponse.nonce` names the nonce of the answered session. The nonce check reads it. `TestStackNonceDecidesTheCheck` pins it. |
| ADR-024 | 3 Status checks with a cached fetcher | Done | `vca/services/verifier-policy/internal/ports` | The fetcher goes through `core/fetchguard` with `ALLOWED_HOSTS`, `ALLOW_PRIVATE_NETWORK`, and `ALLOW_PLAIN_HTTP`. `TestBuildGuardsTheFetcher` pins it. |
| ADR-024 | 4 Trust chain check | Done | `vca/services/verifier-policy/internal/ports` | |
| ADR-024 | 5 Schema check | Done | `vca/core/jsonschema` | |
| ADR-024 | 6 Named policy sets with a version | Done | `vca/services/verifier-policy/internal/service` | |

## ADR-025: Verifier result manager

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-025 | 1 A stored result per verification | Done | `vca/proto/vca/results/v1` | |
| ADR-025 | 2 One card per credential with a check list | Done | `vca/services/verifier-results/internal/portal` | |
| ADR-025 | 3 Retention window, raw data first | Done | `vca/services/verifier-results/internal/results` | |
| ADR-025 | 4 Queries and CSV or JSON export | Done | `vca/services/verifier-results/internal/export` | |
| ADR-025 | 5 A public check page without storage | Done | `vca/services/verifier-results/internal/portal` | |
| ADR-025 | 6 The views meet WCAG 2.2 AA | Done | `vca/ui/a11ytest` | |

## ADR-026: Verifier combined presentation

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-026 | 1 DCQL requests with credential sets | Done | `vca/core/dcql`, `vca/services/verifier-combined/internal/rules` | The check `REQUIRED_MEMBERS` fails a presentation that leaves a required set unanswered. `TestEvaluateCombinedNeedsEveryRequiredMember` pins it. |
| ADR-026 | 2 Combined template with cross rules | Done | `vca/services/verifier-combined/internal/rules` | |
| ADR-026 | 3 Policy per credential, then cross rules | Done | `vca/services/verifier-combined/internal/service` | |
| ADR-026 | 4 Result cards plus a summary card | Done | `vca/services/verifier-results/internal/cards` | |
| ADR-026 | 5 Delegation as the first cross rule set | Done | `vca/core/delegation` | |

## ADR-027: UI overhaul for WCAG 2.2 AA

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-027 | 1 WCAG 2.2 AA with WAI-ARIA 1.2 | Partial | `vca/ui`, `vca/docs/ui.md` | The kit meets the structural criteria. Nobody has audited each portal page against all criteria. |
| ADR-027 | 2 Fix the measured failures | Partial | `vca/ui/static/base.css` | The new kit has none of the named faults. The legacy pages in `verifiably-go/` keep them. |
| ADR-027 | 3 Go and HTMX kit with no third-party module | Done | `vca/ui/components` | |
| ADR-027 | 4 Theme package with a contrast test | Done | `vca/ui/theme` | Superseded in part by ADR-032. |
| ADR-027 | 5 CSS tokens equal the Go constants | Done | `vca/ui/theme` | |
| ADR-027 | 6 Self-hosted font pack | Done | `vca/ui/fonts` | Superseded in part by ADR-032. |
| ADR-027 | 7 Components with one data struct each | Done | `vca/ui/components` | |
| ADR-027 | 8 Accessibility tests in Go at 100 percent | Done | `vca/ui/a11ytest` | |
| ADR-027 | 9 Every page works without JavaScript | Done | `vca/ui/templates` | Superseded in part by ADR-043. |
| ADR-027 | 10 Message catalogues per language | Partial | `vca/ui/components` | The components take a catalogue and set `html lang`. The tree holds the English text alone. |
| ADR-027 | 11 Axe in end to end tests and a manual audit | Partial | `vca/ui/a11ytest` | The Go checks run on each build. No axe job and no manual audit exist yet. |

## ADR-028: Documents in Simplified Technical English

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-028 | 1 ASD-STE100 rules for reader-facing text | Done | `vca/hack/ste-lint.sh` | |
| ADR-028 | 2 English is the source language | Partial | `todo.md`, `verifiably-go/` | The new tree is English. The legacy tree and the root plan file keep the old text. |
| ADR-028 | 3 A short README and a page per service | Done | `vca/README.md`, `vca/docs` | |
| ADR-028 | 4 OpenAPI text from proto comments, linted on each PR | Partial | `vca/Makefile`, `vca/hack/ste-lint.sh` | `make ste-lint` checks the text. No CI job runs it, and the OpenAPI step needs a network. |
| ADR-028 | 5 A catalogue of user-facing errors | Done | `vca/docs/errors.md` | |
| ADR-028 | 6 A glossary of project terms | Done | `vca/docs/glossary.md` | |

## ADR-029: Repository licensing

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-029 | 1 A LICENSE file at the root | Done | `LICENSE` | |
| ADR-029 | 2 Apache-2.0 | Done | `LICENSE` | |
| ADR-029 | 3 An SPDX header in every source file | Done | `vca/core`, `vca/services` | |
| ADR-029 | 4 Documents under CC-BY-4.0 | Done | `docs/LICENSE` | |
| ADR-029 | 5 Third-party notices from the SBOM | Partial | `NOTICE` | The file names the rule. The release workflow fills the list at tag time. |
| ADR-029 | 6 Purge the committed secrets from history | Deferred | `vca/docs/release-checklist.md` | The purge is a release step on the mirror. The tree itself holds no secret now. |

## ADR-030: Migration from the current codebase

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-030 | 1 Lift the tested packages into the core | Done | `vca/core` | |
| ADR-030 | 2 Lift the DPG interop knowledge | Done | `vca/services/dpg-adapter-*` | |
| ADR-030 | 3 Rewrite handlers, main, templates, scripts | Done | `vca/services`, `vca/ui`, `vca/hack` | |
| ADR-030 | 4 Drop the hand-rolled infrastructure | Partial | `vca/services/internal/serve/trace` | The tree has no tracing or Redis package of its own. The upstream SDK and client wait for network access. |
| ADR-030 | 5 Drop the archived dependencies | Done | `vca/core/pdf`, `vca/core/qr` | |
| ADR-030 | 6 Keep the quality gate and the scope documents | Done | `vca/.golangci.yml` | |
| ADR-030 | 7 Build in order, then retire the monolith | Not started | `verifiably-go/` | The services follow the order. No role has moved off the monolith, so the monolith still runs. |
| ADR-030 | 8 Data migration with a migrate command | Done | `vca/internal/migrate` | |

## ADR-031: BBS selective disclosure

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-031 | 1 Target the W3C BBS cryptosuites | Deferred | `ADR.md` | The record defers the work until Recommendation status or two interoperable DPGs. |
| ADR-031 | 2 Reserve the contract places now | Done | `vca/core/policy/derived.go` | |
| ADR-031 | 3 Derivation helpers in the core | Deferred | `vca/core` | No DPG on the matrix issues `bbs-2023` proofs, so the helpers wait. |
| ADR-031 | 4 SD-JWT VC and mdoc until then | Done | `vca/core/sdjwt` | |
| ADR-031 | 5 A quarterly check of the specification | Not started | `vca/docs` | The new tree has no spec-versions page that records the check. |

## ADR-032: Theme and brand from one declarative file

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-032 | 1 One theme file with a path variable | Done | `deploy/vca/theme.yaml`, `vca/internal/themefile` | Every UI service reads `VCA_THEME_FILE`. `TestShippedFileEqualsEmbeddedDefault` and `TestLoadEmptyPathUsesDefault` pin it. |
| ADR-032 | 2 The kit keeps the pairings, the file sets colours | Done | `vca/ui/theme`, `vca/internal/themefile` | `TestLowContrastNamesPairingAndRatio` and `TestDefaultPairingsCoverBrandPairings` pin it. |
| ADR-032 | 3 Two font families and a monospace stack | Done | `vca/ui/fonts` | |
| ADR-032 | 4 Wordmark, logo, radii, spacing, role accents | Done | `vca/internal/themefile/themefile.go` | `TestRebrandExample` and `TestBadPaperDropsRoleAccentLine` pin it. |
| ADR-032 | 5 The YAML reader lives outside the kit | Done | `vca/internal/themefile` | The kit under `vca/ui` imports no YAML module. |
| ADR-032 | 6 Theme check and theme apply commands | Done | `vca/internal/cli/theme.go` | `TestThemeCheckFailsAndNamesPairing` and `TestThemeApplyRestartsOnlyUIServices` pin it. |

## ADR-033: Landing service, role picker, and role intro pages

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-033 | 1 A stateless landing service | Done | `vca/services/landing` | |
| ADR-033 | 2 One landing container per deployment | Done | `deploy/vca/compose.yaml` | |
| ADR-033 | 3 Short text on VCA, the DPGs, and the triangle of trust | Done | `vca/services/landing/internal/pages` | |
| ADR-033 | 4 Live stacks with pinned versions and links | Done | `vca/services/landing/internal/pages` | |
| ADR-033 | 5 The role picker lists live roles only | Done | `vca/services/landing/internal/pages` | |
| ADR-033 | 6 Role intro pages with step cards and sign in | Done | `vca/services/landing/internal/pages` | The sign in band names the provider and the realm from `/auth/providers.json` of the pair. |

## ADR-034: Backend adaptivity through a peer topology and feature lists

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-034 | 1 The CLI writes the peer list | Done | `vca/internal/cli/services.go` | `VCA_PEERS` reaches every UI service, the auth services, admin, and the landing. |
| ADR-034 | 2 A shared probe with a timeout and a cache | Done | `vca/internal/topology` | |
| ADR-034 | 3 Absent, starting, and live pairs | Done | `vca/internal/topology` | The landing reads the states. The portals follow. |
| ADR-034 | 4 Features and DPG information in the adapter answer | Done | `vca/proto/vca/backend/v1` | Each adapter lists only the features whose RPC works today. |
| ADR-034 | 5 Pages show live features only | Done | `vca/internal/topology`, the portal packages | Each page reads the feature list of the live adapter. The `...OnlyWithFeature` tests of every portal pin it. |

## ADR-035: Provider agnostic sign in with one realm per role

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-035 | 1 Four realms with self registration | Done | `vca/internal/cli/realm.go`, `vca/internal/cli/setup.go` | Setup writes `vca-<role>-realm` per stack. `TestBootstrapCreatesTheRoleRealm` and `TestRealmRegistrationOff` pin it. |
| ADR-035 | 2 Keycloak is a provider record, not a dependency | Done | `vca/services/internal/oidcflow`, `vca/services/admin/internal/onboard` | Keycloak is the preset of kind `keycloak`. Other kinds such as WSO2 and eSignet use the same record. |
| ADR-035 | 3 Register action with a fallback | Done | `vca/services/internal/signin` | The chooser of every auth service offers `/auth/register` when the provider supports it. |
| ADR-035 | 4 Three token authentication methods | Done | `vca/services/internal/oidcflow/provider.go` | `client_secret_basic`, `client_secret_post` and `private_key_jwt`. `TestTokenExchangeClientSecretPost`, `TestTokenExchangePrivateKeyJWT` and `TestPresetESignetUsesPrivateKeyJWT` pin them. |
| ADR-035 | 5 The admin portal pushes provider records | Done | `vca/services/admin/internal/fanout` | `CreateAuthProvider` and `UpdateAuthProvider` push to the auth service of every live pair the record names, with the admin session token. The auth services accept it through `oidcflow.AdminJWTAuthorizer`. One audit record per target. |
| ADR-035 | 6 The first admin registers and binds | Done | `vca/services/admin`, `vca/internal/cli/realm.go` | The admin chooser binds with the bootstrap token. The first run checklist marks "Turn off self registration" when `vca dpg realm` runs, and the deploy report lists the steps (P7-01). |
| ADR-035 | 7 The CLI makes the Keycloak password | Done | `vca/internal/cli/setup.go` | Setup generates `KEYCLOAK_ADMIN_PASSWORD` per stack. `TestSetupKeepsTheKeycloakPasswordAcrossRoles` pins it. |

## ADR-036: Verifier staff sign in

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-036 | 1 A verifier-auth service per verifier pair | Done | `vca/services/verifier-auth` | Audience `vca-verifier`, roles `verifier-admin`, `verifier-operator`, `verifier-viewer`. |
| ADR-036 | 2 Verifier staff pages need a session | Done | `vca/services/internal/staffsession` | `verifier-results`, `verifier-discovery`, and `verifier-ingest` guard their staff pages. The citizen check, the catalogue, and the OID4VP endpoints stay open. |
| ADR-036 | 3 Issuer staff pages get the same guard | Done | `vca/services/internal/staffsession` | `schema-registry`, `schema-builder-ui`, and the issuer home of `issuance` guard their pages against `issuer-auth`. |

## ADR-037: Tenants mapped to DPG tenancy

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-037 | 1 A VCA tenant binds to DPG tenants | Done | `vca/services/admin/internal/service/tenants.go` | `TestCreateTenantBindsToStacks` and `TestBindAndUnbindTenant` pin it. |
| ADR-037 | 2 A tenant backend service in the contract | Done | `vca/proto/vca/backend/v1/backend.proto` | `TenantBackendService`. The CREDEBL adapter serves it, and walt.id and Inji answer `unimplemented`. |
| ADR-037 | 3 Tenancy shows only on stacks that have it | Done | `vca/services/admin/internal/portal/tenants.go` | `TestTenantFormOffersOnlyTenancyStacks` pins it. |

## ADR-038: API keys for VCA and for stacks

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-038 | 1 Tenant scope and expiry on VCA keys | Done | `vca/services/admin/internal/portal/keys.go` | `TestKeyFormHasTenantAndExpiry` pins it. |
| ADR-038 | 2 Stack client credentials next to VCA keys | Done | `vca/services/admin/internal/portal/keys.go` | `TestStackCredentialShownOnce` and `TestStackCredentialFormHidesAFullTenant` pin it. |

## ADR-039: Federated audit log

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-039 | 1 An audit service in each recording service | Done | `vca/proto/vca/audit/v1`, `vca/services/internal/auditlog` | The auth services, `issuance`, `issued-credentials`, `trust-registry`, `verifier-results`, and `admin` record events and serve them to the admin only. The service has a second RPC, `SetRetention`, for the retention of each store. |
| ADR-039 | 2 The admin page merges the live peers | Done | `vca/services/admin/internal/auditfed`, `vca/services/admin/internal/portal/audit.go` | The page asks every live peer at once within a budget and names each store that does not answer. It exports CSV and sets the retention. |
| ADR-039 | 3 Events carry no claim values | Done | `vca/services/internal/auditlog`, `vca/services/internal/oidcflow/audit.go` | A failure names a fixed reason or the Connect code, never the error text. The wallet actor is a salted hash. |

## ADR-040: Notifications page before notification delivery

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-040 | 1 Notifications pages list the channels | Done | `vca/services/admin/internal/portal`, `vca/services/issuance/internal/pages` | The admin and the issuer pages list email, SMS, and the VCA webhook as not built in this release. |
| ADR-040 | 2 DPG webhooks and callbacks when the adapter lists them | Done | `vca/services/admin/internal/portal`, `vca/services/issuance/internal/pages` | CREDEBL lists `FEATURE_WEBHOOKS` (ADR-067) and walt.id lists `FEATURE_SESSION_CALLBACKS` (P6-W5). The pages show each card only then. |

## ADR-041: Verifier trust cache and offline verification window

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-041 | 1 Signature checked snapshots | Done | `vca/services/verifier-policy/internal/cache`, `vca/services/trust-registry/internal/service` | The cache keeps the signed snapshot of `ExportSnapshot`, the registry keys, the X.509 anchor chains, and the status lists. It checks each copy first and keeps the last good copy on a failure. The document cache keeps a status list token no longer than its `ttl` (`TestCacheHonoursTheTtlOfAStatusListToken`). |
| ADR-041 | 2 A refresh schedule per source | Done | `vca/services/verifier-policy/internal/cache` | Trust list 6 h, keys 24 h, status lists 1 h by default. `SetCachePolicy` changes them. |
| ADR-041 | 3 An offline window of at most seven days | Done | `vca/services/verifier-policy/internal/cache`, `vca/proto/vca/results/v1` | A check reads a copy only when the source does not answer. The result carries `material_age`. |
| ADR-041 | 4 A stale status list fails the check | Done | `vca/core/policy`, `vca/services/verifier-policy/internal/cache` | `policy.ErrStale` fails the status check in every fail mode when the policy refuses stale status lists. |
| ADR-041 | 5 Cache RPCs and a caching page | Done | `vca/proto/vca/policy/v1`, `vca/services/verifier-results/internal/portal` | `/portal/cache/` shows the state, Sync now, and the policy form. The overview card shows the age and the window. Sync now also hands each fresh status list to the document cache of a check. `TestSyncHandsEachFreshStatusListOn` and the CREDEBL walkthrough pin it. |

## ADR-042: DCQL builder and DIF Presentation Exchange queries

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-042 | 1 A template has a kind | Done | `vca/proto/vca/discovery/v1`, `vca/services/verifier-discovery/internal/portal` | DCQL, PE, and native templates. The AnonCreds builder saves the native kind (ADR-061). |
| ADR-042 | 2 A DCQL builder with a live query view | Done | `vca/core/dcql`, `vca/services/verifier-discovery/internal/portal` | Values, claim sets, and credential sets in `core/dcql`. The preview works without JavaScript. |
| ADR-042 | 3 A claim predicate policy check | Done | `vca/core/policy`, `vca/services/verifier-discovery/internal/service`, `vca/services/verifier-ingest/internal/service` | The rules of a query become the policy set `query-<id>`. The ingestion service evaluates each answer of a request with that set. |
| ADR-042 | 4 PE authoring, validation, and conversion | Done | `vca/services/verifier-discovery/internal/portal`, `vca/services/verifier-discovery/internal/template` | The page at `/discovery/pe/` authors, imports, checks, converts, and versions PE queries. Each conversion shows its loss report. |
| ADR-042 | 5 A pure core package for PE | Done | `vca/core/pex` | Validation against the vendored PE 2.0 schema, and conversion both ways with a loss report. |

## ADR-043: Issuance channels and bulk sources

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-043 | 1 The list of channels | Done | `vca/services/issuance/internal/pages`, `vca/services/issuance/internal/service/issue.go` | The page offers both OID4VCI channels, the Digital Credentials API, and QR on a PDF. It adds the Claim 169 QR, the DIDComm invitation, and the stack email when the adapter lists each. |
| ADR-043 | 2 The page offers live channels only | Done | `vca/services/issuance/internal/pages/issue.go` | `TestDeliveryOptionsFollowCapabilities`. |
| ADR-043 | 3 Digital Credentials API button with a fallback | Done | `vca/ui/static/dcapi.js`, `vca/services/issuance/internal/pages/result.go` | `TestDcApiButtonCarriesOffer`, `TestDcApiFallbackQRAlwaysPresent`. |
| ADR-043 | 4 Bulk issuance from data sources | Done | `vca/services/data-source/internal/pages`, `vca/services/issuance/internal/service/batch.go` | CSV, SQL, and HTTP sources, field map, run, progress, and export. The native import shows when the adapter lists `FEATURE_BULK_NATIVE`. The CREDEBL adapter lists it with a mail provider (ADR-060). |

## ADR-044: Placement of the role pages

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-044 | 1 The issuer home moves to issuance | Done | `vca/services/issuance/internal/pages`, `vca/internal/topology` | `issuance` serves `/issuer/`, `/identity/`, `/issue/`, `/notifications/`, `/help/`, and the shared assets. |
| ADR-044 | 2 Issued credentials and sources pages | Done | `vca/services/data-source/internal/pages`, `vca/services/issued-credentials/internal/pages` | Both run in the issuer shell behind the staff guard. |
| ADR-044 | 3 The verifier home stays on verifier-results | Done | `vca/services/verifier-results/internal/portal` | The overview sits at `/portal/`, the results at `/portal/results/`, the caching page at `/portal/cache/`. An old list URL moves with a `301`. |
| ADR-044 | 4 DCQL, PE, and request pages | Done | `vca/services/verifier-discovery/internal/portal`, `vca/services/verifier-ingest/internal/scanner/request.go` | `/discovery/dcql/`, `/discovery/pe/`, and the request pages under `/scan/requests/`. `TestDcqlBuilderPreviewMatchesSaved` and `TestRequestsListShowsVerdict` pin them. |
| ADR-044 | 5 One role navigation package bound to the routes | Done | `vca/internal/rolenav`, `vca/services/internal/staffshell` | The admin, issuer, holder, and verifier pages draw their side navigation from the package. |

## ADR-045: Full DPG surfacing

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-045 | 1 Each adapter lists every feature of its DPG | Partial | `vca/services/dpg-adapter-*` | Phase 6 lists the features in each adapter document. Gaps stay: EBSI conformance of walt.id, and a dedicated CREDEBL agent without the Docker socket. The CREDEBL platform also makes an organisation DID only with a key of the operator (ADR-070). |
| ADR-045 | 2 New format, protocol, and channel values | Done | `vca/proto/vca/common/v1`, `vca/proto/vca/backend/v1` | `FORMAT_ANONCREDS`, the DIDComm protocols, `PROTOCOL_DC_API`, `CHANNEL_DC_API`, `CHANNEL_DIDCOMM_OOB`, and `CHANNEL_CLAIM169_QR`. |
| ADR-045 | 3 The holder uses the DPG wallet | Done | `vca/services/wallet-portal`, `vca/services/dpg-adapter-*` | The walt.id wallet API, Inji Web through Mimoto, and a tenant wallet of the CREDEBL agent. That wallet replaces the cloud wallet service (ADR-062). The browser store stays for a stack with none. |
| ADR-045 | 4 The whole CREDEBL platform, pinned by digest | Done | `deploy/vca/dpg/credebl.yaml` | `TestCredeblStackRunsEveryPlatformService` and `TestCredeblStackRunsOneReleaseLine` pin it. The status list host builds at one commit (ADR-069). |
| ADR-045 | 5 The walt.id stack adds verifier-api2 | Done | `deploy/vca/dpg/waltid.yaml` | `TestDpgStackFilesExistAndArePinned` and `TestDoctorChecksTheVerifier2Port` pin it. |

## ADR-046: Issuer identity through the DPG

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-046 | 1 Issuer identity RPCs | Done | `vca/proto/vca/backend/v1` | `GetIssuerIdentity`, `ProvisionIssuerIdentity`, and `ImportIssuerIdentity`. The Inji and CREDEBL adapters answer `unimplemented` until P6-I9 and P6-C1. |
| ADR-046 | 2 One click provision or an import | Done | `vca/services/issuance/internal/pages`, `vca/services/dpg-adapter-*` | walt.id provisions and imports a DID or an X.509 chain. Inji provisions and imports a chain (P6-I9). CREDEBL imports a chain; ADR-070 records why its pinned release makes no DID in one click. The walt.id import checks the key, the chain, and the dates of the leaf as CREDEBL does. `TestImportX509ChecksTheChain` pins it. |
| ADR-046 | 3 Trust registry entry in state pending | Done | `vca/services/issuance/internal/pages/identity.go` | The identity page writes a pending entry in the trust registry of the first live admin pair. |
| ADR-046 | 4 No issuer private key in VCA | Done | `vca/services/dpg-adapter-waltid` | The walt.id key stays in the adapter state file with mode 0600, as the decision records. |

## ADR-047: The public RPC surface of a pair

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-047 | 1 Only services with a caller check go public | Done | `vca/internal/cli/publicrpc_test.go`, `vca/services/internal/rpcguard` | The admin, the three auth services, and their `AdminService` are public. Each has `TestAnonymousRPCsAreRefused`. |
| ADR-047 | 2 Internal services stay on the compose network | Done | `vca/internal/cli/services.go`, `vca/internal/cli/dpgconfig.go` | The `Caddyfile` answers `404` to `/vca.*`, and the holder pair to `/auth/vca.*` too. |
| ADR-047 | 3 The CLI uses host ports on `VCA_BIND` | Done | `vca/internal/cli/bootstrap.go` | `vca dpg bootstrap waltid` calls the adapter at `127.0.0.1`. Every other command calls the public `AdminService`. |
| ADR-047 | 4 Protocol paths stay public | Done | `vca/internal/cli/services.go`, `vca/docs/deploy.md` | The status services and the trust registry publish their lists and key sets only. |

## ADR-048: Client assertion keys of a login provider

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-048 | 1 The key type decides the algorithm | Done | `vca/services/internal/oidcflow/flow.go`, `vca/core/jose` | `SignRS256` refuses a key under 2048 bits. |
| ADR-048 | 2 RS256 for a provider that takes nothing else | Done | `vca/core/jose/jose.go` | `Sign` keeps ES256 and EdDSA only. |
| ADR-048 | 3 The eSignet client of the Inji stack | Done | `vca/internal/cli/bootstrap_esignet.go` | The key lives in `deploy/esignet-inji/vca-client.pem`. |

## ADR-049: Two authorization modes of Inji Certify in the Inji stack

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-049 | 1 Two Certify containers on one database and one key store | Done | `deploy/vca/dpg/inji.yaml` | The volume `inji-certify-keys` holds the key store of both. |
| ADR-049 | 2 `inji-certify` is its own authorization server | Done | `deploy/vca/dpg/inji/certify/certify-vca-store.properties` | Superseded by ADR-051. The data provider becomes the VCA claims store. |
| ADR-049 | 3 `inji-certify-esignet` takes eSignet tokens | Done | `deploy/vca/dpg/inji/certify/certify-authcode.properties`, `vca/services/dpg-adapter-inji` | Superseded by ADR-051. The second container takes the tokens of the holder authorization server. |
| ADR-049 | 4 The second container waits for the keys | Done | `deploy/vca/dpg/inji.yaml` | It waits for the readiness check of `inji-certify`. |
| ADR-049 | 5 The doctor names a floor above the target | Done | `vca/internal/cli/dpgconfig.go`, `vca/internal/cli/doctor.go` | The floor report marks `issuer-inji` and `holder-inji`. |

## ADR-050: No mock or sample data in anything VCA ships or deploys

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-050 | 1 No mock artefact or sample data set ships | Done | `vca/`, `deploy/` | `vca dpg bootstrap inji` adds no identity. The Inji stack runs no mock identity system. The guard finds no artefact, and `TestNoPendingRemovals` keeps a list of pending findings out. `hack/contract-tests.sh` refuses a deployment with sample data. |
| ADR-050 | 2 A configurable workflow replaces each artefact | Done | `vca/services`, `vca/internal/cli` | Setup generates the stack secrets and asks for the certificate subject (ADR-055). Certify issues from the claims store (ADR-051), and the holder authorization server replaces eSignet for a claim (ADR-052). eSignet runs only with a real authenticator and signs holders in (ADR-053). Setup writes the walt.id catalogue and wallet files (ADR-054). The admin portal manages the holder providers of the Inji adapter (ADR-052 decision 2). |
| ADR-050 | 3 Test doubles stay in test paths | Done | `vca/internal/cli/nomock_test.go` | `TestNoDeploymentReachesTestdata` and `TestNoBinaryImportsAFakePackage` keep test doubles out of every deployment. |
| ADR-050 | 4 A guard test scans the tree | Done | `vca/internal/cli/nomock_test.go` | The word rule covers every stack file, every Go source that a binary compiles, every Dockerfile, and the operator documents. The allowlist gives a reason per entry and fails on an entry that matches nothing. |
| ADR-050 | 5 A stack secret has no default | Done | `deploy/vca/dpg/*.yaml`, `vca/internal/cli/stackenv.go` | Every stack file requires its passwords with `${NAME:?set by vca setup}`. `TestStackFilesHaveNoSecretDefault` pins it. |

## ADR-051: The VCA claims store is the data provider of Inji Certify

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-051 | 1 Certify reads `certify.vca_claims` | Done | `deploy/vca/dpg/inji/certify/vca_claims.sql`, `deploy/vca/dpg/inji/certify/certify-vca-store.properties` | Both containers run `PostgresDataProviderPlugin` on the foreign table. `TestInjiStackRunsCertifyOnTheVcaStore` pins it. The nightly contract run confirms it against a running Certify. |
| ADR-051 | 2 The adapter writes one file per subject | Done | `vca/services/dpg-adapter-inji/internal/claims` | The volume `inji-claims` sits in memory. The adapter renames each finished file and sweeps expired rows. |
| ADR-051 | 3 One scope for every configuration | Done | `vca/services/dpg-adapter-inji/internal/inji/configs.go` | Every configuration has the scope `vca_credential`. ADR-056 decision 1 adds a guard on `config_id` to every template. |
| ADR-051 | 4 Templates read the columns `c1` to `c64` | Done | `vca/services/dpg-adapter-inji/internal/inji/configs.go`, `vca/services/dpg-adapter-inji/internal/service/configs.go` | The adapter keeps the claim order with the registration. |
| ADR-051 | 5 The subject key per flow | Done | `vca/services/dpg-adapter-inji/internal/service/issuer.go`, `vca/services/dpg-adapter-inji/internal/authz` | The pre-authorized code stages the staging id. A presentation during issuance names its holder. The holder authorization server puts the staging id in its token. |
| ADR-051 | 6 The adapter serves the presentation definition | Done | `vca/services/dpg-adapter-inji/internal/service/iar.go` | `SetPresentationRequirement` stores it. The card "Presentation during issuance" of the issuer identity page sets it (`vca/services/issuance/internal/pages/requirement.go`). |

## ADR-052: The holder authorization server of the Inji adapter

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-052 | 1 An authorization server under `/authz` | Done | `vca/services/dpg-adapter-inji/internal/authz`, `vca/internal/cli/services.go` | RFC 8414 metadata, a key set, authorize, callback, and token. The proxy of the issuer pair publishes `/authz/*`. |
| ADR-052 | 2 The holder signs in at the configured provider | Done | `vca/services/dpg-adapter-inji/internal/app/app.go`, `vca/internal/cli/dpgconfig.go`, `vca/services/admin/internal/portal/signin.go` | Setup seeds the holder realm of the stack Keycloak and the client `vca-inji-authz`. The registry lives in the store of the adapter. With eSignet, setup names it as the holder provider (ADR-053 decision 4). The admin portal adds, edits, turns off and removes holder providers, with their verified claims and the default flag. A seed stays until an admin changes it. `TestHolderProvidersAreManaged` and `TestAnAdminRemovalOfAHolderProviderStays` pin it. |
| ADR-052 | 3 Offer bound and wallet initiated claims | Done | `vca/services/dpg-adapter-inji/internal/authz/authorize.go`, `vca/services/issuance/internal/pages/issue.go`, `vca/services/schema-registry/internal/portal/signin.go` | The binding rule works end to end. The tab "Claims by sign in" names the source of a claim without an offer, and `DataSourceService.Lookup` answers it (ADR-057). |
| ADR-052 | 4 A JWT whose subject is the staging id | Done | `vca/services/dpg-adapter-inji/internal/authz/token.go` | RS256, five minutes, `aud` the credential endpoint of `inji-certify-authcode`. |
| ADR-052 | 5 Registered wallet clients | Done | `vca/services/dpg-adapter-inji/internal/authz/clients.go`, `vca/internal/cli/inji_public.go` | `vca-inji` of Inji Web uses `private_key_jwt` with the key that the holder bootstrap wrote. |
| ADR-052 | 6 The token key signs access tokens only | Done | `vca/services/dpg-adapter-inji/internal/authz/keys.go` | The key sits in the store under AES-256-GCM with the pair session key. |

## ADR-053: eSignet runs only with a real authenticator

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-053 | 1 eSignet under the profile `esignet-inji` | Done | `deploy/vca/dpg/inji.yaml`, `vca/internal/cli/deploy.go`, `vca/internal/cli/esignet.go` | `vca deploy` adds the profile when the pair names an authenticator. `TestDeployAddsTheEsignetProfile` pins it. |
| ADR-053 | 2 The mock components leave the stack | Done | `deploy/vca/dpg/inji.yaml`, `deploy/vca/dpg/inji/esignet/init.sql` | `TestInjiStackRunsEsignetOnlyWithAnAuthenticator` pins it. |
| ADR-053 | 3 The operator supplies the plugin file | Done | `vca/internal/cli/esignet.go`, `proto/vca/config/v1/config.proto` | Setup copies the properties and a custom jar to `deploy/esignet-inji` with mode 0600. |
| ADR-053 | 4 Bootstrap registers the client only when eSignet runs | Done | `vca/internal/cli/bootstrap.go`, `vca/internal/cli/esignet.go`, `vca/services/dpg-adapter-inji/internal/app/app.go` | Bootstrap registers the client only then, with the callback of the holder authorization server. Setup names the client and its key, and the adapter adds eSignet as a holder provider with `private_key_jwt`. `TestBuildSeedsEsignetAsTheHolderProvider` pins it. The server reads the signed userinfo answer of eSignet for the claims of a person (`vca/services/internal/oidcflow/userinfo.go`). `TestABindingMatchesAVouchedUserinfoClaim` pins it. |
| ADR-053 | 5 The feature answer lists eSignet only when it runs | Done | `vca/services/dpg-adapter-inji/internal/service/dpginfo.go` | `VCA_INJI_ESIGNET_URL` turns it on. `TestCapabilitiesListEsignetOnlyWhenConfigured` pins it. |

## ADR-054: VCA writes the walt.id catalogue and wallet configuration

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-054 | 1 Setup writes the issuer catalogue | Done | `vca/internal/cli/waltid_config.go`, `deploy/vca/dpg/waltid.yaml` | One entry per wire format with the prefix `vca_`. `TestIssuerCatalogueHasOneEntryPerFormatAndNoDemoType` pins it. |
| ADR-054 | 2 The adapter answers discovery from its registrations | Done | `vca/services/dpg-adapter-waltid/internal/waltid/build.go`, `vca/services/dpg-adapter-waltid/internal/service/verifier.go` | The adapter borrows `vca_` entries only. `TestListCredentialTypesShowsRegistrationsOnly` pins the list. |
| ADR-054 | 3 Setup writes the wallet configuration | Done | `vca/internal/cli/waltid_config.go`, `vca/internal/cli/stackenv.go` | The keys and the pepper live in `deploy/waltid/.env`. `vca dpg upgrade-secrets` writes `db.conf` again. The login token uses HS256 with a generated key. |
| ADR-054 | 4 The CLI writes files and restarts containers | Done | `vca/internal/cli` | The adapter writes no file. Setup writes the files, and `vca deploy` starts the containers on them. The nightly contract run starts the wallet API on the files. |

## ADR-055: Stack secrets and identities come from setup or the operator

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-055 | 1 Setup generates every stack secret | Done | `vca/internal/cli/stackenv.go`, `deploy/vca/compose.yaml` | Every setup run writes `deploy/<dpg>/.env` for each stack with mode 0600 and keeps the values it finds. The include of each stack file reads it. |
| ADR-055 | 2 Empty values for platform services the stack does not run | Done | `deploy/vca/dpg/inji/mimoto/mimoto-default.properties`, `deploy/vca/dpg/inji/certify/certify-default.properties` | `TestMimotoRunsNoPlatformSecret` pins the empty values. |
| ADR-055 | 3 The certificate subject names the issuer | Done | `vca/internal/cli/stackenv.go`, `deploy/vca/dpg/inji` | Setup asks for the organisation and the unit of an Inji issuer or holder pair. The common name is the public host. |
| ADR-055 | 4 The CREDEBL platform admin is a required setting | Done | `proto/vca/config/v1/config.proto`, `vca/internal/cli/credebl.go`, `vca/internal/cli/bootstrap.go`, `deploy/vca/dpg/credebl.yaml` | `VCA_CREDEBL_PLATFORM_ADMIN_EMAIL` has no default. Bootstrap runs the database initialisation of the release once and signs in as that admin. `TestBootstrapCredeblRunsTheSeedOnce` pins it. |
| ADR-055 | 5 The secret scan checks `key=value` files | Done | `vca/hack/secret-scan.sh`, `vca/hack/secret-scan_test.sh` | The rule covers `.properties`, `.conf`, `.ini` and `.env` files. `TestSecretScanScript` runs the cases. |

## ADR-056: The claims store and the holder authorization server refuse what a claim did not stage

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-056 | 1 A guard on `config_id` in every template | Done | `vca/services/dpg-adapter-inji/internal/inji/configs.go` | `TestARowOfOneConfigurationIssuesNoOtherConfiguration` shows that a farmer row gives no medical licence through the fake Certify. Publish every schema again after the upgrade. |
| ADR-056 | 2 Binding only on vouched claims | Done | `vca/services/dpg-adapter-inji/internal/authz/bind.go`, `vca/services/issuance/internal/pages/issue.go`, `vca/internal/cli/dpgconfig.go` | `TestBindingNeedsAClaimTheProviderVouchesFor` pins the rule. The wizard offers `email`, `sub` and `phone_number` and warns about the rest. The Inji holder realm sets `verifyEmail`. `VCA_INJI_HOLDER_OIDC_VERIFIED_CLAIMS` fills an empty list, and the admin portal edits it through the provider RPCs of the adapter (`vca/services/admin/internal/portal/signin.go`). |
| ADR-056 | 3 The row lives as long as its token | Done | `vca/services/dpg-adapter-inji/internal/authz`, `deploy/vca/dpg/inji/certify/certify-vca-store.properties` | The row lives `RowTTL`, seven minutes. The query casts `expires_at` and compares it with `now()`. `TestCertifyPropertiesNameThePostgresProvider` pins it. |
| ADR-056 | 4 Offer claims go at the token or at expiry | Done | `vca/services/dpg-adapter-inji/internal/service/holderclaim.go`, `vca/services/dpg-adapter-inji/internal/authz/token.go`, `vca/services/dpg-adapter-inji/internal/app/app.go` | `Finish` drops the subject after the token. `SweepOffers` deletes expired offers. A code that fails before any token reopens its offer and logs at Warn. |
| ADR-056 | 5 Bounded parameters, a rate limit, no store walk | Done | `vca/services/dpg-adapter-inji/internal/authz/limit.go`, `vca/services/dpg-adapter-inji/internal/authz/authorize.go`, `vca/services/internal/store/store.go` | The limit sits in the handler, because the stock Caddy has no rate limit module. The file store walks only the folder of a prefix. |
| ADR-056 | 6 A key ring and a rotation command | Done | `vca/services/dpg-adapter-inji/internal/authz/keys.go`, `vca/internal/cli/rotate.go` | The adapter serves the rotation at `/internal/authz/rotate-key` on its host port. `TestNoPublicRouteReachesTheRotation` pins that no route leads there. |
| ADR-056 | 7 Claim values without control characters | Done | `vca/services/dpg-adapter-inji/internal/claims/claims.go`, `vca/services/dpg-adapter-inji/internal/inji/claims.go` | `CreateOffer` refuses the value with the claim name. `Put` refuses any field. |

## ADR-057: The holder sign in reads one row of a data source with a service token of its pair

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-057 | 1 `Lookup` returns the one row of a value | Done | `vca/services/data-source/internal/service/service.go`, `vca/services/data-source/internal/reader/reader.go` | `TestLookupCsvByField` and `TestLookupHttpFiltersRows` pin it. Two rows set `ambiguous`. |
| ADR-057 | 2 A service token of the pair opens `Lookup` only | Done | `vca/services/internal/servicetoken`, `vca/services/data-source/internal/authz/authz.go`, `vca/services/dpg-adapter-inji/internal/authz/datasource.go` | `TestServiceTokenOpensLookupOnly` pins it. No route of the proxy leads to the RPCs. |
| ADR-057 | 3 A source names `holder-sign-in` on its issue rule | Done | `vca/services/schema-registry/internal/portal/signin.go` | The tab adds the role with the session of the staff member. |
| ADR-057 | 4 A staff test gets masked values | Done | `vca/services/data-source/internal/service/service.go` | `TestLookupMasksTheRowForStaff` pins it. |
| ADR-057 | 5 The SQL kind filters in the database | Done | `vca/services/data-source/internal/sqlsrc/sqlsrc.go` | `TestLookupSqlWrapsTheQuery` records the statement and its argument. |
| ADR-057 | 6 Only a vouched claim names a source | Done | `vca/services/dpg-adapter-inji/internal/service/signin.go` | `TestHolderSignInSourceNeedsAVouchedClaim` pins it. The server checks the claim again at each claim. |

## ADR-058: The CREDEBL platform runs on generated credentials, its own realm, and the webhook of its gateway

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-058 | 1 Setup writes the master table of the initialisation | Done | `vca/internal/cli/credebl_master.go`, `deploy/vca/dpg/credebl.yaml` | `TestNoUpstreamCredeblCredentialSurvives` pins it. |
| ADR-058 | 2 The platform realm in the Keycloak of the stack | Done | `vca/internal/cli/credebl_realm.go`, `deploy/vca/dpg/credebl.yaml` | `TestSetupWritesTheCredeblPlatformRealm` pins it. |
| ADR-058 | 3 The bootstrap run creates a missing platform realm | Done | `vca/internal/cli/credebl_realm.go` | `TestBootstrapCredeblCreatesThePlatformRealm` pins it. |
| ADR-058 | 4 The shared agent sends its events to the gateway | Done | `vca/internal/cli/credebl_webhook.go`, `deploy/vca/dpg/credebl.yaml` | `TestBootstrapCredeblPointsTheAgentWebhook` pins it. |

## ADR-059: DIDComm issuance channels and the formats each channel carries

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-059 | 1 DIDComm offers, out of band and over a connection | Done | `vca/services/dpg-adapter-credebl/internal/service/didcomm.go` | `TestOobOfferGivesInvitation` and `TestConnectionOfferNamesTheRecord` pin it. |
| ADR-059 | 2 The formats of each channel | Done | `vca/services/issuance/internal/service/issue.go`, `vca/services/issuance/internal/pages/issue.go` | `TestIssueRefusesAFormatTheChannelDoesNotCarry` and `TestDeliveryCardsFollowTheDidcommChannels` pin it. |
| ADR-059 | 3 A stack that mails its own offers | Done | `vca/services/issuance/internal/service/issue.go` | `TestIssueByEmailThroughTheStack` pins it. |
| ADR-059 | 4 The configuration of a DIDComm format, and no status entry | Done | `vca/services/issuance/internal/service/issue.go` | `TestIssueOverTheDidcommChannel` pins it. |
| ADR-059 | 5 The wallet portal names a DIDComm invitation | Done | `vca/services/wallet-portal/internal/detect/didcomm.go`, `vca/services/wallet-portal/internal/portal/didcomm.go` | `TestWalletDetectsOobInvitation` pins it. |
| ADR-059 | 6 The file volume, the mail provider, and the values of the operator | Done | `deploy/vca/dpg/credebl.yaml`, `vca/internal/cli/stackenv.go` | `TestCredeblStackKeepsFilesOnAVolume` and `TestStackEnvKeepsTheValuesOfTheOperator` pin it. |

## ADR-060: The CSV bulk import of a stack that mails each row

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-060 | 1 The bulk import in the answer of GetCapabilities | Done | `vca/proto/vca/backend/v1/backend.proto`, `vca/services/issuance/internal/clients/clients.go` | `TestFeatureBulkNativeListed` and `TestCapabilitiesNameTheBulkImport` pin it. |
| ADR-060 | 2 A batch that the stack mails | Done | `vca/services/issuance/internal/service/batch.go`, `vca/services/dpg-adapter-credebl/internal/service/bulk.go` | `TestIssueBatchNativeMailsThroughTheStack` and `TestIssueBatchMailsEachRowThroughTheImport` pin it. |
| ADR-060 | 3 The bulk import service | Done | `vca/services/dpg-adapter-credebl/internal/service/bulk.go` | `TestBulkUploadPreviewIssue` and `TestBulkRetry` pin it. The other adapters answer `Unimplemented`. |
| ADR-060 | 4 The pages of the import | Done | `vca/services/issuance/internal/pages/bulk.go`, `vca/services/data-source/internal/pages/run.go` | `TestStackBulkImportIsASource`, `TestBulkHistoryAndRetry` and `TestBulkNativeMailAsksForTheEmailColumn` pin it. |
| ADR-060 | 5 The CREDEBL import | Done | `vca/services/dpg-adapter-credebl/internal/credebl/bulk.go` | The fixtures come from the platform sources; `TestContractBulkImport` checks a live platform. |

## ADR-061: DIDComm proof requests and the AnonCreds proof request builder

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-061 | 1 DIDComm proof requests, out of band and over a connection | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestOobProofRequest`, `TestConnectionProofRequest` and `TestListProofRequests` pin it. |
| ADR-061 | 2 AnonCreds proof requests with predicates | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestOobProofRequest` and `TestListProofSchemas` pin it. |
| ADR-061 | 3 The stack verifies, and VCA reads the revealed values | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestProofResultVerified` and `TestProofResultStates` pin it. |
| ADR-061 | 4 The AnonCreds builder | Done | `vca/core/anoncreds`, `vca/services/verifier-discovery/internal/portal/anoncreds.go` | `TestAnonCredsBuilderPredicates`, `TestBuildNativeAnonCreds` and `TestAnonCredsSchemasComeFromTheStacks` pin it. |
| ADR-061 | 5 The DIDComm option of the request page | Done | `vca/services/verifier-ingest/internal/service/request.go`, `vca/services/verifier-ingest/internal/scanner/request.go` | `TestAnonCredsRequestGoesOverDidcomm`, `TestRequestPageOffersDidcommProofRequest` and `TestRequestListShowsStackProofRequests` pin it. |
| ADR-061 | 6 The schema of a PE descriptor on CREDEBL | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestPeProofRequestOverDidcomm` pins it. |

## ADR-062: The DIDComm holder wallet of a CREDEBL stack

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-062 | 1 A tenant wallet per holder in the shared agent | Done | `vca/services/dpg-adapter-credebl/internal/credebl/agent.go` | `TestAgentTenantAndTokens` and `TestCreateCloudWallet` pin it. |
| ADR-062 | 2 The hashed subject maps onto the tenant | Done | `vca/services/dpg-adapter-credebl/internal/service/holder.go` | `TestCreateCloudWallet` pins it. |
| ADR-062 | 3 The DIDComm wallet RPCs | Done | `vca/services/dpg-adapter-credebl/internal/service/holder.go` | `TestAcceptOfferThroughInvitation`, `TestAcceptProofRequest`, `TestOpenInvitationKeepsTheConnection` and `TestListInbox` pin it. |
| ADR-062 | 4 The wallet portal shows an invitation before the wallet takes it | Done | `vca/services/wallet-portal/internal/service/didcomm.go`, `vca/services/wallet-portal/internal/portal/didcommwallet.go` | `TestScannedOfferWaitsForTheHolder`, `TestOfferInvitationShowsTheValuesFirst` and `TestConnectionsPage` pin it. |
| ADR-062 | 5 AnonCreds and W3C credentials, and permanent ones | Done | `vca/services/dpg-adapter-credebl/internal/service/holder.go`, `vca/services/wallet-portal/internal/portal/home.go` | `TestListCloudCredentials` and `TestPermanentCardHasNoRemoveButton` pin it. |
| ADR-062 | 6 The keys page with DIDs alone | Done | `vca/services/dpg-adapter-credebl/internal/service/holder.go`, `vca/services/wallet-portal/internal/portal/keys.go` | `TestWalletDids` and `TestKeysPageOnlyWithFeature` pin it. |
| ADR-062 | 7 The holder role with the agent, and setup | Done | `vca/services/dpg-adapter-credebl/internal/service/service.go`, `vca/internal/cli/credebl.go` | `TestCapabilitiesListHolderRole` and `TestCredeblHolderPairReachesTheAgent` pin it. Since the amendment of 2026-10-04 every pair reaches the agent, and an issuer or a verifier pair only resolves DIDs there. `TestAResolverOnlyAgentServesNoWallet`, `TestBuildWiresAResolverOnlyAgent` and `TestLoadReadsAResolverOnlyAgent` pin that. The admin asks every live pair of a stack. `TestUpsertTrustEntryAsksEveryPairOfAStack` and `TestAFeatureOfALaterPairCounts` pin that. |
| ADR-062 | 8 OID4VCI claims and OID4VP answers through the same wallet | Done | `vca/services/dpg-adapter-credebl/internal/service/holder_oid4vc.go` | `TestAcceptOid4vciOfferThroughTheAgent` and `TestPresentOid4vpThroughTheAgent` pin it. |

## ADR-063: The consent of a stack wallet that picks the claims itself

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-063 | 1 The whole query feature, the consent check and the shared claims | Done | `vca/services/dpg-adapter-credebl/internal/service/holder_oid4vc.go`, `vca/services/wallet-portal/internal/service/service.go` | `TestPresentOid4vpRefusesAnUntickedClaim`, `TestResolvedRequestDisclosures`, `TestConsentMarksEveryClaimWhenTheStackSharesTheWholeQuery` and `TestHistoryNamesWhatTheStackShared` pin it. |
| ADR-063 | 2 A request by value stays with the browser store | Done | `vca/services/wallet-portal/internal/service/service.go` | `TestStackWalletRefusesARequestByValue` and `TestPresentFromUploadedRequestFile` pin it. A stack wallet gets one request shape, `openid4vp://authorize` with `client_id` and `request_uri`. `TestStackWalletGetsOneRequestShape` and `TestPresentTakesThePortalRequestShape` of each adapter pin it. |
| ADR-063 | 3 The two fetches of a request URI | Done | `vca/docs/dpg-adapter-credebl.md` | The adapter document names the fetches and the allowlist that bounds them. |

## ADR-064: The issuer of an AnonCreds proof over DIDComm

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-064 | 1 A trusted template binds each part to a credential definition | Done | `vca/core/anoncreds/anoncreds.go`, `vca/services/verifier-discovery/internal/template/template.go` | `TestCheckBoundNeedsACredentialDefinition`, `TestTrustedAnonCredsTemplateNeedsACredentialDefinition` and `TestAnonCredsBuilderRefuses` pin it. |
| ADR-064 | 2 `any_issuer` and the refusal of an unbound part | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go`, `vca/services/verifier-ingest/internal/service/request.go` | `TestProofRequestNeedsABoundIssuer` and `TestDidcommRequestNamesAnyIssuer` pin it. |
| ADR-064 | 3 The issuer of the view comes from the recorded request | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestProofViewIssuerComesFromTheRequest` pins it. |
| ADR-064 | 4 No issuer and a failed check for an unbound part | Done | `vca/services/dpg-adapter-credebl/internal/service/proofs.go` | `TestProofViewNamesNoIssuerWhenTheRequestBindsNone` pins it. |

## ADR-065: The Indy networks of a CREDEBL stack are a setting of the operator

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-065 | 1 The setting with no default | Done | `proto/vca/config/v1/config.proto`, `vca/internal/cli/stackenv.go` | `TestCredeblLedgersAreASetting` and `TestBuildPlanEveryPairNeedsNoValue` pin it. |
| ADR-065 | 2 Setup writes the agent file | Done | `vca/internal/cli/credebl_master.go`, `deploy/vca/dpg/credebl.yaml` | `TestCredeblLedgersAreASetting` and `TestCredeblStackReadsTheStackEnv` pin it. |
| ADR-065 | 3 Only the chosen ledgers are active | Done | `vca/internal/cli/credebl_master.go` | `TestCredeblLedgersAreASetting` and `TestNoUpstreamCredeblCredentialSurvives` pin it. |
| ADR-065 | 4 No agent file without a network | Done | `vca/internal/cli/stackenv.go` | `TestCredeblAgentConfigNeedsANetwork` pins it. |

## ADR-066: The CREDEBL stack runs one release line of the platform

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-066 | 1 Every platform image from the line `v2.2.1` | Done | `deploy/vca/dpg/credebl.yaml` | `TestCredeblStackRunsOneReleaseLine` pins it. |
| ADR-066 | 2 The stack file does not follow `latest` | Done | `deploy/vca/dpg/credebl.yaml`, `vca/docs/deploy.md` | The deploy document names the two lines. |
| ADR-066 | 3 The adapter reports the release and the digest | Done | `vca/services/dpg-adapter-credebl/internal/config/config.go` | `TestDefaultVersionsMatchTheStackFile` pins it. |

## ADR-067: The webhook, the holder notification address and the client credential of a CREDEBL organisation

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-067 | 1 A signed webhook, with no copy of the secret | Done | `vca/services/dpg-adapter-credebl/internal/service/webhook.go`, `vca/services/admin/internal/service/webhooks.go` | `TestSetWebhook` and `TestStackWebhookPassesTheSigningSecret` pin it. |
| ADR-067 | 2 A webhook stays once set | Done | `vca/services/dpg-adapter-credebl/internal/service/webhook.go`, `vca/services/admin/internal/portal/notifications.go` | `TestSetWebhook` and `TestFixedWebhookHasNoClearAction` pin it. |
| ADR-067 | 3 The adapter keeps the holder notification address | Done | `vca/services/dpg-adapter-credebl/internal/service/webhook.go` | `TestNotificationEndpoint` and `TestStackNotificationEndpointRPCs` pin it. |
| ADR-067 | 4 One client credential, with the secret shown once | Done | `vca/services/dpg-adapter-credebl/internal/service/tenant.go` | `TestClientCredentialCreatedOnce` pins it. |
| ADR-067 | 5 The three features and the portal parts | Done | `vca/services/dpg-adapter-credebl/internal/service/bulk.go`, `vca/services/admin/internal/portal/notifications.go` | `TestFeaturesListed` and `TestHolderNotificationsOnlyWithFeature` pin it. |

## ADR-068: CREDEBL ecosystems and the X.509 issuer identity

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-068 | 1 The ecosystem RPCs and the feature | Done | `proto/vca/backend/v1/backend.proto`, `vca/services/dpg-adapter-credebl/internal/service/ecosystem.go` | `TestListEcosystems`, `TestFeaturesListed` and the tenant tests of the walt.id and Inji adapters pin it. |
| ADR-068 | 2 The invitation of the platform admin and the new sign in | Done | `vca/services/dpg-adapter-credebl/internal/credebl/ecosystem.go` | `TestEcosystemCalls` and `TestListEcosystems` pin it. |
| ADR-068 | 3 A member joins at once or gets an invitation | Done | `vca/services/dpg-adapter-credebl/internal/service/ecosystem.go` | `TestListEcosystems` and `TestEcosystemRefusals` pin it. |
| ADR-068 | 4 The realm keeps the ecosystem roles | Done | `vca/internal/cli/credebl_realm.go` | `TestCredeblRealmAllowsEcosystemAccess` pins it. |
| ADR-068 | 5 The Ecosystems tab of the admin portal | Done | `vca/services/admin/internal/portal/ecosystems.go`, `vca/services/admin/internal/service/ecosystems.go` | `TestEcosystemsTabOnlyWithFeature`, `TestEcosystemsPageRunsEachStep` and `TestStackEcosystemRPCs` pin it. |
| ADR-068 | 6 The X.509 import with a certificate row | Done | `vca/services/dpg-adapter-credebl/internal/service/x509.go` | `TestImportX509Certificate` pins it. |
| ADR-068 | 7 The checks, the activation and the kept chain | Done | `vca/services/dpg-adapter-credebl/internal/service/x509.go` | `TestImportX509Certificate` and `TestImportX509Refusals` pin it. |
| ADR-068 | 8 No DID import | Done | `vca/services/dpg-adapter-credebl/internal/service/x509.go` | `TestImportDidUnimplementedWithoutFeature` pins it. |

## ADR-069: The CREDEBL stack runs the status list host of the platform

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-069 | 1 The status list host, built at one commit | Done | `deploy/vca/dpg/credebl.yaml` | `TestCredeblStackRunsTheStatusListHost` pins it. |
| ADR-069 | 2 One address for the platform, the agent and the verifier | Done | `deploy/vca/dpg/credebl.yaml`, `vca/docs/deploy.md` | `TestCredeblStackRunsTheStatusListHost` pins it. The deploy document names the public route. |
| ADR-069 | 3 The generated key and the setting of the issuer pair | Done | `vca/internal/cli/stackenv.go`, `vca/internal/cli/services.go` | `TestCredeblStackEnvHoldsTheStatusListKey` and `TestCredeblIssuerPairNamesTheStatusList` pin it. |
| ADR-069 | 4 Revocable offers, `Revoke` and no suspension | Done | `vca/services/dpg-adapter-credebl/internal/service/issuer.go` | `TestRevokeSession`, `TestOfferIsRevocableWithAStatusList` and `TestRevocationListedWithAStatusList` pin it. |
| ADR-069 | 5 The ledger entry and the actions of the issued page | Done | `vca/services/dpg-adapter-credebl/internal/service/ledger.go`, `vca/services/issued-credentials/internal/pages/detail.go` | `TestLedgerEntryCarriesTheStatusListEntry` and `TestLedgerRecordOffersOnlyTheStackActions` pin it. |

## ADR-070: The operator makes each DID of a CREDEBL organisation

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-070 | 1 The pinned gateway needs the key of every DID | Done | `vca/services/dpg-adapter-credebl/testdata/doc/SOURCE.md` | The fixture sources cite the validator and the DID controller of the pinned tags. |
| ADR-070 | 2 No provision and no DID for a new tenant | Done | `vca/services/dpg-adapter-credebl/internal/service/identity.go`, `vca/services/dpg-adapter-credebl/internal/service/tenant.go` | `TestProvisionNeedsTheKeyOfTheOperator` and `TestCreateTenantCreatesOrg` pin it. |
| ADR-070 | 3 The operator makes the DID, and the pages say so | Done | `vca/docs/dpg-adapter-credebl.md`, `vca/services/admin/internal/portal/tenants.go`, `vca/services/issuance/internal/pages/identity.go` | `TestOperatorDidMethodsAndLimitsListed`, `TestTenantDetailMakesADidPrimary` and `TestIdentityPageSaysTheOperatorMakesTheDid` pin it. |
| ADR-070 | 4 `SetTenantPrimaryDid` and "Make primary" | Done | `proto/vca/backend/v1/backend.proto`, `proto/vca/admin/v1/admin.proto`, `vca/services/admin/internal/service/tenants.go` | `TestSetTenantPrimaryDid` of the adapter and of the admin service, and `TestTenantDetailMakesADidPrimary`, pin it. |
| ADR-070 | 5 The key reference shape and the one import kind | Done | `vca/services/issuance/internal/pages/identity.go` | `TestIdentityPageNamesTheOneImportKindAndItsKeyReference` pins it. |
| ADR-070 | 6 The client credential limit | Done | `vca/services/admin/internal/portal/keys.go` | `TestStackCredentialFormHidesAFullTenant` pins it. |

## ADR-071: A verifier checks a status list with the key set under its address

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-071 | 1 The keys of the issuer come first | Done | `vca/core/policy/status.go` | `TestStatusToken` pins it. |
| ADR-071 | 2 Then the key set under the list address | Done | `vca/core/policy/status.go` | `TestStatusListSignedUnderItsAddress`, `TestStatusListKeysNeedTheListAddress` and the walt.id walkthrough pin it. |
| ADR-071 | 3 The evidence names the key set | Done | `vca/core/policy/status.go` | `TestStatusListSignedUnderItsAddress` pins it. |
| ADR-071 | 4 The cache reads a self resolving DID | Done | `vca/services/verifier-policy/internal/cache/sync.go` | `TestStatusListOfASelfResolvingIssuer` and the CREDEBL walkthrough pin it. |

## ADR-072: An offer names the status entry its credential carries

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-072 | 1 The offer answer names the entry | Done | `proto/vca/backend/v1/backend.proto`, `vca/services/dpg-adapter-*/internal/service/issuer.go` | `TestCreateOfferNamesTheStatusEntryOfTheStack`, `TestCreateOfferNamesTheStatusEntryTheCredentialCarries` and `TestCreateOfferNamesTheStatusEntryOfTheRow` pin it. |
| ADR-072 | 2 The record holds the entry the credential carries | Done | `vca/services/issuance/internal/service/issue.go` | `TestAnOfferOfAStackWithItsOwnListRecordsTheStackEntry` and `TestAnOfferWhoseCredentialCarriesNoStatusRecordsNone` pin it. |
| ADR-072 | 3 A change of a stack entry goes to the adapter or fails | Done | `vca/services/issued-credentials/internal/service/service.go` | `TestAStackListEntryChangesThroughTheAdapter` and `TestAStackListEntryTheStackCannotChangeIsRefused` pin it. |
| ADR-072 | 4 The record page names the holder of the list | Done | `vca/services/issued-credentials/internal/pages/detail.go` | `TestDetailNamesTheListThatHoldsTheStatus`, `TestAStackListRecordOffersOnlyWhatTheStackDoes` and the CREDEBL walkthrough pin it. |

## ADR-073: The browser store signs with a holder key of its own

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-073 | 1 A signing key that no script exports | Done | `vca/services/wallet-portal/internal/static/wallet.js` | `TestTheBrowserSigningKeyStaysInTheBrowser` runs the script in node when node is on the path. |
| ADR-073 | 2 The proof and the key binding with ES256 | Done | `vca/services/wallet-portal/internal/holderkey` | `TestProofSignedInTheBrowserPassesTheIssuerCheck` and `TestBindingSignedInTheBrowserPassesTheVerifierCheck` pin it. An issuer with a nonce endpoint gets `proofs` of OID4VCI 1.0. Any other issuer gets `proof` of draft 13. `TestClaimReadsTheAnswerOfOid4vci10` and `TestClaimSendsTheProofOfDraft13` pin that. An answer with several bound credentials carries one key binding per query. `TestBrowserStoreSendsEveryChosenCredential` pins it. |
| ADR-073 | 3 The portal runs the protocol calls | Done | `vca/services/wallet-portal/internal/service/browserclaim.go` | `TestClaimIntoTheBrowserStoreSignsWithTheBrowserKey` and `TestClaimRefusals` pin it. |
| ADR-073 | 4 The portal checks each signature | Done | `vca/services/wallet-portal/internal/holderkey` | `TestCheckBindingCoversTheAnswer` and `TestClaimRefusals` pin it. |
| ADR-073 | 5 The browser seals a claimed credential | Done | `vca/services/wallet-portal/internal/static/wallet.js`, `vca/services/wallet-portal/internal/portal/browser.go` | `TestTheBrowserStoreClaimsWithTheKeyOfTheBrowser` and both walkthroughs pin it. |
| ADR-073 | 6 A bound answer needs the key binding | Done | `vca/services/wallet-portal/internal/service/binding.go` | `TestAnswerOfABoundCredentialCarriesTheBrowserKeyBinding`, `TestABoundAnswerNeedsTheBrowserKeyBinding`, `TestTheBindingAndTheAnswerShareOneRequest` and both walkthroughs pin it. The portal keeps the request object of the first read, so the nonce of the binding holds. It refuses an object above 64 KiB and sweeps the expired records on a timer. `TestARequestObjectAboveTheCapIsRefused` and `TestTheAppSweepsExpiredRecordsOnATimer` pin that. |

## ADR-074: The role switches of the umbrella chart sit under global

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-074 | 1 The role switches under global | Done | `deploy/vca/helm/vca/values.yaml`, `deploy/vca/helm/vca/templates/peers-configmap.yaml` | `TestUmbrellaChartTurnsRolesOn` and `TestUmbrellaWritesPeers` pin it. |
| ADR-074 | 2 One condition per service of one role or per adapter | Done | `vca/internal/cli/helm.go`, `deploy/vca/helm/vca/Chart.yaml` | `TestChartConditionHonoursEveryRole` and `TestUmbrellaChartTurnsRolesOn` pin it. |
| ADR-074 | 3 A service of several roles checks each role | Done | `deploy/vca/helm/dpg-adapter-*` | `TestMultiRoleChartsHonourEveryRole` renders the gate for each role. |
| ADR-074 | 4 The old switch stops the render | Done | `deploy/vca/helm/vca/templates/roles-moved.yaml` | `TestUmbrellaRefusesTheOldRoleSwitch` pins it. |

## ADR-075: Each internal Connect service checks which service calls it

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-075 | 1 One authority per deployment, kept by the CLI | Done | `vca/internal/cli/peer.go` | `TestSetupGivesEveryServiceAnIdentity` pins it. |
| ADR-075 | 2 An identity file per service | Done | `vca/internal/cli/peer.go`, `vca/internal/cli/compose.go`, `vca/hack/secret-scan.sh` | `TestSetupGivesEveryServiceAnIdentity` and `TestComposeGivesEachServiceItsIdentity` pin it. Since the amendment of 2026-10-04 the key is a file of its own that compose mounts read only. `TestEnvRoundTrip`, `TestSetupWritesTheLandingEnv` and the cases of `hack/secret-scan_test.sh` pin that. |
| ADR-075 | 3 A signed token per call and one shared interceptor | Done | `vca/internal/peerauth`, `vca/internal/cli/peer.go` | `TestCheck`, `TestAnUnlistedCallerIsRefused` and the peer checks of the walkthroughs pin it. The amendment of 2026-10-04 binds each token to the host of its callee and makes the time window symmetric. `TestATokenNamesItsCallee` and `TestTheTimeWindowIsSymmetric` pin that. The amendment of 2026-10-04 on deployment scoped callers binds the tokens of `cli` and the landing too. Each service of a pair lists its published names in `VCA_PEER_HOSTS`. `TestATokenNamesItsCallee`, `TestIdentitiesNameThePublishedPorts` and `TestCLIClientSignsWithTheAuthority` pin that. |
| ADR-075 | 4 The callers next to the routes of the catalogue | Done | `vca/internal/cli/services.go` | `TestEveryInternalConnectServiceListsItsCallers` and `TestEveryServiceLinkIsAListedCaller` pin it. |
| ADR-075 | 5 The upgrade of an earlier deployment | Done | `vca/internal/cli/peer.go`, `vca/internal/cli/doctor_peer.go` | `TestUpgradeAddsPeerIdentities` pins it. `vca doctor` names a missing authority and a missing or stale identity. It also names a key file that the container user cannot read. Each line gives its fix. `TestDoctorChecksThePeerIdentities` and `TestDoctorRunsThePeerChecks` pin that. |
| ADR-075 | 6 One Secret per Helm chart | Done | `deploy/vca/helm/*/templates/deployment.yaml`, `vca/internal/cli/peer.go` | `TestServiceChartsReadTheirPeerSecret` and `TestHelmPeerSecrets` pin it. Since the amendment of 2026-10-04 a second Secret holds the key, and each pod mounts it as a file. A checksum of both Secrets rolls the pods. `TestHelmPeerSecretsTwiceChangesNothing` pins that a second run reuses the Secrets, as decision 5 promises for compose. |
| ADR-075 | 7 The guard test of the handlers | Done | `vca/internal/cli/peerguard_test.go` | `TestEveryConnectHandlerChecksItsCaller` pins it over every Go file of `vca/`. It resolves each constructor by import path and finds the wrappers itself. `TestTheGuardSeesEverySpelling` pins the spellings it must see. |

## ADR-076: The answer of Issue names the status entry its credential carries

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-076 | 1 `IssueResponse` names the entry | Done | `proto/vca/backend/v1/backend.proto`, `vca/services/dpg-adapter-inji/internal/service/issuer.go` | `TestIssueNamesTheStatusEntryOfTheRow` pins it. walt.id and CREDEBL serve no `Issue`. |
| ADR-076 | 2 `credential_id` for a list of the stack | Done | `vca/services/issuance/internal/service/issue.go` | `TestADocumentOfAStackWithItsOwnListRecordsTheEntryOfIssue` pins it. |
| ADR-076 | 3 The record of a document keeps the entry of the answer | Done | `vca/services/issuance/internal/service/issue.go`, `vca/services/issuance/internal/service/batch.go`, `vca/services/dpg-adapter-inji/internal/service/issuer.go` | `TestADocumentWhoseCredentialCarriesNoStatusRecordsNone` and `TestADocumentRecordsTheVcaEntryTheAnswerNames` pin it. Since the amendment of 2026-10-04 each item of `IssueBatchResponse` names its entry too. `TestIssueBatchNamesTheStatusEntryOfEachRow` and `TestANativeBatchRecordsTheEntryEachItemNames` pin that. |

## ADR-077: The schema registry registers each published version again at start

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-077 | 1 Every published version again at start | Done | `vca/services/schema-registry/internal/service/service.go`, `vca/services/schema-registry/main.go` | `TestRepublishRegistersEveryPublishedVersionAgain` pins it. |
| ADR-077 | 2 A second registration answers as the first | Done | `vca/services/dpg-adapter-waltid/internal/service/service.go`, `vca/services/dpg-adapter-credebl/internal/service/schemas.go` | `TestARegistrationAgainReplacesTheRetiredVct` pins the walt.id adapter. `TestARegistrationAgainFindsTheSchemaOfThePlatform`, `TestARegistrationAgainWritesOnlyTheMissingCredDef` and `TestARegistrationAgainOfATemplateWritesOneSchema` pin the CREDEBL adapter. Until the amendment of 2026-10-04 this row claimed the CREDEBL adapter, which found only the template of an SD-JWT configuration. |
| ADR-077 | 3 The registry tries again while the stack refuses | Done | `vca/services/schema-registry/internal/app/app.go`, `vca/services/schema-registry/internal/service/republish.go`, `vca/services/schema-registry/internal/store/store.go`, `vca/services/schema-registry/internal/portal/portal.go` | `TestRepublishWaitsForTheStack`, `TestRepublishBacksOffAndStopsOnARefusal`, `TestRepublishSortsTheRefusals` and `TestDetailPageShowsAStoppedRegistration` pin it, as the amendment of 2026-10-04 changed it. The store keeps each stopped registration, and the list page counts, flags, and filters them. `TestStoppedRegistrationsSurviveAReopen`, `TestAStoppedRegistrationOutlivesARestart` and `TestListPageFlagsStoppedRegistrations` pin that. |

## ADR-078: The vca command manages the combined templates of a verifier pair

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-078 | 1 `vca combined list`, `create` and `delete` | Done | `vca/internal/cli/combined.go`, `vca/internal/cli/command.go` | `TestCombinedCommandsManageTheTemplatesOfThePair` pins it. |
| ADR-078 | 2 The caller `cli` of the combined service | Done | `vca/internal/cli/services.go` | `TestCombinedCommandsManageTheTemplatesOfThePair` calls a service that takes the callers of the catalogue. |

## ADR-079: The ingestion service requests and evaluates combined templates

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-079 | 1 The combined template kind | Done | `proto/vca/discovery/v1/discovery.proto`, `proto/vca/ingest/v1/ingest.proto`, `vca/services/verifier-discovery/internal/template/template.go` | `TestBuildRefusesACombinedKind` pins the refusal of the discovery service. |
| ADR-079 | 2 Merge, send, and evaluate | Done | `vca/services/verifier-ingest/internal/service/request.go`, `vca/services/verifier-ingest/internal/app/app.go` | `TestACombinedRequestSendsTheMergedQueryAndEvaluatesTheCombination`, `TestACombinedRequestThroughAStack`, `TestACombinedRequestRefusals`, and `TestBuildCallsTheCombinedServiceOfTheLink` pin it. |
| ADR-079 | 3 `Update` of the combined service | Done | `proto/vca/combined/v1/combined.proto`, `vca/services/verifier-combined/internal/service/service.go`, `vca/services/verifier-combined/internal/combos/combos.go` | `TestUpdateKeepsTheIdAndReplacesTheMembers` and `TestUpdateReplacesTheTemplate` pin it. |
| ADR-079 | 4 The combined query pages and the request page | Done | `vca/services/verifier-discovery/internal/portal/combined.go`, `vca/services/verifier-ingest/internal/scanner/request.go`, `vca/internal/rolenav/rolenav.go`, `vca/services/internal/staffshell/staffshell.go` | `TestCombinedPagesListCreateEditAndDelete`, `TestCombinedPagesHideWhenThePairRunsNoCombinedService`, `TestCombinedPagesReadTheCombinedServiceOfTheLink`, `TestACombinedTemplateIsAQueryOfTheRequestPage`, `TestVerifierNavShowsCombinedOnlyWhenThePairRunsIt`, and `TestRunsReadsTheServicesOfTheOwnPair` pin it. |
| ADR-079 | 5 The callers of the combined service | Done | `vca/internal/cli/services.go`, `docs/deploy.md` | `TestEveryConnectHandlerChecksItsCaller` and `TestDeployDocClassifiesEveryRPC` keep the table and the catalogue in step. |

## Counts

| Status | Decisions |
|---|---|
| Done | 398 |
| Partial | 19 |
| Deferred | 3 |
| Not started | 5 |
| Total | 425 |
