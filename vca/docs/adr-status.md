# ADR status

This page records the state of every decision in the architecture
decision records. The root record set is [ADR.md](../../ADR.md). It
holds ADR-001 to ADR-031. The records from ADR-032 on are files in
[adr](adr), listed in the [index](adr.md). The page covers ADR-001 to
ADR-046, one row per decision.

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
| ADR-002 | 5 Connect calls with mutual service identity | Partial | `vca/services/internal/dpgclient` | The calls use Connect. No service holds a peer identity check yet. |
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
| ADR-004 | 6 Playwright end to end tests on each PR | Not started | `.github/workflows/vca-ci.yml` | The branch has no browser test suite and no runner. |
| ADR-004 | 7 Flaky tests go to quarantine in one day | Not started | `vca/docs/ci.md` | No page names the quarantine rule and no CI job tracks it. |
| ADR-004 | 8 Accessibility tests with axe-core | Not started | `vca/ui/a11ytest` | Go tests check the structure. No axe run exists, because no browser suite exists. |

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
| ADR-008 | 5 One Helm chart per service and an umbrella | Done | `deploy/vca/helm` | |
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
| ADR-009 | 6 Append-only audit log | Done | `vca/services/admin/internal/audit` | |

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
| ADR-011 | 6 Entities named by DID or x509 subject | Done | `vca/core/did` | |
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
| ADR-013 | 3 Schema sync as an adapter RPC | Partial | `vca/services/dpg-adapter-*/internal/service` | The walt.id adapter records the setup itself. The Inji adapter refuses, so the deployment applies it. |
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
| ADR-017 | 3 Portal with revoke and reinstate | Partial | `vca/proto/vca/issued/v1`, `vca/services/issued-credentials/internal/export` | The RPCs and the export work. No portal page of the UI kit renders them yet. |
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
| ADR-020 | 4 Holder key binding in the browser or the DPG | Done | `vca/services/wallet-portal/internal/blobs` | |
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
| ADR-024 | 2 VCA runs the mandatory checks itself | Done | `vca/core/policy` | |
| ADR-024 | 3 Status checks with a cached fetcher | Done | `vca/services/verifier-policy/internal/ports` | |
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
| ADR-026 | 1 DCQL requests with credential sets | Done | `vca/core/dcql` | |
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
| ADR-032 | 1 One theme file with a path variable | Not started | `deploy/vca/theme.yaml` | Proposed record. No work exists yet. |
| ADR-032 | 2 The kit keeps the pairings, the file sets colours | Not started | `vca/ui/theme` | Proposed record. No work exists yet. |
| ADR-032 | 3 Two font families and a monospace stack | Done | `vca/ui/fonts` | |
| ADR-032 | 4 Wordmark, logo, radii, spacing, role accents | Not started | `vca/internal/themefile` | Proposed record. No work exists yet. |
| ADR-032 | 5 The YAML reader lives outside the kit | Not started | `vca/internal/themefile` | Proposed record. No work exists yet. |
| ADR-032 | 6 Theme check and theme apply commands | Not started | `vca/internal/cli` | Proposed record. No work exists yet. |

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
| ADR-034 | 5 Pages show live features only | Not started | `vca/ui` | No page reads the feature list yet. |

## ADR-035: Provider agnostic sign in with one realm per role

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-035 | 1 Four realms with self registration | Not started | `deploy/vca` | Proposed record. No work exists yet. |
| ADR-035 | 2 Keycloak is a provider record, not a dependency | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-035 | 3 Register action with a fallback | Done | `vca/services/internal/signin` | The chooser of every auth service offers `/auth/register` when the provider supports it. |
| ADR-035 | 4 Three token authentication methods | Not started | `vca/core/oidc` | Proposed record. No work exists yet. |
| ADR-035 | 5 The admin portal pushes provider records | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-035 | 6 The first admin registers and binds | Partial | `vca/services/admin` | The admin chooser registers with the bootstrap token in one flow. The first run checklist item waits for P2-01. |
| ADR-035 | 7 The CLI makes the Keycloak password | Not started | `vca/internal/cli` | Proposed record. No work exists yet. |

## ADR-036: Verifier staff sign in

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-036 | 1 A verifier-auth service per verifier pair | Not started | `vca/services/verifier-auth` | Proposed record. No work exists yet. |
| ADR-036 | 2 Verifier staff pages need a session | Not started | `vca/services/verifier-*` | Proposed record. No work exists yet. |
| ADR-036 | 3 Issuer staff pages get the same guard | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |

## ADR-037: Tenants mapped to DPG tenancy

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-037 | 1 A VCA tenant binds to DPG tenants | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-037 | 2 A tenant backend service in the contract | Not started | `vca/proto/vca/backend/v1` | Proposed record. No work exists yet. |
| ADR-037 | 3 Tenancy shows only on stacks that have it | Not started | `vca/services/admin` | Proposed record. No work exists yet. |

## ADR-038: API keys for VCA and for stacks

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-038 | 1 Tenant scope and expiry on VCA keys | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-038 | 2 Stack client credentials next to VCA keys | Not started | `vca/services/admin` | Proposed record. No work exists yet. |

## ADR-039: Federated audit log

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-039 | 1 An audit service in each recording service | Not started | `vca/proto/vca/audit/v1` | Proposed record. No work exists yet. |
| ADR-039 | 2 The admin page merges the live peers | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-039 | 3 Events carry no claim values | Not started | `vca/proto/vca/audit/v1` | Proposed record. No work exists yet. |

## ADR-040: Notifications page before notification delivery

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-040 | 1 Notifications pages list the channels | Not started | `vca/services/admin` | Proposed record. No work exists yet. |
| ADR-040 | 2 DPG webhooks and callbacks when the adapter lists them | Not started | `vca/services/admin` | Proposed record. No work exists yet. |

## ADR-041: Verifier trust cache and offline verification window

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-041 | 1 Signature checked snapshots | Not started | `vca/services/verifier-policy` | Proposed record. No work exists yet. |
| ADR-041 | 2 A refresh schedule per source | Not started | `vca/services/verifier-policy` | Proposed record. No work exists yet. |
| ADR-041 | 3 An offline window of at most seven days | Not started | `vca/services/verifier-policy` | Proposed record. No work exists yet. |
| ADR-041 | 4 A stale status list fails the check | Not started | `vca/services/verifier-policy` | Proposed record. No work exists yet. |
| ADR-041 | 5 Cache RPCs and a caching page | Not started | `vca/proto/vca/policy/v1` | Proposed record. No work exists yet. |

## ADR-042: DCQL builder and DIF Presentation Exchange queries

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-042 | 1 A template has a kind | Not started | `vca/services/verifier-discovery` | Proposed record. No work exists yet. |
| ADR-042 | 2 A DCQL builder with a live query view | Not started | `vca/services/verifier-discovery` | Proposed record. No work exists yet. |
| ADR-042 | 3 A claim predicate policy check | Not started | `vca/services/verifier-policy` | Proposed record. No work exists yet. |
| ADR-042 | 4 PE authoring, validation, and conversion | Not started | `vca/services/verifier-discovery` | Proposed record. No work exists yet. |
| ADR-042 | 5 A pure core package for PE | Not started | `vca/core/pex` | Proposed record. No work exists yet. |

## ADR-043: Issuance channels and bulk sources

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-043 | 1 The list of channels | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |
| ADR-043 | 2 The page offers live channels only | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |
| ADR-043 | 3 Digital Credentials API button with a fallback | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |
| ADR-043 | 4 Bulk issuance from data sources | Not started | `vca/services/data-source` | Proposed record. No work exists yet. |

## ADR-044: Placement of the role pages

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-044 | 1 The issuer home moves to issuance | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |
| ADR-044 | 2 Issued credentials and sources pages | Not started | `vca/services/issued-credentials` | Proposed record. No work exists yet. |
| ADR-044 | 3 The verifier home stays on verifier-results | Not started | `vca/services/verifier-results` | Proposed record. No work exists yet. |
| ADR-044 | 4 DCQL, PE, and request pages | Not started | `vca/services/verifier-discovery` | Proposed record. No work exists yet. |
| ADR-044 | 5 One role navigation package bound to the routes | Not started | `vca/internal/rolenav` | Proposed record. No work exists yet. |

## ADR-045: Full DPG surfacing

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-045 | 1 Each adapter lists every feature of its DPG | Not started | `vca/services/dpg-adapter-*` | Proposed record. No work exists yet. |
| ADR-045 | 2 New format, protocol, and channel values | Not started | `vca/proto/vca/common/v1` | Proposed record. No work exists yet. |
| ADR-045 | 3 The holder uses the DPG wallet | Not started | `vca/services/wallet-portal` | Proposed record. No work exists yet. |
| ADR-045 | 4 The whole CREDEBL platform, pinned by digest | Not started | `deploy/vca` | Proposed record. No work exists yet. |
| ADR-045 | 5 The walt.id stack adds verifier-api2 | Not started | `deploy/vca` | Proposed record. No work exists yet. |

## ADR-046: Issuer identity through the DPG

| ADR | Decision | Status | Where | Note |
|---|---|---|---|---|
| ADR-046 | 1 Issuer identity RPCs | Not started | `vca/proto/vca/backend/v1` | Proposed record. No work exists yet. |
| ADR-046 | 2 One click provision or an import | Not started | `vca/services/issuance` | Proposed record. No work exists yet. |
| ADR-046 | 3 Trust registry entry in state pending | Not started | `vca/services/trust-registry` | Proposed record. No work exists yet. |
| ADR-046 | 4 No issuer private key in VCA | Not started | `vca/services/dpg-adapter-*` | Proposed record. No work exists yet. |

## Counts

| Status | Decisions |
|---|---|
| Done | 171 |
| Partial | 20 |
| Deferred | 3 |
| Not started | 70 |
| Total | 264 |
