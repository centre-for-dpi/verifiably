# Verifiable Credentials Adapters: Architecture Decision Records

Reviewed commit: https://github.com/centre-for-dpi/verifiably main @ 9aca9bf (2026-09-12).

## ADR-001: Rebrand and redefined purpose
- Status: Proposed
- Owner: CDPI Architects
- Scope: Project name, purpose statement, and product boundary.
- Decision:
  1. Rename the project from "verifiably" to "Verifiable Credentials Adapters" (VCA), Go module path `github.com/centre-for-dpi/vc-adapters`, replacing the unowned module path `github.com/verifiably/verifiably-go` ([go.mod#L1](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/go.mod#L1)).
  2. Define the product as a set of independent adapters, each adding one citizen-facing capability that walt.id, Inji, or CREDEBL does not ship by default, following the per-DPG gap analysis already in the repo ([docs/dpg-matrix.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/dpg-matrix.md#L1)).
  3. Keep the principle "the adapter mediates, the DPG issues and signs" ([technical-scope.md#L132](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L132)); adapters never hold issuer signing keys for credentials.
  4. Replace the README claim that backends can be swapped "without touching the UI" ([README.md#L12](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L12)), which 576 vendor-name violations in the core contradict ([scripts/ci/agnosticism.sh](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/scripts/ci/agnosticism.sh#L1)), with a measurable rule: vendor names appear only inside adapter plug-in packages.
  5. Target audience is split: operators (deploy), issuer and verifier staff (portals), citizens (wallet and public verify), and non-technical readers (docs), per ADR-028.
  6. Success metric per adapter: deployable alone with one DPG, one image, one config file, one command (ADR-005, ADR-007, ADR-008).
- Consequences:
  1. All images, charts, packages, and docs carry the new name; a redirect note stays in the old README for one release.
  2. Each feature in the client list becomes one service with its own ADR (ADR-009 to ADR-026); nothing is built that a target DPG already provides.
  3. Credential signing stays in walt.id, Inji Certify, and CREDEBL; adapters sign only their own artefacts (status lists, trust lists, session tokens).
  4. The agnosticism guard becomes blocking in CI with a zero violation floor for core packages.
  5. Four audiences drive four documentation sets and two UI shells (staff portal, citizen portal).
  6. An adapter that cannot run alone is rejected at design review.

## ADR-002: Decompose the monolith into per-feature microservices
- Status: Proposed
- Owner: CDPI Architects
- Scope: Service boundaries, shared contracts, inter-service calls, state ownership.
- Decision:
  1. Split the single binary ([main.go#L613](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L613)) along the existing env-gated route groups ([main.go#L719](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L719), [roles.go#L21](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/roles/roles.go#L21)) into these services: `admin` (super admin API and portal), `trust-registry`, `issuer-auth`, `schema-registry`, `schema-builder-ui`, `data-source`, `issuance`, `issued-credentials`, `status-bitstring`, `status-token`, `wallet-auth`, `wallet-portal`, `verifier-discovery`, `verifier-ingest`, `verifier-policy`, `verifier-results`, `verifier-combined`, plus one `dpg-adapter-{waltid,inji,credebl}` per backend.
  2. Replace the 25-method `Adapter` interface that forces `ErrNotSupported` stubs ([adapter.go#L32](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/backend/adapter.go#L32), [waltid/issuer.go#L789](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/waltid/issuer.go#L789), [credebl/issuer.go#L244](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/credebl/issuer.go#L244)) with one small protobuf service per role capability (`IssuerBackend`, `HolderBackend`, `VerifierBackend`, `CatalogBackend`); a DPG adapter implements only the services its DPG supports and advertises them in a `Capabilities` RPC.
  3. Each service owns its data. The seven tables now created inline at startup ([pg/db.go#L43](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/storage/pg/db.go#L43)) are assigned to owning services; no service reads another service's tables.
  4. Forbid writes into DPG databases and Docker-socket control of sibling containers ([subjects.go#L195](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/storage/pg/subjects.go#L195), [inji_schema.go#L23](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/inji_schema.go#L23), [esignet_config.go#L97](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/esignet_config.go#L97), [waltid/docker.go#L14](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/waltid/docker.go#L14), [start-container.sh#L22](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/scripts/start-container.sh#L22)); DPG configuration goes through the DPG's own HTTP API or is applied at deploy time (ADR-008).
  5. Inter-service calls use the protobuf contract of ADR-003 over Connect with mutual service identity; the current bearer-key HTTP+JSON hub call ([adapters/verifiably](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/verifiably/adapter.go#L1)) is retired.
  6. Keep W3C Trace Context propagation already present ([httpx/client.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/httpx/client.go#L1)) but via the OpenTelemetry SDK, retiring the hand-rolled tracer ([tracing/tracer.go#L10](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/tracing/tracer.go#L10)).
  7. One shared `vc-core` library holds only pure functions (credential parsing, JWS, status-list bit maths) lifted per ADR-030; no HTTP, no storage.
- Consequences:
  1. About twenty small services replace one 43k-line binary; each is deployable and testable alone, and unused features are not deployed.
  2. DPG adapters shrink to the RPCs they support; the fan-out registry ([registry.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/registry/registry.go#L1)) becomes routing by capability.
  3. Schema migrations move to versioned files per service; no shared database.
  4. The adapter container no longer needs host root; the 14 SSRF and path-traversal gosec findings tied to proxying ([technical-scope.md#L93](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L93)) lose their attack surface.
  5. Every cross-service call is typed, versioned, and traceable.
  6. Traces export to any OTLP collector without custom code.
  7. Duplicate crypto and parsing code across services is impossible by construction.

## ADR-003: Protocol buffers as the canonical contract
- Status: Proposed
- Owner: CDPI Architects
- Scope: API definition language, wire protocols, OpenAPI generation, compatibility checks.
- Decision:
  1. Define every service API in proto3 ([Protocol Buffers language guide](https://protobuf.dev/programming-guides/proto3/)); the repo currently has no machine-readable contract beyond Go types and explicitly avoids protobuf ([tracing/exporter.go#L86](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/tracing/exporter.go#L86)).
  2. Serve each service with the Connect protocol, which speaks gRPC, gRPC-Web, and plain JSON over HTTP/1.1 from one handler ([Connect protocol reference](https://connectrpc.com/docs/protocol/), [Connect Go](https://connectrpc.com/docs/go/getting-started/)); JSON bodies follow ProtoJSON ([ProtoJSON format](https://protobuf.dev/programming-guides/json/)).
  3. Generate OpenAPI 3.1 documents from the proto files with `protoc-gen-connect-openapi` ([repo](https://github.com/sudorandom/protoc-gen-connect-openapi), [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)), replacing the hand-written 3.0.3 file that covers 24 of about 38 API routes with untyped bodies ([openapi.yaml#L1143](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/static/openapi.yaml#L1143)).
  4. Run `buf lint` and `buf breaking` against the last release tag in CI ([buf lint](https://buf.build/docs/lint/), [buf breaking](https://buf.build/docs/breaking/)); a breaking change requires a new major package version `vca.<service>.v2`.
  5. Express field constraints with protovalidate ([protovalidate](https://github.com/bufbuild/protovalidate)) so validation is in the contract, not in handler code.
  6. Model credentials and presentations as opaque `bytes` or `string` payloads plus a typed `format` enum (`vc+sd-jwt`, `dc+sd-jwt`, `jwt_vc_json`, `ldp_vc`, `mso_mdoc`), matching the formats OID4VCI names ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)); adapters never re-encode credentials.
  7. Standards-defined HTTP endpoints (`/.well-known/openid-credential-issuer`, `/.well-known/jwks.json`, OID4VP `direct_post`, status-list GET) stay as plain HTTP handlers with their standard JSON, documented in the same OpenAPI file.
- Consequences:
  1. One `proto/` module is the single source of truth; clients in any language are generated, not hand-written.
  2. Browsers, curl, and gRPC clients all talk to the same port with no gateway process.
  3. API docs are always complete and always match the code; the CDN-loaded Scalar page ([scalar.html#L33](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/static/scalar.html#L33)) is replaced by a self-hosted renderer.
  4. Incompatible changes cannot reach `main` unnoticed.
  5. Input validation is uniform across services and languages.
  6. New credential formats are an enum value, not a schema change.
  7. Wallets and DPGs that implement the open standards interoperate without knowing about protobuf.

## ADR-004: Test-driven development and functional-style code standard
- Status: Proposed
- Owner: CDPI Architects
- Scope: Test pyramid, coverage gate, code style, CI enforcement.
- Decision:
  1. Every RPC is written test-first against its proto contract; the current codebase measures 34.1% statement coverage with a CI floor of 31.5% ([quality.yml#L127](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/quality.yml#L127)) and nine packages at 0%.
  2. Coverage gate: 90% statements per package, 100% for `vc-core` pure functions, enforced with `go test -race -cover` and no `continue-on-error`.
  3. Code style: pure functions for parsing, validation, and policy evaluation; side effects only at service edges; no package-level mutable state; errors as values; the 39-field handler struct pattern ([handlers.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/handlers.go#L1)) and 690-line `main()` ([technical-scope.md#L35](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L35)) are not allowed.
  4. Contract tests: each DPG adapter runs against a recorded fixture set and, in a nightly job, against the real DPG container; the current tests use only `httptest` fakes ([technical-scope.md#L220](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L220)).
  5. Property and fuzz tests for all decoders (SD-JWT, CBOR, base45, QR payloads) using Go native fuzzing ([Go fuzzing](https://go.dev/doc/tutorial/fuzz)).
  6. End-to-end tests run in CI on every PR with Playwright against the compose stack; the 74 puppeteer scripts have no runner and are never executed ([technical-scope.md#L662](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L662)).
  7. Flaky tests are quarantined within one day and fixed within one week; the repo shows two de-flake commits in two days ([quality.yml#L99](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/quality.yml#L99)).
  8. Accessibility tests (axe-core) run in the e2e suite against every page, per ADR-027.
- Consequences:
  1. Untested behaviour cannot be merged; design happens in the proto file and the test before the handler.
  2. Coverage is a hard gate; packages are small enough that 90% is cheap.
  3. Handlers become thin adapters over pure functions that are trivial to unit test.
  4. Interop regressions with a DPG version bump are caught before release.
  5. Malformed input crashes are found by the fuzzer, not by citizens.
  6. UI regressions block merge; e2e scripts stop rotting.
  7. Test reliability is a tracked metric.
  8. WCAG regressions block merge.

## ADR-005: One container image per service
- Status: Proposed
- Owner: CDPI Architects
- Scope: Image base, runtime user, privileges, labels, signing, SBOM.
- Decision:
  1. Each service builds one static Go binary into `gcr.io/distroless/static-debian13:nonroot` ([distroless](https://github.com/GoogleContainerTools/distroless)), keeping the pattern already in the Dockerfile ([Dockerfile#L24](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/Dockerfile#L24)).
  2. Containers run as non-root with a read-only root filesystem and no capabilities; Trivy misconfiguration checks that today are report-only ([image.yml#L117](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/image.yml#L117)) become blocking.
  3. No image mounts `/var/run/docker.sock` ([start-container.sh#L22](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/scripts/start-container.sh#L22)); no image restarts other containers.
  4. Every image carries `org.opencontainers.image.{title,description,version,revision,source,licenses,created}` labels ([OCI annotations](https://github.com/opencontainers/image-spec/blob/main/annotations.md)).
  5. Every image is signed keyless with cosign ([cosign](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)), extending the existing step ([image.yml#L174](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/image.yml#L174)), and ships an SBOM attestation in SPDX and CycloneDX generated by syft ([SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/), [CycloneDX](https://cyclonedx.org/specification/overview/), [syft](https://github.com/anchore/syft)).
  6. Each image exposes one port, a `/healthz` and `/readyz` endpoint, and a `-healthcheck` subcommand as today ([main.go#L276](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L276)).
  7. Images vendor all web assets; no runtime CDN loads ([base.html#L11](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/layouts/base.html#L11)).
- Consequences:
  1. Attack surface per image is the binary alone; image size is a few megabytes.
  2. A compromised service cannot escalate on the host.
  3. Host root via the Docker socket is gone; DPG restarts move to the deploy tool.
  4. Operators can audit provenance of any running image from labels.
  5. Deployers can verify signatures and check CVEs offline from the SBOM.
  6. Orchestrators (compose, Kubernetes) get uniform probes.
  7. Air-gapped deployments work.

## ADR-006: CI/CD with version tags per release
- Status: Proposed
- Owner: CDPI Architects
- Scope: Branching, commit format, versioning, release workflow, artefact tags.
- Decision:
  1. Versions follow SemVer 2.0.0 ([semver.org](https://semver.org/spec/v2.0.0.html)); the repo has zero git tags and publishes only `:sha` and `:latest` images ([image.yml#L84](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/image.yml#L84)).
  2. Commits follow Conventional Commits 1.0.0 ([conventionalcommits.org](https://www.conventionalcommits.org/en/v1.0.0/)) and are checked in CI; `feat`, `fix`, and `BREAKING CHANGE` drive the version bump and CHANGELOG.
  3. A release workflow runs on `push: tags: v*` ([GitHub Actions events](https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows)): build all images, tag `:vX.Y.Z`, `:vX.Y`, `:vX`, sign, attach SBOMs, package Helm charts and CLI binaries, create a GitHub Release.
  4. One monorepo, one version for all services per release; a service whose proto did not change still gets the release tag.
  5. PR workflow: gofmt, golangci-lint (existing config, [.golangci.yml](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/.golangci.yml#L1)), buf lint and breaking, unit and contract tests, coverage gate, Trivy fs and image (blocking), gosec (blocking, replacing report-only [technical-scope.md#L93](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L93)), shellcheck (blocking), e2e, axe.
  6. Workflows live at repository root `.github/workflows/`, never under a subdirectory, which silently disabled CI until 2026-09-10 ([technical-scope.md#L72](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L72)).
  7. Nightly job runs real-DPG contract tests and the Kubernetes render and kind deploy that today "has never converged" ([k8s.yml#L12](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/k8s.yml#L12)).
- Consequences:
  1. Deployers pin a version; upgrades and rollbacks are explicit.
  2. CHANGELOG and version bumps are generated, not written.
  3. A tag is the only path to a published release.
  4. Compatibility matrices are one-dimensional.
  5. Nothing report-only remains; every check either passes or blocks.
  6. CI cannot be accidentally disabled by layout.
  7. Slow and environment-heavy checks do not slow PRs but still run daily.

## ADR-007: Interactive one-click setup CLI per role per DPG with env prefill
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `vca` CLI `setup` command, its inputs, outputs, and precedence rules.
- Decision:
  1. Replace the 1,411-line bash wizard ([deploy.sh#L726](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/deploy.sh#L726)) and 8.7k lines of shell with a Go CLI `vca` built on cobra; the current binary has no CLI beyond `-healthcheck` ([main.go#L303](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L303)).
  2. `vca setup --role {issuer|holder|verifier|admin} --dpg {waltid|inji|credebl}` asks only the questions that role and DPG need, with defaults, validation, and a summary before write.
  3. `--env-file <path>` prefills answers from a dotenv file; `--non-interactive` fails on any missing value.
  4. Precedence, highest first: CLI flag, process environment, `--env-file`, interactive answer, default; config is environment variables per the twelve-factor rule ([12factor.net/config](https://12factor.net/config)).
  5. Output is one `.env` per role-DPG pair plus generated DPG config (realm JSON, Caddyfile) written to `deploy/<role>-<dpg>/`; secrets are generated by the CLI and written with mode 0600, unlike today where setup rewrites `.env` and omits secrets ([deploy-reproducibility.md#L41](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/deploy-reproducibility.md#L41)).
  6. Every setup variable is declared once in a proto `Config` message with description and validation; the CLI, docs, and services derive from it, replacing 67 scattered `os.Getenv` calls with no validation layer ([main.go#L346](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L346)).
  7. `vca setup --all` composes the three role setups plus admin into one run.
- Consequences:
  1. One tested Go binary replaces untested shell; `tests/test_roles.sh` logic moves to Go unit tests.
  2. A verifier operator never sees issuer questions.
  3. Fleet operators script setup from prefilled files.
  4. Behaviour is predictable and documented in one table.
  5. Setup is re-runnable and does not lose secrets.
  6. Config drift between docs, CLI, and services is impossible.
  7. The demo path is one command.

## ADR-008: One-click deploy per role and combined deploy
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `vca deploy` command, compose profiles, Helm charts.
- Decision:
  1. `vca deploy --role <role> --dpg <dpg>` runs `docker compose --profile <role>-<dpg> up -d` against one committed compose file using profiles ([Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)); this replaces the ad-hoc `docker run` outside compose ([start-container.sh#L15](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/scripts/start-container.sh#L15)).
  2. `vca deploy --all` enables all role profiles for the chosen DPGs, replacing `./deploy.sh up all` ([README.md#L105](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L105)).
  3. DPG stacks are separate compose files included by reference and pinned to the versions listed in the DPG matrix ([docs/dpg-matrix.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/dpg-matrix.md#L1)); VCA services never need a DPG rebuild.
  4. DPG post-boot configuration (realm import, DID provisioning, CREDEBL org) is done by idempotent `vca` Go subcommands calling DPG APIs, replacing bootstrap shell such as the 2,205-line CREDEBL script ([scripts/bootstrap-credebl.sh](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/scripts/bootstrap-credebl.sh#L1)).
  5. Kubernetes: one Helm chart per service and one umbrella chart with `roles.<role>.enabled` values ([Helm charts](https://helm.sh/docs/topics/charts/)); the walt.id-only umbrella and unconverged workloads layer ([docs/k8s/resume.md#L9](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/k8s/resume.md#L9)) are replaced.
  6. `vca deploy --dry-run` prints the rendered compose or manifests; `vca status` and `vca down` complete the lifecycle.
  7. Resource floor per single role is one VCA service set plus one DPG, targeted under 4 GB RAM, versus 8 to 12 GB and about 25 ports for the whole stack today ([README.md#L30](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L30)).
- Consequences:
  1. Deploy is declarative and diffable; no bind-mount inode or `--add-host` surprises.
  2. Full demo and partial production use the same file.
  3. DPG upgrades are a version bump in one place.
  4. Bootstrap is testable and re-runnable; the 13 troubleshooting scenarios ([README.md#L1091](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L1091)) shrink.
  5. Kubernetes reaches parity with compose and is exercised nightly (ADR-006).
  6. Operators can review before applying.
  7. A single-role deployment fits a small VM.

## ADR-009: Super Admin CLI and UI portal with man pages and help page
- Status: Proposed
- Owner: CDPI Architects
- Scope: `vca admin` commands, admin service, admin portal, generated documentation.
- Decision:
  1. All admin operations (tenants, trust entries, auth providers, API keys, service health) are RPCs on the `admin` service; the CLI and the portal are two clients of the same proto.
  2. `vca admin ...` is a cobra command tree; man pages are generated with `doc.GenManTree` ([cobra/doc](https://pkg.go.dev/github.com/spf13/cobra/doc)) and shipped in release artefacts; today only `deploy.sh help` and `make help` exist ([Makefile#L56](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/Makefile#L56)).
  3. The portal `/admin/help` page renders the same command descriptions from the same source so CLI and UI help are identical.
  4. Every RPC has a `description` proto option in Simplified Technical English (ADR-028) that generates CLI help, man pages, portal help, and OpenAPI descriptions.
  5. The admin portal replaces the shared username and password login ([README.md#L818](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L818), [main.go#L242](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L242)) with OIDC (ADR-010).
  6. Admin actions are written to an append-only audit log with actor, action, and request id.
- Consequences:
  1. No admin action exists in the UI that cannot be scripted, and vice versa.
  2. `man vca-admin-trust-add` works on any Linux host.
  3. Help never drifts between CLI and UI.
  4. One sentence written once appears in four places.
  5. No default passwords ship.
  6. Every privileged change is attributable.

## ADR-010: Super Admin OIDC onboarding via CLI and UI
- Status: Proposed
- Owner: CDPI Architects
- Scope: How a super admin identity is bootstrapped and authenticated.
- Decision:
  1. Admin authentication is OpenID Connect only ([OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)) with provider discovery ([OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)), reusing the operator OIDC library that exists for issuers ([README.md#L793](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L793)).
  2. Authorization code flow with PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)) and the OAuth 2.0 Security BCP ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)); no implicit flow, exact redirect URI match.
  3. CLI onboarding: `vca admin onboard --issuer <url>` performs discovery, registers a client via Dynamic Client Registration when the IdP supports it ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html)) or accepts a client id and secret, and writes the provider to the admin service.
  4. The first super admin is bound by a one-time bootstrap token printed by `vca setup`; the admin logs in through OIDC and the token binds `iss` and `sub` to the super admin role.
  5. UI onboarding: the same steps as a wizard in the portal, available only to an existing super admin.
  6. CLI login uses device authorization or a loopback redirect with PKCE; no passwords are ever stored by VCA.
  7. CSRF protection for all browser POSTs uses synchronizer tokens plus `SameSite`; today there is no token ([session.go#L397](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/session.go#L397), [OWASP CSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)).
- Consequences:
  1. Any Keycloak, WSO2 IS, or national IdP can hold admin identities.
  2. Token interception and mix-up attacks are mitigated by design.
  3. Onboarding is scriptable for fleet rollouts.
  4. No default credential exists at any moment.
  5. Additional admins are added without shell access.
  6. Operators use their existing SSO.
  7. The open CSRF item ([TODO.md#L392](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/TODO.md#L392)) is closed.

## ADR-011: Signed trust registry with DeDi and ETSI as distinct methods
- Status: Proposed
- Owner: CDPI Architects
- Scope: Trust list data model, publication formats, signing, consumption by verifiers.
- Decision:
  1. Keep an internal canonical trust entry (entity DID or x509 identifier, role, status, validity, credential types) and publish it through pluggable `TrustListPublisher` methods; the current registry publishes only a self-defined ES256 JWT ([trust/jwt.go#L49](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/trust/jwt.go#L49), [main.go#L749](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L749)).
  2. Method `etsi`: publish a List of Trusted Entities in the JSON binding of ETSI TS 119 602 V1.1.1 ([ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf)) and accept ETSI TS 119 612 XML trusted lists for import ([ETSI TS 119 612 V2.3.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.03.01_60/ts_119612v020301p.pdf)); signed as JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html)) with keys published as JWK Set ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)).
  3. Method `dedi`: publish signed directory files and a `/.well-known/dedi.index.json` manifest as defined by the Decentralized Directory protocol repository ([LF-Decentralized-Trust-labs/decentralized-directory-protocol](https://github.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol)) and its documentation ([dedi-global.gitbook.io/docs](https://dedi-global.gitbook.io/docs)); the older `dedi.global/docs` and `/spec` paths return 404 ([technical-scope.md#L370](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L370)), so the GitHub repository and the gitbook are the normative sources and their file schemas are vendored with a commit hash.
  4. Both methods are enabled independently per deployment; the maintainers' advice not to choose between trust frameworks ([technical-scope.md#L390](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L390)) is followed.
  5. Signing keys are ES256 or Ed25519 only; the HS256 development fallback ([trust/jwt.go#L15](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/trust/jwt.go#L15), [main.go#L434](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L434)) is removed; keys live in a KMS or file with rotation and `kid`.
  6. Entities are identified by DID ([DID Core 1.0](https://www.w3.org/TR/did-1.0/)), with `did:web` ([did:web method](https://w3c-ccg.github.io/did-method-web/)) resolved through the lifted resolver ([internal/didresolver](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/didresolver/resolver.go#L1)), or by x509 subject for ETSI entries.
  7. The verifier policy service (ADR-024) consumes both list types through one `TrustLookup` RPC with a cached, signature-verified copy and configurable fail-open or fail-closed.
- Consequences:
  1. Admin edits once; every enabled format is regenerated.
  2. EU-style relying parties can consume the list with existing ETSI tooling.
  3. DeDi crawlers and CORD-based ecosystems can index the same entries; if the DeDi spec changes, only the vendored schema and publisher change.
  4. A deployment may run ETSI only, DeDi only, or both.
  5. A trust list can never be forged with a session secret.
  6. Issuers, holders, and verifiers are named the same way in trust lists and credentials.
  7. "Trusted issuer" becomes a checkable policy result with provenance.

## ADR-012: Issuer OIDC auth flows
- Status: Proposed
- Owner: CDPI Architects
- Scope: Staff login to issuer portals and issuer API access.
- Decision:
  1. Lift the existing OIDC provider set (Keycloak, WSO2 IS, any discovery-capable IdP) with PKCE ([internal/auth](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/auth/providers.go#L1), 87% covered) into the `issuer-auth` service.
  2. Session tokens issued by `issuer-auth` are JWTs ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)) signed ES256 and validated by other issuer services via JWKS; no shared session table.
  3. Roles `issuer-admin`, `issuer-operator`, `issuer-viewer` are mapped from IdP claims by a configurable claim path; per-subject scoping of schemas and credentials is kept.
  4. Machine access uses OAuth 2.0 client credentials from the same IdP; the static bearer keys `VERIFIABLY_API_KEYS` ([README.md#L957](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L957)) are deprecated after one release.
  5. Providers are registered through the admin service (ADR-009), not JSON files on a bind mount ([README.md#L793](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L793)).
  6. Internal versus public URL rewriting stays configurable for split-horizon deployments ([architecture.md#L161](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/architecture.md#L161)).
- Consequences:
  1. Proven, tested code is reused; no new login bugs.
  2. Issuer services scale horizontally with no sticky sessions.
  3. Access control is declarative and auditable.
  4. API secrets rotate under IdP control.
  5. Provider changes need no restart or file edit.
  6. Docker-internal and public hostnames both work.

## ADR-013: Issuer schema management portal
- Status: Proposed
- Owner: CDPI Architects
- Scope: Schema registry service and its portal pages.
- Decision:
  1. Schemas are JSON Schema 2020-12 documents ([JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)) referenced from credentials per W3C VC JSON Schema ([VC JSON Schema](https://www.w3.org/TR/vc-json-schema/)); today there is no schema validation library and no versioning ([README.md#L865](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L865)).
  2. Each schema carries an immutable version; updates create a new version; a schema is `draft`, `published`, or `retired`.
  3. Schema-to-DPG sync is an RPC on the DPG adapter (`RegisterCredentialConfiguration`) instead of editing walt.id HOCON files ([catalog.go#L13](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/waltid/catalog.go#L13)) or Inji's database plus container restarts ([inji_schema.go#L355](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/inji_schema.go#L355)).
  4. Public read: `GET /api/schemas` and the OID4VCI issuer metadata `credential_configurations_supported` ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) are generated from published schemas, as the current discovery handler does ([main.go#L729](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L729)).
  5. SD-JWT VC type metadata (`vct`) documents are generated per schema ([SD-JWT VC draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)).
  6. Portal pages: list, search, filter, detail, version history, publish, retire; all actions are RPCs.
- Consequences:
  1. Every credential can be validated against its schema by any party.
  2. Issued credentials always point at the exact schema version used.
  3. DPG side effects are explicit, typed, and testable.
  4. Wallets discover offerings from a standard endpoint.
  5. SD-JWT VC wallets can render and validate credentials by type.
  6. UI and API cannot diverge.

## ADR-014: Issuer schema builder with live view
- Status: Proposed
- Owner: CDPI Architects
- Scope: Schema builder UI and preview generation.
- Decision:
  1. Keep the debounced live preview pattern ([issuer_schema_builder.html#L48](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/pages/issuer_schema_builder.html#L48)) but render the preview from a pure `PreviewCredential(schema, sample)` function in `vc-core`.
  2. Builder edits produce a JSON Schema 2020-12 document; field types, required flags, enums, formats, and selective-disclosure flags are first-class.
  3. Live view shows three tabs: sample credential JSON, wallet card (using OID4VCI display metadata), and PDF preview (ADR-016).
  4. Builder is accessible: every control keyboard-operable, preview region is `aria-live="polite"` ([WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/)).
  5. Save creates a `draft` schema version in the registry (ADR-013); no DPG side effect until publish.
  6. Import from an existing JSON Schema or from a DPG catalog is supported.
- Consequences:
  1. Preview logic is unit tested with no browser.
  2. Output is standard and portable.
  3. Authors see what citizens will see.
  4. Screen-reader users can build schemas.
  5. Experiments never break production issuance.
  6. Existing schemas migrate without retyping.

## ADR-015: Issuer data sourcing portal
- Status: Proposed
- Owner: CDPI Architects
- Scope: Data source connectors, access control, preview, mapping.
- Decision:
  1. Lift CSV, HTTP API, and database sourcing with column-to-field mapping ([bulk.go#L60](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/bulk.go#L60), [testdata/bulk-issuance/README.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/testdata/bulk-issuance/README.md#L1)) into a `data-source` service with a `Source` proto: `CsvSource`, `HttpSource`, `SqlSource`.
  2. Each source stores credentials (DSN, bearer token, basic auth, mTLS cert) in a secret reference, never in the source record; secrets come from environment or a KMS.
  3. Access per source is role-scoped (ADR-012): who may view fields, who may preview rows, who may issue from it.
  4. `PreviewFields` returns the inferred field names and types; `PreviewRows` returns at most N masked rows; both are RPCs.
  5. Mapping is a stored `FieldMap` from source field to schema property with optional transforms (trim, date format, constant, concat); transforms are pure functions in `vc-core`.
  6. HTTP sources are subject to an allowlist and SSRF guard; the open SSRF backlog ([technical-scope.md#L93](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L93)) is closed by design.
  7. Bulk issuance jobs run as a separate `issuance` job with progress streamed over a server-streaming RPC, replacing SSE ([main.go#L577](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L577)).
- Consequences:
  1. Sources are typed and reusable across schemas.
  2. Secrets never appear in logs, exports, or the UI.
  3. Data protection roles are enforced, not assumed.
  4. Operators map fields with real data in view.
  5. Mappings are tested with table tests.
  6. The service cannot be used to reach internal networks.
  7. Progress works through any proxy and any client language.

## ADR-016: Issuer multi-format issuance
- Status: Proposed
- Owner: CDPI Architects
- Scope: Issuance channels and credential formats produced through DPGs.
- Decision:
  1. Primary channel is OID4VCI 1.0 ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)), pre-authorized code and authorization code, delegated to the DPG adapter; the current code targets draft-13 ([spec-versions.md#L13](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/spec-versions.md#L13)).
  2. Formats: SD-JWT VC ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html), [SD-JWT VC draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)), W3C VCDM 2.0 with Data Integrity or JOSE ([VCDM 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [VC Data Integrity](https://www.w3.org/TR/vc-data-integrity/), [VC JOSE COSE](https://www.w3.org/TR/vc-jose-cose/)), and ISO mdoc ([ISO/IEC 18013-5](https://www.iso.org/standard/69084.html)) where the DPG supports it; HAIP is the interoperability target ([HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)).
  3. PDF channel: a `pdf-render` service produces a document with the credential QR for every DPG, lifting the Inji-only implementation ([injicertify/pdf.go#L61](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/injicertify/pdf.go#L61)) and replacing the archived `gofpdf` dependency ([go.mod#L8](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/go.mod#L8)).
  4. QR payloads on PDF follow the MOSIP Claim 169 CWT profile ([Claim 169 spec](https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification), [IANA CWT claim 169](https://www.iana.org/assignments/cwt/cwt.xhtml), [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html)) or a credential offer URI, encoded as ISO/IEC 18004 QR ([ISO/IEC 18004](https://www.iso.org/standard/83389.html)).
  5. Delivery channels (email, SMS, download link) are a `delivery` message with a pluggable sender; batch and deferred issuance ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) are exposed when the DPG supports them.
  6. Each DPG adapter declares its supported formats and channels in `Capabilities`; the UI only offers what is possible.
- Consequences:
  1. Wallets built for the final spec work without vendor patches such as the Inji pre-auth proxy ([README.md#L46](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L46)).
  2. One issuer can serve EU-profile and national-ID-profile wallets.
  3. Paper fallback exists for every DPG.
  4. Printed credentials are verifiable offline by any Claim 169 reader.
  5. Citizens without a wallet app still receive credentials.
  6. No `ErrNotSupported` at runtime.

## ADR-017: Issuer issued-credentials portal
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `issued-credentials` service and portal pages.
- Decision:
  1. Every issuance writes one record (id, schema version, subject reference, format, status index, DPG, timestamp, hash) to a tamper-evident log; lift the hash-chained log ([internal/issuance/log.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/issuance/log.go#L1), 75% covered) onto PostgreSQL.
  2. Personal data is not stored; only a salted subject reference and the fields the issuer marks as searchable.
  3. Portal: list, search, filter, detail, revoke, reinstate, export; revoke and reinstate call the status services (ADR-018, ADR-019) and record the reason.
  4. Hash chain head is published daily and signed, so auditors can prove no record was removed.
  5. Retention per schema is configurable; expired records are pruned by a scheduled job.
- Consequences:
  1. Issuance history survives DPG replacement.
  2. Data minimisation holds even in the issuer's own logs.
  3. Revocation is one click with an audit trail.
  4. Integrity is externally checkable.
  5. Legal retention rules are enforceable.

## ADR-018: Bitstring Status List
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `status-bitstring` service.
- Decision:
  1. Implement W3C Bitstring Status List v1.0 ([Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)), lifting the encoder ([bitstring.go#L162](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/statuslist/bitstring.go#L162)) and publisher ([status_list.go#L51](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/status_list.go#L51)) into a single service.
  2. Lists are published as VCDM 2.0 credentials secured with `eddsa-rdfc-2022` or `ecdsa` Data Integrity proofs ([Data Integrity EdDSA](https://www.w3.org/TR/vc-di-eddsa/)) or as JOSE ([VC JOSE COSE](https://www.w3.org/TR/vc-jose-cose/)), replacing the legacy `Ed25519Signature2020` proof ([ldproof.go#L81](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/statuslist/ldproof.go#L81)).
  3. Purposes `revocation`, `suspension`, and `message` are supported; minimum list size is 131,072 entries as the spec requires.
  4. Index allocation is random within the list to prevent correlation; allocation and flip are RPCs used by the issuance and issued-credentials services.
  5. Lists are served with cache headers and ETag; a signed copy is stored so the service can restart without re-signing.
  6. Signing keys are per issuer, identified by `did:web` or `did:key`, kept in a KMS or a file, with rotation; the per-DPG self-managed key pattern ([main.go#L95](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L95)) is generalised.
- Consequences:
  1. Well-tested code (76%) is reused with a tighter boundary.
  2. Any VCDM 2.0 verifier can validate the list.
  3. Issuers can suspend without revoking.
  4. Verifiers cannot infer issuance order from indices.
  5. Verifier load does not hit the signer.
  6. Key compromise is scoped to one issuer and rotatable.

## ADR-019: Token Status List
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `status-token` service.
- Decision:
  1. Implement the IETF Token Status List ([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), in RFC Editor queue at draft 21), lifting the encoder ([statuslist/token.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/statuslist/token.go#L1)) and JWS typ `statuslist+jwt` ([jws.go#L66](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/statuslist/jws.go#L66)).
  2. Serve both JWT (`application/statuslist+jwt`) and CWT (`application/statuslist+cwt`, [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)) representations from the same bit array.
  3. Status sizes of 1, 2, 4, and 8 bits are supported as the draft defines; the `status_list` claim is embedded in SD-JWT VC and mdoc by the DPG using the URI and index this service allocates.
  4. Share the allocation, storage, and key management code with ADR-018 through `vc-core`; the two services differ only in encoding and signing envelope.
  5. Track draft-to-RFC changes with a conformance test vector suite pinned to the draft revision in `go.mod` metadata.
- Consequences:
  1. SD-JWT VC and mdoc credentials from any DPG have standard revocation.
  2. Constrained verifiers can use the CBOR form.
  3. Multi-state statuses are possible.
  4. Both status services stay small and consistent.
  5. RFC publication is a version bump, not a rewrite.

## ADR-020: Wallet OIDC auth flows
- Status: Proposed
- Owner: CDPI Architects
- Scope: Citizen login to the web wallet portal and holder binding.
- Decision:
  1. Citizens log in through OIDC with PKCE ([OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)) to national IdPs such as eSignet; the wallet store is keyed by `iss|sub` as today ([main.go#L191](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L191)).
  2. The `wallet-auth` service issues short-lived session JWTs and holds no personal data beyond the pairwise subject.
  3. Authorization-code issuance uses the IdP token as the OID4VCI authorization grant where the DPG supports it, following the security BCP ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)).
  4. Holder key binding: the portal creates a per-citizen key pair in the browser (WebCrypto, non-extractable) or in the DPG wallet (walt.id wallet-api, [wallet.go#L91](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/waltid/wallet.go#L91)); the adapter never holds holder private keys in a file, replacing the encrypted JSON file store ([internal/storage/injiwallet](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/storage/injiwallet/store.go#L1)).
  5. Logout revokes the session and, when the IdP supports it, performs RP-initiated logout.
  6. Rate limiting and OTP are Redis-backed, not in-process ([TODO.md#L275](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/TODO.md#L275)).
- Consequences:
  1. Citizens reuse their national ID login.
  2. A breach of the wallet-auth service exposes no credentials.
  3. Claiming a credential needs no second login.
  4. Credential theft from the server is impossible by design.
  5. Shared devices are safe.
  6. The portal scales to many replicas.

## ADR-021: Wallet credentials portal
- Status: Proposed
- Owner: CDPI Architects
- Scope: Citizen web wallet pages: discover, claim, view, present, delete.
- Decision:
  1. Discovery page lists schemas that issuers publish for pre-authorized issuance, read from issuer metadata ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) aggregated by `verifier-discovery` (ADR-022); the current discovery API has no in-app UI ([docs/features/binding-discovery.md](https://github.com/centre-for-dpi/verifiably/blob/main/docs/features/binding-discovery.md#L1)).
  2. Claimable page lists credentials the logged-in citizen may obtain through authorization-code flows, using an eligibility RPC that returns only yes or no per schema.
  3. Claim, scan, paste, accept, and reject actions ([handlers/wallet.go](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/wallet.go#L1)) are RPCs on `wallet-portal` that delegate to the DPG holder adapter.
  4. Credential storage is the DPG wallet when one exists; otherwise browser-side encrypted storage bound to the WebCrypto key of ADR-020.
  5. Presentation follows OID4VP 1.0 ([OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)) with a consent screen that lists each disclosed claim before submit.
  6. Every card shows issuer trust status (ADR-011), validity, and revocation state in plain language (ADR-028).
- Consequences:
  1. Citizens find what they can get without knowing issuer URLs.
  2. Eligibility checks leak no data about other citizens.
  3. Wallet behaviour is the same across DPGs.
  4. The server holds no credential it does not need to.
  5. Citizens control disclosure.
  6. Trust is visible, not implied.

## ADR-022: Verifier schema discovery portal
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `verifier-discovery` service and its pages.
- Decision:
  1. The service crawls trusted issuers from the trust list (ADR-011), fetches `/.well-known/openid-credential-issuer` ([OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) and published schemas, and caches them with a TTL, generalising the hub aggregator ([main.go#L531](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L531)).
  2. Portal pages let a verifier browse issuers and credential types, inspect fields, and select the claims a presentation request will ask for, replacing `/verifier/verify/build` ([main.go#L899](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/cmd/server/main.go#L899)).
  3. Selection produces a stored `PresentationTemplate` expressed in DCQL ([OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)); Presentation Exchange is generated only for DPGs that need it, as walt.id 0.18 does ([spec-versions.md#L14](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/spec-versions.md#L14)).
  4. Templates are versioned and reusable by the ingestion service (ADR-023) and the combined-presentation service (ADR-026).
  5. The same catalogue is exposed read-only to wallets (ADR-021).
- Consequences:
  1. Verifiers see the live ecosystem, not a hard-coded list.
  2. Non-technical staff design requests by clicking fields.
  3. Requests are standard and minimal.
  4. Request design is done once.
  5. One catalogue serves both sides.

## ADR-023: Verifier multi-format ingestion
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `verifier-ingest` service: accepting a presentation in any supported carrier and normalising it.
- Decision:
  1. Carriers: OID4VP request and response ([OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)), image upload, PDF upload, XML, JSON paste, ordinary QR, Claim 169 QR; the current code handles OID4VP, JSON paste ([verifier.go#L911](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/verifier.go#L911)), and QR from images and PDFs ([qr_decode.go#L7](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/qr_decode.go#L7)), and has no XML or explicit Claim 169 support.
  2. Every carrier decodes to one `RawPresentation` message: carrier, format, bytes, and detected type; decoders are pure functions in `vc-core` with fuzz tests (ADR-004).
  3. QR decoding follows ISO/IEC 18004 ([ISO/IEC 18004](https://www.iso.org/standard/83389.html)); Claim 169 payloads are base45-decoded, decompressed, parsed as CWT ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html)) with COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)) and claim key 169 ([IANA CWT claims](https://www.iana.org/assignments/cwt/cwt.xhtml), [MOSIP Claim 169](https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification)); PixelPass is kept as a legacy decoder.
  4. XML ingestion accepts an XML document that embeds a credential as text or base64 in a configured XPath; no XML signature validation is attempted in the first release.
  5. OID4VP `request_uri` fetches are allowlisted and size-limited; the current unrestricted fetch is the highest-risk finding ([inji_present.go#L193](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/handlers/inji_present.go#L193)).
  6. Browser camera scanning stays client-side (lifted [scanner.js](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/static/js/scanner.js#L1)) and posts only the decoded text.
- Consequences:
  1. A verifier accepts whatever a citizen brings.
  2. Policy evaluation never sees carrier details.
  3. National ID QR cards verify offline-style with the same policy engine.
  4. Legacy XML exchanges can be bridged without a new service.
  5. SSRF via presentation requests is closed.
  6. Camera frames never leave the device.

## ADR-024: Verifier presentation policy checklist
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `verifier-policy` service: independent checks over a normalised presentation.
- Decision:
  1. Policies are a list of named checks, each a pure function `(presentation, context) -> CheckResult`; the current checkbox set ([verifier_verify.html#L46](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/pages/verifier_verify.html#L46), [adapter.go#L314](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/backend/adapter.go#L314)) is the seed.
  2. Mandatory checks are performed by VCA itself, not only by the DPG: signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [VC Data Integrity](https://www.w3.org/TR/vc-data-integrity/)), key binding for SD-JWT ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)), `nbf`, `exp`, audience and nonce; today no independent verification is done and kb-jwt is not re-verified ([haip-conformance.md#L66](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/haip-conformance.md#L66)).
  3. Status checks query Bitstring ([Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)) and Token Status Lists ([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)) through a cached fetcher with fail-open or fail-closed per verifier.
  4. Trust chain check: the issuer is on an enabled trust list (ADR-011), and for chained credentials each link's issuer is trusted and each link references the previous one by id.
  5. Schema check validates the credential against its declared JSON Schema ([VC JSON Schema](https://www.w3.org/TR/vc-json-schema/)).
  6. Verifiers save a named policy set and reuse it; results carry the policy set version.
- Consequences:
  1. Checks are composable and unit tested in isolation.
  2. A DPG bug cannot make an invalid presentation pass.
  3. Revocation is checked even when the DPG ignores it.
  4. "Part of a credential chain" is a concrete, checkable result.
  5. Malformed but signed credentials are rejected.
  6. Audit shows exactly which rules applied.

## ADR-025: Verifier presentation result manager
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `verifier-results` service and its pages.
- Decision:
  1. Each verification stores a `VerificationResult`: overall verdict, per-check results, credential summaries, and the raw presentation reference; lift the result types ([adapter.go#L451](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/backend/adapter.go#L451)) into proto.
  2. UI is a card per credential: issuer name and trust badge, subject display fields, verdict, and a check list; a control expands the full JSON with syntax highlighting and copy.
  3. Personal data in stored results is retained only as long as the verifier's configured window; the raw presentation is deleted first.
  4. Results are queryable by time, verdict, issuer, and template, and exportable as CSV and JSON.
  5. Public citizen-facing verify page (lifted from [public/verify.html](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/public/verify.html#L1)) shows the same card without storage.
  6. Card and expanded views meet WCAG 2.2 AA (ADR-027): expandable regions use `aria-expanded`, JSON is in a labelled region.
- Consequences:
  1. UI, API, and CLI display the same object.
  2. Staff read a verdict in two seconds and can drill down.
  3. Verifiers hold no data beyond need.
  4. Reporting needs no database access.
  5. Citizens can self-check a credential.
  6. Screen-reader users get the same information.

## ADR-026: Verifier multi-credential combined presentation
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `verifier-combined` service: requesting and evaluating several credentials in one OID4VP transaction.
- Decision:
  1. Requests use DCQL from OID4VP 1.0 ([OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)) with `credential_sets` for alternatives; the current implementation is limited to walt.id N descriptors and the delegated pair ([waltid/verifier.go#L100](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/adapters/waltid/verifier.go#L100), [TODO.md#L404](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/TODO.md#L404)).
  2. A combined template is a list of ADR-022 templates plus cross-credential rules (same subject identifier, delegation link, date ordering), evaluated as pure functions.
  3. Each credential in the response is run through the ADR-024 policy set independently, then the cross-credential rules run; the overall verdict is the conjunction.
  4. Results reuse the ADR-025 card list with one card per credential and a summary card for the cross rules.
  5. The delegated-access evaluator ([internal/delegation](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/delegation/delegation.go#L1), 73% covered) is lifted as the first cross-credential rule set.
- Consequences:
  1. Any DCQL-capable wallet can answer combined requests.
  2. Rules are readable, testable data.
  3. A weak credential cannot hide behind a strong one.
  4. Staff see per-credential and combined outcomes at once.
  5. Guardianship and delegation scenarios work on day one.

## ADR-027: UI overhaul for WCAG 2.2 AA with composable Go + HTMX components
- Status: Proposed
- Owner: CDPI Architects
- Scope: All staff and citizen pages, the shared UI kit, theme and font packs.
- Decision:
  1. Conformance target is WCAG 2.2 Level AA ([WCAG 2.2](https://www.w3.org/TR/WCAG22/), [How to Meet WCAG](https://www.w3.org/WAI/WCAG22/quickref/)) using WAI-ARIA 1.2 ([WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/)); the current UI has seven `aria-*` attributes in total and no accessibility references ([base.html#L37](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/layouts/base.html#L37)).
  2. Fix the measured failures: remove `outline: none` on focus ([style.css#L193](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/static/css/style.css#L193)), add `alt` to every QR image ([public/verify.html#L172](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/public/verify.html#L172)), raise `--ink-mute` and `--warn` contrast to at least 4.5:1 ([style.css#L1](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/static/css/style.css#L1)), set `<html lang>` from the active language ([base.html#L2](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/templates/layouts/base.html#L2)), add a skip link, `:focus-visible` styles, `prefers-reduced-motion`, and live regions for toasts.
  3. Adopt the UI architecture of adammwaniki/adamndegwa (main @ 0173066, Apache-2.0 [LICENSE](https://github.com/adammwaniki/adamndegwa/blob/main/LICENSE)) as the `vca-ui` kit: Go standard library only, `html/template` rendering with contextual auto-escaping ([html/template](https://pkg.go.dev/html/template)), HTMX vendored in `static/` ([layout.html#L77](https://github.com/adammwaniki/adamndegwa/blob/main/views/layout.html#L77)), and no third-party Go modules ([README.md#L8](https://github.com/adammwaniki/adamndegwa/blob/main/README.md#L8)).
  4. Themes are a Go package: colour constants are the single source of truth ([brand.go#L12](https://github.com/adammwaniki/adamndegwa/blob/main/internal/brand/brand.go#L12)), every foreground and background pairing in use is declared with its minimum ratio ([brand.go#L55](https://github.com/adammwaniki/adamndegwa/blob/main/internal/brand/brand.go#L55)), a WCAG contrast function computes the ratio ([contrast.go#L42](https://github.com/adammwaniki/adamndegwa/blob/main/internal/wcag/contrast.go#L42), [WCAG contrast ratio](https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio)), and a unit test fails the build when any pairing is below AA ([compliance_test.go#L13](https://github.com/adammwaniki/adamndegwa/blob/main/internal/wcag/compliance_test.go#L13)). A `Theme` is one such package; `vca-ui` ships `default-light` and `default-dark` and a deployment selects or adds a theme by providing one Go package and one token block.
  5. Theme tokens are CSS custom properties on `:root`, overridden under `[data-theme="dark"]` ([style.css#L16](https://github.com/adammwaniki/adamndegwa/blob/main/static/style.css#L16)); a test asserts the CSS tokens equal the Go constants ([compliance_test.go#L33](https://github.com/adammwaniki/adamndegwa/blob/main/internal/wcag/compliance_test.go#L33)); the theme is applied before first paint from `prefers-color-scheme` or the user's stored choice, with a fail-safe when storage throws ([layout.html#L54](https://github.com/adammwaniki/adamndegwa/blob/main/views/layout.html#L54)); the light-mode `data-theme` stamp is `light`, dark is `dark`, absent means system.
  6. Fonts are a second pack: four named roles, display, heading, body, meta, each a Go constant ([brand.go#L38](https://github.com/adammwaniki/adamndegwa/blob/main/internal/brand/brand.go#L38)) with a fallback stack; font files are self-hosted in `static/fonts/` with `font-display: swap` ([CSS Fonts Level 4 font-display](https://www.w3.org/TR/css-fonts-4/#font-display-desc)) instead of the Google Fonts CDN link the source uses ([layout.html#L33](https://github.com/adammwaniki/adamndegwa/blob/main/views/layout.html#L33)), per the no-CDN rule of ADR-005; a font pack is swapped by replacing the constants and the files.
  7. Components are named `html/template` partials with one data struct each ([card.html#L1](https://github.com/adammwaniki/adamndegwa/blob/main/views/partials/card.html#L1)), rendered by handlers that return the partial for `HX-Request` and the full layout otherwise, with the page title sent in `HX-Title` ([server.go#L98](https://github.com/adammwaniki/adamndegwa/blob/main/internal/server/server.go#L98)); every VCA portal page is composed only from kit components (card, nav, form field, table, status badge, toast, dialog, QR image, JSON viewer); no page-local CSS.
  8. Accessibility is tested in Go: every rendered page is asserted to have one `h1`, `lang`, a skip link, a labelled `nav`, a `main` landmark, named icon buttons, `aria-expanded` wiring, and no `href="#"` ([a11y_test.go#L24](https://github.com/adammwaniki/adamndegwa/blob/main/internal/server/a11y_test.go#L24)); the kit adds assertions for 24 by 24 CSS pixel targets, `alt` on images, `aria-live` regions, and `prefers-reduced-motion` ([style.css#L67](https://github.com/adammwaniki/adamndegwa/blob/main/static/style.css#L67)); UI packages hold 100% statement coverage with a CI gate ([check-coverage.sh#L13](https://github.com/adammwaniki/adamndegwa/blob/main/scripts/check-coverage.sh#L13), [ci.yml#L25](https://github.com/adammwaniki/adamndegwa/blob/main/.github/workflows/ci.yml#L25)), which is stricter than the 90% floor of ADR-004.
  9. Progressive enhancement: every page works without JavaScript; HTMX adds partial swaps; camera scanning is the only JavaScript-required feature and has a file-upload fallback; `hx-*` attributes appear only inside kit components.
  10. Internationalisation uses message catalogues per language with human review, replacing runtime machine translation ([architecture.md#L169](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/architecture.md#L169)); `<html lang>` follows the active catalogue.
  11. Automated axe checks in e2e (ADR-004) plus a manual audit with screen reader and keyboard only before each minor release; results are published in an accessibility statement.
- Consequences:
  1. A clear, testable target replaces zero evidence.
  2. Known failures are closed in the first sprint.
  3. The UI has no JavaScript framework, no build step, and no template injection class of bug; the kit is one Go module any service imports.
  4. A theme that fails AA cannot compile into a release; a national deployment rebrands by adding one Go package.
  5. CSS and Go can never disagree on a colour; light, dark, and system modes work on first paint with no flash.
  6. Fonts load offline and in air-gapped sites; a typeface change touches two places.
  7. Every page is assembled from tested parts; visual consistency is enforced by construction, and a component fix propagates to all services.
  8. Structural WCAG regressions fail unit tests in milliseconds, before the slower e2e and axe runs.
  9. Low-end devices, text browsers, and assistive technology all work.
  10. Translations are accurate and stable.
  11. Regressions are caught by CI and confirmed by humans.

## ADR-028: Documentation and OpenAPI in Simplified Technical English
- Status: Proposed
- Owner: CDPI Architects
- Scope: README, per-service docs, CLI help, portal help, OpenAPI descriptions, error messages.
- Decision:
  1. All reader-facing text follows ASD-STE100 Issue 9 ([ASD-STE100](https://www.asd-ste100.org/)): approved vocabulary, one instruction per sentence, active voice, sentences at most 20 words, no idiom.
  2. English is the source language; the Spanish files ([todo.md](https://github.com/centre-for-dpi/verifiably/blob/main/todo.md#L1), log strings [roles.go#L52](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/roles/roles.go#L52)) are translated or dropped; stale documents ([INTEGRATION.md#L3](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/INTEGRATION.md#L3), [README.md#L64](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L64)) are deleted.
  3. Structure: one README of at most 200 lines with purpose, one-command start, and links; one `docs/<service>/` per service with "What it does", "How to run", "How to check it works", "Reference"; a glossary; the 1,512-line README ([README.md](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L1)) is split accordingly.
  4. OpenAPI 3.1 descriptions come from proto comments (ADR-003); a linter checks the STE word list and sentence length on every PR.
  5. Error messages returned to users are catalogued, STE-checked, and tell the user what to do next.
  6. A dictionary of project terms (issuer, holder, verifier, credential, presentation, schema, status list, trust list) is kept in `docs/glossary.md` and reused by the UI.
- Consequences:
  1. Non-technical readers can follow the docs; translators have a controlled source.
  2. One language, no stale pages.
  3. Readers find the one page they need.
  4. API docs are complete and readable at the same time.
  5. Support load drops.
  6. Everyone uses the same word for the same thing.

## ADR-029: Repository licensing
- Status: Proposed
- Owner: CDPI Architects
- Scope: Licence of source code, documentation, and container images.
- Decision:
  1. Add a `LICENSE` file at the repository root; none exists and the README points to a file that is not there ([README.md#L1509](https://github.com/centre-for-dpi/verifiably/blob/main/README.md#L1509)).
  2. Licence is Apache-2.0, an OSI-approved licence on the SPDX list ([SPDX License List](https://spdx.org/licenses/), [OSI licences](https://opensource.org/licenses)) with an explicit patent grant, compatible with the Apache-2.0 and MIT dependencies in `go.mod`.
  3. Every source file carries `SPDX-License-Identifier: Apache-2.0`; images carry `org.opencontainers.image.licenses=Apache-2.0` (ADR-005).
  4. Documentation is CC-BY-4.0, stated in `docs/LICENSE`.
  5. Third-party notices are generated from the SBOM (ADR-005) into `NOTICE`.
  6. Committed secrets and vendor keystores ([config/federation.json#L16](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/config/federation.json#L16), [oidckeystore.p12](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/deploy/compose/injiweb/config/certs/oidckeystore.p12)) are purged from history before the first tagged release.
- Consequences:
  1. Reuse is legally possible.
  2. Governments and vendors can adopt without legal review of an unusual licence.
  3. Licence is machine-checkable per file and per image.
  4. Docs can be copied into national portals with attribution.
  5. Compliance is automatic.
  6. The first release has a clean provenance.

## ADR-030: Migration and asset carry-over from the current codebase
- Status: Proposed
- Owner: CDPI Architects
- Scope: What is lifted, what is rewritten, what is dropped, and in what order.
- Decision:
  1. Lift into `vc-core` with tests: `internal/statuslist` (76% covered), `internal/vp` (78%), `internal/delegation` (73%), `internal/auth` and `auth/oidc` (87%, 69%), `internal/didresolver` (97%), `internal/trust` (54%, minus HS256), `backend/normalized.go`, `vctypes` ([technical-scope.md#L26](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L26)).
  2. Lift the DPG interop knowledge in `internal/adapters/{waltid,injicertify,injiverify,credebl}` and `docs/dpg/*.md` into the three DPG adapter services, keeping their `httptest` fixtures; drop `adapters/{verifiably,injiweb,libretranslate,mock,factory}`.
  3. Rewrite from scratch: `internal/handlers` (17.5k lines, 30% covered, vendor-coupled), `cmd/server/main.go`, all templates, `deploy.sh`, `scripts/*.sh`, the 74 e2e scripts.
  4. Drop hand-rolled infrastructure in favour of maintained libraries: `internal/tracing` (0% covered), `internal/storage/redis` (0%), `internal/metrics`, `internal/jose`, `internal/httpx`; use OpenTelemetry SDK, a maintained Redis client, and a maintained JOSE library.
  5. Drop `gofpdf` (archived) and `go-qrcode` (2020) ([go.mod#L5](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/go.mod#L5)) for maintained equivalents; keep `pgx`, `cbor`, `gozxing`, `pdfcpu`.
  6. Keep the CI quality gate configuration ([.golangci.yml](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/.golangci.yml#L1), [quality.yml](https://github.com/centre-for-dpi/verifiably/blob/main/.github/workflows/quality.yml#L1)) and the maintainers' scope, conformance, and version documents ([technical-scope.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/technical-scope.md#L1), [haip-conformance.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/haip-conformance.md#L1), [spec-versions.md](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/docs/spec-versions.md#L1)) as inputs.
  7. Order: proto contracts and `vc-core` first; then `status-bitstring`, `status-token`, `trust-registry` (smallest, best tested); then issuer services; then verifier services; then wallet services; then admin and UI shells; the monolith is kept running until each role has parity and is retired role by role.
  8. Data migration: export `issued_credentials`, `status_lists`, `trusted_issuers` ([pg/db.go#L43](https://github.com/centre-for-dpi/verifiably/blob/main/verifiably-go/internal/storage/pg/db.go#L43)) with a `vca migrate` command; sessions and caches are not migrated.
- Consequences:
  1. About 6k lines of proven code are reused with tests intact.
  2. Interop workarounds are not rediscovered.
  3. The untested, coupled 60% of the codebase is replaced, not patched.
  4. Test burden for infrastructure moves to upstream maintainers.
  5. No archived dependencies at release.
  6. Existing quality bar and knowledge are retained.
  7. Value ships early and risk is spread across releases.
  8. Issuers keep their history and revocation state across the cutover.

## ADR-031: BBS+ selective disclosure (deferred)
- Status: Proposed
- Owner: CDPI Architects
- Scope: Unlinkable selective disclosure for W3C credentials, scheduled after the services above ship.
- Decision:
  1. Target the W3C Data Integrity BBS Cryptosuites, currently a Candidate Recommendation Draft ([Data Integrity BBS](https://www.w3.org/TR/vc-di-bbs/)); implementation waits for Recommendation status or two interoperable DPG implementations; there is no BBS code in the repo today.
  2. Contract preparation now: the `format` enum (ADR-003) reserves `ldp_vc+bbs`; the policy service (ADR-024) reserves a `derived_proof` check; the wallet consent screen (ADR-021) already lists claims per disclosure.
  3. Issuance stays delegated to the DPG (ADR-001); VCA adds only derivation and verification helpers in `vc-core` when a DPG can issue `bbs-2023` proofs.
  4. Until then, selective disclosure is provided by SD-JWT VC ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)) and mdoc ([ISO/IEC 18013-5](https://www.iso.org/standard/69084.html)), which HAIP mandates ([HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)).
  5. Review trigger: a quarterly check of the BBS specification status recorded in `docs/spec-versions.md`.
- Consequences:
  1. No effort is spent on a moving target.
  2. Adding BBS later changes no service boundary.
  3. Key custody principles are unchanged.
  4. Citizens have selective disclosure from the first release.
  5. The decision is revisited on evidence, not on a date.
