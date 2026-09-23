# Verifiably — Secure and Scalable: Feature Roadmap

**Purpose:** scope of work for a time-and-materials engagement. Unrefined by design — sizes are ranges, not commitments; refine per epic at the point of pick-up.
**Date:** 2026-09-23. Baseline measured against `main` @ `dff8d45`.

**This is the single handover document.** It is self-contained: § 2.1 summarises the target architecture, so a reader without access to the internal source documents can work from this file alone. Appendix C specifies one epic to implementation depth as the worked example of what "refine at pick-up" means for the rest.

**Sources, in order of precedence:**

1. *Verifiably Wishlist* + *Verifiable Credentials Adapters: Architecture Decision Records* (internal, ADR-001…031, reviewed commit `9aca9bf`) — the **target architecture**. Referenced below as **ADR-nnn** / **W-n**, and summarised in § 2.1.
2. `docs/technical-scope.md` (rev 7, 2026-09-12) — the **measured baseline and incremental plan** for the current codebase. Referenced as **A.n…G.n**.
3. `TODO.md`, `docs/haip-conformance.md`, `docs/spec-versions.md`, SonarCloud / Trivy / gosec output — facts.

Where the two plans disagree, § 2 says which wins and why. Where this document differs from either, it says so inline.

---

## 1. Where it stands — measured

| Area | State today | Evidence |
|---|---|---|
| Codebase | One Go binary, 42.9k LOC app + 16.8k test, 39 packages; `main()` 690 lines; 8.6k lines of deploy shell | technical-scope § 2.1 |
| Test coverage | ~32 % overall; `internal/handlers` (41 % of the code) at 27.6 %; 9 packages at 0 % including `storage/pg`, `httpx`, `tracing` | § 2.2 |
| CI | Running since 2026-09-10 (it had never run before). Lint zero-tolerance, coverage floor 31.5 %, SonarCloud gate ≥ 80 % on new code, Trivy fs blocking, Trivy image + gosec + shellcheck report-only | A.1, A.2 |
| SonarCloud security rating | **C**. HIGH 0 (three `S5542` accepted with justification), MEDIUM 6 (1 fixed on `fix/import-registry-seg`, 5 SSRF deferred to allowlist design), LOW 31 | queried 2026-09-18 |
| Secrets in tree | Demo PKI removed (#18). `config/federation.json` and `oidckeystore.p12` still to purge from history before first tagged release | ADR-029.6 |
| Keys | Trust-registry and status-list keys are PEM files or an HS256 dev fallback; holder keys in an encrypted JSON file; DPG keys managed by the DPGs | F.5, ADR-011.5, ADR-020.4 |
| Auth | Admin: shared username/password. Issuer staff: OIDC (Keycloak/WSO2) with PKCE, 87 % covered. Machine: static bearer keys. No CSRF tokens | ADR-009.5, ADR-010.7, ADR-012.4 |
| Deploy | Compose: 3 DPG stacks, `deploy.sh` wizard, 8–12 GB RAM, ~25 ports. K8s: 22-phase workplan implemented, charts render, **walt.id umbrella has never converged on a real cluster** | G.1, G.2 |
| Release | Zero git tags; images `:sha` and `:latest` only; no LICENSE file | ADR-006.1, ADR-029.1 |
| Open PRs | #14 (mDL, +28k lines, lift candidate) and #15 (handler tests, +18k lines) still open since 2026-09-10 | § 3 of technical-scope |
| Standards | OID4VCI draft-13 (final is 1.0), OID4VP via walt.id 0.18 (PEX, not DCQL), no JARM, kb-jwt not independently verified, no schema validation | haip-conformance, spec-versions |

---

## 2. The decision that shapes everything: evolve or revamp

The ADR set proposes a rewrite — new name (**VCA**), ~20 Connect/protobuf services, distroless image per service, a Go CLI replacing all shell, WCAG 2.2 AA UI kit, 90 % coverage per package (ADR-001…008, 027, 030). `technical-scope.md` proposes hardening the monolith in place (A–G).

### 2.1 The target architecture in brief

The ADR set (ADR-001…031) is internal; this is what a provider needs from it to read the rest of this document.

| ADR | Proposes |
|---|---|
| 001 | Rebrand to **Verifiable Credentials Adapters (VCA)**, module `github.com/centre-for-dpi/vc-adapters`. Product is a set of adapters, each adding one capability a DPG (walt.id, Inji, CREDEBL) does not ship. Principle kept: **the adapter mediates, the DPG issues and signs.** Vendor names allowed only inside adapter packages. Each adapter deployable alone: one DPG, one image, one config file, one command |
| 002 | Decompose the single binary into ~20 services along the existing role boundaries (admin, trust-registry, issuer-auth, schema-registry, schema-builder, data-source, issuance, issued-credentials, status-bitstring, status-token, wallet-auth, wallet-portal, verifier-{discovery,ingest,policy,results,combined}, plus one adapter per DPG). Each owns its data. No Docker-socket control, no writes into DPG databases. Replaces the 25-method `Adapter` interface (which forces `ErrNotSupported` stubs) with small per-capability services advertising a `Capabilities` RPC |
| 003 | **Protobuf is the canonical contract.** proto3 + Connect (gRPC, gRPC-Web and JSON from one handler), OpenAPI 3.1 generated from proto, `buf lint`/`buf breaking` in CI, protovalidate for field constraints. Credentials modelled as opaque bytes + a format enum — adapters never re-encode. Standards endpoints (`/.well-known/*`, OID4VP `direct_post`, status-list GET) stay plain HTTP |
| 004 | Test-first against the proto contract. 90 % statements per package, 100 % for the pure core. Contract tests against real DPG containers nightly; fuzz tests on every decoder; Playwright e2e + axe on every PR |
| 005 | One distroless static image per service: non-root, read-only root filesystem, no capabilities, OCI labels, cosign keyless signature, SPDX + CycloneDX SBOM, `/healthz` + `/readyz`, all web assets vendored (no runtime CDN) |
| 006 | SemVer tags, Conventional Commits, release workflow on `v*`; every PR check blocking (nothing report-only); slow cluster and real-DPG checks nightly |
| 007–008 | A Go CLI (`vca`) replaces 8.7k lines of shell: `setup --role --dpg` with env prefill and non-interactive mode, config declared once in a proto `Config` message; `deploy` over compose profiles and Helm, with `--dry-run`, `status`, `down`. Single role + one DPG under 4 GB RAM |
| 009–010 | Admin CLI and portal are two clients of one proto; man pages and portal help generated from the same source. **OIDC only** — no shared password, first admin bound by a one-time bootstrap token; CSRF tokens on every browser POST |
| 011 | Signed trust registry with **two publication methods**: `etsi` (TS 119 602 JSON out, TS 119 612 XML in) and `dedi` (Decentralized Directory files + `/.well-known/dedi.index.json`). Both enabled independently. ES256/Ed25519 only — the HS256 dev fallback is removed. One `TrustLookup` RPC serves the verifier |
| 012 | Issuer staff auth via OIDC with role claims; stateless ES256 session JWTs; static API keys deprecated |
| 013–017 | Issuer surface: versioned JSON Schema 2020-12 registry synced to DPGs by RPC (no HOCON edits, no DB writes, no restarts); schema builder with live preview; typed data sources (CSV/HTTP/SQL) with secret references and masked preview; multi-format issuance on **OID4VCI 1.0** plus a PDF channel with Claim 169 QR for every DPG; hash-chained issued-credentials log with signed daily head |
| 018–019 | Both revocation standards as services sharing one core: W3C Bitstring Status List and IETF Token Status List (JWT **and** CWT), random index allocation, ≥ 131 072 entries, cached and signed-at-rest |
| 020–021 | Citizen OIDC to national IdPs; **holder keys never on the server** (browser WebCrypto non-extractable, or DPG wallet custody); discovery, eligibility, claim and OID4VP consent listing every disclosed claim |
| 022–026 | Verifier surface: crawl trusted issuers to build **DCQL** templates by clicking fields; ingest any carrier (OID4VP, image, PDF, XML, JSON, QR, Claim 169) into one normalised message; policy as named pure checks **performed by VCA itself, not only the DPG**; results manager with retention; multi-credential combined presentations with cross-credential rules |
| 027 | UI overhaul to **WCAG 2.2 AA**: Go stdlib + `html/template` + vendored HTMX, no JS framework, no build step. Themes as Go packages whose contrast is unit-tested — a theme below AA fails the build. Self-hosted fonts. Structural a11y assertions in Go tests, axe in e2e, manual audit per release |
| 028 | All reader-facing text in Simplified Technical English (ASD-STE100): README ≤ 200 lines, one docs set per service, glossary, STE linter in CI, catalogued error messages |
| 029 | Apache-2.0 LICENSE (none exists today), SPDX headers, CC-BY-4.0 docs, NOTICE from SBOM, committed secrets purged from history before the first tag |
| 030 | **Migration plan**: lift the well-tested pure packages, rewrite `internal/handlers` / `main.go` / templates / shell / e2e, drop hand-rolled infrastructure for maintained libraries. Order: contracts and core → status and trust services → issuer → verifier → wallet → admin and UI. Monolith runs until each role reaches parity, then retires role by role |
| 031 | BBS+ unlinkable disclosure deferred until the spec is a Recommendation or two DPGs interoperate; SD-JWT VC and mdoc provide selective disclosure until then |

The **Wishlist** (W-1…W-5) adds: 80 % UI test coverage; SonarCloud grade A; a full UI/UX overhaul with a named design lead; a schema builder that can introspect APIs and ingest schemas from external sources including blockchains; and DID/PKI implementation walkthroughs so a country can go from bootcamp to national-scale operation.

### 2.2 Recommendation

**Recommendation: adopt the ADR target architecture, execute it as a strangler migration in ADR-030's order, and stop investing in anything ADR-030 marks for rewrite unless it must stay in production during the migration.** Concretely:

| Bucket | What | Roadmap treatment |
|---|---|---|
| **Lift** (ADR-030.1–2) | `statuslist`, `vp`, `delegation`, `auth`+`auth/oidc`, `didresolver`, `trust` (minus HS256), `backend/normalized.go`, `vctypes`, the four DPG adapters' interop knowledge, PR #14's `mdl`/`mdoc`/`signer` | Harden now; tests written here are not wasted |
| **Rewrite** (ADR-030.3) | `internal/handlers` (17.5k lines), `cmd/server/main.go`, all templates, `deploy.sh`, `scripts/*.sh`, 74 e2e scripts | **No new feature work.** Security fixes only where the monolith carries production traffic before its replacement ships |
| **Drop** (ADR-030.4–5) | `tracing`, `storage/redis`, `metrics`, `jose`, `httpx` (→ OTel SDK, maintained Redis + JOSE libs); `gofpdf`, `go-qrcode` | Do not write the tests technical-scope A.3/M1 asked for on `httpx`/`tracing` |

Three consequences the ADRs do not state and this roadmap does:

1. **A rewrite does not remove the need for an outbound-destination policy.** ADR-002 consequence 4 says the SSRF findings "lose their attack surface"; ADR-015.6 and ADR-023.5 then re-introduce the allowlist. The design in **Appendix C** is the spec for that shared component regardless of which codebase hosts it. Build it once, in `vc-core` or an `outbound` package, and lift it.
2. **"20 services" and "under 4 GB per role" (ADR-008.7) need to be reconciled.** Recommend a *modular monolith deployable as N processes*: every service is a Connect handler in its own Go package with its own data ownership; a build flag or `--services` list decides whether one binary hosts one service or several. Small VM gets one process; K8s gets one pod per service. Same code, no premature per-service Postgres.
3. **PRs #14 and #15 need a decision now.** #14 carries the `internal/signer` seam and the mdoc packages the ADRs lift — merge after it clears ≥ 80 % new-code coverage. #15's 15.6k lines test `internal/handlers`, which ADR-030 rewrites — merge only if the monolith will serve production for more than ~two quarters; otherwise close with thanks and lift its `coverage-gate.sh` alone.

---

## 3. Epics

Sizes are per-engineer effort, unrefined: **S** ≤ 1 wk · **M** 1–3 wk · **L** 3–8 wk · **XL** > 8 wk. "Blocks" lists what cannot start until this lands.

### E0 — Foundations: contracts, core library, quality bar

*Why:* everything else in the ADR set is defined in terms of a proto contract and a pure-function core. Without them the rewrite has no shape and the coverage bar has no unit.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E0.1 | `proto/` module: service definitions for every ADR-002 service, `buf lint` + `buf breaking` in CI, protovalidate constraints, OpenAPI 3.1 generated | ADR-003 | **L** | Design-heavy. First deliverable is the *contract*, reviewed before any implementation. Credentials are opaque bytes + format enum. |
| E0.2 | `vc-core`: lift the ADR-030.1 packages as pure functions; 100 % coverage gate; fuzz tests on every decoder (SD-JWT, CBOR, base45, QR, Claim 169) | ADR-004.2/5, ADR-030.1 | **L** | Includes removing HS256 from `trust`. |
| E0.3 | Coverage and CI policy: 90 % per new package, `-race`, no `continue-on-error`; gosec, shellcheck, Trivy image → blocking; conventional-commit check | ADR-004, ADR-006.5 | **S** | Mechanical once E0.2 exists. Keep the existing SonarCloud ≥ 80 %-on-new-code gate throughout. |
| E0.4 | Outbound-destination policy (`OutboundPolicy`, dial-time IP check, redirect re-check, per-purpose allowlist seeded from config) | **Appendix C**, ADR-015.6, ADR-023.5 | **M** (~5.5 d scoped) | Closes the 5 open MEDIUMs → rating **B** on the current tree; lifted unchanged into VCA. |
| E0.5 | OpenTelemetry SDK replaces hand-rolled tracer; maintained Redis and JOSE clients | ADR-002.6, ADR-030.4 | **S–M** | |
| E0.6 | LICENSE (Apache-2.0), SPDX headers, docs CC-BY-4.0, NOTICE from SBOM; **purge committed secrets from history** | ADR-029 | **S** | History rewrite needs every fork/clone to re-pull — schedule and announce. |
| E0.7 | Decide and land PRs #14 / #15 (see § 2) | technical-scope § 3 | **S–M** | #14 needs 0.5–4.6 coverage points on `mdl`/`mdoc`/`signer`. |

**Blocks:** every other epic depends on E0.1–E0.2 for new services; E0.4 is independent and can start immediately.

### E1 — Application security

*Why:* the items here are the ones an external pentest of a national deployment would find first. Several are one-liners in scope and weeks in consequence.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E1.1 | Security rating **B → A**: the 31 LOWs — `Secure`/`HttpOnly` cookie flags gated on TLS, `--proto '=https'` on remaining `curl`s, SRI on the two CDN `<script>` tags (moot once ADR-005.7 vendors assets), `%q` on one logged field | SonarCloud LOW list; W-2 | **S** | **W-2 says "A corresponds to a score above 90 %". SonarCloud ratings are not percentages: security A = zero open vulnerabilities. Correct the wishlist wording.** |
| E1.2 | Admin auth → OIDC only; one-time bootstrap token binds first super-admin; no default password anywhere; CLI login via device-auth/loopback PKCE | ADR-009.5, ADR-010 | **M** | Reuses `internal/auth` (87 %). |
| E1.3 | CSRF synchronizer tokens + SameSite on every browser POST | ADR-010.7, TODO.md L392 | **S** | Do in the monolith too if it stays in service — cheap and real. |
| E1.4 | Machine access via OAuth 2.0 client credentials; deprecate `VERIFIABLY_API_KEYS` after one release | ADR-012.4 | **S–M** | |
| E1.5 | Remove Docker-socket control and direct writes into DPG databases; DPG config through DPG APIs or at deploy time | ADR-002.4, ADR-005.3 | **M** | Touches Inji schema sync and walt.id restart paths; converges with E5.3. |
| E1.6 | Independent verification: VCA re-checks signature, kb-jwt/`cnf`, `nbf`/`exp`, `aud`/nonce, status, schema, trust chain — never trusts the DPG alone | ADR-024.2, D.3, B.4 | **M–L** | `internal/vp` (78 %) is the seed. Required before any Hub verifies members on other stacks. |
| E1.7 | Redis-backed rate limiting and OTP; audit log for admin actions and exports | ADR-020.6, ADR-009.6, B.3.3 | **S–M** | |
| E1.8 | Data minimisation: salted subject refs only in issued-credentials log; retention windows on verification results; raw presentation deleted first | ADR-017.2/5, ADR-025.3 | **M** | Policy input needed on retention periods. |

### E2 — Keys, PKI and HSM

*Why:* W-5 asks for national-scale key-management walkthroughs. Today the platform's own signing keys are PEM files with an HS256 fallback. Nothing "HSM-backed" can be claimed until this epic lands, and F.5's boundary (DPGs sign credentials; VCA signs its own artefacts) must be stated in every claim.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E2.1 | Generalise PR #14's `internal/signer` to a `Provider` (JWS + COSE, `KeyID`, `CertificateChain`, `Close`); backends `pem` (default), `pkcs11` (build-tagged), `cloudkms`, `x509chain` wrapper, Vault Transit | F.1, F.2 | **L** | **Decision:** which cloud KMS first (AWS is path of least resistance given EKS Terraform). |
| E2.2 | Wire trust-registry JWT, both status lists, and any locally-signed credential through the provider; per-issuer keys with `did:web`/`did:key` `kid` | F.2, ADR-011.5, ADR-018.6 | **M** | Depends on E2.1 and, for the monolith, A.5 (`main()` seam) — in VCA it is native. |
| E2.3 | `x5c` in JWT headers; `GET /.well-known/ca-bundle.pem`; `client_id_scheme=x509_san_dns` | F.3, D.1 | **M** | Closes HAIP Gap 2. |
| E2.4 | Key rotation with overlap window in the DID document; fold the 2026-07-23 rotation design (Spanish) into the contract | F.4 | **M** | |
| E2.5 | Holder keys never on the server: WebCrypto non-extractable in browser or DPG wallet-api; retire `storage/injiwallet` file store | ADR-020.4 | **M** | **Decision:** browser-bound keys mean a credential is bound to one browser profile — conflicts with multi-device use and B.3 portability. Choose per deployment or default to DPG wallet custody. |
| E2.6 | Walkthroughs: DID and PKI implementation guides per DPG, from bootcamp to national scale | W-5 | **M** | Documentation, STE per ADR-028; needs E2.1–E2.3 to be true first. |
| E2.7 | K8s: `signingKey.existingSecret` for walt.id issuer/verifier; Vault bootstrap after init | G.3.4, G.3.7 | **S** | |

### E3 — Supply chain, images and release

*Why:* a government cannot deploy what it cannot pin, verify, or audit offline.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E3.1 | One distroless static image per service; non-root, read-only FS, no capabilities; OCI labels; `/healthz` + `/readyz`; all web assets vendored | ADR-005 | **M** | Per service it is small; the count is the size. |
| E3.2 | Cosign keyless signing + SBOM (SPDX + CycloneDX via syft) attached; Kyverno verify-at-admission | ADR-005.5, G.4.1 | **S–M** | Scaffolding exists in `image.yml`. |
| E3.3 | Trivy image and misconfiguration → blocking after clearing the backlog (EKS `0.0.0.0/0`, unrestricted egress, `readOnlyRootFilesystem` on wso2is/libretranslate, one false positive) | G.4.2, G.4.4 | **S–M** | Needs a running cluster (E5.2) to validate the two chart fixes. |
| E3.4 | SemVer tags, conventional commits, release workflow on `v*` (images `:vX.Y.Z`/`:vX.Y`/`:vX`, Helm packages, CLI binaries, GitHub Release, generated CHANGELOG) | ADR-006 | **S–M** | First tag only after E0.6's history purge. |
| E3.5 | Demo TLS certs generated at bootstrap, never committed | G.4.5 | **S** | |

### E4 — Runtime scalability

*Why:* the current design has sticky sessions, in-process rate limits, one shared database, and sequential bulk issuance. None of it scales past one replica.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E4.1 | Stateless services: ES256 session JWTs validated via JWKS; no shared session table | ADR-012.2, ADR-020.2 | **M** | Prerequisite for HPA. |
| E4.2 | Each service owns its data; versioned migrations per service; the seven inline-created tables assigned owners | ADR-002.3 | **M–L** | With the modular-monolith option (§ 2) this is schema ownership first, physical separation later. |
| E4.3 | Wallet HPA validated with the existing k6 load test (`deploy/k8s/test/load/`); zero session drift under scale-out | G.3.3 | **S** | After E4.1. |
| E4.4 | True batch issuance (`/batch_credential` where the DPG supports it; sequential fallback) | C.1, ADR-016.5 | **M** | |
| E4.5 | Deferred issuance (`transaction_id`, review queue, `pending_review → approved → issued`) | C.2, ADR-016.5 | **M** | Required for any credential a civil servant must approve. |
| E4.6 | Bulk jobs as server-streaming RPC with progress; job runner separate from request path | ADR-015.7 | **S–M** | `internal/jobs` (72 %) is the seed. |
| E4.7 | Status lists: random index allocation, ≥ 131 072 entries, ETag + cache headers, signed copy persisted so restarts do not re-sign; JWT + CWT representations | ADR-018, ADR-019 | **M** | Lifts `statuslist` (76 %). |
| E4.8 | Observability: OTLP export (E0.5); walt.id has **no metrics endpoint** (verified) — exporter sidecar or documented blind spot; real probe paths instead of `/` | G.3.1, G.3.2 | **S–M** | |

### E5 — Deployment scalability and operability

*Why:* W-context — "implementable by any country… with or without a service provider". Today that is a 1.4k-line bash wizard, a 2.2k-line CREDEBL bootstrap, and a K8s path for one of three stacks that has not been seen running.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E5.1 | `vca` CLI (cobra): `setup --role --dpg` with env-file prefill and `--non-interactive`; config declared once in a proto `Config` message with validation; secrets generated, mode 0600 | ADR-007 | **L** | Replaces `deploy.sh` and 67 unvalidated `os.Getenv`s. |
| E5.2 | **Run the K8s stack on real infrastructure** (≥ 32 GiB or EKS): clear the failed state, fix the `auth-providers.json` crashloop, first green nightly | G.2 | **M** | Unknown unknowns live here; do it *before* building more charts. |
| E5.3 | `vca deploy`: compose profiles per role-DPG, DPG stacks included by reference and version-pinned, idempotent Go bootstrap subcommands replacing shell (Keycloak realm, DID, CREDEBL org) | ADR-008.1–4 | **L** | |
| E5.4 | K8s parity: Helm chart per service, umbrella with `roles.<role>.enabled`; Inji umbrella (5 components + eSignet + mock-identity); CREDEBL umbrella (18 services + NATS) | ADR-008.5, G.1 | **L** (Inji) + **XL** (CREDEBL) | **Decision:** confirm CREDEBL is in the production topology before the XL. |
| E5.5 | CI shape: render tier on every PR (exists), cluster tier nightly → restore `push: main` once E5.2 converges; minimal platform profile (13 Helm releases today, all-or-nothing); caching after that | G.5 | **M** | |
| E5.6 | Backup/restore runbook for CNPG Postgres — the trust registry is the one state that cannot be regenerated | G.4.3 | **S** | |
| E5.7 | Resource floor: single role + one DPG under 4 GB; `vca deploy --dry-run`, `status`, `down` | ADR-008.6–7 | **M** | Depends on § 2 consequence 2. |
| E5.8 | e2e: Playwright runner with tagged manifest, `@smoke` in CI, axe-core on every page; delete rotted scripts | A.4, ADR-004.6/8 | **M** | |

### E6 — Trust registry and cross-border

*Why:* highest strategic value, least existing code. A Hub that can only trust what its own table says is not cross-border.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E6.1 | **Spike: pin the DeDi wire format** from the LF Decentralized Trust repo + gitbook; vendor schemas with a commit hash; `docs/dedi-integration.md` | E.1, ADR-011.3 | **S** | **Hard gate** for E6.3–E6.6. ADR-011 has located normative sources technical-scope could not — verify they are complete. |
| E6.2 | Canonical trust entry + pluggable `TrustListPublisher`; `etsi` method (TS 119 602 JSON out, TS 119 612 XML import) signed JWS with JWKS | ADR-011.1–2 | **M–L** | |
| E6.3 | `dedi` method: signed directory files + `/.well-known/dedi.index.json`; resolver client with signature verification and cache; `trust.Registry` backed by DeDi (read-only) | ADR-011.3, E.2, E.3 | **M** | |
| E6.4 | `trust.Chain`: ordered registries with provenance on every result ("trusted — via X, resolved through DeDi"); `TrustLookup` RPC with fail-open/closed | E.4, ADR-011.7 | **M** | Also the long-term data source for the OID4VP verifier allowlist (E0.4). |
| E6.5 | Publish this deployment as a DeDi registry; DeDi subscribe for revocations into the notification channel | E.5, E.6 | **M** | Symmetry is what makes it a network. |
| E6.6 | Cross-border recognition policy (`recognisedRegistries`: which namespaces, which credential types, what legal basis) | E.7 | **S** (code) | **Decision needed outside engineering** — policy owner. |
| E6.7 | Signed VICAL-style IACA anchor list replacing the POC `/trust/mdoc-anchors` | B.5.3 | **M** | After #14 merges. |
| E6.8 | OpenID Federation as a second `Registry` — only if a partner ecosystem requires it | 8.4, ADR-011.4 | **L** | Deferred. |

### E7 — Issuer capability

*Why:* W-4 (schema builder with API introspection and external sourcing) and the issuer half of the ADR portals.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E7.1 | Schema registry: JSON Schema 2020-12, immutable versions, draft/published/retired, `RegisterCredentialConfiguration` RPC to DPGs (no HOCON edits, no DB writes, no restarts), OID4VCI metadata and SD-JWT `vct` documents generated | ADR-013 | **L** | |
| E7.2 | Schema builder with live view (sample JSON, wallet card, PDF); **introspect an API or DB to propose a schema**; import from JSON Schema / DPG catalog / blockchain source | ADR-014, W-4 | **L** | W-4's "blockchains" source needs a named target chain and a use case before scoping. |
| E7.3 | Data-source service: `CsvSource`/`HttpSource`/`SqlSource`, secret references never in records, role-scoped preview with masking, stored `FieldMap` with pure transforms; HTTP sources through E0.4 | ADR-015 | **L** | Lifts `bulk.go` sourcing. |
| E7.4 | Multi-format issuance on OID4VCI **1.0** (not draft-13): SD-JWT VC, VCDM 2.0 (DI or JOSE), mdoc where the DPG supports it; HAIP target; capabilities advertised per adapter — no `ErrNotSupported` at runtime | ADR-016.1–2/6 | **L** | Spec bump is upstream-dependent per DPG; track in `spec-versions.md`. |
| E7.5 | PDF channel for every DPG with Claim 169 CWT QR or offer URI; maintained PDF lib; delivery by email/SMS/link | ADR-016.3–5 | **M** | Lifts Inji-only `pdf.go`. |
| E7.6 | Issued-credentials portal: hash-chained log on Postgres, daily signed chain head, revoke/reinstate with reason, retention pruning | ADR-017 | **M** | |
| E7.7 | Display metadata surfaced on wallet cards; issuance-time policy hook (presentation-during-issuance, wallet attestation) | C.3, C.4 | **S–M** | |

### E8 — Wallet (holder) capability

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E8.1 | Citizen OIDC with PKCE to national IdPs (eSignet); IdP token as OID4VCI grant; RP-initiated logout | ADR-020.1–5 | **M** | |
| E8.2 | Credentials portal: discovery from aggregated issuer metadata, eligibility RPC (yes/no only), claim/scan/paste/accept/reject, OID4VP 1.0 consent screen listing each disclosed claim | ADR-021 | **L** | |
| E8.3 | Lifecycle on the card: valid/expired/revoked/status-unavailable; background re-check honouring fail-open/closed; one-click renewal | B.1 | **M** | `statuslistcache` exists. |
| E8.4 | One notification channel (webhook, email, in-app) for issued/revoked/expiring/renewal/presentation-requested; Hub fan-out | B.2 | **M** | E6.5 reuses it. |
| E8.5 | Export/import of held credentials in original wire format, with the key-binding limitation stated in the UI | B.3 | **M** | Interacts with E2.5. |

### E9 — Verifier capability

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E9.1 | Discovery: crawl trusted issuers' metadata + schemas with TTL; click-to-select claims → versioned `PresentationTemplate` in **DCQL** (PEX generated only for walt.id 0.18) | ADR-022 | **M–L** | |
| E9.2 | Multi-format ingestion to one `RawPresentation`: OID4VP, image, PDF, XML (XPath, no XML-sig in v1), JSON paste, plain QR, **Claim 169** (base45 → CWT/COSE_Sign1); decoders pure + fuzzed; `request_uri` fetch through E0.4 | ADR-023 | **L** | |
| E9.3 | Policy checklist: named pure checks, mandatory set performed by VCA itself (E1.6), status + trust chain + schema; saved policy sets with versions | ADR-024 | **M** | |
| E9.4 | Results manager: `VerificationResult` proto, card per credential with trust badge, drill-down JSON, retention window, CSV/JSON export, public verify page | ADR-025 | **M** | |
| E9.5 | Combined presentations: DCQL `credential_sets`, cross-credential rules as data (same subject, delegation link, date ordering), per-credential + summary cards; lift `internal/delegation` as first rule set | ADR-026, D.4 | **L** | Prerequisite for guardianship/delegation. |

### E10 — UI/UX, accessibility, documentation

*Why:* W-1 (80 % UI coverage), W-3 (full UI/UX overhaul led by Kaushal), ADR-027/028.

| # | Item | Refs | Size | Notes |
|---|---|---|---|---|
| E10.1 | Fix measured WCAG failures first sprint: `outline: none`, missing `alt` on QR, contrast < 4.5:1, `<html lang>`, skip link, `:focus-visible`, reduced-motion, live regions | ADR-027.2 | **S** | Do in the monolith too — it is CSS and template lines. |
| E10.2 | `vca-ui` kit: Go stdlib + `html/template` + vendored HTMX; themes as Go packages with a contrast test that fails the build; self-hosted fonts; named partials with one struct each; HX-Request partial rendering; progressive enhancement | ADR-027.3–9 | **L** | **Flag:** the source kit is a personal repo (`adammwaniki/adamndegwa`, Apache-2.0). Fork into the org on day one; do not depend on it upstream. |
| E10.3 | Information architecture and interaction redesign across staff and citizen portals; four audiences → two shells | W-3, ADR-001.5 | **XL** | Design lead named (Kaushal); engineering follows E10.2. |
| E10.4 | Go-side a11y tests on every rendered page + axe in e2e + manual screen-reader audit per minor release + published accessibility statement; UI packages at 100 % (stricter than W-1's 80 %) | ADR-027.8/11, W-1 | **M** | |
| E10.5 | i18n via reviewed message catalogues (replaces runtime LibreTranslate); `<html lang>` follows catalogue | ADR-027.10 | **M** | LibreTranslate adapter dropped per ADR-030.2. |
| E10.6 | Docs in Simplified Technical English: README ≤ 200 lines, `docs/<service>/` per service, glossary, STE linter on PRs, catalogued error messages, man pages + portal help from the same proto descriptions | ADR-028, ADR-009.2–4 | **L** | Continuous; budget as a fraction of every epic. |

### E11 — Deferred and upstream-blocked (do not bid)

| Item | Why deferred | Trigger |
|---|---|---|
| BBS+ unlinkable disclosure | Spec is a CR draft; no DPG issues it | W3C Recommendation or two interoperable DPGs (ADR-031; quarterly check) |
| JARM / `direct_post.jwt` | walt.id 0.18.2 lacks it; parameter already passes through | walt.id release (D.2) |
| mDL proximity (BLE/NFC), mdoc revocation | #14 covers issuance only | After #14 lands; revocation may ride on E4.7's token status list |
| OpenID Federation registry | No partner requires it | Partner ask (E6.8) |

---

## 4. Sequencing

Dependencies, not dates. Each phase is what one team of 3–5 can run in parallel without colliding; the "unblocks" column is the reason for the order.

```
Phase 0 — now, on the current tree (weeks, not months)
  E0.4 outbound policy → rating B      E1.1 LOWs → rating A
  E1.3 CSRF   E10.1 WCAG fixes   E3.5 certs at bootstrap   E5.6 backup runbook
  E0.6 LICENSE + history purge   E0.7 decide #14/#15
  E6.1 DeDi spike   E5.2 K8s on real infra        ← both are gates, both are cheap
  unblocks: a defensible security posture while the rewrite is designed

Phase 1 — foundations
  E0.1 proto contracts ── E0.2 vc-core ── E0.3 quality bar ── E0.5 OTel
  E2.1 signer Provider ── E2.2 wiring ── E2.7 K8s key secrets
  E3.1 images ── E3.2 cosign/SBOM ── E3.4 release tags
  E5.1 vca CLI (setup)
  unblocks: every service in Phases 2–3; first tagged release

Phase 2 — smallest services first (ADR-030.7), trust before portals
  E4.7 status-bitstring + status-token ── E6.2/E6.3 trust-registry (etsi + dedi) ── E6.4 chain
  E1.2 admin OIDC ── E1.7 rate-limit/audit ── E4.1 stateless sessions ── E4.2 data ownership
  E5.3 vca deploy + compose profiles ── E5.4 Inji umbrella ── E5.5 CI cluster tier on main
  E10.2 UI kit
  unblocks: monolith's trust and status paths retired; HPA (E4.3) becomes testable

Phase 3 — issuer, then verifier, then wallet (ADR-030.7)
  E7.1 schema registry ── E7.2 builder ── E7.3 data sources ── E7.4/E7.5 issuance + PDF ── E7.6 log
  E1.6 independent verification ── E9.2 ingestion ── E9.3 policy ── E9.4 results ── E9.1 discovery ── E9.5 combined
  E8.1 wallet OIDC ── E8.2 portal ── E8.3 lifecycle ── E8.4 notifications
  E2.3 x5c + x509_san_dns ── E2.4 rotation ── E2.5 holder keys
  E4.4 batch ── E4.5 deferred ── E4.6 streaming jobs
  E10.3 IA/UX redesign (design runs ahead, engineering follows per portal)
  unblocks: monolith retired role by role; HAIP Gap 2 closed

Phase 4 — network and scale-out
  E6.5 publish as DeDi + subscribe ── E6.6 recognition policy ── E6.7 VICAL anchors
  E5.4 CREDEBL umbrella (if confirmed) ── E5.7 resource floor
  E8.5 export/import ── E1.8 retention ── E2.6 walkthroughs
  E10.4/E10.5/E10.6 a11y audit, i18n catalogues, STE docs (continuous from Phase 1)
```

**Rough cumulative sizing** (one engineer-equivalent, unrefined, excluding E10.3 design and E5.4 CREDEBL):

| Phase | Effort | Comment |
|---|---|---|
| 0 | 4–6 weeks | Mostly small, all on the existing tree; visible outcomes (rating A, first real K8s run) |
| 1 | 3–4 months | Contract design dominates; do not compress |
| 2 | 3–4 months | |
| 3 | 6–9 months | Three role surfaces; parallelises across a team |
| 4 | 2–4 months | |

A 3–5 person team lands Phases 0–2 in roughly two quarters and Phase 3 in the following two, if the decisions in § 5 are made before Phase 1 starts.

---

## 5. Decisions needed before or during Phase 1

| # | Decision | Owner | Blocks |
|---|---|---|---|
| D0 | Is **Phase 0 in this engagement**, or done in-house before it starts? It is 4–6 weeks on the existing tree and moves the security rating to A; the answer changes where the engagement begins, not what the work is | CDPI | Contract shape |
| D1 | Evolve vs revamp (§ 2) — and if revamp, "20 processes" vs "modular monolith deployable as N" | CDPI architects | Everything in Phase 1+ |
| D2 | Fate of PRs #14 and #15 | Maintainers | E0.7, E2.1, E6.7 |
| D3 | Cloud KMS provider to build first (AWS / Azure / GCP) | Deployment owner | E2.1 |
| D4 | Holder key custody: browser-bound WebCrypto vs DPG wallet, per deployment | Product | E2.5, E8.5 |
| D5 | Is CREDEBL in the production topology? | Product | E5.4 XL |
| D6 | Dev-mode "any verifier" opt-in for OID4VP `request_uri` | Product/security | E0.4 |
| D7 | Cross-border recognition policy: namespaces, credential types, legal basis | Policy owner outside engineering | E6.6 |
| D8 | DeDi spec access / confirmation that the LF repo + gitbook are complete and normative | CDPI / Dhiway | E6.3–E6.5 |
| D9 | Retention periods for issued-credential log and verification results | Data-protection owner | E1.8, E7.6, E9.4 |
| D10 | Rename to VCA and module path move — when, and one-release redirect | CDPI | E3.4 first tag |
| D11 | W-4 "blockchain" schema source — which chain, which use case | Product | E7.2 |
| D12 | Correct W-2's "A = above 90 %" to SonarCloud's actual definition | Wishlist owner | Reporting |

---

## 6. Risks

| # | Risk | Response |
|---|---|---|
| R1 | Rewrite stalls with the monolith still in production and neither fully secured | Phase 0 hardens the monolith to a defensible floor first; ADR-030.7 retires it role by role so value ships each phase |
| R2 | 20 services × per-service DB exceeds the < 4 GB single-role floor | Modular-monolith deployment option (§ 2); measure before physically splitting databases |
| R3 | DeDi spec incomplete or moving | E6.1 is a hard gate; vendor schemas by commit hash; nothing in E6.3+ is scheduled until it lands |
| R4 | walt.id 0.18 limits (no JARM, PEX not DCQL, no metrics) | Track upstream; do not fork; generate PEX only for walt.id; sidecar exporter |
| R5 | K8s path has never run end-to-end | E5.2 in Phase 0, before any new chart; first green nightly is the milestone |
| R6 | UI kit sourced from a personal repository | Fork into org; treat as owned code |
| R7 | History rewrite for secret purge disrupts contributors | Announce, do once, before the first tag |
| R8 | Coverage gates gamed | Sonar ≥ 80 % on new code is the real control; 100 % for `vc-core` and UI kit; per-function gate from #15 for handlers if kept |
| R9 | "HSM-backed" over-claimed | F.5 boundary stated in docs and UI: which path signed a given credential |
| R10 | Estimates here are unrefined | Each epic is re-estimated at pick-up; sizes are for ordering and staffing, not for fixed-price |

---

## Appendix A — Cross-reference

| Wishlist / ADR | technical-scope | Roadmap |
|---|---|---|
| W-1 UI 80 % coverage | — | E10.4 (100 % for the kit) |
| W-2 SonarCloud A | G.4.6, D.5 | E0.4, E1.1 (+ D12 wording) |
| W-3 UI/UX overhaul | — | E10.3 |
| W-4 schema builder + external sourcing | — | E7.2, E7.3 |
| W-5 DID/PKI walkthroughs | F | E2.6 |
| ADR-001/002/030 rebrand, decompose, migrate | § 2 (evolve) | § 2 decision, E0.1–E0.2 |
| ADR-003 protobuf/Connect | — | E0.1 |
| ADR-004 TDD, 90 % | A.3, A.4 | E0.3, E5.8 |
| ADR-005 images | G.4.1/2/4 | E3.1–E3.3 |
| ADR-006 releases | — | E3.4 |
| ADR-007/008 CLI, deploy | G.1, G.3, G.5 | E5.1, E5.3–E5.5, E5.7 |
| ADR-009/010 admin, OIDC | — | E1.2, E1.3, E1.7 |
| ADR-011 trust lists | E.1–E.7, B.5.3 | E6 |
| ADR-012 issuer auth | — | E1.4, E4.1 |
| ADR-013–017 issuer portals | C.1–C.4 | E7 |
| ADR-018/019 status lists | F.2 | E4.7 |
| ADR-020/021 wallet | B.1–B.4 | E8, E2.5 |
| ADR-022–026 verifier | D.1, D.3, D.4 | E9, E1.6 |
| ADR-027/028 UI, docs | — | E10 |
| ADR-029 licence | — | E0.6 |
| ADR-031 BBS+ | — | E11 |
| F.1–F.5 signer | ADR-011.5, 018.6 | E2 |
| G.2 real-infra run | ADR-006.7 | E5.2 |
| D.5 SSRF allowlist | ADR-015.6, 023.5 | E0.4 + Appendix C |

## Appendix B — Where the sources disagree, and what this roadmap does

| Topic | ADRs | technical-scope | Roadmap |
|---|---|---|---|
| Strategy | Rewrite as ~20 services | Harden in place | Rewrite, strangler order, monolith hardened to a floor only (§ 2) |
| SSRF findings | Decomposition removes the surface (ADR-002.c4) | Allowlist design (D.5) | Allowlist is needed either way; build once (E0.4) |
| Coverage bar | 90 % per package, 100 % core | Ratchet 40→70 %, ≥ 80 % new code | 90 % new packages, 100 % core/UI kit, keep ≥ 80 % new-code gate throughout |
| `httpx`/`tracing`/`jose` | Drop for maintained libs | Write tests (M1) | Drop; do not write the tests |
| e2e scripts | Rewrite with Playwright | Tag and run the 73 | Rewrite; delete rotted ones now (E5.8) |
| PR #15 | Handlers are rewritten | Merge first | Merge only if monolith serves > ~2 quarters (D2) |
| HS256 dev fallback | Remove | Keep behind `pem` default | Remove in E0.2 |
| i18n | Reviewed catalogues | LibreTranslate at runtime | Catalogues (E10.5) |
| Holder keys | Browser WebCrypto or DPG wallet | DPG custody | Decision D4; default DPG custody |

---

## Appendix C — Worked example: E0.4 specified to implementation depth

*Every other epic in § 3 is one table row. This is what one of them looks like once refined — the level of detail to reach before starting any item, and the format in which to hand it back. E0.4 is used because it is fully analysed, independent of the architecture decision in § 2, and closes five of the six open security findings.*

### C.1 Why this item exists

SonarCloud security rating on `main` is **C**, on a worst-open-finding-wins ladder:

| Impact | Open on `main` | Rating floor |
|---|---|---|
| HIGH | 0 — three `go:S5542` (RS256 / PKCS#1 v1.5, CryptoJS AES-CBC) accepted with written justification | — |
| MEDIUM | **6** → 1 fixed (a missing boundary check in `registry-admin/app.py`), **5 are this item** | **C** |
| LOW | 31 (cookie flags, `http://` in bootstrap scripts, SRI, one log-injection) → E1.1 | B |

The five are `gosecurity:S5144` — request-derived input reaching an outbound URL. They were reviewed individually in PR #21 and deliberately **not** patched, because the obvious fix is wrong for this stack:

> `internal/handlers/ssrf.go` already has `ssrfBlockHost`, a denylist of private / loopback / link-local / metadata ranges. Every DPG this service talks to — `certify-nginx`, `walt-issuer`, `credebl-minio`, the Sunbird registries — lives on a Docker bridge or a cluster-internal address. `VERIFIABLY_PUBLIC_HOST=172.24.0.1` is the *documented default*. A denylist of RFC1918 rejects the product's own backends and permits nothing useful.

The correct control is an **allowlist derived from what the deployment already declares** — a design change, which is why it was deferred rather than patched.

**Do not** clear these by marking them Accepted: `inji_present.go:193` is a genuine third-party exposure. **Do not** clear them by re-spelling the call so the taint engine loses the path (§ C.6).

### C.2 Acceptance criteria

1. The five `S5144` findings are **Closed** on the `main` analysis, not Accepted.
2. `security_rating` = 2.0 (**B**) via `api/measures/component`.
3. Quality gate passes; new code ≥ 80 % coverage.
4. The localhost compose stack and the kind e2e still work with **no additional configuration** — the allowlist is seeded from existing config, not from a new variable an operator must discover.
5. A documented way to widen the allowlist for the two operator-driven features, and a recorded per-site decision for all five.

### C.3 The five sites

Each row is one unit of work. They differ in trust model; do not apply one blanket control.

| Site | Who controls the URL | Control |
|---|---|---|
| `inji_present.go:193` — `fetchInjiVPRequest` dereferences `request_uri` from a scanned or pasted `openid4vp://` URI (callers `:738`, `:791`) | **Anyone who can put a QR in front of the user. Genuinely third-party — highest risk** | Host must match a federation member `serviceEndpoint` or a configured verifier list; `https` only; redirects re-checked; response size cap. Shape the hook so E6.4's `trust.Chain` can replace its data source without touching the call site. **Needs D6**: whether a dev mode may accept any verifier (explicit opt-in, off by default, logged at startup) |
| `bulk.go:672` — `fetchJSONRows` GETs an operator-typed URL with an operator-typed auth header (callers `bulk.go:170`, `identity.go:253`) | An authenticated operator; the feature's purpose is fetching from an arbitrary registry | Allowlist seeded from `VERIFIABLY_REGISTRIES` + `backends.json`, plus an operator-extendable `VERIFIABLY_OUTBOUND_ALLOW`. Metadata ranges and the service's own listen address blocked regardless. The one site where accept-by-design is defensible — but state which, and only after the other four are closed |
| `inji_schema.go:190` — `sunbirdSchemas(baseURL)` | Deployment config (`VERIFIABLY_REGISTRIES`, parsed at `inji_schema.go:104`) — the engine is following env → config → URL. **Effectively false positives** | Validate `registryProvider` at parse time (scheme, non-empty host, entity matching `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`) and return a **constructed `url.URL`**, not the input string. Config *is* the allowlist. Under a day including tests |
| `inji_schema.go:282` — `searchRegistryAll(p.URL, entity)` | as above | as above |
| `admin_federation.go:418` — `federationHealthz` GETs `{serviceEndpoint}/healthz` (callers `:136`, `:386`) | An admin adding a federation member — already a trust decision. Lowest risk | Normalise `serviceEndpoint` on write (`https` outside localhost, no userinfo, no fragment), store the normalised form, health-check the stored value |

### C.4 Design

**One policy, one client.** `internal/outbound` (package rather than a file in `handlers`, so `cmd/inji-preauth-proxy` can adopt it later):

```go
type Purpose int // PurposeVerifier, PurposeRegistry, PurposeFederation, PurposeOperatorFetch

type OutboundPolicy struct {
    allow      map[Purpose][]hostRule // exact host, wildcard suffix, or CIDR
    denyAlways []*net.IPNet           // metadata, self
    devOpen    bool                   // opt-in per D6; log loudly
}

func (p *OutboundPolicy) Check(purpose Purpose, u *url.URL) error
func (p *OutboundPolicy) Client(purpose Purpose) *http.Client
```

`Client(purpose)` returns a client whose `DialContext` **re-checks the resolved IP at dial time** and whose `CheckRedirect` re-runs `Check` on every hop. This closes two holes the existing `ssrfBlockHost` has:

- **TOCTOU / DNS rebinding** — it calls `LookupHost`, then the client resolves again. The check must happen on the address actually dialled.
- **Redirects** — `outboundClient` follows them unchecked, so `https://allowed.example/` → `http://169.254.169.254/` currently succeeds.

Replace `outboundClient` (6 call sites after PR #21) with `policy.Client(purpose)`, keeping the 30 s timeout.

**Seeding — no new mandatory config:**

| Source | Feeds |
|---|---|
| `VERIFIABLY_REGISTRIES` provider URLs | Registry, OperatorFetch |
| `backends.json` DPG base URLs | Registry, OperatorFetch |
| Federation member `serviceEndpoint`s — looked up at check time, not a startup snapshot (members are added at runtime) | Verifier, Federation |
| `VERIFIABLY_PUBLIC_HOST` | denied for all purposes (self-loop) |
| `VERIFIABLY_OUTBOUND_ALLOW` (new, optional) | OperatorFetch, Verifier |
| `VERIFIABLY_OUTBOUND_DEV_OPEN=1` (new, optional) | Verifier only; refuses to start with a non-localhost `VERIFIABLY_PUBLIC_HOST` |

Rejections return 4xx naming the purpose and, for operator-facing features, the variable to extend. Log at WARN with the rejected **host** — never the full URL, which may carry tokens.

### C.5 Work breakdown

| # | Item | Depends on | Est. |
|---|---|---|---|
| 1 | `OutboundPolicy` + dial-time IP check + redirect check + unit tests (rebinding, redirect-to-metadata, IPv6 literal, `[::ffff:169.254.169.254]`, `https://allowed@evil/`) | — | 1.5 d |
| 2 | Seeding from `VERIFIABLY_REGISTRIES`, `backends.json`, federation store; startup wiring | 1 | 1 d |
| 3 | `inji_schema.go` ×2: validate at parse, return constructed URL; tests | — | 0.5 d |
| 4 | `admin_federation.go`: normalise on write, health-check stored value; tests | 1 | 0.5 d |
| 5 | `inji_present.go`: verifier allowlist from federation members, dev-open flag; tests — note `inji_present_http_test.go` and `_f24_test.go` use `httptest` servers on 127.0.0.1 and will need the policy injected | 1, 2 | 1 d |
| 6 | `bulk.go`: operator fetch through the policy, `VERIFIABLY_OUTBOUND_ALLOW`, UI error text; tests | 1, 2 | 0.5 d |
| 7 | Compose + kind e2e green with no new config; `deploy.md` and per-site decisions recorded | 2–6 | 0.5 d |
| 8 | Confirm the five are Closed on `main` and the rating reads B; if any survives, read § C.6 before touching code | 7 | 0.25 d |

**~5.5 engineer-days.** One PR per site (rows 3–6) rather than one large PR, so each rating movement is attributable.

### C.6 Lessons from the four security PRs that preceded this

1. **A validator that returns its argument does not terminate a taint path.** PR #21 validated `entity` and returned `value`; the finding survived. PR #22 returned `m.group(0)` and it closed. Return something *derived* — a match group, a parsed `url.URL`, a rebuilt string. It is also better code: the returned object is validated by construction rather than by assertion.
2. **PR analysis only reports new code.** A finding on unchanged lines will not appear on a PR's SonarCloud page. Verify on `main` after merge: `api/issues/search?componentKeys=centre-for-dpi_verifiably&rules=gosecurity:S5144&resolved=false`.
3. **Count the call sites.** PR #21 said "validated across all 8 handlers"; there were nine, and the ninth reopened the finding on a different taint path.
4. **Do not dodge the rule.** Wrapping the call so the engine loses the flow would close the findings with zero security change. Review diffs the analyser's flow, not the count.
