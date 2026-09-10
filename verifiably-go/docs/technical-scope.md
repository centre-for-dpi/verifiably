# Technical Scope — Quality, Capability and Trust

**Status:** proposed
**Date:** 2026-09-10
**Applies to:** `verifiably-go/` (Go 1.25, 39 packages)
**Companion documents:** [`TODO.md`](../TODO.md) (task backlog), [`docs/haip-conformance.md`](haip-conformance.md) (spec gaps), [`docs/k8s/resume.md`](k8s/resume.md) (K8s state), [`federated-emission.md`](../federated-emission.md) (Hub architecture)

**Revised 2026-09-10** after surveying the three open pull requests — §3 below. Two of them deliver scope items outright, and the plan is adjusted rather than duplicating their work.

---

## 1. Why this document exists

`verifiably-go` is a mature demo platform — four DPG stacks, three roles, a federation Hub, a trust registry, two revocation standards, K8s and Compose deploy paths. What it does not yet have is a **mechanism that keeps it mature as it grows**. There is a rich feature backlog in `TODO.md` and no gate that prevents the next feature from eroding what already works.

This scope covers seven workstreams. Workstream A is largely **already implemented** as part of producing this document — the numbers below are measurements, not estimates. B through G are proposals with acceptance criteria.

Two of the three open pull requests already deliver parts of it. §3 records what they cover, in what order to land them, and which items here they retire — the plan builds on that work rather than restating it.

---

## 2. Baseline — measured 2026-09-10

Every figure here came from running the tooling against `main` at `b571e62`.

### 2.1 Size

| Metric | Value |
|---|---|
| Go application code (non-test) | 42,885 lines |
| Go test code | 16,774 lines |
| Packages | 39 |
| Shell (deploy + bootstrap) | 8,558 lines across 33 scripts (`deploy.sh` alone: 1,402) |
| E2E driver scripts | 73 `.mjs` files in `e2e/` |
| Largest single function | `cmd/server/main.go:298` — `main()`, **690 lines** |

### 2.2 Test coverage

**30.7% overall** (`go test ./...`), **32.0%** under the CI invocation (`-race -coverpkg=./...`).

The distribution matters more than the total. Coverage is inverted relative to risk: the small pure-logic packages are well covered, and the large packages that touch the network, the database and the user are not.

| Package | Coverage | Non-test LOC |
|---|---|---|
| `internal/federation` | 100.0% | 90 |
| `internal/jose` | 100.0% | 52 |
| `internal/didresolver` | 97.3% | 138 |
| `internal/auth` | 87.4% | 1,110 |
| `internal/storage/injiwallet` | 79.5% | — |
| `internal/vp` | 77.8% | 196 |
| `internal/statuslist` | 76.1% | 1,168 |
| `internal/issuance` | 75.2% | 452 |
| `internal/delegation` | 73.2% | 923 |
| `internal/jobs` | 71.7% | 304 |
| `backend` | 67.2% | — |
| `internal/metrics` | 65.1% | 402 |
| `internal/roles` | 64.0% | 78 |
| **`internal/trust`** | **54.1%** | 732 |
| `internal/statuslistcache` | 40.0% | 442 |
| `internal/adapters/credebl` | 29.7% | — |
| **`internal/handlers`** | **27.6%** | **17,551** |
| `internal/adapters/injiverify` | 27.1% | — |
| `internal/adapters/waltid` | 25.3% | — |
| `internal/adapters/injicertify` | 22.5% | — |
| `internal/verification` | 16.7% | 136 |
| `cmd/server` | 13.8% | 1,615 |
| `vctypes` | 10.3% | — |
| `internal/httpx`, `internal/tracing`, `internal/storage/pg`, `internal/storage/redis`, `internal/schemacache`, `internal/mailer`, `internal/injidid`, `internal/adapters/{factory,injiweb,libretranslate,verifiably}` | **0.0%** | ~4,000 combined |

`internal/handlers` is 41% of the application by volume and 27.6% covered. `internal/trust` — the package that decides whether an issuer is authorised — is at 54.1%. `internal/storage/pg`, which holds every persistence path, has no tests at all.

### 2.3 The CI finding

**The repository's CI has never run.**

`image.yml` (build, vet, test, Trivy filesystem + image scan, GHCR push) and `k8s-e2e.yml` (kind cluster, full stack, e2e smoke) were located at `verifiably-go/.github/workflows/`. GitHub Actions only reads `.github/workflows/` at the **repository root**. Confirmed against the API:

```
$ gh run list --limit 200 --json name --jq '.[].name' | sort | uniq -c
 170 pages build and deployment
```

170 runs of the GitHub Pages builder; zero runs of `image` or `k8s-e2e`. Every guarantee those workflows appear to provide — that `main` compiles, that tests pass, that the image has no HIGH/CRITICAL CVEs — has not held at any point. This is fixed in Workstream A.

The blast radius is wider than `main`. PR&nbsp;#15 adds an excellent per-function coverage gate and wires it into the same dead workflow, so **that gate has never run either**. Anything added to `verifiably-go/.github/workflows/` before the move is inert by construction — worth checking on any branch opened before this change lands.

### 2.4 Static analysis

With no linter configured, the tree was:

- **49 files not `gofmt`-clean**
- **44 findings** from `golangci-lint`'s default linter set
- **58 `gosec` findings**, of which the interesting classes are 14 × G704 (SSRF via taint analysis), 5 × G703 (path traversal), 4 × G705 (XSS), 4 × G124 (cookie missing `Secure`/`HttpOnly`/`SameSite`), 3 × G120 (unbounded form parsing), 1 × G501 (`crypto/md5`), 1 × G117 (a `ClientSecret` field marshalled into JSON)
- **38 × `govet` shadow** — reviewed, all idiomatic `if err := f(); err != nil` in a scope that already has an `err`; none are defects, and the check is disabled

### 2.5 One behavioural defect found while linting

`internal/handlers/verifier.go` emitted the `verification_completed_total` counter **before** running `attachDelegationVerdict`, which can set `res.Valid = false`. A dead `directStatus = "error"` below the counter (flagged by `ineffassign`) was the intended correction. Direct-verify failures caused by a delegation-gate rejection were therefore counted as `ok`. Fixed: the counter now runs after the gates.

This is what a lint gate buys — a metric that had been quietly lying was found by a checker for unused assignments.

---

## 3. Open pull requests

Three PRs are open. Two of them deliver scope items in this document outright, so the plan below is adjusted to build on them rather than duplicate them. Every claim here was verified against the fetched branches, not read from the descriptions.

| PR | Verdict | Verified state |
|---|---|---|
| **#11** — Documental security fix | **Close** | Its commit `ae1e8d4` is already in `main` (`git branch --contains`). A retroactive record of a branch-protection bypass, pointed at a synthetic `retro-base-fdfec55` base. Closing loses nothing; the audit trail persists on the closed PR. |
| **#15** — Walt id bulk | **Merge first** | Builds. `internal/handlers` measured at **98.3%** (claim was 98.4%). **1** merge conflict against the quality gate (`Makefile`). One failing test, macOS-only — see below. |
| **#14** — mDL / ISO 18013-5 | **Merge second** | Builds green, full suite passes. New packages `internal/mdl` 75.4%, `internal/mdoc` 79.5%, `internal/signer` 77.8%. **4** merge conflicts. |

### 3.1 What they already deliver

**PR #15 supersedes part of A.3.** It takes `internal/handlers` from 27.6% to 98.3% with ~15.6k lines of new tests, and adds `scripts/ci/coverage-gate.sh` — a per-function 100% gate with 36 individually justified exclusions, each citing line numbers and a reason. That is a stricter instrument than the package floor proposed here, and the two are complementary. Keep both.

**PR #14 delivers B.5 and part of F.1.** This document proposed mDL as "spike first, do not commit". That branch has done the spike *and* the implementation: `internal/mdl/`, `internal/mdoc/`, Annex-B-compliant IACA/DSC PKI generation, MSO assembly and COSE_Sign1 signing, across two independent emitters (walt.id `issuer-api2` and Inji Certify Pre-Auth).

It also creates `internal/signer/`. Its `Signer` interface is COSE-scoped:

```go
type Signer interface {
    Sign(ctx context.Context, payload []byte) ([]byte, error)
    CertificateChain() []*x509.Certificate
    Algorithm() cose.Algorithm
}
```

That is narrower than the `Provider` in §9 — it serves ISO 18013-5 `IssuerAuth`, not the JWS paths (trust registry, status lists, SD-JWT VC). **F.1 must extend this package, not create a rival one.** The `CertificateChain()` shape and the working IACA/DSC generation are exactly the groundwork F.3 needs for `x5c`.

Notably, PR #14's own ADR (`docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md`) reverted in-process signing because it violates "verifiably mediates, the DPGs issue" — arriving independently at the boundary stated in F.5.

### 3.2 Two problems nobody has flagged

**PR #15's coverage gate has never run.** It was wired into `verifiably-go/.github/workflows/image.yml` — the dead path from §2.3. It only begins working once the workflows sit at the repository root. The merge resolves this correctly: git's rename detection follows the move, PR #15's steps land in the root `image.yml`, and the `working-directory: verifiably-go` default makes its `sh scripts/ci/…` paths resolve unchanged. Verified on the merged tree.

**A semantic conflict git cannot see.** The dead-code removal in A.1 deleted `heldClaims` and `hasField` — correctly, they were unreferenced on `main`. PR #15 *adds tests* for both, so the merged tree merges cleanly and then fails to build:

```
vet: internal/handlers/inji_holder_test.go:907:12: undefined: heldClaims
```

Resolution: take PR #15's version of `inji_holder.go` and `schema.go`. Confirmed that `unused` accepts test-only references under `tests: true`, so the restored functions do not re-trip the gate. The other seven deletions stay dead in both branches.

### 3.3 Merge order, and why

**Quality gate → #15 → #14.**

Both PRs inherit ~53 of the same baseline findings already fixed in A.1, and carry only **5–12 findings of their own** (measured by running the new `.golangci.yml` against each branch: 114 total on #14, 107 on #15, against a 102 baseline). Merging the gate first means their rebase auto-resolves the inherited debt instead of each author fixing it independently. The conflict cost is small and was measured, not estimated: 4 files on #14, 1 on #15.

**The gate applies to these PRs too — decided 2026-09-10.** An earlier draft of this document recommended deferring the required check until both had landed, on the grounds that PR #14's new packages measure 75.4 / 79.5 / 77.8% against a ≥80%-on-new-code bar. That recommendation is withdrawn: a gate with a grandfather clause on the two largest changes in flight is not a gate. Both PRs meet it before merging.

What that concretely requires:

| PR | Coverage on new code | Lint findings of its own | Also |
|---|---|---|---|
| **#15** | Clears it — `internal/handlers` at 98.3% | ~5 | Confirm `TestSetDocsRoot` passes on Linux |
| **#14** | **Short by 0.5–4.6 points.** `internal/mdl` 75.4%, `internal/mdoc` 79.5%, `internal/signer` 77.8% | ~12 | — |

For #14 the package figure is a fair proxy for the new-code figure, because almost all of its code is new. `internal/mdoc` needs roughly half a point; `internal/mdl` needs about five. That is a handful of tests on CBOR encoding and MSO assembly — code that is worth having tested anyway, given it signs credentials.

Note the ordering consequence: if #14 must clear the gate, the gate must exist first. That reinforces "quality gate → #15 → #14" rather than weakening it.

**One caveat on #15 before rebasing.** `TestSetDocsRoot/unresolvable_working_directory` deletes the cwd and expects `os.Getwd` to fail — true on Linux, not on APFS — so it fails on macOS today. It will most likely pass on `ubuntu-latest`, but that is a prediction; the first CI run settles it. It is also a fair argument that 100%-per-function is not free.

---

## 4. Workstream A — Quality gates and coverage

**Status: implemented.** Included here so the rest of the plan has a defined starting line.

### A.1 What landed

| Change | File | Effect |
|---|---|---|
| Workflows moved to the repo root | `.github/workflows/` | CI runs at all, for the first time |
| Path filters and build context rebased on `verifiably-go/` | `image.yml`, `k8s-e2e.yml` | The moved workflows resolve correctly |
| New quality workflow | `.github/workflows/quality.yml` | gofmt, lint, `-race` coverage, coverage floor, SonarCloud + Quality Gate, gosec SARIF, shellcheck |
| Linter configuration | `verifiably-go/.golangci.yml` | 10 linters, zero tolerance (`max-issues-per-linter: 0`) |
| SonarCloud configuration | `verifiably-go/sonar-project.properties` | Coverage ingestion, scoped exclusions |
| Whole tree formatted | 49 files | `gofmt -l` returns empty |
| All 53 blocking findings fixed | 24 files | `golangci-lint run ./...` → **0 issues** |
| Local mirror of the gate | `Makefile`: `fmt`, `lint`, `cover`, `cover-html`, `quality` | CI and laptop cannot disagree — same pinned `v2.13.2` |

Blocking linters: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, `bodyclose`, `rowserrcheck`, `nilerr`, `errorlint`, plus `gofmt`/`goimports`.

`bodyclose` and `rowserrcheck` are in the blocking set deliberately: this service holds long-lived HTTP conversations with four external DPG stacks and hand-rolls its own pgx queries, so a leaked response body or an unchecked `Rows.Err()` is a production failure mode here rather than a style nit.

The eleven `nilerr` findings were each reviewed and are all deliberate graceful-degradation paths (`BootstrapOffers` returning an empty slice when a backend is unreachable is required by the `backend.Adapter` contract). They carry `//nolint:nilerr` with the reason inline, rather than a blanket exclusion — the distinction matters, because a future genuine swallowed error still fails the build.

### A.2 What is deliberately report-only

Two scanners run without blocking, each with the backlog named in the workflow comment:

- **gosec** — the 58 findings in §2.4 need triage, not suppression. SARIF is uploaded to the repo's Security tab.
- **shellcheck** — 8,558 lines of deploy shell that runs in front of every demo.

This mirrors the repo's existing idiom (`agnosticism.sh` and the Trivy image scan are already report-only with a stated reason). The rule is: **report-only requires a named backlog and an owner, never a permanent exemption.**

### A.3 Coverage ratchet

`quality.yml` enforces `COVERAGE_FLOOR`, currently `31.5` (measured 32.0%). The floor rises in the same PR that raises real coverage; it never falls.

Proposed schedule, with the target chosen by risk rather than by an even sweep:

| Milestone | Overall floor | Package-specific requirement |
|---|---|---|
| M1 | 40% | `internal/storage/pg` ≥ 60% (currently 0%); `internal/httpx` ≥ 80% (currently 0%) |
| M2 | 50% | `internal/trust` ≥ 85%; `internal/verification` ≥ 80% |
| M3 | 60% | `internal/handlers` ≥ 50%; every adapter ≥ 45% |
| M4 | 70% | `cmd/server` ≥ 40% (requires A.5) |

The SonarCloud gate additionally requires **≥ 80% coverage on new code**, which is the more important of the two numbers: it stops the ratio degrading regardless of where the overall figure sits.

**Superseded in part by PR #15.** That branch takes `internal/handlers` to 98.3% (independently verified) and adds `scripts/ci/coverage-gate.sh` — a *per-function* 100% gate with 36 individually justified exclusions, each citing line numbers and a reason. That is a stricter and better-argued instrument than a package floor, and the two are complementary: **keep both**. Once #15 merges, the M3 handlers target is already met, `COVERAGE_FLOOR` rises to whatever the merged tree measures, and the ladder above collapses to M1/M2/M4.

One caveat the per-function gate earns honestly: chasing the last statement produced `TestSetDocsRoot/unresolvable_working_directory`, which deletes the cwd and expects `os.Getwd` to fail — true on Linux, not on APFS. It fails on macOS today. 100%-per-function is a good target for a handler package; it is not free.

### A.4 Making the 73 e2e scripts count

`e2e/` holds 73 hand-driven Playwright/Node scripts named `walkA.mjs` … `walkX.mjs`. They encode a great deal of real knowledge about how the four stacks behave, and none of it is executable in CI or discoverable by name.

- **A.4.1** Add `e2e/package.json` with a runner and a tagged manifest (`@waltid`, `@inji`, `@credebl`, `@smoke`, `@federation`) mapping each script to the stack and flow it exercises. Rename on the way (`walkQ.mjs` → `waltid-bulk-csv-issue.mjs`).
- **A.4.2** Promote the `@smoke` subset into `k8s-e2e.yml`, which already stands up a kind cluster and calls `run-against-cluster.sh`.
- **A.4.3** Delete or archive scripts that no longer run. A script that has silently rotted is worse than no script.

### A.5 Decompose `main()`

`cmd/server/main.go:main()` is 690 lines and the package sits at 13.8% coverage — the two facts are the same fact. Extract into testable constructors (`buildAdapterRegistry`, `buildTrustRegistry`, `buildSigner`, `buildRouter`, `loadConfig`), each returning a value and an error, with `main()` reduced to wiring. This is a prerequisite for the M4 coverage milestone and for Workstream F, which needs a seam to inject a signer provider.

### A.6 Operator setup required

SonarCloud is configured but not yet connected. One-time, by a repo admin:

1. Import the repo at sonarcloud.io (free for public repos). The project key is `centre-for-dpi_verifiably` — the repo's *name* is `verifiably` even though the clone URL says `demo-daas-3-0`.
2. **Turn Automatic Analysis off.** Open the **project** (not the org dashboard) → **Administration** in the project sidebar, near the bottom → **Analysis Method**. Skip only if it already reads CI-based, which it will if you chose "With GitHub Actions" at import. The org-level equivalent is Enterprise-only, so this is per-project. If the Administration menu is not visible at all, you lack *Administer* permission on the project — an org admin grants it at organization **Administration → Projects Management**. It matters because automatic analysis cannot ingest coverage reports, and per Sonar's docs a CI analysis run while it is enabled will *fail*.
3. Add the `SONAR_TOKEN` repository secret.
4. Set New Code to "Previous version" or "30 days".
5. Mark `quality / lint`, `quality / unit tests + coverage` and `quality / SonarCloud` as required checks on `main`. **This applies to the open PRs as well** — see §3.3 for what each must do to clear it.

Until step 3, the `sonarcloud` job fails; `lint` and `test` gate correctly regardless.

---

## 5. Workstream B — Cloud wallet feature richness

**Direction confirmed:** enrich the adapter layer. Key custody stays with walt.id `wallet-api`, Inji Web/Mimoto and CREDEBL; `verifiably-go` closes the gaps in the holder surface it owns. This preserves the backend-agnostic architecture and avoids taking on custody of citizen keys.

The `backend.Adapter` interface currently exposes six holder operations: `ListWalletCredentials`, `DeleteWalletCredential`, `ListExampleOffers`, `ParseOffer`, `ClaimCredential`, `PresentCredential`, `BootstrapOffers`. That is enough to demo a wallet and not enough to operate one.

### B.1 Credential lifecycle (P1)

Today `vctypes.Credential` has `Status string // "pending" | "accepted"`. A real wallet has more states than that, and the holder currently cannot see the ones that matter most.

- **B.1.1 — Surface expiry and revocation on the wallet card.** `internal/statuslistcache` already fetches and caches both W3C BSL 2023 and IETF Token Status List. Wire it into the holder view so a held credential renders `valid` / `expired` / `revoked` / `status unavailable` without the holder having to present it to a verifier to find out. Extend `vctypes.Credential` with `NotBefore`, `ExpiresAt`, `RevocationStatus`, `StatusCheckedAt`.
  `vctypes/vctypes.go`, `internal/handlers/wallet.go`, `internal/statuslistcache/`
- **B.1.2 — Background re-check job.** `internal/jobs` already has a queue (71.7% covered). Add a periodic status refresh per held credential, honouring the per-issuer `StatusListPolicy` (`fail-open` / `fail-closed`) already in `trust.TrustedIssuer`.
  `internal/jobs/`, `internal/statuslistcache/`
- **B.1.3 — Renewal.** When a credential is within N days of `ExpiresAt` and its issuer advertises a matching credential configuration in its OID4VCI metadata, offer the holder a one-click re-issuance. Depends on the discovery work already scoped in `TODO.md` § "Credential Discovery & Self-Service Issuance".

### B.2 Holder notification channel (P1)

`docs/credential-delivery.md` § "Mechanisms not yet on the roadmap" makes the correct architectural call: push-revocation and push-issuance are **one channel, not two webhooks**. Build it once.

- **B.2.1** — `internal/notify/` with a `Channel` interface and implementations for webhook, email (`internal/mailer` exists, 0% covered) and in-app inbox.
- **B.2.2** — Emit on: credential issued, credential revoked, credential expiring, renewal available, presentation requested.
- **B.2.3** — The Hub fans out to member deployments over the existing federation member list.

### B.3 Backup, export and portability (P2)

A custodial wallet the holder cannot leave is not a wallet.

- **B.3.1** — `GET /wallet/export` producing a signed, encrypted archive of held credentials in their original wire format (SD-JWT VC, `ldp_vc`, `mso_mdoc` all preserved verbatim — re-serialising breaks signatures).
- **B.3.2** — Import of the same archive into a different deployment, with a clear statement in the UI that **key-bound credentials do not survive the move** unless the target holds the same key. This limit is inherent, and hiding it would be worse than stating it.
- **B.3.3** — Audit log of every export.

### B.4 Key binding verification (P2)

HAIP §6 and `docs/haip-conformance.md` both flag this: `verifiably-go` extracts claims from the `kb-jwt` without re-verifying its signature, and does not independently check the `cnf` claim. Both are currently delegated entirely to walt.id. In a federated deployment the Hub verifies credentials issued by members it does not control, so "the DPG checked it" stops being a sufficient answer.

- **B.4.1** — Verify the `kb-jwt` signature against the `cnf` key in the SD-JWT VC in `internal/vp` (77.8% covered, good foundation).
- **B.4.2** — Assert `cnf` ↔ holder DID binding at claim time.

### B.5 Offline and mDL — delivered by PR #14 (was P3)

**Superseded.** This item was scoped as "spike first, not a commitment". PR #14 has done both: ISO/IEC 18013-5 mdoc issuance across two independent emitters (walt.id `issuer-api2` and Inji Certify Pre-Auth), CBOR types with correct ISO tag handling, Annex-B IACA/DSC PKI, MSO assembly and COSE_Sign1 signing, and `GET /trust/mdoc-anchors` serving live IACAs. The walt.id-versus-library question the spike was meant to answer is answered: two production emitters, with in-process signing explicitly rejected by ADR.

What remains after it merges:

- **B.5.1** — Revocation for `mso_mdoc`. Still absent; `docs/haip-conformance.md` marks the format ⚠️ for exactly this reason.
- **B.5.2** — Proximity presentation (BLE / NFC / QR device engagement). PR #14 covers issuance, not the 18013-5 device-retrieval flows.
- **B.5.3** — Replace the POC trust-anchor endpoint. PR #14 documents `/trust/mdoc-anchors` as an unsigned POC mechanism; the Hub-signed VICAL-style list is designed but unimplemented, and it belongs with Workstream E — a signed list of recognised IACAs is a trust registry by another name.

---

## 6. Workstream C — Issuance

### C.1 True batch issuance (P1)

`internal/handlers/bulk.go` issues N sequential single credentials against the DPG. OID4VCI defines `/batch_credential`; `docs/haip-conformance.md` marks this ⚠️. For a national deployment issuing to a cohort, the difference is N round-trips versus one.

- Extend `backend.IssueBulkRequest` with a `PreferBatch bool`, add `BatchIssuer` as an optional interface adapters may implement (the same pattern `PresentationPreviewer` already uses), fall back to the sequential loop when unimplemented.
  `backend/adapter.go`, `internal/adapters/*/issuer.go`, `internal/handlers/bulk.go`

### C.2 Deferred issuance (P1)

OID4VCI's `transaction_id` flow. `docs/credential-delivery.md` argues correctly that this is required the moment self-service issuance is real: a licence a civil servant must review cannot be issued synchronously. Without it, every government credential worth issuing is out of scope.

- Add `IssuanceState` (`pending_review` / `approved` / `rejected` / `issued`) to `internal/issuance`, a review queue in `internal/handlers`, and the `transaction_id` endpoints.

### C.3 Display metadata (P2)

`display` arrays from OID4VCI issuer metadata are parsed but not surfaced — the wallet card renders a schema name where the issuer supplied a logo, background colour and localised label. `backend.CredentialConfigsFromSchemas` already assembles the metadata; the UI simply drops it.

### C.4 Issuance-time policy (P2)

Presentation-during-issuance (`TODO.md` P3) and wallet attestation validation (HAIP Gap 3) are both "check something before minting". Build one policy hook in `internal/issuance` rather than two special cases.

---

## 7. Workstream D — Verification

`docs/haip-conformance.md` is a good audit and its three gaps are still open. Two of them are blocked on walt.id upstream; the third is not.

### D.1 `client_id_scheme=x509_san_dns` (P1 — unblocks with Workstream F)

HAIP §4.3. Currently `client_id` is the verifier's `redirect_uri`, so a wallet cannot distinguish a legitimate verifier from a phishing site. The certificate half of this arrives with Workstream F; the `verifiably-go` half is small — add `ClientIDScheme` to `vctypes.OID4VPTemplate` and thread it through `RequestPresentation`.

### D.2 `response_mode=direct_post.jwt` / JARM (P1 — upstream-blocked)

HAIP §5.5 requires the response to be JWT-encrypted to the verifier's key. walt.id 0.18.2 supports `direct_post` only. **Action: track walt.id releases and re-test; do not build around it.** The parameter already passes through `RequestPresentation`, so the `verifiably-go` change is expected to be zero once upstream lands.

### D.3 Independent verification (P1)

Related to B.4 and more consequential. `docs/haip-conformance.md` marks four checks as "verified by walt.id; verifiably-go trusts the adapter's success/error": `iss` validation, credential `exp`, DPoP binding, `cnf`. Fine for a single-vendor demo. Not fine for the Hub, which verifies credentials from members running different stacks.

- Build `internal/verification/independent.go`: re-verify issuer signature against the resolved DID document, check `exp`/`nbf`, check `iss` matches the trust-registry entry — **regardless of what the adapter reported**. `internal/verification` is at 16.7% coverage and 136 lines; this is where it grows.

### D.4 Multi-credential presentation (P1)

Already scoped in `TODO.md` § "Multi-Credential Presentation (OID4VP)" and a hard prerequisite for the delegation and guardianship policies. No change to that plan; noting the dependency.

---

## 8. Workstream E — Trust and DeDi cross-border

This is the workstream with the highest strategic value and the least existing code.

### 8.1 Where trust stands today

`internal/trust` implements a national trust registry: a `Registry` interface over Postgres, a signed `GET /trust-registry` JWT, per-issuer API keys, and health checks. `internal/federation` models a Hub with members. The package comment already anticipates the next step:

> *"A future implementation can satisfy the same interface using OpenID Federation entity-statement resolution without touching any handler code."*

That is the right seam, and DeDi fits it too. The constraint today is that trust is **hub-shaped**: a member is trusted because *this* Hub's registry says so. Cross-border requires trusting an issuer whose registry belongs to a different authority entirely.

### 8.2 What DeDi provides

DeDi (Decentralised Directory Protocol, [dedi.global](https://dedi.global)) publishes public registries as cryptographically signed, machine-readable files — "DNS for Trust". Its model:

- **Namespace** → **Registry** → **Record** (e.g. `central_bank` / `licensed_banks` / `bank-7`)
- `GET /dedi/lookup/{namespace}/{registry}/{record}` — resolve one record
- `GET /dedi/query/{namespace}/{registry}` — search a registry
- Webhook **subscribe** for revocations and updates
- Every response carries the original publisher's signature

The mapping onto this codebase is almost one-to-one: `trust.TrustedIssuer` is a DeDi record, the Hub's registry is a DeDi registry, and the ecosystem is a namespace.

> **Verification note.** The data model, the three endpoints and the signing model above were confirmed against dedi.global on 2026-09-10. The exact request/response JSON, the signature suite and the record-versioning semantics were **not** obtainable — `dedi.global/docs` and `/spec` both return 404 and no reference implementation was locatable on GitHub. E.1 below is therefore scoped as a spike whose first deliverable is a pinned wire format, and no schedule should be committed until it lands.

### 8.3 Tasks

- **E.1 — Spike: pin the DeDi wire format (P0 for this workstream).** Obtain the specification from CDPI/Dhiway directly. Deliverable: a `docs/dedi-integration.md` recording endpoints, JSON shapes, signature suite, record versioning and revocation semantics. **Everything below is contingent on this.**

- **E.2 — `internal/dedi/` resolver client (P1).** `Resolve(namespace, registry, record)` and `Query(namespace, registry)` over `internal/httpx` (which needs tests regardless — currently 0%), signature verification on every response, and a cache modelled on `internal/statuslistcache` (which already solves the same fetch/cache/verify problem for status lists).

- **E.3 — `trust.Registry` implementation backed by DeDi (P1).** The interface already exists and has four methods. A `dediRegistry` satisfying `IsTrusted` / `TrustedIssuers` / `Add` / `Remove` — the last two returning `ErrNotSupported` for a read-only remote registry — means **no handler changes at all**. This is the payoff for the existing abstraction.

- **E.4 — Composite registry with resolution order (P1).** Real cross-border verification consults several registries: local first, then a recognised foreign registry via DeDi, then reject. Add `trust.Chain` wrapping an ordered list of `Registry` values with per-source provenance on the result, so the verifier UI can say *"trusted — via the Kenyan national registry, resolved through DeDi"* rather than a bare green tick. Provenance is the point: a cross-border trust decision the operator cannot explain is not usable in the field.

- **E.5 — Publish this deployment as a DeDi registry (P2).** The Hub already serves a signed `GET /trust-registry`. Add `GET /dedi/lookup/...` and `GET /dedi/query/...` over the same store so a `verifiably-go` Hub is discoverable *by* other countries, not only a consumer of their registries. Symmetry here is what makes it a network rather than a client.

- **E.6 — DeDi subscribe for revocation (P2).** Wire the webhook into the B.2 notification channel. One channel, again.

- **E.7 — Cross-border trust policy (P2).** Which foreign namespaces are recognised, for which credential types, under what legal basis. Extend `config/federation.json` with a `recognisedRegistries` block. This is a policy artefact as much as a code one and needs a named owner outside engineering.

### 8.4 Relationship to OpenID Federation

DeDi and OpenID Federation solve overlapping problems. The `trust.Registry` seam accommodates both, and E.3/E.4 make that concrete: a future `oidfRegistry` slots into the same `trust.Chain`. **Recommendation: do not choose between them.** Implement DeDi first (simpler, CDPI-aligned, and this is a CDPI project), keep the interface honest, and add OpenID Federation as a second `Registry` implementation if a partner ecosystem requires it.

---

## 9. Workstream F — PKI, HSM and KMS

**Direction confirmed:** all three backends as configurable options behind one abstraction, selected by `VERIFIABLY_SIGNER_TYPE`.

`TODO.md` § "PKI / HSM / KMS Integration" already sketches this. This scope keeps that design and makes the configurability explicit.

> **Start from PR #14, not from zero.** That branch already ships `internal/signer/` with a working software backend, a certificate-chain accessor and 77.8% coverage. Its `Signer` is COSE-scoped (`Algorithm() cose.Algorithm`) because it serves ISO 18013-5 `IssuerAuth`. F.1 generalises that package to cover the JWS paths as well; it does **not** introduce a second signing abstraction beside it. Two signer packages in one binary would be a worse outcome than the bind-mounted PEM file we are replacing.

### F.1 The abstraction (P1 — blocks everything else here)

Widen PR #14's `Signer` rather than replace it — `CertificateChain()` already carries the shape F.3 needs, and the COSE algorithm becomes one of several suites:

```go
// internal/signer — generalising the interface PR #14 introduces
type Provider interface {
    crypto.Signer                      // Public() + Sign() — the JWS paths
    CertificateChain() []*x509.Certificate  // as in PR #14; nil for non-PKI backends
    Algorithm() Algorithm              // COSE or JWS suite, per caller
    KeyID() string                     // kid for JWS headers
    Close() error                      // PKCS#11 sessions need teardown
}
```

The existing `SoftwareSigner` becomes the `pem` backend below with no behavioural change.

Four backends, one env var:

| `VERIFIABLY_SIGNER_TYPE` | Backend | Use |
|---|---|---|
| `pem` (default) | `internal/signer/pem.go` | Current behaviour. Backward-compatible — an existing deployment must not need config changes. |
| `pkcs11` | `internal/signer/pkcs11.go` | SoftHSM2 for dev, SafeNet / nCipher / Utimaco in production, via `miekg/pkcs11`. **Behind build tag `pkcs11`** so the default binary stays CGO-free and statically linkable. |
| `cloudkms` | `internal/signer/cloudkms.go` | AWS KMS / CloudHSM, Azure Key Vault Managed HSM, GCP Cloud KMS. Sub-selected by `VERIFIABLY_KMS_PROVIDER`. Natural fit — deployment is already Terraform/EKS. |
| `x509chain` | `internal/signer/x509chain.go` | National PKI / eIDAS-style CA. Wraps any of the above and adds chain material. |

`x509chain` composes rather than competes: a national-PKI deployment is typically `x509chain` **over** `pkcs11` or `cloudkms`, because the key lives in hardware and the certificate chain comes from the CA. Modelling it as a wrapper rather than a fifth peer is what makes all three options genuinely simultaneous rather than mutually exclusive.

### F.2 Wiring (P1)

Three call sites take keys directly today and must go through `signer.Global()`:

- `internal/trust/jwt.go` — the trust registry JWT
- `internal/statuslist/jws.go` — status list JWS
- `internal/statuslist/ldproof.go` — the Ed25519 LD-proof key

`cmd/server/main.go` constructs the provider at startup. Depends on A.5 (`main()` decomposition) for a testable seam.

Note that Vault Transit is already scaffolded at `deploy/k8s/terraform/platform/vault-bootstrap.tf` (commented out pending Vault init, per `docs/k8s/resume.md`). Vault Transit should be a fifth `Provider` implementation rather than a parallel mechanism.

### F.3 Credential signing and `x5c` (P2)

- Expose the provider to adapters for locally-signed SD-JWT VC issuance.
- When `Certificate() != nil`, emit the chain as `x5c` in the JWT header.
- Serve `GET /.well-known/ca-bundle.pem` so verifiers can anchor.
- This is what closes **HAIP Gap 2** (D.1) — the certificate that `client_id_scheme=x509_san_dns` requires is the one this workstream provisions.

### F.4 Key rotation (P2)

There is a design document at `docs/superpowers/specs/2026-07-23-issuer-key-rotation-design.md` (written in Spanish) covering issuer key rotation across walt.id, Inji Certify and CREDEBL. It notes correctly that Inji Certify's HSM sits behind MOSIP's own Key Manager, so `verifiably-go` configures it rather than driving it. Fold that design into `internal/signer` as the rotation contract: `Provider` gains a `Rotate()` and publishes both old and new keys in the DID document during an overlap window, so credentials signed before rotation stay verifiable.

### F.5 Boundaries — stated plainly

`verifiably-go` signs the **trust registry JWT, status lists, and locally-signed credentials**. Credentials issued by walt.id, Inji Certify or CREDEBL are signed by **those stacks' own key managers**, which have their own HSM configuration (`mosip.kernel.keymanager.hsm.*` for Certify). This workstream does not and cannot change that. Any claim that "the platform is HSM-backed" must be qualified by which of the two paths a given credential took, and the UI should say so.

---

## 10. Workstream G — Finish K8s support

All 22 phases of `docs/k8s/workplan.md` are implemented: Terraform bootstrap for kind / k3s / EKS, a platform module (ingress-nginx, cert-manager, CNPG, MinIO, External Secrets, Vault, kube-prometheus, Loki, Promtail, Argo CD, Kyverno), seven Helm charts, an umbrella, and a `k8s-deploy.sh` orchestrator mirroring `deploy.sh`. Charts lint and render; Terraform validates.

What remains is the gap between "renders" and "runs".

### G.1 The scenario gap (P1 — the largest item)

Compose supports three DPG stacks. K8s supports one.

```
deploy/k8s/helm/umbrella/
  waltid/          ← the only umbrella
```

There is no `umbrella/inji` and no `umbrella/credebl`, and no charts for Inji Certify, eSignet, Mimoto, Inji Web, Inji Verify, mock-identity-system, or CREDEBL's 18 services. `k8s-deploy.sh up inji` has nothing to install. Until this closes, K8s is a walt.id-only deployment path while the README advertises three stacks.

- **G.1.1** — `walt-*`-style charts for the five Inji components + eSignet + mock-identity-system, plus `umbrella/inji`. The compose definitions in `deploy/compose/stack/` and the per-service inventory in `docs/k8s/inventory.md` are the source material.
- **G.1.2** — `umbrella/credebl`. 18 microservices with a NATS backbone and a bootstrap that provisions a Keycloak realm, platform admin, DID and credential template. Materially harder than G.1.1; scope it separately and do not bundle the estimate.
- **G.1.3** — Extend `k8s-deploy.sh` scenario dispatch, matching the `--role` granularity `deploy.sh` already has.

### G.2 Real-infrastructure verification (P1)

`docs/k8s/resume.md` records the blocker precisely: the last run reached platform-layer green, then the umbrella stalled because Docker Desktop's ~3.8 GiB × 3 nodes could not hold platform + workloads. This is an environment ceiling, not a code defect, and it means **the workloads layer has never been observed running**.

- **G.2.1** — Run the full `up waltid --target=local` on a machine with headroom (≥ 32 GiB), or on a real EKS cluster via the existing `bootstrap/aws-eks` module.
- **G.2.2** — Clear the known-failed state first: `helm uninstall waltid` / `terraform state rm helm_release.waltid` (`resume.md` § "Known TODOs still pending").
- **G.2.3** — Fix the `auth-providers.json` shape crashloop that took down the `verifiably-go` pod.
- **G.2.4** — Wire `k8s-e2e.yml` into the gate. It is now at the repo root and will run for the first time; expect it to fail initially and treat the first green run as the actual milestone.

### G.3 Calibration (P2)

`docs/k8s/resume.md` § "Known TODOs / loose ends" lists ten items with the file each lives in. The substantive ones:

- **G.3.1** — HTTP probe paths are `/` placeholders across every chart. Tighten to real endpoints. Keycloak is already verified (TCP 8080 liveness, `/realms/master` readiness).
- **G.3.2** — `serviceMonitor.enabled` must stay `false` for walt.id charts: **walt.id 0.18.2 exposes no Prometheus endpoint on any listenable port** (verified 2026-05-01 — `/metrics`, `/actuator/prometheus`, `/health` all 404). Either ship an exporter sidecar or document the blind spot. It should not stay an unexplained `false`.
- **G.3.3** — Wallet HPA: run the k6 load test in `deploy/k8s/test/load/`, confirm zero session drift under horizontal scale, then enable. Session affinity behaviour under scale-out is the actual risk and the test exists to answer it.
- **G.3.4** — Locate walt.id issuer/verifier signing-key paths and set `signingKey.existingSecret`. **This is the K8s-side prerequisite for Workstream F** — a signer abstraction is worth little if the key still arrives as a bind-mounted file.
- **G.3.5** — Replace every `ghcr.io/REPLACE_ME` placeholder with the real GHCR org.
- **G.3.6** — Inline the Keycloak realm JSON into `umbrella/waltid/values.yaml`.
- **G.3.7** — Vault Transit: uncomment `vault-bootstrap.tf` after init (runbook exists at `deploy/k8s/runbooks/vault-init.md`). Converges with F.2.
- **G.3.8** — Verify WSO2IS passes PodSecurity `restricted`. If it does not, narrow the container-level concession — **never downgrade the namespace label**, per the workplan's own ground rule.

### G.4.6 — The security badge reads E, and why (P1)

The README's SonarCloud security badge shows **E**. That is not a scanner artefact and it should not be made green by triage. Sonar's rating is worst-finding-wins: **one BLOCKER means E**, and there are nine. All nine are secrets-class, and eight of them are key material committed to a public repository.

| # | Finding | Assessment | Action |
|---|---|---|---|
| 1 | `walt-wallet/config/auth.conf:19` + its `deploy/k8s/config/wallet/` twin — **RSA private key** (`tokenKey`) | **The most serious finding in this document.** It signs wallet auth tokens, and it is a *chart default* — every deployment that does not override it shares one key, so anyone with the repo can mint valid wallet tokens against it. The file's own comment already says "treat the JWK below as a high-sensitivity secret". | Externalise like `encryptionKey`/`signKey`, or land the Vault Transit reference the comment calls the real fix. Not attempted here: `auth.conf` is bind-mounted verbatim and resolved by walt.id itself, so the change cannot be verified without running walt.id. Belongs with **Workstream F**. |
| 2–4 | `nginx.key` ×2, `wso2.key` — self-signed TLS keys | Low impact: `subject == issuer`, CN is a Docker service name, no CA, no public DNS. Wrong pattern, small blast radius. | G.4.5 — generate at bootstrap. |
| 5 | `wso2carbon.jks` — weak password `wso2carbon` | WSO2's documented default, in a demo keystore. Same class as 2–4. | G.4.5. |
| 6 | `common.sh:47` — `VERIFIABLY_PG_PASSWORD:=verifiably` | **Real.** Postgres was published on `0.0.0.0:5439` with `verifiably:verifiably`, holding sessions, the issuance log and status lists — a guessable-credential database on the public internet for any VPS/EC2 deployment. | **Partly fixed:** Postgres and Redis are now bound to `127.0.0.1` in compose. The literal default remains; `deploy.sh setup` already generates a random password (`deploy.sh:1157`), so the fix is to remove the fallback and generate-if-missing on the `ensure_credebl_env` pattern. |
| 7 | `bootstrap-credebl.sh:129` — `SMTP_PASS=mailpit` | **False positive.** Mailpit is a local dev mail catcher on `credebl-mailpit:1025` that accepts anything; there is no account behind it. | Mark *Safe* in SonarCloud with this justification. |
| 8 | `oob-redirect.py:13` — user-controlled data in a response header | **Real, and worse than the rule title suggests.** `self.path` was concatenated onto the MinIO bucket URL (path traversal out of the bucket), the stored value was passed to `send_header` verbatim (open redirect, and CR/LF gives response splitting), and upstream exceptions were echoed to the caller (leaking internal hostnames). | **Fixed.** Strict key allowlist, scheme allowlist plus C0-control rejection on the redirect target, generic upstream errors. 23 assertions cover it. |

So the badge moves off E only when the committed key material goes. Two of the nine are addressed here; **finding 1 is the one to schedule first**, and it is a Workstream F item rather than a deploy chore.

A note on what *not* to do: SonarCloud lets these be marked Won't Fix, which would turn the badge green in a minute. Only finding 7 deserves that. Doing it to the rest would leave a repository publishing a signing key behind an A rating, which is worse than the E.

### G.5 CI cost and shape for the K8s path (P1)

The first runs of the cluster e2e produced this profile:

```
setup (helm, terraform, kind, kubectl, node)      ~20s
bring up cluster + waltid stack               18m 12s   ← step timeout
  └─ helm_release.waltid: Still creating…     12m 40s   never converged
tear down                                     10m 23s
                                              ────────
                                              ~29 min, cancelled by the 25m ceiling
```

Three separate runs ended this way, and three ran **concurrently** on one branch because no workflow had a concurrency group. Two conclusions: the job could not pass as configured, and it was costing ~90 runner-minutes per push to learn that.

- **G.5.1 — Two tiers, done.** `k8s.yml` replaces `k8s-e2e.yml`. A `render` job runs on every PR in ~40s with no cluster (measured: 37s): `helm lint` per chart, `helm dep update` + `helm template` on the umbrella, `kubeconform` on the rendered manifests, and `terraform fmt -check` + `validate` on all five modules. The `cluster` job keeps the real bring-up but runs nightly, on `workflow_dispatch`, or on a PR labelled `k8s-e2e`.

  It found a bug on its first run: **every Ingress emitted a duplicate `cert-manager.io/cluster-issuer` annotation** — the chart's own `values.yaml` sets it and the template appended the global one as a second line. Invalid YAML; Kubernetes resolves a duplicate key by silently taking the last value. Four charts fixed by merging the maps rather than concatenating.

- **G.5.2 — Restore `push: main` for the cluster tier once G.2 converges.** Deliberately absent today: a check that always fails teaches people to ignore CI. The nightly is the interim signal.

- **G.5.3 — Trim the platform for CI.** The smoke set is four UI tests, and the platform installs **13 Helm releases** to run them — Argo CD, Loki, Promtail, kube-prometheus-stack, MinIO, Vault, Kyverno, MetalLB, ESO, cert-manager, ingress-nginx, CNPG. `platform/variables.tf` has no toggles, so it is all-or-nothing. A minimal profile is the largest single lever on bring-up time, and plausibly on convergence too — the resource ceiling is a live hypothesis for why the umbrella never becomes ready.

- **G.5.4 — Caching, after the above.** Worth being precise: caching shortens *pulls*, not *convergence*, and much of the 18 minutes is waiting for pods to be ready. In payoff order: the kind node image (~1 GB), pre-pulled platform images `kind load`ed in, the Helm repo cache (already wired in the render job), `TF_PLUGIN_CACHE_DIR`, and reusing the image `image.yml` already built rather than rebuilding.

- **G.5.5 — Vendored chart staleness.** `umbrella/waltid/charts/*.tgz` are committed. `helm dep build` honours `Chart.lock` and reuses them, so a chart template edited without re-running `helm dep update` is packaged — and deployed — in its stale form. The render job runs `dep update` for this reason, but the underlying hazard remains: consider generating the vendored charts at deploy time instead of committing them.

### G.4 Production posture (P2)

- **G.4.1** — Cosign keyless signing is scaffolded in `image.yml` (`id-token: write` is already requested) but not implemented. Complete it and add verification at admission via the Kyverno policies already deployed.
- **G.4.2** — Flip the Trivy **image** scan from `exit-code: '0'` to `'1'`. The filesystem scan already blocks; the image scan was left report-only "to tighten in Phase 7.2", which has now shipped.

- **G.4.4 — Clear the Trivy misconfiguration backlog, then make it blocking.** The first-ever run of `image.yml` produced these, and they are currently report-only (SARIF to the Security tab) because every real one sits in infrastructure that has never been observed running — see G.2. Fixing `readOnlyRootFilesystem` blind, on two containers that write at runtime, on a stack that has never booted, buys a green gate and a broken deploy.

  | Finding | Severity | Where | Assessment |
  |---|---|---|---|
  | `AWS-0040` / `AWS-0041` | CRITICAL | `bootstrap/aws-eks` | **Real.** The EKS control plane is reachable from `0.0.0.0/0`. Acceptable for a dev bootstrap, not for the production topology the module is meant to serve. Restrict to a CIDR allowlist, or put the API behind a bastion/VPN. |
  | `AWS-0104` | CRITICAL | `bootstrap/aws-eks` | **Real**, lower practical severity — unrestricted egress on the cluster security group. Tighten once the workload's outbound dependencies are enumerated. |
  | `KSV-0014` ×2 | HIGH | `wso2is`, `libretranslate` charts | **Real.** Neither sets `readOnlyRootFilesystem`. Both genuinely write at runtime (WSO2IS to its deployment tree, LibreTranslate to its model cache), so the fix is an `emptyDir` for the writable paths plus the flag — which needs a running cluster to validate. Converges with G.3.8. |
  | `DS-0031` | CRITICAL | `Dockerfile` | **False positive.** `VERIFIABLY_AUTH_PROVIDERS_FILE` is a path (`/app/config/auth-providers.json`), flagged by a name heuristic. Resolve with a scoped Trivy ignore carrying this justification, not a blanket suppression. |

- **G.4.5 — Generate the demo TLS certificates at bootstrap instead of committing them.** Trivy's secret scanner blocks on three private keys in the tree:

  ```
  deploy/compose/stack/inji/certify-nginx/certs/nginx.key
  deploy/compose/stack/inji/certify-preauth-nginx/certs/nginx.key
  deploy/compose/stack/wso2-certs/wso2.key
  ```

  Each is self-signed with `subject == issuer` and a CN that is a Docker service name (`certify-nginx`, `wso2`), not a routable domain, and `deploy.sh` does not regenerate them. So the exposure is genuinely small — the key authenticates nothing outside a container network already told to trust that exact certificate, there is no CA, and anyone can mint an equivalent in a second. It is still the wrong pattern to ship from a project about verifiable credentials, and every deployment shares one key.

  Fix: generate on first `deploy.sh up`, `.gitignore` the outputs, remove the committed keys (and, since they are in history, treat them as compromised and never reuse them elsewhere). Held out of the gate PR deliberately — it changes how the stack comes up on a clean host, which needs verifying against a real Docker daemon rather than asserting. Until then a **scoped, expiring** ignore in `.trivyignore.yaml` covers exactly these three paths; a committed key anywhere else still fails the build.

  Sonar's secret detector independently flagged the same three, plus `wso2carbon.jks`, an SMTP password in `bootstrap-credebl.sh`, a PostgreSQL password in `common.sh`, and — the one that matters most — **JWK private keys in the `walt-wallet` chart defaults**, which means every deployment that does not override them shares a wallet signing key. That last one belongs with Workstream F, not here.

  Sequencing: G.2 (a verified cluster) → fix → flip `exit-code` to `1`. The split in `image.yml` is deliberate — vulnerability and secret scanning stay **blocking** (that pair caught 8 real CVEs on its first run), and only misconfiguration is deferred.
- **G.4.3** — Backup and restore runbook for CNPG Postgres. Nothing in the deploy tree currently restores a Hub's trust registry after loss, which is the one piece of state that cannot be regenerated.

---

## 11. Sequencing

Dependencies, not dates. Ordered so that each phase unblocks the next rather than running in parallel and colliding.

```
Phase 0 — landed
  A.1 CI at repo root · lint gate green · coverage floor · Sonar config
  └── A.6 operator: connect SonarCloud, Automatic Analysis OFF  ← human, do first
      (mark checks REQUIRED — they apply to #14/#15 too)

Phase 0.5 — land what is already written   ← do before starting anything new
  #11 close (already in main)
  #15 rebase → merge   delivers A.3 for internal/handlers (27.6% → 98.3%)
   │                   take its inji_holder.go / schema.go at the conflict
   └── raise COVERAGE_FLOOR to the merged measurement
  #14 rebase → merge   delivers B.5 · seeds F.1 (internal/signer)
   └── must first clear ≥80% on new code (mdl 75.4 · mdoc 79.5 · signer 77.8) on main

Phase 1 — foundations (parallel)
  A.5 decompose main()  ──┬── F.1 generalise PR #14's internal/signer
  A.3 coverage → M1       │        └── F.2 wire trust/statuslist signing
  A.4 e2e runner + tags   │   (M3 handlers target already met by #15)
  G.2 K8s real-infra run ─┘        E.1 DeDi spike ← blocks all of Workstream E
  G.3.4 signing-key secrets ───────┘ (converges with F.2)

Phase 2 — capability
  B.1 credential lifecycle ──── B.2 notification channel ──── E.6 DeDi subscribe
  C.1 batch issuance                                          (one channel)
  D.3 independent verification ─── B.4 key-binding verification
  E.2 DeDi client ──── E.3 DeDi trust.Registry ──── E.4 composite chain
  G.1.1 Inji charts + umbrella

Phase 3 — assurance
  F.3 x5c + CA bundle ──── D.1 client_id_scheme=x509_san_dns   (HAIP Gap 2 closed)
  F.4 key rotation
  C.2 deferred issuance
  E.5 publish as DeDi registry · E.7 cross-border policy
  A.3 coverage → M3
  G.1.2 CREDEBL umbrella · G.4 cosign, Trivy blocking, CNPG backup

Phase 4 — long lead
  B.3 backup/export
  B.5.1/2/3 mdoc revocation · proximity presentation · signed VICAL-style
            anchor list  ← the remainder of mDL after #14 lands
  D.2 JARM  ← upstream-blocked on walt.id; track, do not build around
  E.4+ OpenID Federation as a second Registry, if a partner requires it
```

---

## 12. Risks and open decisions

| # | Risk | Impact | Response |
|---|---|---|---|
| R1 | DeDi spec not publicly obtainable | Blocks all of Workstream E | E.1 is a hard gate. Obtain from CDPI/Dhiway before committing any E schedule. |
| R2 | walt.id 0.18.2 lacks JARM and exposes no metrics | HAIP Gap 1 stays open; K8s observability has a hole | Track upstream (D.2). Sidecar exporter or documented blind spot (G.3.2). Do not fork. |
| R3 | 58 gosec findings are report-only | Real vulnerabilities could ship | Triage in Phase 1. SSRF taint (14) and path traversal (5) first — `internal/handlers/ssrf.go` exists and is tested, so several are likely false positives, but "likely" needs to become "verified". |
| R4 | Coverage floor invites gaming | 70% of trivial code proves nothing | Sonar's ≥80%-on-new-code gate is the real control. Package-specific targets in A.3 are set by risk, not evenly. |
| R5 | Signing responsibility is split | "HSM-backed" could be claimed too broadly | F.5 states the boundary. Surface the signing path per credential in the UI. |
| R6 | K8s supports 1 of 3 advertised stacks | README overstates the deployment story | G.1. Until it lands, state the limitation in the README rather than leaving it implied. |
| R7 | K8s workloads layer never observed running | Unknown unknowns behind a green `helm template` | G.2 on real hardware before any K8s production claim. |
| R8 | `main()` at 690 lines | Blocks A.5, F.2 and coverage M4 | A.5 early in Phase 1. |
| R9 | 73 e2e scripts, unrun and unowned | Silent rot; false confidence | A.4.3 — delete what no longer runs. |
| R10 | Two large PRs (+28k and +18k lines) age against a moving `main` | Rebase cost grows; review quality falls | Phase 0.5 — land both before starting new work. Conflict cost is small today (4 and 1 files) and measured; it will not stay that way. |
| R11 | PR #14 is 0.5–4.6 points short of the ≥80% new-code coverage bar | A 149-commit branch cannot merge until it closes the gap | Accepted deliberately: the gate applies to the open PRs, no grandfather clause. The ask is a handful of tests on CBOR encoding and MSO assembly — code that signs credentials and is worth testing regardless. Budget for it in Phase 0.5 rather than discovering it at merge time. |
| R12 | `unused` deleted `heldClaims` / `hasField`, which PR #15 tests | Merged tree compiles-then-fails `go vet` | Take PR #15's file versions at the conflict. Verified that test-only references satisfy `unused`. |

### Decisions needed from outside engineering

1. **DeDi specification access** (R1) — who at CDPI/Dhiway provides it.
2. **Cross-border recognition policy** (E.7) — which foreign namespaces are recognised, for which credential types, on what legal basis. This is not an engineering decision.
3. **Cloud KMS provider** (F.1) — AWS is the path of least resistance given the existing EKS Terraform, but the abstraction supports all three; the choice only fixes which backend gets built and tested first.
4. **CREDEBL on K8s** (G.1.2) — 18 microservices is a real investment. Confirm CREDEBL is in the target production topology before building it.
5. **Merge window for PRs #14 and #15** (§3.3) — both are large and both are aging. Landing them is a scheduling decision, not a technical one, and everything in Phase 1 is cheaper afterwards.
   *Settled 2026-09-10: the quality gate applies to both; neither is exempted.*
6. ~~**mDL** (B.5) — spike before committing.~~ *Resolved: PR #14 delivers issuance across two emitters. What remains (revocation, proximity presentation, a signed anchor list) is ordinary backlog, not a decision.*

---

## 13. Changelog

- **2026-09-10** — Initial scope. Baseline measured at `b571e62`. Workstream A implemented; B–G proposed.
- **2026-09-11 (rev 6)** — Assessed the E security badge finding by finding (G.4.6). Fixed the oob-redirect path-traversal/open-redirect/header-injection issue and bound Postgres and Redis to loopback. Recorded that the badge cannot leave E until the committed wallet signing key is removed, and that marking the remainder Won't Fix would be worse than the E.
- **2026-09-11 (rev 5)** — Added G.5 after profiling the cluster e2e: two-tier split landed (render on every PR, cluster nightly/on-demand), concurrency groups added to all three workflows, CI teardown reduced from a 10-minute cascading terraform destroy to `kind delete cluster`. The render tier immediately found a duplicate-annotation bug in four Ingress templates.
- **2026-09-11 (rev 4)** — First CI runs landed. Recorded the Trivy misconfiguration backlog as G.4.4 with a per-finding assessment; noted that vulnerability/secret scanning stays blocking while misconfiguration is report-only until G.2 provides a cluster to validate fixes against.
- **2026-09-10 (rev 3)** — Decision recorded: the quality gate is a required check and applies to PRs #14 and #15; the earlier recommendation to defer it is withdrawn. §3.3 now states what each PR must do to clear it, and R11 reframed accordingly.
- **2026-09-10 (rev 2)** — Surveyed the three open PRs against the fetched branches. Added §3. B.5 reduced to three remainder items (PR #14 delivers the rest); F.1 rebased onto PR #14's `internal/signer` instead of proposing a new package; A.3 adopts PR #15's per-function gate alongside the floor; A.6 corrected (project key `centre-for-dpi_verifiably`, Analysis Method path, required-checks timing). Added Phase 0.5 and risks R10–R12.
