# CI for the Verifiable Credentials Adapters

This page describes the workflows that check and ship the code under `vca/`.
The workflows follow ADR-006. They live at the repository root in
`.github/workflows/` (ADR-006 decision 6). All workflow files for this
code start with `vca-`. The legacy monolith under `verifiably-go/` keeps its
own workflows (`quality.yml`, `image.yml`, `k8s.yml`).

Every check either passes or blocks. No job uses `continue-on-error`.
No check is report-only.

## Workflows

| Workflow | File | Runs when | Purpose |
| --- | --- | --- | --- |
| vca-ci | `.github/workflows/vca-ci.yml` | Pull request or push to `main` or `vc-adapter` that changes `vca/**` | The merge gate |
| vca-release | `.github/workflows/vca-release.yml` | Push of a tag that matches `v*` | Build, sign and publish a release |
| vca-nightly | `.github/workflows/vca-nightly.yml` | Every day at 02:30 UTC, or manual start | Slow checks that do not fit a PR |

## vca-ci: the merge gate

Each job runs alone. A failure in one job blocks the merge.

| Job | What it checks | Tool |
| --- | --- | --- |
| conventional commits | Every commit subject in the PR follows Conventional Commits 1.0.0 | `vca/hack/check-commits.sh` |
| shellcheck | Every script under `vca/hack/` is clean at the `style` level, and `check-commits_test.sh` passes | `shellcheck` |
| gofmt + go vet + golangci-lint | Formatting, vet, and the linters in `vca/.golangci.yml` (`gosec` and `errcheck` included, no exclusions) | golangci-lint v2 |
| buf lint + breaking | Proto style, and no breaking change against the last `v*` tag | `buf` |
| go test + coverage gate | Unit tests with the race detector; each package at 90 percent or more, `vca/core/...` at 100 | `go test`, `vca/hack/coverage.sh` |
| secret scan (blocking) | No key store, PEM private key, 64 hex API key, or literal password in the tracked tree | `vca/hack/secret-scan.sh` |
| trivy fs (blocking) | No HIGH or CRITICAL vulnerability, secret, or misconfiguration under `vca/` | Trivy |

Notes:

- `buf breaking` compares against the newest tag that matches `v*`. When
  the repository has no such tag, or the tag has no `vca/proto`, the step
  prints a notice and passes. The first release creates the baseline.
- The commit check accepts these types: `build`, `chore`, `ci`, `docs`,
  `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, `test`. A scope is
  optional and must be lower case. A `!` before the colon marks a breaking
  change. The check ignores merge commits.
- Coverage uses `go test -race -coverprofile`. The gate reads the per
  package numbers. Packages under `gen/` and `cmd/` are not gated.
- The secret scan reads the files that git tracks, in the whole
  repository (ADR-029 decision 6). It never reads the history, because the
  history purge is a release step, see
  [release-checklist.md](release-checklist.md). A known legacy finding
  sits in `vca/hack/secret-scan-allow.txt` with its reason, and the scan
  prints it as a warning.

To run the same checks on your machine:

```sh
cd vca
make lint          # buf lint, go vet, gofmt
golangci-lint run ./...
make test
make cover
shellcheck hack/*.sh
./hack/secret-scan.sh
./hack/check-commits.sh origin/main..HEAD
```

## vca-release: publish a release

A push of a tag `vX.Y.Z` starts the workflow. See
[release.md](release.md) for the operator steps. The jobs are:

1. `version`: parses the tag as SemVer 2.0.0 and discovers every service
   under `vca/services/*/` that has a `Dockerfile`. A tag that is not
   SemVer fails the workflow.
2. `images`: one job per service. It builds the image and pushes
   `ghcr.io/<owner>/vca-<service>:vX.Y.Z`, `:vX.Y` and `:vX`. It sets the OCI
   labels `title`, `description`, `version`, `revision`, `source`,
   `licenses=Apache-2.0` and `created` (ADR-005 decision 4). It scans the
   image with Trivy (blocking) and signs it keyless with cosign. It also
   attaches SBOM attestations in SPDX and CycloneDX (ADR-005 decision 5).
   A pre-release tag such as `v1.2.0-rc.1` does not move the `vX.Y` and
   `vX` tags.
3. `cli`: builds the `vca` binary for linux and darwin on amd64 and arm64
   with plain `go build`, when `vca/cmd/vca` exists.
4. `charts`: lints and packages every chart under `deploy/vca/helm/*`, when
   that directory exists.
5. `release`: it generates release notes with `vca/hack/release-notes.sh`
   and lists the image digests. It creates the GitHub Release with the
   binaries, checksums, chart packages, SBOM files and digest files attached.

All services get the same version per release (ADR-006 decision 4).

## vca-nightly: slow checks

| Job | What it does | Script |
| --- | --- | --- |
| make test | Full unit suite and the coverage gate | `make test`, `make cover` |
| contract tests (real DPGs) | Runs contract tests against real DPG containers named in the repository variable `VCA_CONTRACT_DPGS`. With no names, prints a message and passes. | `vca/hack/contract-tests.sh` |
| helm render + kind deploy | Creates a kind cluster, lints, renders and installs every chart under `deploy/vca/helm/*`, and waits for the deployments. With no charts, prints a notice and passes. | `vca/hack/k8s-smoke.sh` |

A nightly failure does not block a merge. It shows on the Actions page.
The team must fix it before the next release.

## Pinned actions

Pin every third party action to a version tag. Pin Trivy to an
exact release. Do not use `@master` or `@main`.

## Scripts in `vca/hack/`

| Script | Purpose |
| --- | --- |
| `bootstrap.sh` | Installs buf plugins, with mirrors on a restricted network |
| `coverage.sh <floor>` | Fails when a package is below the floor; `core/...` must be 100 |
| `check-commits.sh <range>` | Validates commit subjects in a git range |
| `check-commits_test.sh` | Tests `check-commits.sh` with good and bad subjects |
| `release-notes.sh <from> <to> [version]` | Writes a CHANGELOG section from Conventional Commits |
| `contract-tests.sh` | Runs contract tests for the DPGs in `VCA_CONTRACT_DPGS` |
| `k8s-smoke.sh` | Deploys the Helm charts into the current cluster and waits |
