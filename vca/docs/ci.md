# CI for the Verifiable Credentials Adapters

This page describes the workflows that check and ship the code under `vca/`.
The workflows follow ADR-006. They live at the repository root in
`.github/workflows/` (ADR-006 decision 6). All workflow files for this
code start with `vca-`. The legacy monolith under `verifiably-go/` keeps its
own workflows (`quality.yml`, `image.yml`, `k8s.yml`).

Every check either passes or blocks. No job uses `continue-on-error`.
Two outputs feed reports only, and the check behind each one blocks. The
lint job writes a checkstyle report for Sonar, and the golangci-lint step
of the same job blocks. The gosec job sends its findings to the Security
tab, and the gosec linter of golangci-lint blocks.

## Workflows

| Workflow | File | Runs when | Purpose |
| --- | --- | --- | --- |
| vca-ci | `.github/workflows/vca-ci.yml` | Each pull request or push to `main` or `vc-adapter`, or a manual start | The merge gate |
| vca-release | `.github/workflows/vca-release.yml` | Push of a tag that matches `v*` | Build, sign and publish a release |
| vca-nightly | `.github/workflows/vca-nightly.yml` | Every day at 02:30 UTC, or manual start | Slow checks that do not fit a PR |

## vca-ci: the merge gate

Each job runs alone, except `sonarcloud`, which waits for `lint` and
`test`. A failure in one job blocks the merge.

The workflow has no path filter. It is a required status check. A
required check that filters itself out by path leaves a pull request
without its status. A manual start (`workflow_dispatch`) runs it on any
branch. A new push to a branch cancels the run in progress on that
branch (concurrency group `vca-ci-<ref>`).

| Job | What it checks | Tool |
| --- | --- | --- |
| conventional commits | Every commit subject in the PR follows Conventional Commits 1.0.0 | `vca/hack/check-commits.sh` |
| shellcheck | Every `*.sh` file under `vca/` and `deploy/vca/` is clean at the `style` level, and `check-commits_test.sh` passes | `shellcheck` |
| gofmt + go vet + golangci-lint | Formatting, vet, and the linters in `vca/.golangci.yml` (`gosec` and `errcheck` included, no exclusions). A second step writes the checkstyle report for Sonar and never fails the job | golangci-lint v2.5.0 (`GOLANGCI_LINT_VERSION`) |
| buf lint + breaking | Proto style, and no breaking change against the last `v*` tag or the merge base with `main` | `buf`, `vca/hack/buf-breaking.sh` |
| go test + coverage gate | Unit tests with the race detector; each package at 90 percent or more, `vca/core/...` at 100; the total at or above `COVERAGE_FLOOR`. The job writes a coverage summary to the run page | `go test`, `vca/hack/coverage.sh` |
| SonarCloud | The SonarCloud quality gate of project `centre-for-dpi_verifiably_vca` passes. The job skips a pull request from a fork | `sonarqube-scan-action`, `sonarqube-quality-gate-action` |
| gosec SARIF (report for the Security tab) | Sends every gosec finding to the Security tab, category `gosec-vca`. It fails only when gosec cannot run | gosec v2.29.0 |
| secret scan (blocking) | No key store, PEM private key, 64 hex API key, or literal password in the tracked tree | `vca/hack/secret-scan.sh` |
| trivy fs (blocking) | No HIGH or CRITICAL vulnerability, secret, or misconfiguration under `vca/` | Trivy |
| wallet.js in Chromium (Playwright) | `TestWalletScriptInChromium` drives the wallet pages in a headless Chromium against the walt.id walkthrough | Playwright 1.56.1, Chromium |

Notes:

- `vca/hack/buf-breaking.sh` runs the check. It compares against the
  newest tag that matches `v*`. A repository with no such tag gets the
  merge base with `main` instead (ADR-003 decision 4). A tag without a
  `vca/proto` directory gets the same treatment. A repository with no tag
  and no `main` branch has no baseline. The script then prints a message
  and passes. Set `BUF_BREAKING_REF` to compare against one reference.
- The commit check accepts these types: `build`, `chore`, `ci`, `docs`,
  `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, `test`. A scope is
  optional and must be lower case. A `!` before the colon marks a breaking
  change. The check ignores merge commits.
- Coverage uses `go test -race -coverprofile`. The gate reads the per
  package numbers. Packages under `gen/` and `cmd/` are not gated. A
  package that holds tests only, such as the walkthrough, has no
  statements, so the gate skips it.
- The test step names `shell: bash`. The default shell of a step has no
  `pipefail`, so `go test | tee` would report a failed suite as a pass.
- The test step writes `coverage.out` with `-coverpkg=./...`. A line
  counts when the tests of any package reach it. The step also writes
  `test-output.txt`, the `go test -json` stream that Sonar reads. The job
  uploads both files as the artifact `vca-coverage`.
- The coverage summary of the run page shows the total and the 40
  functions with the lowest coverage. The total leaves out `gen/`, every
  `cmd/` package and the kit example page `ui/example/`.
- The coverage floor is a ratchet. The total must not drop below
  `COVERAGE_FLOOR` in the test job. See "Raise the coverage floor".
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
find . ../deploy/vca -name '*.sh' -type f -print0 | xargs -0 -r shellcheck -S style
./hack/secret-scan.sh
./hack/check-commits.sh origin/main..HEAD
```

### Raise the coverage floor

`COVERAGE_FLOOR` sits in the step "Coverage floor (ratchet)" of the test
job. Raise it in the change that raises the coverage. Never lower it. To
read the total, run these lines in `vca/`:

```sh
go test -race -count=1 -covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./...
grep -vE '/(gen|cmd)/|/ui/example/' coverage.out > coverage-gated.out
go tool cover -func=coverage-gated.out | tail -1
```

Round the total down to one decimal, and set `COVERAGE_FLOOR` to that
value. The floor was 95.6 when the ratchet started.

### SonarCloud

The analysis root is `vca/`. The configuration is
`vca/sonar-project.properties`. The scan reads three reports from the
other jobs: `coverage.out`, `test-output.txt` and
`golangci-lint-report.xml`. The quality gate step waits for the result
and blocks the merge when the gate fails.

The owner must do these steps once, before the job can pass:

1. Create the project `centre-for-dpi_verifiably_vca` in the organisation
   `centre-for-dpi` in SonarCloud. It is separate from
   `centre-for-dpi_verifiably`, the project of `verifiably-go/`.
2. Turn Automatic Analysis off for the project (Administration, Analysis
   Method). Automatic Analysis cannot read the Go coverage report.
3. Set the main branch of the project to `vc-adapter` (Administration,
   Branches and Pull Requests, rename the main branch). A new project
   names its main branch `master`. Until the rename, the scan treats
   `vc-adapter` as a short lived branch. The log then says "Could not
   find ref 'master'". Such a branch has no reference for new code, so
   the gate reads the whole tree as new code. After the merge, set the
   main branch to `main`.
4. Keep the quality gate "Sonar way" on new code, or set a stricter one.
5. Give the organisation a plan that covers the size of `vca/`. The free
   plan allows 50 000 lines of code for the whole organisation, and the
   first analysis counted 120 114 for `vca/` (Go 116 970). Until then the
   background task of every analysis fails at the limit, so the job runs
   with `continue-on-error` and reports only. Once the plan covers it,
   remove that line from the job and the suffix of its name, so the gate
   blocks again.

The scan job trims the coverage report to the analysed code before the
scan. The full report covers every package and exceeds 20 MB. The
scanner drops a source file of that size and warns once per generated
file.

The repository secret `SONAR_TOKEN` already exists. If the token is a
project analysis token, give it access to the new project too. Until the
project exists, the SonarCloud job fails, and the merge stays blocked.
A pull request from a fork gets no secret, so the job skips it.

### Trivy

The trivy job scans `vca/` for vulnerable modules, secrets and Dockerfile
misconfigurations and blocks on HIGH and CRITICAL. `vca/.trivyignore.yaml`
holds the accepted findings. Each entry names its files and its reason;
a finding in any other file still fails. Today it holds one check,
DS-0031, for four Dockerfiles whose ENV names carry the words AUTH or
TOKEN. Those ENV set a listen address and a state directory, not a
secret. The release workflow scans each image for vulnerabilities and
secrets only; the Dockerfile checks run once, on the files.

### gosec

The gosec job runs gosec v2.29.0 from `vca/`, with `-no-fail`. It leaves
out rule G104, because errcheck in golangci-lint covers it. It also
leaves out generated files, as `vca/.golangci.yml` does. The job sends
the SARIF file to the Security tab, category `gosec-vca`. A pull request
from a fork has a read only token, so the job skips the upload there. To
move gosec to a new release, change the version in the step. Read the
tags with `git ls-remote --tags https://github.com/securego/gosec.git`.

## The walkthrough

`vca/services/walkthrough` runs a whole deployment in one Go test
(P7-05). The test builds the command of each service into the user
cache. It then starts the four pairs of one DPG and the landing as
processes. `vca setup` writes the settings of each pair, as on a host.
The test points each compose address at the loopback address. A small
proxy in front of each pair follows the routes of its `Caddyfile`. Test
doubles stand in for the identity provider and for the DPG.

The test acts as each person at a browser. It follows each sign in,
fills each form, and checks every page with `a11ytest.AssertPage`.

| Test | Path |
| --- | --- |
| `TestWalkthroughWaltid` | The staff makes a walt.id identity, publishes a schema, and issues. The holder loads the credential into the browser store. A check names the issuer untrusted. The admin approves the issuer, and a DCQL request gets a valid verdict. |
| `TestWalkthroughCredebl` | The same path on CREDEBL. The operator made the DID, and the admin adds the trust entry. A revocation through the platform turns the verdict to invalid. |
| `TestWalletScriptInChromium` | The walt.id path in a real browser. Chromium claims the offer, and `wallet.js` makes its key in IndexedDB and signs the proof. Chromium answers the request, `wallet.js` signs the key binding, and the verifier reads a valid answer. |

The package runs in about ten seconds with the race detector. The first
run builds the commands, so it takes longer. The test runs on Linux and
macOS.

`TestWalletScriptInChromium` runs when the environment names `VCA_PLAYWRIGHT`. It runs
`testdata/wallet_e2e.cjs` with node, once to claim and once to present.
Both runs share one browser profile, so the key of the browser stays.
The job of vca-ci installs Playwright with Chromium and sets the
variable.
The test finds Chromium in the directory of `PLAYWRIGHT_BROWSERS_PATH`,
else in the default cache of Playwright, `~/.cache/ms-playwright`.
It hands that directory to node.
A skip names the variable that is missing: `VCA_PLAYWRIGHT`,
`PLAYWRIGHT_BROWSERS_PATH`, or `PATH` for node.
To run it on a machine that has both:

```sh
cd vca
NODE_PATH=<the node_modules that hold playwright> \
  PLAYWRIGHT_BROWSERS_PATH=<the directory of the browsers> \
  VCA_PLAYWRIGHT=1 go test -run TestWalletScriptInChromium ./services/walkthrough/
```

No axe-core check runs yet. The package is not in the offline
toolchain of the build machine. Each page of the walkthroughs passes
`a11ytest.AssertPage` instead.

The time limit of a walk starts after the build. A loaded machine can
spend most of a minute on the build. A limit that counted the build
stopped the services in the middle of a walk. The proxy of a pair then
read an unexpected EOF. The errors of each proxy now join the failure
report, beside the output of each service.

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
| contract tests (real DPGs) | Runs contract tests against real DPG containers named in the repository variable `VCA_CONTRACT_DPGS`. With no names, prints a message and passes. The job writes the marker of a test deployment first. | `vca/hack/contract-tests.sh` |
| helm render + kind deploy | Creates a kind cluster, lints, renders and installs every chart under `deploy/vca/helm/*`, and waits for the deployments. With no charts, prints a notice and passes. | `vca/hack/k8s-smoke.sh` |

A nightly failure does not block a merge. It shows on the Actions page.
The team must fix it before the next release.

## Pinned actions

Every action of `vca-ci.yml`, `vca-release.yml`, and `vca-nightly.yml`
runs at a full commit SHA, with the version of its tag in a comment.
`TestEveryWorkflowActionIsPinnedToACommit` fails on any other `uses:`
line. To move an action, read the commit of the new tag with
`git ls-remote https://github.com/<owner>/<action> 'refs/tags/<tag>*'`.
An annotated tag lists its commit on the line that ends in `^{}`.
Do not use `@master`, `@main`, or a bare tag.

## Scripts in `vca/hack/`

| Script | Purpose |
| --- | --- |
| `bootstrap.sh` | Installs buf from its release with a SHA-256 check, and the buf plugins, with mirrors on a restricted network |
| `coverage.sh <floor>` | Fails when a package is below the floor; `core/...` must be 100 |
| `check-commits.sh <range>` | Validates commit subjects in a git range |
| `check-commits_test.sh` | Tests `check-commits.sh` with good and bad subjects |
| `contract-tests_test.sh` | Tests that `contract-tests.sh` refuses a deployment without the marker or with sample data |
| `release-notes.sh <from> <to> [version]` | Writes a CHANGELOG section from Conventional Commits |
| `contract-tests.sh` | Runs contract tests for the DPGs in `VCA_CONTRACT_DPGS`, and makes the Inji test holder when the job gives none. It runs only on a test deployment whose deploy root holds `contract.env` |
| `k8s-smoke.sh` | Deploys the Helm charts into the current cluster and waits |
