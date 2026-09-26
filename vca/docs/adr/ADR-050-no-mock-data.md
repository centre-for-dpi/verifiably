## ADR-050: No mock or sample data in anything VCA ships or deploys
- Status: Proposed
- Owner: CDPI Architects
- Scope: `vca/`, `deploy/`, every image, chart, setup and bootstrap output, and every document that tells an operator what to run.
- Extends: ADR-004 decision 1, ADR-029 decision 6.
- Decision:
  1. VCA ships no mock image, mock identity system, mock issuer, mock credential, sample data set or seed identity. A deployment starts with no row the operator did not put there.
  2. A workflow the operator configures against their own systems replaces each such artefact. The portal shows that configuration.
  3. Test doubles live in `_test.go` files, `testdata/` folders and `internal/fake` packages that no service binary imports. A deployment file never names them.
  4. A guard test under `vca/internal/cli` scans the tree for named artefacts. It also scans deployment files for the words mock, dummy, fake, sample, seed and demo. Its allowlist names each exception with a reason.
  5. A stack secret has no default. Setup generates it or the operator supplies it.
- Consequences:
  1. The first issuance of a fresh deployment needs an issuer who published a schema and typed or uploaded subject data.
  2. Upstream compose folders remain a source of layout, never of data.
  3. The guard blocks a commit that brings a sample back.
