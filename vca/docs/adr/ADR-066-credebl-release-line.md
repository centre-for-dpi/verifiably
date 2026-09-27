## ADR-066: The CREDEBL stack runs one release line of the platform
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL stack file, the CREDEBL adapter, and the deploy document.
- Extends: ADR-008 decision 3, ADR-045 decision 4. Replaces the rule of P6-C0 that pinned the digest that `latest` named.
- Decision:
  1. Every platform image of the stack file comes from the release line `v2.2.1`, pinned by the digest of its release tag. An image that the release did not build again carries the newest tag of the same line.
  2. The stack file does not follow `latest`. On 2026-09-27 `latest` named the `v2.1.3` hotfix line for most images, and the newest `v2.2.1` tag for the others.
  3. The adapter reports the release tag and the digest of the API gateway. A test binds the adapter and the stack file. A test checks that every platform image carries a tag of the line.
- Consequences:
  1. The API gateway routes the ecosystem, OpenID for Verifiable Credentials and X.509 calls that the adapter makes. The seed makes the tables of those services.
  2. The seed reads the master table at the path where setup mounts it, so the generated credentials take effect.
  3. A move to another release is one change of the stack file and of the adapter, with this record superseded.
