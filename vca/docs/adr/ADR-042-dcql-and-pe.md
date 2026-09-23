## ADR-042: DCQL builder and DIF Presentation Exchange queries
- Status: Proposed
- Owner: CDPI Architects
- Scope: Query authoring in `verifier-discovery`.
- Extends: ADR-022 decision 3, ADR-026 decision 1.
- Decision:
  1. A template has a kind: DCQL, PE, or a stack native proof request.
  2. The DCQL builder edits credential queries, claim paths, claim values, claim sets, and credential sets, with a live query view.
  3. Constraints that DCQL cannot express, for example a date range, become rules of a new `claim_predicate` policy check.
  4. Staff author and import PE definitions. The service validates them against PE 2.0. It converts them to and from DCQL where the conversion loses nothing. A lossy conversion names the lost parts.
  5. A pure package `core/pex` holds validation and conversion.
- Consequences:
  1. Staff build a request without JSON.
  2. Stacks that read PE only still get requests.
