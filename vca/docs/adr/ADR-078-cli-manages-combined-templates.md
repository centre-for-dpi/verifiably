## ADR-078: The vca command manages the combined templates of a verifier pair
- Status: Proposed
- Owner: CDPI Architects
- Scope: The `vca combined` command and the callers of `vca.combined.v1.CombinedService`.
- Extends: ADR-026, ADR-075 decision 4. Follows the security review of 2026-10-04, which found the combined service with no caller.
- Decision:
  1. `vca combined list`, `create` and `delete` call the combined service of a verifier pair. They reach it on its host port. `create` reads one `CombinedTemplate` in the JSON form of the proto API.
  2. The command signs each call with its identity of the deployment. So the catalogue lists the caller `cli` for the combined service. No other service calls it yet.
- Consequences:
  1. An operator can store, list and remove combined templates. Before this record, no workflow could store one.
  2. `EvaluateCombined` and `BuildDcql` still have no caller. The ingestion service is their planned caller (ADR-023), in a later record.
  3. The combined service stays on the compose network. No party outside the host calls it.
