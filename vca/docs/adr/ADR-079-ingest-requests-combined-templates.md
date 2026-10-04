## ADR-079: The ingestion service requests and evaluates combined templates
- Status: Proposed
- Owner: CDPI Architects
- Scope: `CreateOid4vpRequest` of the ingestion service, the request pages, the combined query pages of the discovery service, and the `Update` RPC of `vca.combined.v1.CombinedService`.
- Extends: ADR-023, ADR-026, ADR-078. Follows consequence 2 of ADR-078, which left `BuildDcql` and `EvaluateCombined` with no caller.
- Decision:
  1. `TEMPLATE_KIND_COMBINED` of the discovery contract names a combined template of the combined service. The discovery service stores no template of that kind. `CreateOid4vpRequest` takes the kind in `template_kind`.
  2. A request of a combined template calls `BuildDcql`. It sends the merged query through the VCA verifier or a stack that reads it. The answer goes to `EvaluateCombined`, which stores the result. The transaction keeps the result id and reports the kind.
  3. `Update` of the combined service replaces the name, the members, the rules, and the policy set of a stored template. The id, the tenant, and the creation time stay.
  4. The discovery service serves the combined query pages: list, create, edit, and delete. They show only when the own pair lists `verifier-combined` in its peer list and runs. The side navigation gates the page on the same rule. The request page offers each combined template next to the saved queries.
  5. The catalogue lists `verifier-discovery` and `verifier-ingest` as callers of the combined service, next to `cli`.
- Consequences:
  1. Staff build, send, and read a combined request in the portal. Before this record, only the vca command stored a combined template. No page sent one.
  2. The combined service runs the policy set on each credential. So the ingestion service runs no single evaluation for such a request.
  3. A stack that reads PE only takes a combined request when the PE form of the merged query loses nothing.
  4. The navigation table can gate a page on a service of the own pair. A page that needs another service of the pair uses the same rule.
