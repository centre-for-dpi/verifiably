## ADR-044: Placement of the role pages
- Status: Proposed
- Owner: CDPI Architects
- Scope: Which service serves which page.
- Extends: ADR-013 decision 6, ADR-017 decision 3, ADR-023, ADR-025.
- Decision:
  1. The issuer home moves to `issuance` at `/issuer/`. `issuance` also serves `/identity/`, `/issue/`, `/notifications/`, and `/help/`.
  2. `issued-credentials` serves `/issued/`. `data-source` serves `/sources/`.
  3. The verifier home stays on `verifier-results` at `/portal/`, with results at `/portal/results/` and caching at `/portal/cache/`.
  4. `verifier-discovery` serves `/discovery/dcql/` and `/discovery/pe/`. `verifier-ingest` serves `/scan/request/` and `/scan/requests/`.
  5. One package, `vca/internal/rolenav`, lists the pages per role. A CLI test binds it to the route table.
- Consequences:
  1. Each page sits with the service that owns its RPCs.
  2. The side navigation and the route table cannot drift.
