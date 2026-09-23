## ADR-036: Verifier staff sign in
- Status: Proposed
- Owner: CDPI Architects
- Scope: Sessions on the verifier staff pages.
- Extends: ADR-025, ADR-022 decision 2.
- Decision:
  1. A `verifier-auth` service runs in every verifier pair. It shares the flow code of `services/internal/oidcflow` with `issuer-auth`. Its audience is `vca-verifier` and its roles are `verifier-admin`, `verifier-operator`, and `verifier-viewer`.
  2. Staff pages of `verifier-results`, `verifier-discovery`, and `verifier-ingest` need a session. The citizen check, the catalogue, and the OID4VP endpoints stay public.
  3. Issuer staff pages get the same guard against `issuer-auth`.
- Consequences:
  1. No staff page is open on a public host.
  2. One more service per verifier pair, 96 MiB.
