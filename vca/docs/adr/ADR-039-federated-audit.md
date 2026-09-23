## ADR-039: Federated audit log
- Status: Proposed
- Owner: CDPI Architects
- Scope: Events across services.
- Extends: ADR-009 decision 6, ADR-017 decision 1.
- Decision:
  1. A new `vca.audit.v1.AuditService` with one `Query` RPC. The auth services, `issuance`, `issued-credentials`, `trust-registry`, `verifier-results`, and `admin` record events in an append only store and serve it.
  2. The admin audit page queries every live peer with the admin session token and merges the answers in time order. The page names each peer that does not answer.
  3. Events carry actor, action, target, result, request id, service, and pair. They carry no claim values.
- Consequences:
  1. Sign ins, trust changes, issuance, and verification show on one page.
  2. No service reads another service's store.
