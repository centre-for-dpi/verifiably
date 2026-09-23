## ADR-037: Tenants mapped to DPG tenancy
- Status: Proposed
- Owner: CDPI Architects
- Scope: The tenant record of the admin service.
- Extends: ADR-009 decision 1.
- Decision:
  1. A VCA tenant binds to zero or more DPG tenants, one per stack.
  2. A new `TenantBackendService` in `backend.proto` creates, lists, reads, and deletes DPG tenants and their client credentials. An adapter implements it only when its DPG has tenancy.
  3. The tenant page offers a stack only when its adapter lists `FEATURE_MULTI_TENANCY`.
- Consequences:
  1. CREDEBL organisations become visible and manageable.
  2. Stacks with no tenancy show no tenancy control.
