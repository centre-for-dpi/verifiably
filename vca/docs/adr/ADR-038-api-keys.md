## ADR-038: API keys for VCA and for stacks
- Status: Proposed
- Owner: CDPI Architects
- Scope: Machine access.
- Extends: ADR-012 decision 4.
- Decision:
  1. VCA API keys keep their current model and gain a tenant scope and an expiry in the form.
  2. Stack client credentials of a DPG tenant appear next to them when the adapter lists `FEATURE_TENANT_CLIENT_CREDENTIALS`. A secret shows once.
- Consequences:
  1. One page answers "which machine can call what".
