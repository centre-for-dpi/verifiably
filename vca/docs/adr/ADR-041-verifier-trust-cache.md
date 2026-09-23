## ADR-041: Verifier trust cache and offline verification window
- Status: Proposed
- Owner: CDPI Architects
- Scope: Offline checks in `verifier-policy`.
- Extends: ADR-011 decision 7, ADR-024 decision 3.
- Decision:
  1. `verifier-policy` keeps signature checked snapshots of the trust lists, the registry keys (DID documents, JWKS, X.509 chains), and the status lists.
  2. A schedule refreshes each source: trust lists every 6 h, keys every 24 h, status lists every hour, by default.
  3. A policy allows verification with no network for a window of at most 7 days after the last sync. A result that used cached material carries the material age.
  4. A status list older than the window makes the status check fail when the policy says so.
  5. `PolicyService` gains `GetCacheState`, `SyncCache`, and `SetCachePolicy`. The verifier portal shows them on a caching page.
- Consequences:
  1. A verifier works in a place with no network for a known time.
  2. Staff see how old the material is.
