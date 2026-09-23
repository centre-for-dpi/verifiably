## ADR-034: Backend adaptivity through a peer topology and feature lists
- Status: Proposed
- Owner: CDPI Architects
- Scope: How every page learns what runs.
- Extends: ADR-002 decision 2, ADR-016 decision 6.
- Decision:
  1. The CLI writes `VCA_PEERS` into every UI service and the landing: all twelve candidate pairs, each with its public URL and the internal URL of each of its services.
  2. A shared package probes `/readyz` of each candidate and `GetCapabilities` of its adapter in parallel. The probe has a 1 s timeout and a 15 s cache.
  3. A candidate whose host does not resolve is absent and hidden. A candidate that resolves but is not ready shows "Starting". Only a ready pair is live.
  4. `GetCapabilitiesResponse` gains a feature list, the DID methods, the status mechanisms, and `DpgInfo` with components, versions, and links.
  5. A page shows a feature on a stack only when the live adapter lists it. No page labels a DPG feature as "soon".
- Consequences:
  1. One role on one DPG shows only that pair.
  2. A new adapter feature appears in the UI without a UI release.
  3. The probe adds about 12 small requests every 15 s per UI service.
