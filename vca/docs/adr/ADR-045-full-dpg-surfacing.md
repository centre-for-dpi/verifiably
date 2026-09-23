## ADR-045: Full DPG surfacing
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract.
- Extends: ADR-002 decision 2, ADR-003 decision 6, ADR-016 decision 6.
- Decision:
  1. Each adapter implements every feature its pinned DPG release has, and lists it in the `GetCapabilities` answer.
  2. The `Format` enum gains `FORMAT_ANONCREDS`. The `Protocol` enum gains DIDComm issue and present protocols and the Digital Credentials API. The `Channel` enum gains `CHANNEL_DC_API`, `CHANNEL_DIDCOMM_OOB`, and `CHANNEL_CLAIM169_QR`.
  3. The holder role uses the DPG wallet where one exists: walt.id wallet API, Inji Web through Mimoto, CREDEBL cloud wallet. The browser store stays for a holder with no DPG wallet.
  4. The CREDEBL stack file runs the whole platform, pinned by digest.
  5. The walt.id stack adds `verifier-api2` of the same release.
- Consequences:
  1. The UI hides nothing a DPG can do.
  2. The CREDEBL floor rises above the 4 GB target of ADR-008 decision 7. `vca doctor` reports it.
  3. The contract grows by one protocol family.
