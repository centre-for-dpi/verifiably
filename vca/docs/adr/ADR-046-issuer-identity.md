## ADR-046: Issuer identity through the DPG
- Status: Proposed
- Owner: CDPI Architects
- Scope: Issuer keys, identifiers, and metadata.
- Extends: ADR-001 decision 3, ADR-011 decision 6.
- Decision:
  1. `IssuerBackendService` gains `GetIssuerIdentity`, `ProvisionIssuerIdentity`, and `ImportIssuerIdentity`.
  2. One click asks the DPG to make a key and an identifier. Import takes a DID or an X.509 chain with a key reference in the DPG key store.
  3. The identity page can ask the trust registry for an entry in state `pending`. An admin approves it.
  4. VCA never stores an issuer private key. The walt.id community release needs the key in each request. That key stays in the adapter state file with mode 0600. It stays there until an operator sets an external key store.
- Consequences:
  1. An issuer starts in one click or with its own PKI.
  2. The trust list gains a review step.
