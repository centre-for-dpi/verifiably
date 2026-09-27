## ADR-062: The DIDComm holder wallet of a CREDEBL stack
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, the CREDEBL adapter, the wallet portal and its pages, and `vca setup`.
- Extends: ADR-020 decision 3, ADR-021 decisions 3 and 5, ADR-034 decision 5, ADR-055 decision 1, ADR-059, ADR-061.
- Decision:
  1. The CREDEBL adapter serves the holder role with one tenant wallet per holder. The tenants live in the shared Credo agent of the stack. The adapter calls the multi-tenancy API of the agent with the agent API key. It does not call the cloud wallet service of the platform. That pinned service reads the agent with a call that the pinned agent refuses. Its proof paths hold a stray brace. Its holder account needs a mail check and a Keycloak user role.
  2. `Register` maps the hashed pairwise subject of ADR-020 onto a tenant. The adapter store keeps the subject hash and the tenant id only. No holder password exists. The agent signs the tenant token with its own secret. Setup generates the API key of the agent (ADR-055 decision 1). `Register` makes a `did:key` for a new tenant and returns it.
  3. An adapter whose wallet speaks DIDComm lists `FEATURE_WALLET_DIDCOMM`. `AcceptOffer` then takes an out of band invitation that carries a credential offer. `Present` takes one that carries a proof request. `OpenInvitation` opens an invitation that carries neither and keeps the connection. `ListInbox` lists the offers and the proof requests that came over a connection. `AcceptOffer` and `Present` take the id of an inbox entry. `ListWalletConnections` lists the connections.
  4. The wallet portal reads a scanned invitation and shows what it carries. That is the values of an offer, or the attributes and the predicates of a proof request. The wallet receives the invitation only after the holder accepts. A decline forgets the invitation and sends nothing, because the agent has no decline call. The page "Connections" lists the inbox and the connections.
  5. The adapter lists an AnonCreds credential from its finished exchange as the JSON view of ADR-061 decision 3. It lists a W3C credential as the agent keeps it. The agent removes a W3C credential and cannot remove an AnonCreds credential. `WalletCredential.permanent` marks such a credential, and the wallet portal offers no remove button for it.
  6. The keys page shows with `FEATURE_WALLET_DIDS`. It lists keys and makes a key only with `FEATURE_WALLET_KEYS`. It offers a default DID only with `FEATURE_WALLET_DEFAULT_DID`. The CREDEBL adapter lists the DIDs of the tenant and makes a `did:key`.
  7. The adapter answer lists `ROLE_HOLDER` only when the adapter has the agent URL and the agent API key. `vca setup` writes both into the `.env` of a CREDEBL holder pair. The holder pair runs no extra service, so the memory floor does not change.
- Consequences:
  1. A citizen holds AnonCreds and W3C JSON-LD credentials from a CREDEBL issuer. The citizen answers a DIDComm proof request from the pages of VCA.
  2. The holder sees an offer or a request before the wallet contacts the other party.
  3. The pinned agent has no basic message call, so VCA offers no basic messages.
