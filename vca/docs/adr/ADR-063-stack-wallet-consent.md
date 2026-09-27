## ADR-063: The consent of a stack wallet that picks the claims itself
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, the CREDEBL adapter, and the wallet portal.
- Extends: ADR-021 decision 5, ADR-062 decision 8.
- Decision:
  1. An adapter whose wallet answers an OID4VP request with every claim of each query lists `FEATURE_WALLET_WHOLE_QUERY`. The consent screen of the wallet portal then marks every requested claim as required. `Present` reads what the wallet sends before it answers. It refuses with `FailedPrecondition` when `disclosed_claims` leave out a claim that the wallet sends. `shared_claims` name what the wallet sends, and the presentation history records them.
  2. The wallet portal hands a stack wallet a request by reference only. A request that came by value stays with the browser store. Through a stack wallet the portal refuses it with a reason. The stack wallet never reads the `response_uri` of the verifier as a request.
  3. The CREDEBL agent fetches the `request_uri` again for the answer. The adapter reads the request once to check the consent and the agent reads it again to answer. Only a verifier on the request host allowlist of the portal reaches that step. The allowlist is the control until the agent answers a request by the id of the resolved request.
- Consequences:
  1. The history of a holder never names fewer claims than the stack sent.
  2. A holder who wants to leave a claim out declines the request of a stack wallet.
  3. A verifier on the allowlist can serve a wider query on the second fetch. The adapter refuses a pick of another credential, but not a wider claim set.
