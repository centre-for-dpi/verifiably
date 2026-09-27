## ADR-061: DIDComm proof requests and the AnonCreds proof request builder
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, the verifier discovery service, the verifier ingest service and its pages, and the CREDEBL adapter.
- Extends: ADR-042 decisions 1 and 4, ADR-045 decisions 1 and 2, ADR-024 decision 2.
- Decision:
  1. An adapter that asks for a proof over DIDComm lists `PROTOCOL_DIDCOMM_PRESENT_V2`. `CreateRequest` with `didcomm` or `anoncreds_request` makes an out of band invitation that carries the proof request. With a `connection_id` it sends the request over a connection of the verifier instead. The state of the answer names the proof exchange. `ListVerifierConnections` lists the connections, and `ListProofRequests` lists the proof requests of the stack.
  2. An adapter that asks for an AnonCreds proof with predicates lists `FEATURE_ANONCREDS_PROOF` and serves `ListProofSchemas`. The request is the proof request of the AnonCreds specification. A schema id and a credential definition id restrict each attribute group and each predicate.
  3. The stack verifies a DIDComm proof. `GetResult` then answers accepted with the check of the stack. It returns one JSON view of the revealed values per credential: the schema, the issuer, the credential definition, and the values under `credentialSubject`, with no proof. A proof that fails the check, and a request that the holder declines, answer rejected with no view. The policy checks of VCA run on the view, and the signature check skips it.
  4. A template of the kind native holds an AnonCreds proof request. The discovery service validates it. The AnonCreds builder shows only when a live verifier stack lists `FEATURE_ANONCREDS_PROOF`. It offers the schemas of `ListProofSchemas`.
  5. The request page offers "<stack>, DIDComm proof request" for a stack that lists `PROTOCOL_DIDCOMM_PRESENT_V2`. The stack reads AnonCreds templates, PE templates, and DCQL templates with a lossless PE form. The delivery "Connected wallet" sends the request over a connection of that stack. The request list shows the proof requests of each such stack.
  6. The platform needs the schema of each PE input descriptor. The CREDEBL adapter reads it from the filter on the credential type.
- Consequences:
  1. A verifier asks a DIDComm wallet for an AnonCreds or a PE proof from the pages of VCA.
  2. A verifier proves an age or an amount without the value of the holder.
  3. VCA shows what the stack verified. It does not check an AnonCreds proof again.
