## ADR-069: The CREDEBL stack runs the status list host of the platform
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL stack file, setup and doctor, the CREDEBL adapter, and the issued credentials pages.
- Extends: ADR-008 decision 3, ADR-034 decision 5, ADR-066. Closes the P6-C5b row of the plan.
- Decision:
  1. The stack file runs the status list host that the pinned platform names as `STATUS_LIST_HOST` and the pinned agent as `STATUS_LIST_SERVER_URL`. CREDEBL publishes no image of it. Compose builds it from the repository of its authors at one commit. The build repeats the Dockerfile of that commit with its base image pinned by digest.
  2. The platform and the agent reach the host on one address. The agent writes that address into each revocable credential. On a public host the operator sets it to the public address and publishes only the reads of the lists.
  3. Setup generates the API key that guards the writes of the host. It tells the adapter of an issuer pair that the stack runs the host.
  4. The adapter then asks for a revocable offer and lists `FEATURE_REVOCATION`. `Revoke` calls the revoke route of the platform with the issuance session. The agent sets a bit and clears none, so the adapter lists no suspension.
  5. The issued list reads the Token Status List entry of each credential from its session. A record from the ledger of a stack that lists a change offers only the changes the stack lists.
- Consequences:
  1. The first start of a CREDEBL pair needs access to GitHub and to the registry of the base image.
  2. The DPG floor of CREDEBL rises by 64 MiB. The doctor checks host port 17183.
  3. An image of the host from CREDEBL replaces decision 1 through a new record.
  4. A DIDComm credential of the stack stays without revocation, since its credential definition has no revocation registry.
