## ADR-065: The Indy networks of a CREDEBL stack are a setting of the operator
- Status: Proposed
- Owner: CDPI Architects
- Scope: `vca setup`, the CREDEBL stack file, and the master table of the CREDEBL initialisation.
- Extends: ADR-050 decision 1, ADR-055 decisions 1 and 4, ADR-058.
- Decision:
  1. `VCA_CREDEBL_INDY_LEDGERS` names the Indy networks of a CREDEBL stack. Every CREDEBL pair but the admin one needs it, and it has no default. It takes `bcovrin:testnet`, `indicio:testnet`, `indicio:demonet` and `indicio:mainnet`.
  2. Setup writes the configuration of the shared agent with those networks alone into `deploy/credebl/credebl-agent.json`. The stack file mounts that file. The repository holds no agent file with a list of ledgers.
  3. The master table marks those networks active and every other ledger inactive. The row `no_ledger` stays active for `did:key` and `did:web`. The Polygon rows stay inactive, because the stack sets no funded key and no RPC address for them.
  4. A run that knows no network writes no agent file. The pinned agent falls back to the BCovrin test network when its file names none. So the stack never runs without the list of the operator.
- Consequences:
  1. A fresh deployment writes no DID on a public test network that the operator did not pick.
  2. A change of the networks needs a new setup run. The platform database keeps the ledgers of its first initialisation.
