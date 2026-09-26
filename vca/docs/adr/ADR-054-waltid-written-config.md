## ADR-054: VCA writes the walt.id catalogue and wallet configuration
- Status: Proposed
- Owner: CDPI Architects
- Scope: The walt.id issuer API and wallet API containers, setup, and the walt.id adapter.
- Extends: ADR-002 decision 4, ADR-008 decision 3, ADR-046 decision 4.
- Decision:
  1. Setup writes `credential-issuer-metadata.conf` for the issuer API with one entry per wire format under a VCA name and no demo type.
  2. The walt.id adapter borrows only those entries and answers every catalogue and discovery call from its own registrations.
  3. Setup writes the wallet API configuration. It holds generated keys, a generated pepper and the database password of the stack. It has no default issuer, and developer mode is off.
  4. The adapter still writes no configuration file and restarts no container. The CLI does both.
- Consequences:
  1. No page of VCA shows a credential type the operator did not publish.
  2. A wallet session token of one deployment is worthless on another.
  3. The nightly contract run must start the wallet API on the mounted files.
