## ADR-072: An offer names the status entry its credential carries
- Status: Proposed
- Owner: CDPI Architects
- Scope: `CreateOfferResponse` and `StatusListBinding` of the backend contract, the issuance service, the issued credentials service, and the three DPG adapters.
- Extends: ADR-017 decision 3, ADR-018, ADR-019, ADR-034 decision 5, ADR-069 decision 4. Found by a review of the CREDEBL walkthrough.
- Decision:
  1. `CreateOfferResponse` names the status entry that the credential of the offer carries. An adapter whose DPG embeds the entry of the spec returns that entry. An adapter whose DPG writes an entry of its own list returns that entry with `dpg_list` set. It puts the id that `Revoke` takes in `credential_id`. An empty entry means the credential carries none.
  2. The issuance service allocates an index of VCA only for a list kind in `status_mechanisms` of the adapter. It records the entry that the answer names, and the `credential_id` as `dpg_credential_id`. An offer whose answer names no entry gets a record with no entry.
  3. The issued credentials service sends every change of an entry with `dpg_list` to `Revoke` of the adapter. When the adapter lists no feature for the change, the service refuses it. It never changes such an entry in a status service of VCA.
  4. The record page of an issued credential names the list that holds the status: the list of the stack, or a status service of VCA. It offers only the changes that the holder of the list can make.
- Consequences:
  1. A revoke of a CREDEBL credential reaches the list that its verifier reads. Before, the service flipped a bit in a VCA list that the credential never named.
  2. A CREDEBL stack without the status list host issues credentials that no list can revoke, and the record says so.
  3. An mdoc of walt.id and a credential body of the caller carry no entry, so their records name none.
