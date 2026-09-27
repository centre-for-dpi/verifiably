## ADR-071: A verifier checks a status list with the key set under its address
- Status: Proposed
- Owner: CDPI Architects
- Scope: The status check of `core/policy`, the trust cache of the verifier policy service, and the status services of an issuer pair.
- Extends: ADR-018 decision 6, ADR-019, ADR-024 decision 3, ADR-041 decision 1. Found by the walkthrough of P7-05.
- Decision:
  1. The status check tests the signature of a status list with the keys of the credential issuer first. A stack such as CREDEBL signs its lists with the key of the issuer, so nothing changes for it.
  2. A status service of VCA signs the lists of an issuer whose key sits in a DPG, such as walt.id. The key of the issuer cannot check such a list. The service publishes its key set under the list address: `<base>/.well-known/jwks.json` for a list at `<base>/status/<id>`. The issuer names the list address in the signed credential. The check then tests the list with that key set.
  3. The evidence of the check names the key set that passed. It says `valid` for the keys of the issuer. It says `valid, key set of the list` for the key set under the list address. A list that neither key set passes fails the check.
  4. The trust cache reads the key of a `did:key` or a `did:jwk` issuer from the DID itself. It then keeps the status lists that such an issuer signs.
- Consequences:
  1. A walt.id credential with a status entry of VCA passes the status check of the VCA verifier.
  2. The trust in the list rests on the issuer signature over the list address. An unsigned bitstring list, which the check already reads, rests on the same address.
  3. A status service of VCA on another address needs a new record.
