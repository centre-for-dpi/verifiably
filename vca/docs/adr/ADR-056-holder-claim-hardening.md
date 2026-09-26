## ADR-056: The claims store and the holder authorization server refuse what a claim did not stage
- Status: Proposed
- Owner: CDPI Architects
- Scope: The Certify templates of the Inji adapter, the VCA claims store, and the holder authorization server of the adapter.
- Extends: ADR-051 decisions 2 and 3, ADR-052 decisions 3, 4 and 6.
- Decision:
  1. Every template that the adapter registers opens with a guard on the column `config_id` of the row. The body renders only when the row holds the id of that configuration. The shared scope `vca_credential` stays, so a new schema still needs no restart of Certify.
  2. A binding rule and a sign in source match only a claim that the provider vouches for. These are `email` with `email_verified` true, `phone_number` with `phone_number_verified` true, and `sub`. A provider record can list more claims in `verified_claims`. The holder realm of the Inji stack verifies email.
  3. A claims row of the holder authorization server lives as long as its code and its token. The query of Certify reads only a row whose `expires_at` lies ahead.
  4. The adapter deletes the claims of an offer when the holder gets the token or when the offer expires. A code that fails before any token reopens its offer.
  5. The authorization server bounds every parameter before it writes a record. It limits the requests of each source, and no request walks the store.
  6. The token key is a key ring. A rotation publishes the next key first and signs with it after the key set cache of Certify ends. `vca dpg rotate-authz-key inji` starts it.
  7. A claim value holds valid UTF-8. It holds no control character except a tab, a line feed or a carriage return.
- Consequences:
  1. A token for the row of one configuration gives no credential of another. The guard relies on Certify 0.14.0, which passes the row columns to Velocity 1.7 and fails on an empty render. A new Certify release needs the same check. A template from an earlier release, or one that an operator edits in Certify, has no guard. So publish every schema again after the upgrade. Certify signs the identity QR code of the requested configuration before the credential fails. It returns neither. Scopes per configuration stay the fallback if a release breaks the guard.
  2. A user name or an attribute that a person picks at a provider claims no offer of another person. With the stack Keycloak, the realm needs a mail server before a self registered holder can claim.
  3. A row serves a credential request for five minutes at most after its token. Certify does not tell the adapter that it issued. So a row can serve more than one request in that time.
  4. A copy of the adapter volume holds no subject of an old offer. The issuer sees an offer that a stolen code closed open again.
  5. A flood of requests fills neither the volume nor the memory of the adapter.
  6. A compromised token key goes without a restart. An immediate rotation makes Certify refuse new tokens until its key set cache ends.
  7. One bad value cannot stop the foreign table for every holder.
