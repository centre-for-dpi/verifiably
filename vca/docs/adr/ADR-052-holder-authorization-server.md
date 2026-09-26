## ADR-052: The holder authorization server of the Inji adapter
- Status: Proposed
- Owner: CDPI Architects
- Scope: The authorization code channel of the Inji issuer pair, Inji Web and every OID4VCI wallet that claims from it.
- Extends: ADR-035 decision 2, ADR-043 decision 1, ADR-047 decision 4.
- Decision:
  1. The Inji adapter is an OAuth 2.0 authorization server for the authorization code grant under `/authz` of its public URL. It publishes RFC 8414 metadata and a JWKS.
  2. It signs the holder in at the enabled holder provider of the stack from the shared provider registry. The setup seed is the holder realm of the stack Keycloak. The admin can replace it with any OIDC provider, including an eSignet with a real authenticator.
  3. A request with an offer id issues the claims of that offer. The binding rule of the issuer must first match an ID token claim. A request without an offer uses the holder sign in source of the configuration. That source returns the claims for the ID token claim. No source means no credential.
  4. The token is a JWT whose subject is the staging id of the claims row. Certify checks it against the JWKS of the adapter.
  5. Wallet clients register with their redirect URIs. A public client uses PKCE. `vca-inji` of Inji Web uses `private_key_jwt` with the key the holder bootstrap wrote.
  6. The token key signs access tokens only. The adapters still hold no issuer key.
- Consequences:
  1. The authorization code flow of the Inji issuer works on a fresh deployment. It needs the stack Keycloak and no other system.
  2. The adapter keeps a token key, a client list and short lived codes in its store.
  3. Inji Web and Mimoto need no change. Their issuer list names the adapter.
