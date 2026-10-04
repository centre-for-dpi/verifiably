## ADR-082: The browser store claims with the authorization code flow
- Status: Proposed
- Owner: CDPI Architects
- Scope: The wallet portal and its claim and offer pages. The messages `ClaimRequest`, `ClaimCompleteResponse` and `OfferSummary`. The laptop settings of the wallet, and the wallet client of the Inji holder authorization server.
- Extends: ADR-021 decision 3, ADR-052 decision 5, ADR-073.
- Decision:
  1. The browser store runs the OID4VCI authorization code flow. The holder starts it from the claim page or from an offer that names the authorization code grant.
  2. The authorization request carries PKCE with `S256` always. It carries the `issuer_state` of the offer and the configuration in `authorization_details`. It goes as a pushed authorization request when the server names a `pushed_authorization_request_endpoint` (RFC 9126).
  3. The holder signs in at the authorization server of the issuer in the same browser. The callback trades the code and the PKCE verifier for an access token. The wallet keeps the token and its `c_nonce` as an authorized offer.
  4. The callback page carries the claim form, and the browser signs the proof with its own key (ADR-073). The token never reaches the browser.
  5. A laptop setup lets the wallet read a local issuer and its server over plain http on the loopback address.
  6. Setup registers the client `vca-wallet` at the holder authorization server of the Inji adapter as a public client with PKCE. Its redirect URIs are the callbacks of the holder pairs.
- Consequences:
  1. The same flow claims from walt.id and from Inji Certify through the adapter. It claims from any issuer whose metadata names an authorization server.
  2. A CREDEBL issuer offer names no authorization code grant. The stack runs no server that its OID4VC issuer trusts. The adapter document records this with the upstream source.
  3. An authorized offer lives as long as a pending record. A holder who leaves the page signs in again.
