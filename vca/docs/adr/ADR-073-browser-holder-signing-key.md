## ADR-073: The browser store signs with a holder key of its own
- Status: Proposed
- Owner: CDPI Architects
- Scope: `wallet.js` and the claim and present pages of the wallet portal, when the browser store keeps the credentials.
- Extends: ADR-020 decision 4, ADR-021 decisions 3, 4 and 5, ADR-024 decision 2.
- Decision:
  1. `wallet.js` keeps a signing key in IndexedDB beside the content key: an ECDSA key on P-256 that no script can export. The server never sees the private key.
  2. The key signs two JWTs with ES256. One is the proof of an OID4VCI credential request. The other is the key binding JWT of an SD-JWT answer.
  3. The wallet portal runs the protocol calls. It reads the offer, trades the pre-authorized code, and posts the credential request. The page sends only the public key and each signature.
  4. The portal hands the page the signing input of each JWT. It checks each returned signature with the public key before it uses the JWT.
  5. The browser seals a claimed credential into its blob store, as it does a pasted one.
  6. A holder bound SD-JWT of the browser store needs a key binding JWT for an answer. The portal checks that the JWT covers the disclosed token, the audience and the nonce of the request. With no key binding, the portal refuses the answer and says why.
- Consequences:
  1. A holder bound credential now claims and presents from the browser store. Before, the store held unbound credentials only.
  2. The page needs JavaScript to claim and to answer with a bound credential. The wallet says so when it runs without it.
  3. The key lives in one browser. A holder who clears the site data loses the key, and a verifier then refuses the credentials bound to it.
  4. The portal fetches the offer and the metadata only from a host on the request host list.
