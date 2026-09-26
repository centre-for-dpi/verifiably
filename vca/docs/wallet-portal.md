# Wallet portal

This page describes the `wallet-portal` service (ADR-021 and ADR-020
decision 4). The service README at
[`services/wallet-portal/README.md`](../services/wallet-portal/README.md)
says how to run it. This page says how it works.

## The parts

| Package | Work |
|---|---|
| `session` | It checks the session token of ADR-020 against the key set of `wallet-auth`. It also makes the page tokens. |
| `ports` | It calls the catalogue, the trust registry, the eligibility hook, and the status lists. |
| `cards` | It builds one card per credential, with trust, validity, and withdrawal state. |
| `detect` | It says what a scanned or pasted text is. |
| `present` | It reads an OID4VP request and prepares the consent screen. |
| `blobs` | It keeps the ciphertext of browser storage. |
| `static` | It serves `wallet.js`, the browser side of the wallet. |
| `service` | It answers the RPCs. |
| `portal` | It renders the citizen pages. |

## The holder frame

Every page sits in the holder frame of board Holder-Portal. The frame
comes from the shared shell package `services/internal/staffshell`. The
wallet gives the shell a user hook. The menu then shows the holder of
the wallet session and never a staff session.

| Part | Source |
|---|---|
| Role chip | The holder role. |
| Stack switcher | The holder pairs in `VCA_PEERS` that run. The probe of the peers names each stack. A pair that starts shows as text. |
| User menu | The name in the wallet session and a sign out form. |
| Side navigation | The holder pages of `internal/rolenav`. These are My credentials, Discover, Claim, Present, and Help. |

The own pair is the holder pair whose `wallet-auth` serves the key set
in `AUTH_JWKS_URL`. The page "Keys and identifiers" shows only when the
adapter of the own pair lists `FEATURE_WALLET_KEYS`. The page shows the
holder identifier and where the holder key sits. It lists the keys of
the wallet of the stack and makes a key of a type the adapter lists.
With `FEATURE_WALLET_DIDS` it lists the identifiers, marks the default,
makes an identifier, and picks a new default. With
`FEATURE_WALLET_EVENTS` it shows the latest events of that wallet. A
form of a part the adapter does not list answers 404.

The sign out form posts to `/wallet/signout` with the page token. The
wallet asks `wallet-auth` of the own pair to end the session. It clears
the session cookie and sends the browser to the logout page of the
provider. When `wallet-auth` does not answer, the browser goes to the
login page.

The home page shows one card per credential. A card names the issuer,
the type, the status, and the expiry. The stripe on top of the card
takes the tone of the status: valid, suspended, revoked, expired, not
yet valid, or not checked. The detail of the card holds the trust, the
claims, and the remove button.

## Sessions

Every RPC and every page needs a session. The middleware reads the
token from the `Authorization` header or from the cookie
`vca_wallet_session`. It checks the signature against the key set of
the wallet authentication service. It checks the expiry time. It then
puts the citizen on the request context.

A citizen with no session goes to the login page. A deployment without
a login page gets the status 401.

Every POST carries a synchronizer token. The token binds to the session
id, so a token of one session does not work in another session.

## Discovery and claimable

The discovery page lists the credentials that issuers publish. The page
follows board Holder-Discover. Each row names the issuer and whether the
trust list names it, the credential, the format, and how to claim. The
page needs no personal data.

The list comes from one of two places (spec HO1):

1. The catalogue of the `verifier-discovery` service, which crawls the
   issuer metadata (ADR-022 decision 5). The wallet uses it when it
   answers.
2. A crawl of its own, when the deployment runs no verifier pair or the
   catalogue does not answer. The package `issuers` reads
   `/.well-known/openid-credential-issuer` of each live issuer pair at
   its internal address. It also reads the metadata of each issuer on
   the trust list at its public address.

Every read goes through `core/fetchguard` with a cache. The time in
`CRAWL_TTL` bounds the cache. The wallet reads a live pair only at the
registry host that `VCA_PEERS` names. It reads a trusted issuer under
the address rules of `CRAWL_ALLOWED_HOSTS`, `CRAWL_ALLOW_PRIVATE_NETWORK`,
and `CRAWL_ALLOW_PLAIN_HTTP`.

The column "How to claim" comes from the grants of the metadata:

| Grant | Words on the page |
|---|---|
| `urn:ietf:params:oauth:grant-type:pre-authorized_code` | Code |
| `authorization_code` | Sign in at issuer |

The wallet reads `grant_types_supported` of the issuer metadata first.
Without it, the wallet reads the metadata of the first authorization
server, or of the issuer. An authorization server that names no grant
supports the authorization code grant (RFC 8414). For a live pair, the
channels of its adapter add to the list. An issuer that names no grant
still sends offers, so the page shows Code.

The claimable page shows the same list with one answer per credential:
yes or not now. The answer comes from the eligibility hook. The hook
receives a salted, one way reference of the citizen, the issuer URL, and
the schema id. It never receives the subject itself. It answers with one
field:

```json
{"eligible": true}
```

A deployment with no hook answers with the default, which is no.

## Claim, scan, paste, accept, decline, and delete

Each of these actions goes to the holder backend of the DPG. The
adapter name in `DPG` selects the adapter, and `DPG_ADAPTERS` holds the
base URL of each one.

The claim page shows two cards side by side (spec HO3). The claim card
of the discover page shows the same cards for one credential. It shows
only the ways its issuer allows.

| Card | Flow | What the holder does |
|---|---|---|
| Code or QR | OID4VCI pre-authorized code | Paste the offer and its code. Or scan the QR. |
| Sign in at issuer | OID4VCI authorization code | Pick the credential and sign in at the issuer. |

With the transaction code, or with an offer that needs none, the wallet
claims the credential at once. An offer that needs a code the holder did
not give opens the offer page, which asks for the code.

The camera scanner is the shared script of `services/internal/qrscan`.
The page reads the QR code on the device and posts only the decoded
text to `/wallet/scan/read`. The answer is the offer card, or a redirect
to the next page.

The sign in at the issuer runs the authorization code flow with PKCE.
The wallet reads the authorization server of the issuer from its
metadata. It sends the browser to the authorization endpoint with the
configuration id in `authorization_details`. The issuer sends the
browser back to `/wallet/claim/callback` of the own pair. The wallet
trades the code for an access token. It hands the token to the DPG
wallet in `AcceptOffer` as the authorization grant. An issuer with no
authorization server leaves the flow to the DPG wallet. The DPG wallet
then uses the token of the identity provider (ADR-020 decision 3). In browser
storage the wallet runs no sign in, so the card stays hidden.

The offer page shows the button Decline only when the adapter of the own
pair lists `FEATURE_WALLET_REJECT_OFFER`. Without the feature the
decline address answers 404. A decline reaches the wallet of the stack
through `RejectOffer`, so its event log holds the decline.

### Presentation during issuance

An issuer can ask for a presentation before it issues. The offer then
names an authorization server whose metadata has an
`interactive_authorization_endpoint` (OID4VCI 1.1 draft). The wallet
reads an offer by reference only from a host of `REQUEST_HOSTS`.

With a DPG wallet, Accept runs these steps:

1. It posts the authorization request with PKCE and the interaction
   type `openid4vp_presentation`.
2. The issuer answers with an OpenID4VP request in the response mode
   `iar-post`. Accept keeps it and returns its presentation id.
3. The page opens the consent screen. The card says that the issuer
   asks for a credential before it gives the new one.
4. Share selected posts the `auth_session` and the
   `openid4vp_response` to the same endpoint. The response holds the
   `vp_token` and a `presentation_submission` for the first input
   descriptor.
5. The issuer answers with a code. The wallet trades it with the PKCE
   verifier for an access token. The DPG wallet claims the offer with
   that token.

The outcome page says "Credential received". A refused presentation
claims nothing. Decline ends the step and posts nothing. The browser
store claims no offer, so it runs no such step.

A scan or a paste goes through the `detect` package first. The package
reads three kinds of text:

1. A credential offer, as an `openid-credential-offer` URI or as the
   offer object.
2. A presentation request, as an `openid4vp` URI.
3. A credential, in SD-JWT, JWT, or JSON-LD form.

The service keeps the offer or the request for the time in
`PENDING_TTL`. A pending record holds no credential content.

## Credential storage

The deployment holds the credentials in one of two places.

The DPG wallet holds them when the deployment names an adapter that
serves the holder RPCs. The service then reads the wallet with
`ListCredentials` and shows one card per credential.

The browser holds them when the deployment names no adapter. The server
then stores ciphertext only. The file `wallet.js` does this work:

1. It creates a P-256 key pair with WebCrypto. The private key is not
   extractable, and it stays in IndexedDB of that browser.
2. It derives one shared secret from that key pair, then one AES-256-GCM
   content key with HKDF-SHA256.
3. It encrypts each credential and sends the envelope to the server.

The envelope is this JSON document:

```json
{"v":1,"kdf":"HKDF-SHA256","alg":"A256GCM","iv":"<base64url>","ct":"<base64url>"}
```

The HKDF salt is `vca-wallet-portal`. The HKDF info is
`vca-wallet-blob-v1`. The nonce has 12 bytes. The Go package `blobs`
writes and reads the same format. A unit test round trips it, so one
format serves both sides.

The server keys each blob by the wallet key of the citizen. It cannot
read a blob, because it never holds the content key.

The browser page also offers a file upload and a paste box. A citizen
with no camera still loads a credential that way.

### A stack wallet beside the browser store

Some stack wallets claim an offer only in their own pages. The adapter
of such a stack lists `FEATURE_WALLET_CLAIM_IN_STACK`. The wallet then
uses both places:

| Action | Where it runs |
| --- | --- |
| List | The stack wallet first. Then the credentials the holder loaded into the browser store. When the stack does not answer, the browser credentials stay on the page. A note above them names the stack. `ListMineResponse.stack_problem` carries the sentence. A locked stack wallet shows its PIN card beside the browser credentials. |
| Claim an offer | The page of the stack. The offer page and the claim page link to the component of the adapter answer that has a public address. |
| Load a file or a paste | The browser store, as without an adapter. |
| Present | The stack for a stack credential. The wallet itself for a browser credential. |
| Delete | Where the credential sits. |
| Document | `GET /wallet/document?id=` returns the PDF of a stack credential through the `Document` RPC. The card shows the link when the adapter lists `FEATURE_WALLET_DOCUMENT`. |
| PIN | `GET /wallet/pin` asks for the PIN of the stack wallet when the adapter lists `FEATURE_WALLET_PIN`. On first use the holder sets it and types it twice. Later the holder enters it once per session. The home page lists the stack only after that step. |

The PIN belongs to the holder. The service passes it to the adapter
with `UnlockWallet` and keeps it nowhere. The wallet page of the stack
asks for the same PIN, so the holder claims there with it. Too many
wrong PINs lock the stack wallet, and the page then names the way out.

The service asks the live probe of the own pair on each request. The
blob routes answer `404` while the wallet keeps no browser store. A card
of the stack carries `in_browser` false. A stack can list a credential
by name only. Its card then shows the type and the issuer name, and the
document shows what the credential says.

## Presentation

The presentation follows OpenID for Verifiable Presentations 1.0. The
present page follows board Holder-Present and spec HO4. A request comes
in one of three ways:

1. The camera reads the QR code of the verifier.
2. The holder pastes the request link.
3. The holder uploads a request file. The file holds a request link, or
   a request object as JSON or as a signed request.

The wallet then reads the request:

1. A link with a `request_uri` names the address of the request object.
   The host of that address must be on the allowlist in
   `REQUEST_HOSTS`. The allowlist stops a request URI that points at a
   private address.
2. The wallet reads the request object. It reads a DCQL query, or a
   Presentation Exchange definition, which it maps to the same shape.
   An optional field of a definition becomes a claim that a smaller
   claim set leaves out.
3. The request card names the verifier and its identifier. A badge says
   whether the trust list names the verifier. The card shows the
   purpose and the matched credential.
4. The list "They ask for" shows each claim with the value the wallet
   would send. The page ticks and locks each required claim. An optional
   claim stays off until the holder turns it on.
5. Share selected sends the `vp_token` to the response address with
   `direct_post`. Decline sends the OID4VP error `access_denied` to the
   same address.

With a DPG wallet the `Present` RPC of the holder backend does the
submit. Without one the service builds the SD-JWT presentation itself.
It keeps only the disclosures the citizen agreed to, so the verifier
reads nothing more.

The response mode is `direct_post` only. The wallet refuses another
response mode.

Each answer leaves a presentation record: the time, the verifier, the
names of the shared claims, and the result. The result takes one of
four words: Accepted, Refused, Declined, or Not sent. A record holds no claim value. The
wallet keeps the newest 100 records of each wallet. The home page lists
the newest five under "Recent presentations".

## Cards

A card carries these parts (ADR-021 decision 6):

| Part | Source |
|---|---|
| Title | The display metadata of the catalogue, or the credential type. |
| Issuer trust | `TrustLookup` of the trust registry service. |
| Validity | The `validFrom` and `validUntil` claims, or `nbf` and `exp`. |
| Withdrawal state | The status list the credential names. |
| Claims | The credential claims, with the SD-JWT disclosures resolved. |
| Status line | One sentence per part, in Simplified Technical English. |

The withdrawal state reads a Bitstring Status List or a Token Status
List. A cached fetcher reads the list, so one list serves many cards.
The state is one of these words: in force, stopped, withdrawn, no list,
or not checked.

## What the service never does

- It never holds an issuer signing key.
- It never holds a holder private key.
- It never reads a ciphertext blob of browser storage.
- It never sends the citizen subject to the eligibility hook.
- It never keeps a claim value in a presentation record.
- It never fetches a request object from a host that is not on the
  allowlist.
