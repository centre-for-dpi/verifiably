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
| Side navigation | The holder pages of `internal/rolenav`. These are My credentials, Discover, Claim, Present, and Help. Connections and Keys and identifiers show when the adapter of the own pair lists their features. |

The own pair is the holder pair whose `wallet-auth` serves the key set
in `AUTH_JWKS_URL`. The page "Keys and identifiers" shows only when the
adapter of the own pair lists `FEATURE_WALLET_DIDS` (ADR-062 decision
6). The page shows the holder identifier and where the holder key sits.
A stack wallet binds a new credential to its default identifier, with
a key the stack keeps. A browser store binds it to the key of the
browser. A browser store asks no wallet of the stack on this page.
After the binding below it names the `did:jwk` of the browser key and
the thumbprint of the key.
For a stack wallet the page lists the identifiers of the wallet. It
makes an identifier of a method the adapter lists. With `FEATURE_WALLET_KEYS` it
lists the keys and makes a key of a type the adapter lists. It then
also makes an identifier with a key of the wallet. With `FEATURE_WALLET_DEFAULT_DID`
it marks the default identifier and picks a new default. With
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
then uses the token of the identity provider (ADR-020 decision 3).

The browser store runs the same sign in (ADR-082). The holder picks a
credential on the claim page, or pastes an offer that names the
authorization code grant. The offer page then says that the issuer asks
for a sign in first. The wallet sends the `issuer_state` of the offer,
the configuration in `authorization_details`, and PKCE with `S256`. It
pushes the request to the `pushed_authorization_request_endpoint` of the
server when the server names one (RFC 9126). The browser then opens the
authorization endpoint with the `request_uri` alone. The holder signs
in at the server in the same browser. The server sends the browser back
to `/wallet/claim/callback`. The wallet trades the code and the PKCE
verifier for an access token. It keeps the token and its `c_nonce` as
an authorized offer. The callback page carries the claim form, and
`wallet.js` signs the proof with the browser key (ADR-073). On a laptop
setup lets the wallet read a local issuer over plain http
(`VCA_WALLET_PORTAL_CRAWL_ALLOW_PLAIN_HTTP` and
`VCA_WALLET_PORTAL_CRAWL_ALLOW_PRIVATE_NETWORK`).

The offer page names what the holder accepts. The wallet reads the
offer object, by value or through `credential_offer_uri`. It then reads
the issuer metadata from a host on the request host list. The page
shows the display name and the address of the issuer, and its trust
state from the trust registry. It shows the display name of each
offered credential and the display names of its claims. The claims
come from the claim list of OID4VCI 1.0, the claim map of draft 13, or
the `credentialSubject` of a W3C configuration. The display and the
claims sit at the top of each configuration, or under
`credential_metadata` as OID4VCI 1.0 nests them. A wallet that cannot
read the metadata says so, and the page names the address of the
issuer.

Some stacks list one generic entry per wire format, with no display.
The adapter of such a stack adds the parameter `vca_configuration` to
the offer URI. It names the configuration that the schema registry
publishes for the schema. Say the entry of the stack has no display.
The page then reads that configuration from the registry of a live
issuer pair. It shows its display and its claims only when the format
matches the entry of the stack. Otherwise the page names the entry id.

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
reads four kinds of text:

1. A credential offer, as an `openid-credential-offer` URI or as the
   offer object.
2. A presentation request, as an `openid4vp` URI.
3. A credential, in SD-JWT, JWT, or JSON-LD form.
4. A DIDComm invitation, in the query parameter `oob`, `c_i` or `d_m`
   (ADR-059 decision 5).

A DIDComm invitation gets a page of its own. The page depends on the
wallet of the stack.

- A stack wallet that lists `FEATURE_WALLET_DIDCOMM` opens the
  invitation (ADR-062 decision 4). The page first shows what the
  invitation carries: the values of an offer, or the attributes and the
  predicates of a proof request. A predicate shows as the name, the
  operator, and the number, such as `acres >= 10`. The stack wallet
  receives the invitation only after the holder accepts. Accept takes
  the credential, Share answers the request, and Connect keeps the
  connection. Decline forgets the invitation and sends nothing. The
  answer to a proof request goes into the presentation records.
- Any other wallet names the issuer and says whether the invitation
  carries a credential offer. The page shows the invitation and a link
  that a DIDComm wallet on the device opens. The wallet keeps nothing of
  the invitation.

The page "Connections" shows with `FEATURE_WALLET_DIDCOMM`. It lists
the offers and the proof requests that wait for the holder, with what
each carries. Each came over a connection. Accept and Share answer one
entry. The agent of the stack has no decline call, so an entry waits
until the holder answers it. The page also lists the connections of the
wallet.

The service keeps the offer or the request for the time in
`PENDING_TTL`. A pending record holds no credential content.
The record of a presentation request keeps the request object of the
verifier. The service refuses an object above
`REQUEST_OBJECT_MAX_BYTES`, 64 KiB by default, and keeps none of it.
Every `PENDING_SWEEP`, 5 minutes by default, the service removes the
expired records of every wallet. So a request that nobody answers
leaves no file on the volume.

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

### The signing key of the browser

`wallet.js` keeps a second key in IndexedDB: an ECDSA key on P-256 that
no script can export (ADR-073). It signs two JWTs with ES256: the proof
of a claim, and the key binding JWT of an answer. The server never sees
the private key.

A claim into the browser store takes two steps. The offer page carries
a claim form that `wallet.js` takes over.

1. `POST /wallet/claim/proof` sends the offer, the transaction code, and
   the public key. The portal reads the offer and the metadata of the
   issuer, from a host on `REQUEST_HOSTS` only. It trades the
   pre-authorized code for an access token. It answers the signing
   input of the proof. The key sits in its header, and the nonce of the
   issuer in its payload.
2. `POST /wallet/claim/finish` sends the signature. The portal checks it
   with the public key and posts the credential request. The issuer
   binds the credential to the key in `cnf.jwk`. The portal answers the
   credential, and `wallet.js` seals it into the blob store.

The request carries the proof in the shape of the version of the
issuer. An issuer with a `nonce_endpoint` follows OID4VCI 1.0, so the
request carries the object `proofs` with one JWT (section 8.2). Any
other issuer gets the object `proof` of draft 13. The request never
carries both.

A step runs once. The two answers are JSON. A refusal carries its
sentence in `error`. With no script, the claim form reaches the accept
address, and the page says that the browser signs the claim.

### The binding of the browser key

After the browser makes its signing key, `wallet.js` binds it to the
wallet once (ADR-020 decision 4). A page with the signing script marks
its status line with `data-holder-key="register"` while the session
names no key.

1. `POST /wallet/holder-key/proof` answers the signing input of a JWS
   over the session id.
2. `POST /wallet/holder-key` sends the public key and the signature.
   The portal hands both to `RegisterHolderKey` of the `wallet-auth`
   service of its pair. That service answers a session token that names
   the key, and the portal sets it as the session cookie.

Both steps need the page token. Only a browser store offers them. A
failed binding waits for the next page with the signing script.

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
   The wallet keeps the whole link, so the client id stays with the
   address. A bare http address is the address of the request object,
   even with a query of its own. Only the parameters of a request, such
   as `client_id` or `dcql_query`, make a link a request by value.
   The host of that address must be on the allowlist in
   `REQUEST_HOSTS`. The allowlist stops a request URI that points at a
   private address. Setup of a localhost pair names `localhost` and
   `127.0.0.1`. A public host names its verifier hosts itself.
2. The wallet reads the request object. It reads a DCQL query, or a
   Presentation Exchange definition, which it maps to the same shape.
   An optional field of a definition becomes a claim that a smaller
   claim set leaves out.
3. The request card names the verifier and its identifier. A badge says
   whether the trust list names the verifier. The card shows the
   purpose and the matched credential. A credential matches a query
   of its type and format. The store keeps the format the issuer gave
   an SD-JWT, from the `typ` of its header. SD-JWT VC renamed
   `vc+sd-jwt` to `dc+sd-jwt`, so a query for one matches a credential
   of the other.
4. The list "They ask for" shows each claim with the value the wallet
   would send. The page ticks and locks each required claim. An optional
   claim stays off until the holder turns it on.
5. Share selected sends the `vp_token` to the response address with
   `direct_post`. Decline sends the OID4VP error `access_denied` to the
   same address. A query for several credentials gets every chosen
   credential. The `vp_token` is then a JSON object that maps each query
   id to its presentations. Each bound credential carries its own key
   binding.

With a DPG wallet the `Present` RPC of the holder backend does the
submit. Without one the service builds the SD-JWT presentation itself.
It keeps only the disclosures the citizen agreed to, so the verifier
reads nothing more.

Consent equals disclosure (ADR-081). Some claims travel in every
answer. An SD-JWT claim outside a disclosure is one. Each claim of a
JSON-LD or JWT credential is one too. The card of a credential names
these claims in `fixed_claims`. The consent screen lists each of them,
ticked and locked, with the words "Always sent". It lists them also
when the verifier did not ask for them. The record of an answer from
the browser store names the claims that the posted token reveals. It
does not name the ticks.

A credential of the browser store that names a holder key in
`cnf.jwk` needs a key binding JWT. The consent form carries the field
`key_binding`, which `wallet.js` fills before the form goes.
`POST /wallet/present/binding` answers the signing input: the audience
and the nonce of the request, and the `sd_hash` of the disclosed token.
The browser signs it with its key. The portal checks the JWT against
`cnf.jwk`, the token, the audience, and the nonce before it posts the
answer. Without the binding, the portal refuses the answer and says why.
The portal reads the request object from its `request_uri` once, when
the consent page opens. It keeps that copy with the request. The
binding step and the answer read the copy, so the nonce stays the one
the citizen saw. A verifier that signs a new request at each read gets
the nonce of the first read.

Some stack wallets pick the claims themselves. Such an adapter lists
`FEATURE_WALLET_WHOLE_QUERY` (ADR-063). The CREDEBL agent is one. It
sends every claim of the claim set it picks. The consent screen then
ticks and locks every claim, so the holder shares each claim or
declines. A query with no claim lists each claim of the credential. The
card says that the wallet refuses to send a claim the screen does not
list. The adapter refuses an answer that leaves a claim out, and the
page shows its reason. The record names the claims the stack reports
as shared.

A stack wallet that sends each credential whole lists
`FEATURE_WALLET_WHOLE_CREDENTIAL`. The Mimoto wallet of Inji is one.
The consent screen then lists "Every claim", ticked and locked, with
the path `*`. The record names "Every claim" too.

Every holder adapter runs the same contract test,
`consenttest.Run` of `services/internal/consenttest`. A meta test fails
when an adapter package does not run it (ADR-081 decision 6).

A stack wallet fetches the request itself, so it takes a request link
only. Every stack wallet gets the same shape:
`openid4vp://authorize` with the `client_id` and the `request_uri` of
the request. The portal builds it from the link the holder gave. The
portal refuses a request by value through a stack wallet and says why. The browser store answers such a request (ADR-063 decision 2).

The response mode is `direct_post` only. The wallet refuses another
response mode.

### Formats of the browser store

The browser store claims every format a stack issues over OID4VCI. The
credential request names the format of the configuration, with its
`vct`, its `credential_definition` or its `doctype`. The browser signs
the proof with its key. The store keeps the credential under the
format that the wallet reads from it. `TestBrowserStoreClaimsJwtVcJsonAndMdoc`
claims a `jwt_vc_json` and an `mso_mdoc` credential.

The presentation of the browser store binds an SD-JWT VC only. These
limits are exact:

| Format | What the browser store sends | What a verifier sees |
|---|---|---|
| `dc+sd-jwt`, `vc+sd-jwt` | The disclosed token with a key binding JWT that the browser signs | Holder binding to the nonce and the audience |
| `jwt_vc_json` | The credential JWT as the issuer signed it, without a VP JWT | The claims and the issuer signature, with no holder proof. A verifier that asks for holder binding refuses it. |
| `mso_mdoc` | The `IssuerSigned` structure as the issuer gave it, without a `DeviceResponse` | No device signature over the session transcript. An ISO 18013-7 verifier refuses it. |
| `ldp_vc` | The credential document as issued | The claims and the issuer proof, with no holder proof |

A stack wallet presents these formats with its own keys, as its
adapter document says. A holder who needs holder binding for a
`jwt_vc_json` or an `mso_mdoc` credential uses a stack wallet.

Each answer leaves a presentation record: the time, the verifier, the
request id, the credentials, the names of the shared claims, and the
result. The request id is the last path segment of the request URI,
else the state of the request. A credential goes by the type the
request asked for, else by the query id. After an answer, the page
"What left your wallet" names the verifier, the request, the
credentials and the claims. The result takes one of
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

A card of a credential that the stack wallet cannot remove has no
remove button. The adapter marks it `permanent`, as the CREDEBL adapter
does for an AnonCreds credential (ADR-062 decision 5).

The withdrawal state reads a Bitstring Status List or a Token Status
List. A cached fetcher reads the list, so one list serves many cards.
The state is one of these words: in force, stopped, withdrawn, no list,
or not checked.

## What the service never does

- It never holds an issuer signing key.
- It never holds a holder private key. The signing key of the browser
  store stays in the browser, and the portal sees each signature only.
- It never reads a ciphertext blob of browser storage.
- It never sends the citizen subject to the eligibility hook.
- It never keeps a claim value in a presentation record.
- It never fetches a request object from a host that is not on the
  allowlist.
