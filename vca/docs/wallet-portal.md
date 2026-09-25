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
holder identifier and where the holder key sits.

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

The discovery page lists the credentials that issuers publish. The
list comes from the catalogue of the `verifier-discovery` service, which
crawls the issuer metadata (ADR-022 decision 5). The page needs no
personal data.

The claimable page shows the same list with one answer per credential:
yes or not now. The answer comes from the eligibility hook. The hook
receives a salted, one way reference of the citizen, the issuer URL, and
the schema id. It never receives the subject itself. It answers with one
field:

```json
{"eligible": true}
```

A deployment with no hook answers with the default, which is no.

## Claim, scan, paste, accept, reject, and delete

Each of these actions goes to the holder backend of the DPG. The
adapter name in `DPG` selects the adapter, and `DPG_ADAPTERS` holds the
base URL of each one.

A claim builds an OID4VCI credential offer that names the authorization
code grant. The service sends the offer to `AcceptOffer`. The DPG runs
the flow with the token of the identity provider, as ADR-020 decision 3
describes.

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

## Presentation

The presentation follows OpenID for Verifiable Presentations 1.0.

1. The wallet reads the `openid4vp` URI. A URI with a `request_uri`
   names the address of the request object.
2. The host of that address must be on the allowlist in
   `REQUEST_HOSTS`. The allowlist stops a request URI that points at a
   private address.
3. The wallet reads the request object. The object is a JSON document or
   a signed request object. The wallet reads a DCQL query, or a
   Presentation Exchange definition, which it maps to the same shape.
4. The consent screen lists every requested claim with the value the
   wallet would send. The screen names the verifier and its trust
   status.
5. After the citizen agrees, the wallet sends the `vp_token` to the
   response address with `direct_post`.

With a DPG wallet the `Present` RPC of the holder backend does the
submit. Without one the service builds the SD-JWT presentation itself.
It keeps only the disclosures the citizen agreed to, so the verifier
reads nothing more.

The response mode is `direct_post` only. The wallet refuses another
response mode.

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
- It never fetches a request object from a host that is not on the
  allowlist.
