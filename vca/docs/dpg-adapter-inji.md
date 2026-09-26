# Inji DPG adapter

The Inji DPG adapter connects Verifiable Credentials Adapters to Inji
Certify, Inji Verify, and Mimoto, the backend of Inji Web. It is one of the three DPG adapters of ADR-002
decision 1. The vendor name appears in this service and nowhere else.

## Why the service exists

Inji Certify issues credentials and Inji Verify checks presentations.
Neither ships a wallet for a citizen. The legacy code closed that gap in
two ways. It ran the whole OID4VCI pre-authorized flow itself. It also
printed the credential on paper. This adapter keeps both abilities. It
drops the two acts that ADR-002 decision 4 forbids: it never writes the
Inji database, and it never restarts an Inji container.

## What it serves

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served when the configuration names an Inji Certify URL. |
| `HolderBackendService` | Served when the configuration names a Mimoto URL. `AcceptOffer` points at Inji Web. |
| `VerifierBackendService` | Served when the configuration names an Inji Verify URL. |
| `CatalogBackendService` | Served when the configuration names an Inji Certify URL. |
| `TenantBackendService` | Never served. Inji keeps no tenants. |
| `NotificationBackendService` | Never served. Inji keeps no tenants to hold a webhook. |

## The Inji endpoints

| Endpoint | What the adapter does with it |
| --- | --- |
| `POST /v1/certify/pre-authorized-data` | Stages the claims of one subject. |
| `GET` on the offer document | Reads the pre-authorized code and the issuer. |
| `POST /v1/certify/oauth/token` | Redeems the code for an access token and a nonce. |
| `POST /v1/certify/issuance/credential` | Asks for the signed credential. |
| `GET /v1/certify/issuance/.well-known/openid-credential-issuer` | Reads the catalogue. |
| `GET /v1/certify/credential-configurations/{id}` | Checks whether Certify holds a configuration. |
| `POST /v1/certify/credential-configurations` | Creates a configuration. |
| `PUT /v1/certify/credential-configurations/{id}` | Replaces a configuration. |
| `POST /v1/certify/v2/ledger-search` | Finds issued credentials in the ledger of Certify. |
| `POST /v1/certify/credentials/status` | Sets the revocation bit of a credential of the ledger. |
| `GET /v1/certify/.well-known/did.json` | Reads the issuer DID, which the ledger search needs. |
| `GET /v1/certify/.well-known/oauth-authorization-server` | Reads the interactive authorization endpoint for a presentation during issuance. |
| `GET /v1/certify/rendering-template/{id}` | Reads the SVG card template a credential template names. |
| `GET /v1/certify/system-info/certificate` | Reads the certificate of a signing key. The key manager makes the key when it has none. |
| `POST /v1/certify/system-info/upload-ca-certificate` | Adds a CA certificate to the trust store of the stack. |
| `POST /v1/certify/system-info/uploadCertificate` | Puts a CA signed certificate on a signing key. |
| `POST /v1/verify/vp-request` | Starts an OID4VP transaction. |
| `GET /v1/verify/vp-result/{id}` | Reads the answer of a transaction. |
| `POST /v1/verify/vc-verification` | Checks one uploaded or scanned credential. |
| `POST /v1/mimoto/auth/{provider}/token-login` | Opens a Mimoto session with the ID token of the holder login. |
| `GET /v1/mimoto/wallets` | Lists the wallet of a holder and its lock status. The answer sets the CSRF cookie. |
| `POST /v1/mimoto/wallets` | Makes the Mimoto wallet with the PIN the holder sets on first use. |
| `POST /v1/mimoto/wallets/{id}/unlock` | Puts the wallet key in the session. |
| `GET /v1/mimoto/wallets/{id}/credentials` | Lists the held credentials by name. |
| `GET /v1/mimoto/wallets/{id}/credentials/{credentialId}` | Reads the PDF of a held credential. |
| `DELETE /v1/mimoto/wallets/{id}/credentials/{credentialId}` | Removes a held credential. |
| `POST`, `PATCH /v1/mimoto/wallets/{id}/presentations` | Answers an OID4VP request with held credentials. |

## What the adapter can do

The answer of `GetCapabilities` reports what the deployment supports.

| Item | Value |
| --- | --- |
| Formats | `ldp_vc`, `vc+sd-jwt`, `mso_mdoc` |
| Channels | OID4VCI pre-authorized code, OID4VCI authorization code, document, and identity QR (Claim 169) with a Certify URL |
| Protocols | OID4VCI, OID4VP, OID4VP with Presentation Exchange |
| Roles | The roles whose URL the configuration sets. `ROLE_HOLDER` with a Mimoto URL. |
| Features | `FEATURE_CREDENTIAL_CONFIG_API`, `FEATURE_REVOCATION`, `FEATURE_ISSUED_LEDGER`, `FEATURE_ISSUER_IDENTITY_PROVISION`, and `FEATURE_ISSUER_IDENTITY_IMPORT_X509` with a Certify URL. `FEATURE_PRESENTATION_DURING_ISSUANCE` with a Certify URL and `VCA_INJI_PRESENTATION_DURING_ISSUANCE`. `FEATURE_VERIFY_UPLOAD` with an Inji Verify URL. `FEATURE_WALLET_DOCUMENT`, `FEATURE_WALLET_CLAIM_IN_STACK`, and `FEATURE_WALLET_PIN` with a Mimoto URL. |
| DID methods | `did:web`, the one DID of the Certify configuration |
| Key types | `Ed25519`, `secp256r1`, `secp256k1`, `RSA` |
| Status mechanisms | Bitstring status list and token status list, when the configuration names a Certify URL |
| DPG information | The stack name, the Certify release, one component per wired role plus Keycloak, and the Certify plugins of `VCA_INJI_CERTIFY_PLUGINS`. The holder role adds Mimoto and Inji Web, and the Inji Web component carries the address of `VCA_INJI_WEB_URL`. |

Each component carries its pinned version, its repository, its
documentation, and its licence. The versions come from the
configuration, and a test binds the defaults to the stack file. A page
shows a feature on this stack only when the answer lists it (ADR-034).

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `GetIssuanceStatus` | Inji Certify reports no state of a staged offer. |
| `Revoke` of a VCA status entry | The status service that owns the list changes the bit. The adapter answers `failed_precondition` without a ledger id. |
| `Revoke` with a suspension or a reinstatement | The Certify configuration of the stack allows the revocation purpose only. The answer lists no `FEATURE_SUSPENSION`. |
| `ImportIssuerIdentity` of a DID | Certify reads its DID from its configuration. The adapter lists no `FEATURE_ISSUER_IDENTITY_IMPORT_DID`. |
| Every holder RPC without `VCA_INJI_MIMOTO_URL` | The adapter drives no wallet. |
| `AcceptOffer` | Mimoto downloads a credential only in the browser, with its own client. The answer names Inji Web, where the holder claims. The answer lists `FEATURE_WALLET_CLAIM_IN_STACK`. |
| The bytes of a held credential | Mimoto lists names and logos only. `ListCredentials` returns no `credential`, and the wallet shows the PDF of `GetCredentialDocument`. |
| A PIN that the holder did not type | The adapter never stores the PIN of a Mimoto wallet. The holder sets it on first use and enters it in each session. |
| `Register` without an ID token, or with a token Mimoto does not trust | Mimoto opens a session only from a trusted ID token. The adapter answers `failed_precondition` or `permission_denied`, and the wallet keeps the browser store. |
| Every tenant RPC | Inji keeps no tenants. |
| Every webhook RPC | Inji keeps no tenants to hold a webhook. |
| `VerifyCredential` of a JWT VC, an mDoc, or a Claim 169 QR code | Inji Verify 0.16.0 checks JSON-LD and SD-JWT credentials only. The adapter answers `invalid_argument`. |
| A presentation during issuance without `VCA_INJI_PRESENTATION_DURING_ISSUANCE` | Certify checks the presentation with Inji Verify, and the stack file does not point it there. The adapter answers `failed_precondition` and lists no `FEATURE_PRESENTATION_DURING_ISSUANCE`. |
| A presentation definition per offer | Certify 0.14.0 reads one definition for the deployment from `vp_request_config.json`. The offer cannot name another. |
| An identity QR code beside an mDoc | The adapter asks for the code in `ldp_vc` and `vc+sd-jwt` entries only. An mDoc element needs a digest of its own. |
| An identity QR code of a schema without identity claims | Claim 169 names identity attributes only. The adapter asks for no code, and `Issue` returns none. |

Each of these answers with the Connect code `unimplemented` and a
sentence that names the alternative.

## Credential configurations

`RegisterCredentialConfiguration` writes the configuration API of Inji
Certify 0.14.0. The adapter reads the id first. It creates a new entry
and replaces an entry that Certify holds. Certify then lists the entry
in its issuer metadata, so a wallet sees it at once.

The API takes `ldp_vc`, `vc+sd-jwt`, and `mso_mdoc` in this release.
The adapter refuses `dc+sd-jwt` and `jwt_vc_json` with a reason.

| Contract format | Certify format | What the entry carries |
| --- | --- | --- |
| `FORMAT_LDP_VC` | `ldp_vc` | The data model 2.0 context, the extensions, and the context of the proof suite |
| `FORMAT_VC_SD_JWT` | `vc+sd-jwt` | The `vct`, the disclosable claims, and a token status list claim |
| `FORMAT_MSO_MDOC` | `mso_mdoc` | The `doctype`, one namespace of elements, and the COSE algorithm |
| `FORMAT_JWT_VC_JSON` | none | Refused. Certify 0.14.0 registers no JWT VC. |

A signed JWS proof of a JSON-LD credential is a proof suite, not a
format. `VCA_INJI_LDP_CRYPTO_SUITE` selects it. `Ed25519Signature2018`,
`RsaSignature2018`, and `EcdsaSecp256k1Signature2019` carry a detached
JWS. The entry then names the context of that suite.

An mDoc keeps its claims in one namespace. An mDL type such as
`org.iso.18013.5.1.mDL` uses the namespace `org.iso.18013.5.1`. Another
type uses itself as the namespace. Certify fills the validity itself.
The staging call of an mDoc carries no status marker.

Each entry carries a Velocity template. The template places every
claim of the JSON Schema. A string claim goes in quotes. A number, a
boolean, an object, or an array goes in as JSON. A claim name must be a
template variable name, so the adapter refuses a name with a space.

The entry declares the four markers of the staging call beside the
claims. Certify rejects a staged claim that the entry does not declare.
The `ldp_vc` template writes a bitstring status list entry of VCA when
the staging call passes a status address. The SD-JWT template writes a
token status list claim in the same case. Without an address, the
credential carries no status.

The entry names the Certify key of each format through the settings
`VCA_INJI_LDP_*` and `VCA_INJI_SD_JWT_*`. The defaults match the key
alias mapper of the stack. The stack keeps the keys (ADR-001 decision
3).

When `VCA_INJI_RENDERING_TEMPLATE_ID` names the SVG template of the
deployment, an `ldp_vc` template names it as its render method.
`GetIssuerMetadata` returns the template with each configuration whose
credential template names one. The adapter reads each entry and each
template once per call. It caps a template at 256 KiB.

A refusal keeps the Certify code. A duplicate type gives
`already_exists`. A missing field gives `invalid_argument`.

## The ledger and revocation

Inji Certify keeps a ledger of the credentials it issues with a status
entry of its own. `ListIssuedCredentials` searches it. Certify needs
the issuer DID, the type list, and one indexed attribute with a value.
The adapter reads the DID from the DID document of Certify. A
configuration id becomes the sorted type list of its definition. A bare
type name joins `VerifiableCredential`. Certify returns every match at
once, so the adapter sorts the entries by issuance and pages them.

`Revoke` takes the ledger id of a credential. It sets the bit of the
revocation purpose through the credential status API. Certify writes
the status list credential in its next scheduled run. The issued
credentials pages send only a record of the ledger this way. A record
with a status entry of VCA keeps its bit in a VCA list.

## The credential check

`VerifyCredential` serves the stack check of the scanner. The adapter
reads the carrier with `core/ingest` first. It takes a QR image, a PDF,
a PixelPass text, a JSON-LD document, or an SD-JWT. It sends each
credential to `POST /v1/verify/vc-verification`. The Content-Type names
the format: `application/vc+sd-jwt` for an SD-JWT and
`application/json` for a JSON-LD credential.

Inji Verify answers with one status. The adapter maps it onto the
checks it covers and leaves out a check the status says nothing of.

| Status | Checks |
| --- | --- |
| `SUCCESS` | Signature, expiry, and revocation pass. |
| `EXPIRED` | The signature passes. The expiry fails. |
| `REVOKED` | The revocation fails. |
| `INVALID` | The signature fails. |

Every answer also carries the status itself as the check
`inji-verification-status`. VCA runs its own checks too (ADR-024
decision 2).

## The issuer identity

Inji Certify signs with keys of its MOSIP key manager and serves one
`did:web`. The stack keeps every key (ADR-001 decision 3).

`GetIssuerIdentity` reads the DID document at `/.well-known/did.json`.
It adds the certificate of the signing key from the key manager. The
subject of that certificate becomes the second identifier.

`ProvisionIssuerIdentity` takes the method `did:web` and a key type. It
asks the key manager for the certificate of the key of that type. The
key manager makes the key when it has none. The key names follow the
key alias mapper of the stack.

| Key type | Application id | Reference id |
| --- | --- | --- |
| `Ed25519` | `CERTIFY_VC_SIGN_ED25519` | `ED25519_SIGN` |
| `secp256r1` | `CERTIFY_VC_SIGN_EC_R1` | `EC_SECP256R1_SIGN` |
| `secp256k1` | `CERTIFY_VC_SIGN_EC_K1` | `EC_SECP256K1_SIGN` |
| `RSA` | `CERTIFY_VC_SIGN_RSA` | none |

`ImportIssuerIdentity` takes an X.509 chain in PEM, leaf first, and a
key reference such as
`{"applicationId":"CERTIFY_VC_SIGN_ED25519","referenceId":"ED25519_SIGN"}`.
It uploads each CA certificate to the partner domain of
`VCA_INJI_CA_DOMAIN`. It then puts the leaf on the key. The key manager
refuses a leaf of another key with `KER-KMS-014`, and the adapter
answers `failed_precondition` with that code.

A credential configuration names its key through `VCA_INJI_LDP_*`,
`VCA_INJI_SD_JWT_*`, and `VCA_INJI_MDOC_*`. A new key type takes effect
for the configurations that name it.

## Interoperability knowledge

The adapter carries the knowledge the legacy code proved in the field.

**The proof header names the key once.** The holder proof carries `typ`,
`alg`, and `jwk`. It carries no `kid`. Inji rejects a header that names
the key twice.

**The proof payload has no holder.** The pre-authorized flow of OID4VCI
has no named holder, so the payload carries no `iss` and no `sub`. It
carries `aud`, `iat`, `exp`, and the nonce of the token endpoint.

**The proof audience is the issuer of the offer.** The offer document
names the credential issuer. That value is right in a local deployment
and in a public one. A fixed value breaks the flow the moment the
deployment gets a public name.

**The token endpoint is not under the issuance path.** Inji serves the
pre-authorized token endpoint at `/v1/certify/oauth/token`.

**The status markers are always present.** The credential template
carries two placeholders, `statusIdx` and `statusUri`. The staging call
must fill both, even with the index 0 and an empty address. An unfilled
placeholder makes Inji answer with a bad request. The same two markers
serve two shapes. One is the IETF token status list of an SD-JWT. The
other is the W3C bitstring status list entry of a JSON-LD credential.

**A marker the template never declared is an error.** The adapter adds
the validity markers only when the caller sends a validity window.

**The JSON-LD request repeats the context.** Inji compares the
`@context` of the credential request with the one of the metadata. The
adapter copies the value word for word.

**The offer document keeps its path and loses its host.** Inji advertises
the offer under the public name of the deployment. The adapter reads the
document from the instance it staged the claims on. A deployment with a
public name and an internal name then needs no rewrite rule.

**The adapter hosts the authorization code offer.** Inji Certify hosts
no such offer. The adapter builds the document, serves it at
`/offers/{id}`, and points the wallet at it.

**The offer names eSignet.** The authorization code offer names
`VCA_INJI_AUTHORIZATION_SERVER`. Without it, the offer names the first
authorization server of the Certify metadata. In the stack file that
is eSignet, whose token Certify takes at its credential endpoint.
eSignet is also a login provider of the issuer and holder portals.
`vca dpg bootstrap` registers the VCA client there with an RSA key.

**The wrong credential can pass the DPG check.** Inji Verify sometimes
reports a success for a presentation that answers with another
credential. The adapter records the claim names of the request. When the answer arrives, it checks that at
least one presented credential carries one of those names. It lowers the
verdict when nothing matches, and it adds a failed check that says so.

## Presentation during issuance

Inji Certify 0.14.0 can ask the holder to present a credential before
it issues. It runs an authorization server of its own with an
interactive authorization endpoint, `POST /v1/certify/oauth/iar`. The
wallet flow has four calls:

1. The wallet posts the authorization request with PKCE and the
   interaction type `openid4vp_presentation`.
2. Certify asks Inji Verify for a request and answers
   `require_interaction` with an `auth_session` and an OpenID4VP
   request. Its response mode is `iar-post`.
3. The wallet posts the `auth_session` and the `openid4vp_response`.
   Certify hands the presentation to Inji Verify and answers `ok` with
   a code that starts with `iar_auth_`.
4. The wallet trades the code and the PKCE verifier at
   `/v1/certify/oauth/token` and asks for the credential.

`CreateOffer` with `require_presentation` reads the metadata of that
server. It builds an authorization code offer that names the server as
its `authorization_server`, and the adapter hosts the offer. The answer
names the authorization code channel, also when the caller asked for
the pre-authorized one.

Certify reads the presentation definition from the deployment, not
from the offer. It then reads the claims from its data provider for
the identity of the presented credential. The claims of the staging
call do not reach such a credential.

The setting `VCA_INJI_PRESENTATION_DURING_ISSUANCE` turns the feature
on. Set it once Certify reaches Inji Verify through
`mosip.certify.verify.service.base-url` and holds a
`vp_request_config.json`.

## The identity QR channel

Inji Certify 0.14.0 signs an identity QR code per the MOSIP QR code
specification 1.1.0 beside a credential. The configuration asks for it
with `qrSettings` and `qrSignatureAlgo`. Each entry of `qrSettings` is
a Velocity template of one object. Its keys are the attribute names of
the PixelPass key mapper, such as `Full Name` and `Date of Birth`.
PixelPass turns them into the integer keys of claim 169. Certify signs
the claims as a CWT with the key of the configuration. It then hands
the base45 text to the credential template as `claim_169_values`.

`RegisterCredentialConfiguration` maps each string claim that names an
identity attribute onto its key. `fullName` and `name` become
`Full Name`. `dateOfBirth` and `birthDate` become `Date of Birth`.
`gender`, `email`, `mobileNumber`, `nationality`, and `address` map
too. The entry signs with the algorithm of its credential key. The
template writes the first code into the claim `identityQR`, under a
guard for a credential without a code.

`Issue` reads the claim back from the credential. It checks the text
with the Claim 169 decoder of `core/ingest` and returns it in
`claim169_qr`. The issuance service prints it on a document for the
channel `CHANNEL_CLAIM169_QR`.

The key names of the stack sample differ from the mapper in one place.
The sample writes `Date Of Birth`, and the mapper knows
`Date of Birth`. The adapter uses the mapper name, so the date gets the
key 8.

## The holder role through Mimoto

Spike P6-I7a read the session model of Mimoto 0.21.0, the backend of
Inji Web 0.16.0. This section records what it found and the decision
that P6-I7b builds.

### What Mimoto does

| Topic | Mimoto 0.21.0 |
| --- | --- |
| Session | A servlet session in Redis (`spring.session.store-type=redis`), 30 minutes idle. Every wallet endpoint reads the user and the wallet key from it. |
| Browser login | OAuth2 login with Google, then the session cookie. |
| Login with a token | `POST /v1/mimoto/auth/{provider}/token-login` with `Authorization: Bearer` and an ID token. The provider is a bean of the code, `google` in this release. It checks the issuer of `google.issuer`, the client id of the Google registration, and the key set of `spring.security.oauth2.client.provider.google.jwk-set-uri`. The answer sets the session cookie. |
| Wallet | `POST /wallets` makes a wallet with a PIN of six digits. `POST /wallets/{id}/unlock` puts the wallet key in the session. |
| Held credentials | `GET /wallets/{id}/credentials` lists the issuer name, the type name, the logos, and the id. It returns no credential bytes. |
| PDF | `GET /wallets/{id}/credentials/{credentialId}` with `Accept: application/pdf`. |
| Delete | `DELETE /wallets/{id}/credentials/{credentialId}`. |
| Present | `POST /wallets/{id}/presentations` with `authorizationRequestUrl`, then `GET .../{presentationId}/credentials`, then `PATCH .../{presentationId}` with `selectedCredentials`. |
| Download | `POST /wallets/{id}/credentials` with an issuer of the Mimoto registry, a configuration id, and the `code`, `grantType`, `redirectUri`, and `codeVerifier` of an authorization code flow. The flow runs in the browser with the client of Mimoto and the Inji Web redirect page. |

### Decision

1. A server can drive Mimoto. The token login gives a session without
   a browser, so the adapter drives the holder role server side. The
   default of open question G.10 applies only to the download.
2. `Register` logs in with the ID token of the holder login. The
   wallet authentication service passes it on every login (ADR-020
   decision 3). The adapter keeps the session cookie per wallet. The
   holder sets the PIN of the Mimoto wallet, see "The wallet PIN"
   below (P6-I7c).
3. `ListCredentials`, `Present`, and `DeleteCredential` call Mimoto
   with that session. A listed credential carries the names only,
   because Mimoto returns no credential bytes.
4. The PDF of Mimoto reaches the wallet portal through a holder RPC
   for the document of a credential.
5. `AcceptOffer` answers `unimplemented`. Mimoto downloads only through
   an authorization code flow of its own client in the browser. The
   VCA wallet links the holder to Inji Web for a claim, and the
   credential then shows in the list.
6. The stack file points the token login of Mimoto at the holder realm
   of the stack Keycloak. Without that setting Mimoto refuses the
   token, `Register` fails, and the wallet keeps the browser store.

### What P6-I7b built

The adapter follows the decision. `TestRegisterLeavesThePinToTheHolder`,
`TestListCredentials`, `TestAcceptOfferPointsAtInjiWeb`,
`TestPresentThroughMimoto`, `TestDelete`, and
`TestCapabilitiesListHolderRole` run against the fake Mimoto.
`TestContractHolderThroughMimoto` runs against a real Mimoto with
`VCA_INJI_CONTRACT_MIMOTO_URL` and an ID token or a test holder.

The adapter keeps the session of each wallet in `VCA_INJI_STORE_FILE`.
A store in memory forgets the sessions at a restart. Every holder then
signs in again, and the service warns at start.

### The wallet PIN

Mimoto keeps a PIN of six digits per wallet, and Inji Web asks the
holder for it before a claim. P6-I7c chose the design that keeps the
holder in control. **The holder sets the PIN on first use in the VCA
wallet. The adapter never stores it.** The other design is a PIN that
the adapter makes and the wallet shows once. It puts a secret of the
holder in the adapter store. It also leaves the holder with a PIN that
the holder did not choose.

| Step | What happens |
| --- | --- |
| Login | `Register` opens a Mimoto session and lists the wallets of the user. It makes no wallet and unlocks none. The wallet id it returns is a handle of the adapter, stable per holder. |
| Lock state | `GetWalletLock` lists the wallets again. No wallet gives `WALLET_LOCK_NEEDS_NEW_PIN`. A wallet the session has not opened gives `WALLET_LOCK_NEEDS_PIN`. A wallet that Mimoto lists as locked gives `WALLET_LOCK_LOCKED_OUT`. |
| PIN step | The wallet portal asks for the PIN at `/wallet/pin`. On first use it takes the PIN twice. `UnlockWallet` makes the wallet with that PIN when the holder has none, then unlocks it. The PIN goes to Mimoto and nowhere else. |
| Wrong PIN | Mimoto answers `invalid_pin`, and the fourth wrong PIN `last_attempt_before_lockout`. The page shows the sentence beside the field. The fifth wrong PIN locks the wallet for an hour (423). |
| Claim | Inji Web asks for the same PIN. The holder knows it, so the claim opens the wallet. The credential then shows in the VCA wallet. |
| Lost key | A session that lost the wallet key answers `wallet_locked`. The adapter marks the wallet locked, and the wallet asks for the PIN again. |

The adapter lists `FEATURE_WALLET_PIN` with a Mimoto URL. The wallet
list sets the CSRF cookie of Mimoto. Every call that changes state
repeats it in the `X-XSRF-TOKEN` header.

A record of an earlier release held a random PIN. The next login keeps
its wallet id and removes the PIN from the store. The holder does not
know that PIN. The holder resets it in Inji Web, which deletes that
wallet. The holder then sets a new PIN in the VCA wallet.

The wallet portal uses the stack for what Mimoto does. It lists the
held credentials, presents them, deletes them, and serves their PDF.
It keeps the browser store for what Mimoto does not do. A credential
that the holder loads from a file or a paste stays in the browser store.
For an offer, a link sends the holder to Inji Web to claim into the
stack.

### The stack that runs Mimoto

The `holder-inji` profile of `deploy/vca/dpg/inji.yaml` runs Mimoto
0.21.0 with what it needs (P6-I7d). The files sit in
`deploy/vca/dpg/inji/mimoto/`, and their `SOURCE.md` names the upstream
files.

| Need | How the stack meets it |
| --- | --- |
| Database | A Postgres of its own, prepared by `mimoto_init.sql` of the release |
| Sessions | A Redis, as `application-default.properties` of the release sets it |
| Token login | The provider `google` trusts `vca-holder-realm` of the stack Keycloak, the client `vca-holder`, and the key set of that realm |
| Browser login | Inji Web signs the holder in through the same realm and client |
| eSignet | `mosip.esignet.host` and the issuer list name the eSignet of the stack. `vca dpg bootstrap` writes the key of `vca-inji` into the client key store. |
| Inji Web | Port 3004. It serves the issuer list to Mimoto and sends `/v1/mimoto/` to it. |

## The paper document channel

The `Issue` RPC returns the signed credential without a wallet. The
issuance service turns that credential into a one page document with a
QR code (ADR-016 decisions 3 and 4). The QR payload of the MOSIP reader
is the `core/pixelpass` encoding: the credential becomes CBOR, then zlib
deflate, then base45. A raw JSON payload breaks the base45 reader of the
MOSIP tools at the first character.

## Tests

The recorded set replays answers of Inji Certify 0.14.0 and Inji Verify
0.16.0 from `testdata` through an `httptest` fake. It runs in every
build.

The contract set targets a real Inji deployment. It carries the build
tag `contract_inji`. It skips itself when the variables hold no value.

## Reference

- Service folder: `services/dpg-adapter-inji`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decisions 3, 4, and 6, ADR-030 decision 2
