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
| A presentation during issuance without `VCA_INJI_PRESENTATION_DURING_ISSUANCE` | Certify checks the presentation with Inji Verify. A deployment outside the stack file can leave it unset. The adapter then answers `failed_precondition` and lists no `FEATURE_PRESENTATION_DURING_ISSUANCE`. The stack file points it there, and `vca setup` sets the value. |
| A presentation definition per offer | Certify 0.14.0 reads one definition for the deployment from `GET /iar/presentation-definition.json` of the adapter. The offer cannot name another. |
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

**The offer names the holder authorization server.** With
`VCA_INJI_AUTHZ_ISSUER` set, the authorization code offer names the
holder authorization server of the adapter. Its credential issuer is
`VCA_INJI_OFFER_ISSUER`, the Certify that takes the tokens of that
server. See "The holder authorization server" below. A deployment
outside the stack file can leave the server off. The offer then names
`VCA_INJI_AUTHORIZATION_SERVER`, else the first authorization server of
the Certify metadata.

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
its `authorization_server`, and the adapter hosts the offer. The offer
names the credential issuer of the Certify metadata, because only that
Certify takes the code. The answer
names the authorization code channel, also when the caller asked for
the pre-authorized one.

The offer names its holder in `presentation_subject` of the
`IssueSpec`: an identity claim of the presented credential and its
value. The claim must be one of `VCA_INJI_IAR_IDENTITY_CLAIMS`, which
defaults to `vcaSubject`. The adapter writes the claims of
`subject_data` into the claims store under that value. Certify makes
that claim of the presented credential the subject of its token. So
the data provider finds the row (ADR-051 decision 5).
An offer without a holder fails with `InvalidArgument`.

The issuer names the credential to present with
`SetPresentationRequirement`: a type, a format, the claims it must
carry, and a purpose. The adapter keeps it and serves the
presentation definition at `GET /iar/presentation-definition.json` on
the compose network. Certify reads it there at each interactive
authorization. Before the issuer sets one, the path answers 404, and
an offer with `require_presentation` fails with "configure the
credential to present first". The answer of the call lists the
identity claims of the stack. `GetPresentationRequirement` reads the
stored setting back. The card "Presentation during issuance" of
the issuer identity page calls both.

The setting `VCA_INJI_PRESENTATION_DURING_ISSUANCE` turns the feature
on. The stack file points Certify at Inji Verify through
`mosip.certify.verify.service.*` (P6-I4b). The issuer profile runs
Inji Verify for that, so `vca setup` sets the value to `true` for the
Inji issuer pair. A deployment outside the stack file sets it once its
Certify reaches an Inji Verify.

P6-I4b read the error path in the Certify 0.14.0 sources. Certify
answers 400 in two shapes:

| Case | Body |
| --- | --- |
| Inji Verify refused the presentation | `{"status":"error","code":null}` |
| A presentation without identity attributes, an unknown session, or another Certify error | `{"error":"invalid_request","error_description":"..."}` |

The wallet reads both. It claims nothing and shows the description
when Certify gives one.

## The two Certify containers

Certify 0.14.0 checks every access token against one issuer and one key
set. A deployment can take the tokens of its own authorization server
or the tokens of one other server, not both. So the stack file runs
Certify twice, on one database and one key store (ADR-049, P6-I0).

| Container | Authorization server | What reaches it |
| --- | --- | --- |
| `inji-certify` | Certify itself | Every call of the adapter: staging, `Issue`, the configuration API, the ledger, the keys, and a presentation during issuance |
| `inji-certify-authcode` | The holder authorization server of the adapter | A claim in Inji Web, and an authorization code offer |

`VCA_INJI_CERTIFY_URL` names `inji-certify`. `VCA_INJI_OFFER_ISSUER`
names `inji-certify-authcode` behind the nginx of the stack, and an
authorization code offer names it as the credential issuer. The second
container starts after the first one is ready, so it reads the keys the
first one made. `VCA_INJI_CERTIFY_PLUGINS` lists the plugins of both.

## The claims store

Both containers issue from the VCA claims store (ADR-051). Each runs
`PostgresDataProviderPlugin` of the digital credential plugins 0.6.0.
The plugin reads `sub` and `scope` of the access token. It runs the
query of that scope with `:id` set to `sub`. It returns the first row
with the column names as keys. The one query reads the foreign table
`certify.vca_claims`. `file_fdw` maps it onto every `*.csv` file of the
volume `inji-claims`.

The adapter writes one file per staged subject into
`VCA_INJI_CLAIMS_DIR`. The name of the file is the SHA-256 of the
subject, and it holds one row. The adapter writes a temporary file and
renames it, so the database never reads half a row. A sweep at each
write and every `VCA_INJI_CLAIMS_SWEEP` deletes a row when it expires.
The query of Certify reads only a row whose `expires_at` lies ahead.
So a row serves nothing past its end, even before the sweep (ADR-056
decision 3). The adapter opens no database connection.

| Column | What it holds |
| --- | --- |
| `subject` | The key of the row: the `sub` of the token |
| `config_id` | The credential configuration |
| `expires_at` | The end of the row: the end of the offer, or seven minutes after the sign in for the holder authorization server |
| `v_valid_from`, `v_valid_until` | The validity window |
| `v_status_uri`, `v_status_index` | The status list entry |
| `c1` to `c64` | The claims, in the order of the schema |

`RegisterCredentialConfiguration` keeps the claim order of each
configuration, and its template reads the columns. Every configuration
has the scope `vca_credential`, so one query serves every schema.
Certify picks the configuration from the request body. A schema with
more than 64 claims fails the registration. Every configuration
declares the optional claim `id`.

**The configuration guard.** A token with the scope `vca_credential`
authorizes every configuration of the scope. The wallet names the type
in its request. Certify fills the template of that type from the row
of the token subject. So each template opens with
`#if($config_id == '<id>')` and ends with `#end` (ADR-056 decision 1).
For a row of another configuration, the template renders nothing.
Certify then fails to read the credential as JSON and answers an
error. This holds for every channel, because every channel reads the
same table. The guard quotes the configuration id. So an id holds at
most 128 letters, digits, and the signs `. _ : + ~ -`. A template from an
earlier release has no guard. Publish every schema again after an
upgrade.

The key of a row follows the flow:

| Flow | Key |
| --- | --- |
| Pre-authorized code | The adapter stages `{"id": "<staging id>"}`. Certify puts that JSON text in `sub`. |
| Holder authorization server | The staging id of the row, which the adapter puts in its own token |
| Presentation during issuance | The value of the identity claim of the presented credential |

A configuration that an earlier release registered has no claim order.
Publish the schema again, and the adapter registers it anew.

## The holder authorization server

Certify 0.14.0 trusts the tokens of one authorization server per
container. `inji-certify-authcode` trusts the holder authorization
server of the adapter (ADR-052). The server lives under
`VCA_INJI_AUTHZ_ISSUER`, the public URL of the issuer pair with
`/authz`. The proxy of the pair publishes it. It is plain HTTP, not
Connect.

| Path | What it does |
| --- | --- |
| `GET /authz/.well-known/oauth-authorization-server` | RFC 8414 metadata: the code grant, PKCE S256, the client methods `none` and `private_key_jwt`, and the scope `vca_credential` |
| `GET /.well-known/oauth-authorization-server/authz` | The same metadata where RFC 8414 section 3 puts it. `/.well-known/openid-configuration/authz` and `/authz/.well-known/openid-configuration` serve it too. |
| `GET /authz/.well-known/jwks.json` | The public token key. Its `kid` is the RFC 7638 thumbprint. |
| `GET /authz/authorize` | Checks the client, the redirect URI, the state, and the PKCE challenge. Then it sends the browser to the holder provider. |
| `GET /authz/callback` | Finishes the sign in, finds the claims, writes the claims row, and sends the wallet a one time code |
| `POST /authz/token` | Checks the client, the code, the redirect URI, and the PKCE verifier. Then it returns an RS256 access token. |

The token names the staging id of the claims row in `sub`. Its `aud`
is the credential endpoint of `inji-certify-authcode`. It also carries
the scope `vca_credential`, the client, and a `c_nonce`. It lives five minutes.
Certify reads the key set on the compose network, at
`INJI_ADAPTER_URL`.

**How long the data stays.** The claims row of a sign in lives for the
code, the token, and one more minute: seven minutes in all. Certify does
not tell the adapter that it issued. So a wallet can ask for the
credential more than once while its token lives. An offer keeps its
subject until the holder gets the token. It then keeps only its
document. The sweep deletes every offer when it expires, claimed or not
(ADR-056 decisions 3 and 4).

**Bounds and rate limits.** The server refuses a query over 8 KiB, a
`client_id` over 128 bytes, a `state` over 512 bytes, a `scope` over
1 KiB, and `authorization_details` over 4 KiB. An `issuer_state` must
look like an offer id. The server checks all this before it reads or
writes the store. Each source can send one sign in request a second,
20 at once. Authorize takes 20 requests a second from all sources
together. The token endpoint and the metadata take 20 a second per
source. A request over a limit gets 429. The source is the last entry
of `X-Forwarded-For` that the proxy sets. The sign in sources sit in
one document, so no request walks the store (ADR-056 decision 5).

**Which claims.** A request that names an offer in `issuer_state`
issues the claims of that offer. The issuer set a binding rule in the
wizard: a claim of the ID token must equal a claim of the credential.
The default rule compares the email of both. A mismatch answers
`access_denied` with "This offer is for another person." An offer
opens once.

**Vouched claims only.** A binding rule and a sign in source match only
a claim that the provider vouches for (ADR-056 decision 2):

| Claim | Matches when |
| --- | --- |
| `email` | `email_verified` is `true`. A missing flag counts as unverified. Only ASCII letters compare without case. |
| `phone_number` | `phone_number_verified` is `true` |
| `sub` | Always. It is the account at the provider. |
| Any other claim | The provider record lists it in `verified_claims` |

A user name or an attribute that the holder picks never binds. List a
claim only for a provider that proves it, such as an eSignet with a
real authenticator. The admin portal edits the list under "Holder sign
in claims" of the login providers page. The adapter serves the provider
RPCs of `vca.admin.v1.AdminService` on the compose network for it. They
take a session that the admin key set at `VCA_INJI_ADMIN_JWKS_URL`
signed. The proxy of the pair publishes no path to them. The wizard
offers `email`, `sub` and `phone_number`, and it warns about any claim
other than `email` and `sub`.

**The holder realm.** Setup makes the holder realm of the Inji stack
check the email of each user (`verifyEmail`). Keycloak then sends a
mail before a self registered holder can sign in. Give the realm a
mail server under Realm settings, Email. Without one, turn off self
registration and add each holder yourself:
`vca dpg realm --role holder --dpg inji --registration off`.
A request without an offer uses the holder sign in source of the
credential. The source names a data source, the field that identifies
the person, and the ID token claim with the value. The adapter asks
`DataSourceService.Lookup` for the row. No source answers
`access_denied` with "Claim this credential from an offer of the
issuer." With more than one source, the request names its credential in
`authorization_details`.

The issuer sets the sign in source in the tab "Claims by sign in" of
the schema pages. The tab calls `GetHolderSignInSource` and
`SetHolderSignInSource` of the adapter. The adapter stores a source
only for a claim that the holder provider vouches for. The adapter
lists `FEATURE_HOLDER_SIGN_IN_SOURCE` when the server runs with
`VCA_INJI_DATA_SOURCE_URL`. The adapter calls `Lookup` with a token
that it derives from the pair session key. The data source service
opens `Lookup` for that token and for no other call (ADR-057). The
source must name the role `holder-sign-in` on its `issue` rule. The tab
adds it when staff save.

**The holder provider.** The adapter keeps a provider registry in its
store. Setup seeds it with the holder realm of the stack Keycloak and
the public client `vca-inji-authz`. The server takes the enabled
provider of the holder role for the Inji stack, the default one first.
The admin portal adds, edits, turns off and removes providers through
the provider RPCs of the adapter (`docs/admin.md`). The realm record
of setup stays the default until an admin marks another provider. A
record of setup that an admin removes stays away after a restart. An edit keeps the scopes and
the internal address of a record while its discovery URL stays.

The pair can run eSignet with a real authenticator. Then setup also
names the VCA client of eSignet and its key (ADR-053 decision 4). The
adapter adds the record `esignet` of kind `esignet` with the default
flag. The key in `VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY` signs the client
assertion. The record keeps only the name of that variable. The token
call and the key set go to eSignet on the compose network. The
audience of the assertion is the token endpoint that eSignet
publishes. The first start with eSignet turns
the seeded realm off, so holders sign in at eSignet. An admin can turn
the realm on again, and a later start keeps that choice.

**Claims from userinfo.** eSignet returns the claims of a person only in
its signed userinfo answer. The ID token carries the pairwise `sub`
alone. The server reads userinfo with the access token of the sign in.
It calls only when the ID token does not vouch for the claim of the
rule. A JWT answer needs a signature of a key in the key set of the
provider. Its `iss` must name the provider
and its `aud` the client whenever the answer carries them. The
authenticator plugins of eSignet 1.5.1 sign without `iss` and `aud`. So
the server takes such an answer from its own call over the channel of
the provider. Its `sub` must equal the `sub` of the ID token, or no claim
counts. The server refuses an encrypted answer, and plain JSON from any
other provider works too. Only a claim the provider vouches for joins
the claims of the ID token. That is `email` or `phone_number` with its
flag true, or a claim the provider record lists. A claim of the ID token
always wins. The eSignet client of `vca dpg bootstrap` asks for `name`,
`email` and `phone_number`. Add another claim to that client in eSignet
before you list it.

**Wallet clients.** `VCA_INJI_WALLET_CLIENTS` lists them as JSON:
`client_id`, `redirect_uris`, and an optional public `jwk`. A client
with a key signs a client assertion. A client without one is public and
relies on PKCE. Setup registers `vca-inji` for Inji Web once the holder
bootstrap wrote its public key. Run `vca setup` and `vca deploy` for the
issuer pair after `vca dpg bootstrap inji --role holder`.

**The token key.** The adapter makes a 2048 bit RSA key at the first
start. It keeps the key in its store under AES-256-GCM. The sealing key
comes from the pair session key through HKDF-SHA256. Another session key
cannot open it, so the start fails. The key signs access tokens only.

The store holds a key ring (ADR-056 decision 6). `vca dpg
rotate-authz-key inji` adds a key. The key set lists the new key at
once, and the new key signs six minutes later. Certify keeps the key set
five minutes, so it knows the key first. The old key leaves the key set
when its last token expires. `--now` signs with the new key at once and
drops the old key. The key set allows a cache of one minute. Each sweep
reads the ring again, so every replica follows a rotation. The key of an
earlier release moves into the ring at the first start.

| Setting | What it sets |
| --- | --- |
| `VCA_INJI_AUTHZ_ISSUER` | The issuer. Empty turns the server off. It needs a path. |
| `VCA_INJI_AUTHZ_KEY_SECRET` | The pair session key. Setup copies `VCA_SECRETS_SESSION_KEY`. |
| `VCA_INJI_AUTHZ_AUDIENCE` | The credential endpoint in `aud`. The default follows `VCA_INJI_OFFER_ISSUER`. |
| `VCA_INJI_WALLET_CLIENTS` | The wallet clients |
| `VCA_INJI_HOLDER_OIDC_DISCOVERY_URL`, `VCA_INJI_HOLDER_OIDC_CLIENT_ID`, `VCA_INJI_HOLDER_OIDC_PUBLIC_URL`, `VCA_INJI_HOLDER_OIDC_INTERNAL_AUTHORITY` | The seeded holder provider |
| `VCA_INJI_HOLDER_ESIGNET_CLIENT_ID`, `VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY` | The VCA client of eSignet and the base64 text of its RSA key. With `VCA_INJI_ESIGNET_URL` too, the adapter adds eSignet as a holder provider. Set both or neither. |
| `VCA_INJI_HOLDER_OIDC_VERIFIED_CLAIMS` | The claims beyond `email`, `phone_number` and `sub` that the holder provider verifies, comma separated. A start writes them into the seeded record while it lists none. After that the admin portal owns the list. |
| `VCA_INJI_ADMIN_JWKS_URL` | The key set of the admin pair. The admin portal edits the provider registry of the server with a session it signed. Empty serves no provider RPC. |
| `VCA_INJI_DATA_SOURCE_URL` | The data source service of a claim without an offer |

### Threat model

| Threat | Guard |
| --- | --- |
| A flood of authorization requests fills the volume | Each parameter has a bound. Each source and authorize as a whole have a rate limit. A sign in record lives ten minutes. |
| A copy of the volume gives the subjects of old offers | An offer drops its subject when the holder gets the token. The sweep deletes it when it expires. A row lives seven minutes. |
| A row serves after its token ended | The query of Certify reads only a row whose `expires_at` lies ahead. |
| A code or an error goes to an address of an attacker | The redirect URI must equal a registered one, byte for byte. An unknown client or a wrong redirect URI gets an error page and no redirect. |
| A stolen code works | PKCE S256 binds the code to the verifier of the wallet. The code works once, for one minute, for its client and its redirect URI. A code that comes back removes the claims row of its first token. |
| A leaked code ends the claim of the holder | A code that fails before any token removes its row and opens its offer again. The holder then claims once more. The server logs it at Warn with the offer id (ADR-056 decision 4). |
| The plain PKCE method weakens the check | The server takes S256 only. |
| A forged callback or a login CSRF | The server keeps each sign in under its random state. A callback with another state, or a second callback, fails. The provider checks the nonce of its ID token. |
| Somebody forges or replays a client assertion | Its signature must match the registered key. Its `iss` and `sub` name the client, its `aud` names the token endpoint or the issuer, and its `exp` falls within ten minutes. Its `iat` and `nbf` lie no more than a minute ahead, and it lives ten minutes at most from `iat`. Each `jti` works once. |
| One claim value stops the claims store for every holder | A value with invalid UTF-8 fails at `CreateOffer`. So does a control character other than a tab or a line break. The writer refuses such a row too (ADR-056 decision 7). |
| Another person claims an offer | The binding rule compares a claim of the ID token with a claim of the credential. The claim must be one that the provider vouches for. An email without `email_verified` true never matches. |
| A holder registers the user name or the attribute of another person | Such a claim never binds unless the provider record lists it as verified. The holder realm verifies every email. |
| A look alike address matches | Only ASCII letters of an email compare without case, so the Kelvin sign is not `k`. |
| A copy of the store gives codes or keys | The store keeps the SHA-256 of each code, state, and `jti`. The token key sits under AES-256-GCM with the pair session key. |
| A token key leaks | `vca dpg rotate-authz-key inji --now` replaces it without a restart. The rotation needs a token derived from the pair session key, and the proxy does not publish it. |
| A token reaches another service | `aud` names the credential endpoint of one Certify. The token lives five minutes and carries the scope `vca_credential` only. |
| A token for one credential asks for another type | The template of every configuration renders only a row of that configuration (ADR-056 decision 1). A row of one type gives no credential of another type. |
| A mix up of servers | The redirect carries `iss` (RFC 9207). |
| A wallet that follows RFC 8414 finds no server | The proxy publishes the metadata at the inserted and the appended paths, for both well-known names. |

What stays open: the tokens are bearer tokens, so the server offers no
DPoP. A credential without an offer depends on the sign in source that
the issuer configures. `vca dpg bootstrap` writes the realm clients
through the client API of Keycloak, because a realm update ignores
clients.

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

The code carries the identity claims in the clear. So an SD-JWT entry
names `$.identityQR` in `sdClaim`, and the code travels only to a
verifier that asks for it (ADR-081). Certify 0.14.0 reads `sdClaim` as
JSON paths from the root, split at commas, in
[VelocityTemplatingEngineImpl](https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/vcformatters/VelocityTemplatingEngineImpl.java)
and [SDJsonUtils](https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/utils/SDJsonUtils.java).
The adapter writes each selectively disclosable claim `fullName` as
`$.fullName`. A bare name matches no path, and the claim would travel
in the clear. A JSON-LD credential has no selective disclosure. The
wallet consent screen lists its `identityQR` as always sent.

`Issue` reads the claim back from the credential. It checks the text
with the Claim 169 decoder of `core/ingest` and returns it in
`claim169_qr`. The issuance service prints it on a document for the
channel `CHANNEL_CLAIM169_QR`.

Some Claim 169 writers spell the date key `Date Of Birth`. The mapper
knows `Date of Birth`. The adapter uses the mapper name, so the date
gets the key 8.

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
| Claim in Inji Web | The issuer list names the holder authorization server of the issuer pair. Mimoto trades the code at the adapter on the compose network. Its client assertion names the public token endpoint. `vca dpg bootstrap` writes the key of `vca-inji` into the client key store, and its public half into `vca-inji.jwk.json` beside it. |
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

`hack/contract-tests.sh` makes a test holder and writes claims rows. So
it runs against a test deployment only. It refuses to run unless the
deploy root holds `contract.env` with the line
`VCA_CONTRACT_DEPLOYMENT=test`. Write that file on a test deployment
only. The script also refuses a deploy root with the example
identities of an old release, or with their identity system.
`hack/contract-tests_test.sh` tests both refusals.

The holder case signs a test holder in at the holder realm of the stack
Keycloak. `hack/contract-tests.sh` makes that holder when the job gives
none. It signs in to the Keycloak admin API as the administrator of
`deploy/vca/keycloak-inji/.env`. It makes the user `contract-holder`
with a random password and a random six digit wallet PIN. A second run
finds the user and sets the same password again.

The script keeps the password, the PIN, and the redirect URI of the
holder pair in `deploy/vca/mimoto-inji/contract-holder.env` with mode
0600. It then sets the four `VCA_INJI_CONTRACT_HOLDER_*` variables for
the test run. A variable that the job gives wins over the file.

| Variable | Default |
| --- | --- |
| `VCA_CONTRACT_DEPLOY_DIR` | `deploy/vca` of the repository. It must hold `contract.env`. |
| `VCA_CONTRACT_KEYCLOAK_URL` | `http://127.0.0.1:17080`, the host port of the stack Keycloak |
| `VCA_CONTRACT_PREPARE_ONLY` | empty; `1` makes the holder and runs no test |

## Reference

- Service folder: `services/dpg-adapter-inji`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decisions 3, 4, and 6, ADR-030 decision 2
