# walt.id DPG adapter

The walt.id DPG adapter connects Verifiable Credentials Adapters to the
walt.id Community Stack. It is one of the three DPG adapters of ADR-002
decision 1. The vendor name appears in this service and nowhere else.

## Why the service exists

The legacy code had one adapter interface with 25 methods. Every vendor
had to answer every method, and most answers were a "not supported"
error. ADR-002 decision 2 replaces that interface with one small service
per role. This adapter serves the roles that walt.id supports. It
answers `unimplemented` for every other role.

## What it serves

The service serves seven Connect services from `vca.backend.v1`:

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served when the configuration names an issuer URL. |
| `HolderBackendService` | Served when the configuration names a wallet URL. |
| `VerifierBackendService` | Served when the configuration names a verifier URL or a verifier 2 URL. |
| `CatalogBackendService` | Served when the configuration names an issuer URL. |
| `TenantBackendService` | Never served. The community stack keeps no tenants. |
| `NotificationBackendService` | Never served. The community stack keeps no tenants to hold a webhook. |

## The walt.id stack

The stack of release 0.18.2 has four HTTP services.

| Service | What the adapter calls |
| --- | --- |
| Issuer API | `POST /onboard/issuer`, `POST /openid4vc/{jwt,sdjwt,mdoc}/issue`, `GET /{draft}/.well-known/openid-credential-issuer` |
| Verifier API | `POST /openid4vc/verify`, `GET /openid4vc/session/{id}` |
| Verifier API 2 | `POST /verification-session/create`, `GET /verification-session/{id}/info` |
| Wallet API | `POST /wallet-api/auth/{register,login}`, `GET /wallet-api/wallet/accounts/wallets`, the exchange endpoints, and the credential endpoints |

## What the adapter can do

The answer of `GetCapabilities` reports what the release supports.

| Item | Value |
| --- | --- |
| Formats | `jwt_vc_json`, `vc+sd-jwt`, `dc+sd-jwt`, `mso_mdoc` |
| Channels | OID4VCI pre-authorized code, OID4VCI authorization code |
| Protocols | OID4VCI and OID4VP. A verifier URL adds Presentation Exchange. A verifier 2 URL adds DCQL. |
| Roles | The roles whose URL the configuration sets |
| Features | `FEATURE_CREDENTIAL_CONFIG_API`, `FEATURE_ISSUER_IDENTITY_PROVISION`, `FEATURE_ISSUER_IDENTITY_IMPORT_DID`, and `FEATURE_ISSUER_IDENTITY_IMPORT_X509` when the configuration names an issuer URL |
| DID methods | `did:web`, `did:key`, `did:jwk`, `did:cheqd` |
| Key types | `Ed25519`, `secp256r1`, `secp256k1`, `RSA`. With a key store: `Ed25519`, `secp256r1`, `RSA`. |
| Status mechanisms | Bitstring status list and token status list, when the configuration names an issuer URL |
| DPG information | The stack name, the release, and one component per wired role plus Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. The versions come from the
configuration, and a test binds the defaults to the stack file. A page
shows a feature on this stack only when the answer lists it (ADR-034).

The Verifier API reads a Presentation Exchange definition only. Verifier
API 2 of the same release reads a DCQL query over OID4VP 1.0. The stack
file runs both in the `verifier-waltid` profile, and the CLI gives the
verifier pair `VCA_WALTID_VERIFIER2_URL`. The answer then lists
`PROTOCOL_OID4VP_DCQL`. The release has no document export, so the
answer never lists the PDF channel. The issuance service renders the
PDF itself.

## Requests through Verifier API 2

`CreateRequest` sends a DCQL query to Verifier API 2 as a cross device
session. The body carries the query as the caller wrote it. The check
names map onto the `vc_policies` of Verifier API 2:

| Check name | Policy of Verifier API 2 |
| --- | --- |
| `signature` | `signature` |
| `expired` | `expiration` |
| `not-before` | `not-before` |
| The webhook URL | `webhook` with the URL |

The adapter leaves `status-list` out. The VCA policy service checks the
status of every credential itself. A Presentation Exchange definition
still goes to the Verifier API.

The state of a Verifier API 2 session starts with `v2:`. `GetResult`
reads `/verification-session/{id}/info` for such a state:

| Session status | Result state |
| --- | --- |
| `SUCCESSFUL` | Accepted |
| `FAILED` | Rejected |
| `EXPIRED` | Expired |
| Any other status | Pending |

The presented credentials come from `presented_raw_data`. The format of
each comes from the DCQL query of the session. The checks come from
`policy_results`.

## The Digital Credentials API

With a verifier 2 URL the answer lists `FEATURE_DC_API_VERIFY` and
`PROTOCOL_DC_API`. A `CreateRequest` with `dc_api` and the expected
origins starts two sessions of the same query:

| Session | Flow type | What the page gets |
| --- | --- | --- |
| The browser session | `dc_api_openid4vp` with `expectedOrigins` | The request object in `dc_api_request` |
| The fallback session | `cross_device` | The request URI of the QR code |

The state names both sessions. `SubmitBrowserAnswer` posts the answer of
the browser to `/verification-session/{id}/response` of the browser
session. `GetResult` reads both sessions. The first session with an
answer decides. The request expires when both expire.

## Issuance sessions and callbacks

The issue request can carry the header `statusCallbackUri`. The issuer
API of 0.18.2 then posts each event of the session to that URL. The body
is `{"id", "type", "data"}`. The events are:

| Event | What the adapter does |
| --- | --- |
| `resolved_credential_offer`, `requested_token` | The offer stays pending. |
| `jwt_issue`, `sdjwt_issue`, `generated_mdoc` | The adapter marks the offer issued. It keeps the credential and the time. |
| `issuance_status` `SUCCESSFUL` | The adapter marks the offer issued. |
| `issuance_status` `UNSUCCESSFUL` | The offer failed, with the reason of walt.id. |
| `issuance_status` `EXPIRED` | The offer expired. |

An issued offer stays issued. `VCA_WALTID_CALLBACK_URL` is the address
of the adapter on the compose network, and the CLI writes it for the
issuer pair. With it the answer lists `FEATURE_ISSUANCE_STATUS` and
`FEATURE_SESSION_CALLBACKS`. `CreateOffer` then gives each offer its
own id and a random token of 128 bits. The callback URL is
`<VCA_WALTID_CALLBACK_URL>/callbacks/issuance/<offer>/<token>`. The
adapter keeps the SHA-256 of the token and compares it in constant
time. A wrong token or an unknown offer answers 404. The route is no
public route of the pair, so only the stack on the compose network
reaches it (ADR-047).

`GetIssuanceStatus` reads the state of an offer. The issued credentials
page then shows "Offered, not claimed" for an offer no wallet claimed.
The claimed credential carries the status entry that `CreateOffer` put
in the offer. Revocation stays with the status services of VCA.

## The wallet of the stack

With a wallet URL the answer lists `FEATURE_WALLET_KEYS`,
`FEATURE_WALLET_DIDS`, `FEATURE_WALLET_EVENTS`, and
`FEATURE_WALLET_REJECT_OFFER`. It lists the key types and the DID
methods of the wallet in `wallet_key_types` and `wallet_did_methods`.

| RPC | What the adapter calls |
| --- | --- |
| `ListKeys` | `GET /wallet-api/wallet/{wallet}/keys` |
| `CreateKey` | `POST /wallet-api/wallet/{wallet}/keys/generate` with a `jwk` key of the type |
| `ListDids` | `GET /wallet-api/wallet/{wallet}/dids` |
| `CreateDid` | `POST /wallet-api/wallet/{wallet}/dids/create/{method}` with the key id and the name |
| `SetDefaultDid` | `POST /wallet-api/wallet/{wallet}/dids/default` |
| `RejectOffer` | `useOfferRequest` with `requireUserInput=true`, then `POST .../credentials/{id}/reject` with the note |
| `ListEvents` | `GET /wallet-api/wallet/{wallet}/eventlog`, newest first |

The wallet API has no decline of an offer as such. It takes an offer
as pending credentials, and the adapter rejects each of them at once.
No declined credential reaches the wallet.

The wallet offers `did:key`, `did:jwk`, and `did:cheqd`. A `did:web`
needs a host that the holder serves, so the adapter does not offer it.

`AcceptOffer` sends the transaction code as `pinOrTxCode`. The wallet
API of 0.18.2 redeems a pre-authorized code only. It takes no access
token of the issuer. A request with an `authorization_grant` for an
offer without a pre-authorized code answers `failed_precondition`.

## The issuer identity

The identity page of the issuer calls three RPCs (ADR-046).

| RPC | What the adapter does |
| --- | --- |
| `GetIssuerIdentity` | Returns the DID or the X.509 chain, the key type, the key store, the metadata, and the DID document. |
| `ProvisionIssuerIdentity` | Posts `/onboard/issuer` with the method and the key type of the request. A `did:web` names the host of the pair. |
| `ImportIssuerIdentity` | Binds a DID or an X.509 chain to a walt.id key object. The key object can name an external key store. |

The community release takes the key in each issuance request. So the
adapter keeps the identity in the file that
`VCA_WALTID_IDENTITY_FILE` names, with mode 0600, and reads it at
start (ADR-046 decision 4). Compose and Helm put the file in the data
volume of the adapter. The file has the shape of the onboarding answer.
`vca dpg bootstrap waltid` calls `ProvisionIssuerIdentity`, so the key
goes from the stack into this file and never into the deploy directory. A key of an
external key store keeps the private key out of the adapter.

### Methods, key types, and the key store

`ProvisionIssuerIdentity` takes every pair of a listed method and a
listed key type, with one rule. A `did:cheqd` needs an `Ed25519` key.
walt.id registers a `did:cheqd` through the public cheqd registrar. The
issuer API then needs a route to the internet.
`VCA_WALTID_CHEQD_NETWORK` picks `testnet` or `mainnet`.

An external key store keeps the private key out of the adapter. Set
these variables to make every new key in the HashiCorp Vault transit
engine of walt.id, the key store `tse`:

| Variable | Meaning |
| --- | --- |
| `VCA_WALTID_KMS_BACKEND` | `tse` |
| `VCA_WALTID_KMS_SERVER` | The transit URL, such as `http://vault:8200/v1/transit` |
| `VCA_WALTID_KMS_TOKEN` | A token of the key store. It is a secret. |
| `VCA_WALTID_KMS_ROLE_ID`, `VCA_WALTID_KMS_SECRET_ID` | An AppRole login in place of the token |
| `VCA_WALTID_KMS_NAMESPACE` | The namespace, when the key store uses one |

The onboarding request then names the key store and its settings. The
answer holds a key reference with the login of the key store, and no
private key. The identity file keeps that reference with mode 0600. The
transit engine makes no `secp256k1` key, so the answer lists the three
other key types. A request can still name `jwk` for a local key.

An import checks that a jwk key belongs to a `did:key` or a `did:jwk`.
An X.509 import sends the chain as `x5Chain` in each issuance request.
`VCA_WALTID_ISSUER_KEY` and `VCA_WALTID_ISSUER_DID` pin the identity.
With a pinned identity, provision and import answer
`failed_precondition`. Without any identity, the first offer onboards a
`did:key` and keeps it in the file.

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `Issue` | walt.id signs a credential only when a wallet claims an offer. |
| `IssueBatch` | walt.id has no batch credential endpoint. |
| `GetIssuanceStatus` without `VCA_WALTID_CALLBACK_URL` | The adapter learns the state of an offer from the callbacks of walt.id only. |
| `Revoke` | The community stack hosts no status list and has no revocation API. The status services of VCA own the bits. The answer lists no `FEATURE_REVOCATION`. |
| Every tenant RPC | The community stack keeps no tenants. |
| Every webhook RPC | The community stack keeps no tenants to hold a webhook. |
| `VerifyCredential` | The adapter does not send an uploaded credential to the verifier of the stack. The scanner shows no stack check. |
| `AcceptOffer` with a sign in grant | The wallet API of 0.18.2 redeems a pre-authorized code only. The adapter answers `failed_precondition`. |

Each of these answers with the Connect code `unimplemented` and a
sentence that names the alternative.

## Interoperability knowledge

The adapter carries the knowledge the legacy code proved in the field.

**One issue path per format.** Release 0.18.2 routes the JWT issuer, the
SD-JWT issuer, and the mdoc issuer to three paths. The adapter picks the
path from the format of the credential configuration.

**SD-JWT claims sit at the payload root.** The walt.id disclosure map
matches the claim names at the root of the credential body. A body in
the W3C shape would make only `credentialSubject` disclosable, and the
holder could then hide nothing.

**The disclosure map is not optional.** Without it walt.id writes every
claim into the signed token in the clear.

**A status list index is a string.** The W3C Bitstring Status List entry
carries `statusListIndex` as a string. A verifier rejects a number here.

**The status check needs arguments.** The walt.id policy
`credential-status` needs a discriminator. An SD-JWT uses `ietf`. A W3C
credential uses `w3c`. Its `type` argument holds `BitstringStatusList`.
That value names the type of the list. It does not name the type of the
entry in the credential.

**The adapter sends the whole input descriptor.** A short request of the
shape `{format, vct}` makes walt.id build its own presentation
definition, which the wallet cannot read.

**The adapter never writes the walt.id catalog file.** The legacy code
wrote the walt.id configuration file. It then restarted the container
through the Docker socket. ADR-002 decision 4 forbids both acts. The
adapter instead records the credential type of the schema. It then signs
the credential through a walt.id configuration of the same format. The
signed credential carries the type of the schema, because walt.id signs
the credential body it receives.

**The wallet account comes from the pairwise subject.** The adapter
builds the wallet account name and password from a one way function of
the pairwise subject. A restart then finds the same wallet. The citizen
keeps the credentials they hold. The account mail domain is
`wallet.invalid`. Nobody can register that domain, so no message leaves
the deployment.

**A comparison finds the claimed credential.** walt.id does not echo the
identifier of a claimed credential. The adapter lists the wallet before
the claim and after it. It then returns the credential the wallet
gained.

## Tests

The service has two test sets.

The recorded set replays answers of walt.id 0.18.2 from `testdata`
through an `httptest` fake. It runs in every build. The files under
`testdata/doc` follow the upstream documentation. `testdata/doc/SOURCE.md`
names the page and the date of each. The nightly contract run replaces
them with recordings.

The contract set targets a real walt.id stack. It carries the build tag
`contract_waltid`. It skips itself when the variable
`VCA_WALTID_CONTRACT_ISSUER_URL` holds no value. The DCQL case also
needs `VCA_WALTID_CONTRACT_VERIFIER2_URL`.

## Reference

- Service folder: `services/dpg-adapter-waltid`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decision 6, ADR-030 decision 2
