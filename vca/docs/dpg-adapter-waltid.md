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

The service serves five Connect services from `vca.backend.v1`:

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served when the configuration names an issuer URL. |
| `HolderBackendService` | Served when the configuration names a wallet URL. |
| `VerifierBackendService` | Served when the configuration names a verifier URL. |
| `CatalogBackendService` | Served when the configuration names an issuer URL. |

## The walt.id stack

The stack of release 0.18.2 has three HTTP services.

| Service | What the adapter calls |
| --- | --- |
| Issuer API | `POST /onboard/issuer`, `POST /openid4vc/{jwt,sdjwt,mdoc}/issue`, `GET /{draft}/.well-known/openid-credential-issuer` |
| Verifier API | `POST /openid4vc/verify`, `GET /openid4vc/session/{id}` |
| Wallet API | `POST /wallet-api/auth/{register,login}`, `GET /wallet-api/wallet/accounts/wallets`, the exchange endpoints, and the credential endpoints |

## What the adapter can do

The answer of `GetCapabilities` reports what the release supports.

| Item | Value |
| --- | --- |
| Formats | `jwt_vc_json`, `vc+sd-jwt`, `dc+sd-jwt`, `mso_mdoc` |
| Channels | OID4VCI pre-authorized code, OID4VCI authorization code |
| Protocols | OID4VCI, OID4VP, OID4VP with Presentation Exchange |
| Roles | The roles whose URL the configuration sets |
| Features | `FEATURE_CREDENTIAL_CONFIG_API` when the configuration names an issuer URL |
| DID methods | `did:key`, which the adapter onboards at first use |
| Status mechanisms | Bitstring status list and token status list, when the configuration names an issuer URL |
| DPG information | The stack name, the release, and one component per wired role plus Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. The versions come from the
configuration, and a test binds the defaults to the stack file. A page
shows a feature on this stack only when the answer lists it (ADR-034).

Release 0.18.2 has no DCQL query support, so the answer never lists
`PROTOCOL_OID4VP_DCQL`. The release has no document export, so the
answer never lists the PDF channel. The issuance service renders the
PDF itself.

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `Issue` | walt.id signs a credential only when a wallet claims an offer. |
| `IssueBatch` | walt.id has no batch credential endpoint. |
| `GetIssuanceStatus` | walt.id reports no issuer session state. |
| `Revoke` | walt.id has no revocation API. The status services own the bits. |

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
through an `httptest` fake. It runs in every build.

The contract set targets a real walt.id stack. It carries the build tag
`contract_waltid`. It skips itself when the variable
`VCA_WALTID_CONTRACT_ISSUER_URL` holds no value.

## Reference

- Service folder: `services/dpg-adapter-waltid`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decision 6, ADR-030 decision 2
