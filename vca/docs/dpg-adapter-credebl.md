# CREDEBL DPG adapter

The CREDEBL DPG adapter connects Verifiable Credentials Adapters to a
CREDEBL platform. It is one of the three DPG adapters of ADR-002
decision 1. The vendor name appears in this service and nowhere else.

## Why the service exists

CREDEBL is the largest of the three DPGs. It runs about twenty services
behind one api gateway. This adapter gives the rest of VCA one small
contract instead. It issues through the OID4VCI pre-authorized code
flow, and it checks presentations with DCQL queries.

## What it serves

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served. |
| `HolderBackendService` | Never served. CREDEBL ships no wallet for a citizen. |
| `VerifierBackendService` | Served. |
| `CatalogBackendService` | Served. |
| `TenantBackendService` | Never served yet. The adapter acts for the one configured organisation. It lists no multi tenancy. |
| `NotificationBackendService` | Never served yet. The adapter sets no organisation webhook. It lists no webhooks. |

## The CREDEBL endpoints

| Endpoint | What the adapter does with it |
| --- | --- |
| `POST /v1/auth/signin` | Gets the bearer token of the platform administrator. |
| `GET /v1/orgs/{org}/oid4vc/{issuer}/template` | Reads the credential templates. |
| `POST /v1/orgs/{org}/schemas` | Stores one schema. |
| `POST /v1/orgs/{org}/oid4vc/{issuer}/template` | Stores one credential template. |
| `POST /v1/orgs/{org}/oid4vc/{issuer}/create-offer` | Builds a pre-authorized code offer. |
| `POST /v1/orgs/{org}/oid4vp/verifier` | Creates the OID4VP verifier. |
| `POST /v1/orgs/{org}/oid4vp/presentation` | Starts an OID4VP transaction. |
| `GET /v1/orgs/{org}/oid4vp/verifier-presentation` | Reads the answer of a transaction. |

## What the adapter can do

The answer of `GetCapabilities` reports what the platform supports.

| Item | Value |
| --- | --- |
| Formats | `dc+sd-jwt`, `vc+sd-jwt` |
| Channels | OID4VCI pre-authorized code |
| Protocols | OID4VCI, OID4VP, OID4VP with DCQL |
| Roles | Issuer and verifier |
| Features | `FEATURE_CREDENTIAL_CONFIG_API` |
| DID methods | None. The organisation of the platform holds the issuer DID. |
| Status mechanisms | None. The platform embeds no status entry of VCA. |
| DPG information | The platform name, the image tag, the api gateway, agent provisioning, and Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. CREDEBL publishes no version tag, so
the default version is the image tag `latest` of the stack file. A
test binds the defaults to the stack file. A page shows a feature on
this stack only when the answer lists it (ADR-034).

CREDEBL is the only one of the three DPGs that reads DCQL.

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `Issue` | CREDEBL signs a credential only when a wallet claims an offer. |
| `IssueBatch` | CREDEBL has no batch credential endpoint. |
| `GetIssuanceStatus` | The api gateway reports no issuance session state. |
| `Revoke` | The status services own the status bits. |
| Every holder RPC | CREDEBL ships no wallet for a citizen. |
| Every tenant RPC | The adapter acts for the one configured organisation. |
| Every webhook RPC | The adapter sets no organisation webhook. |

Each of these answers with the Connect code `unimplemented` and a
sentence that names the alternative.

## Interoperability knowledge

The adapter carries the knowledge the legacy code proved in the field.

**The password travels in the CryptoJS form.** The sign in call takes
the password as AES 256 in cipher block chaining mode. The key
derivation is the OpenSSL one that uses MD5. The marker `Salted__` comes
first. CryptoJS encrypts the JSON form of the value, so the plain text
carries the quotation marks of a JSON string. The platform accepts no
other form.

**The token comes back once and lasts.** The adapter caches the token
until one minute before its end. A call that gets the status
unauthorized signs in again once and then gives up.

**A template reads back under another name.** CREDEBL stores the body of
a template in a column named `attributes`. A read returns the body under
that name, although a write sends it under the name `template`.

**The payload carries the claims of the template and nothing else.** The
platform checks the payload against the declared attributes. An extra
member, such as a subject identifier, makes the check fail. The
pre-authorized flow binds the subject to the key of the wallet. That
happens during the exchange, so the payload needs no identifier.

**A validity window fails the call.** The create offer endpoint has no
field for a window. The legacy code dropped the window without a word,
and the credential then verified as valid for ever. An operator who asks
for an end date now gets an error instead.

**The offer names the internal host.** The agent writes its own network
name into the offer, and a wallet outside the deployment cannot reach
that name. The adapter swaps the internal host for the public one. The
address sits in a query parameter, so the swap covers the percent
encoded form as well.

**The adapter creates the verifier once.** It creates the OID4VP
verifier at the first request. It then stores the identifier. After a
restart the create call gets the status conflict. The adapter then looks
the verifier up by its public name.

**A DCQL query arrives in two shapes.** The adapter reads the whole
request body with its `query` member, and the bare query as well.

## Tests

The recorded set replays answers of the CREDEBL 2.x api gateway from
`testdata` through an `httptest` fake. It runs in every build.

The contract set targets a real platform. It carries the build tag
`contract_credebl`. It skips itself when the variables hold no value.

## Reference

- Service folder: `services/dpg-adapter-credebl`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decision 6, ADR-022 decision 3, ADR-030 decision 2
