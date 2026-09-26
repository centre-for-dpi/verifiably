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
| `TenantBackendService` | Served for organisations. The client credential RPCs answer `unimplemented`. |
| `NotificationBackendService` | Never served yet. The adapter sets no organisation webhook. It lists no webhooks. |

## The CREDEBL endpoints

| Endpoint | What the adapter does with it |
| --- | --- |
| `POST /v1/auth/signin` | Gets the bearer token of the platform administrator. |
| `GET /v1/orgs/{org}/oid4vc/{issuer}/template` | Reads the credential templates. |
| `POST /v1/orgs/{org}/schemas` | Stores one schema. |
| `POST /v1/orgs/{org}/oid4vc/{issuer}/template` | Stores one credential template. |
| `POST /v1/orgs/{org}/oid4vc/{issuer}/create-offer` | Builds a pre-authorized code offer. |
| `POST /v1/orgs` | Creates the organisation of a tenant. |
| `GET /v1/orgs` | Lists the organisations. The platform answers not found for none. |
| `GET /v1/orgs/{org}` | Reads one organisation with its agent and primary DID. |
| `DELETE /v1/orgs/{org}` | Removes the organisation of a tenant. |
| `GET /v1/orgs/{org}/dids` | Reads the DIDs of an organisation. |
| `GET /v1/orgs/{org}/users` | Reads the members of an organisation with their roles. |
| `POST /v1/orgs/{org}/agents/wallet` | Gives an organisation a wallet in the shared agent. |
| `POST /v1/orgs/{org}/agents/did` | Asks the agent for a new primary `did:key`. |
| `POST /v1/orgs/{org}/schemas` with the type `indy` | Writes an AnonCreds schema on a ledger. |
| `POST /v1/orgs/{org}/cred-defs` | Writes the credential definition of an AnonCreds schema. |
| `POST /v1/orgs/{org}/schemas` with the schema type `no_ledger` | Stores a W3C JSON-LD schema in the schema file server. |
| `GET /v1/platform/ledgers` | Reads the names of the ledgers. |
| `GET /v1/orgs/{org}/oid4vc/credential-offer/{id}` | Reads the issuance session of one offer. |
| `GET /v1/orgs/{org}/oid4vc/credential-offer` | Lists the issuance sessions, for the issued list. |
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
| Features | `FEATURE_CREDENTIAL_CONFIG_API`, `FEATURE_MULTI_TENANCY`, `FEATURE_ISSUER_IDENTITY_PROVISION`, `FEATURE_ISSUANCE_STATUS`, `FEATURE_ISSUED_LEDGER` |
| DID methods | `did:key` |
| Key types | `Ed25519`, `secp256r1`, `secp256k1` |
| Schema formats | AnonCreds on each ledger of the organisation, and W3C JSON-LD |
| Ledgers | The Indy ledgers where the organisation holds a DID, with the names of the platform |
| Status mechanisms | None. The platform embeds no status entry of VCA. |
| DPG information | The platform name, `main at 2026-09-26` with the digest of the api gateway, every platform service, the shared Credo agent, and Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. CREDEBL publishes from its main branch.
The stack file pins each image by the digest that `latest` named on
2026-09-26, beside the release tag of that image. A component shows the
tag and the first twelve digits of the digest. A test binds the adapter
to the stack file. A page shows a feature on this stack only when the
answer lists it (ADR-034).

CREDEBL is the only one of the three DPGs that reads DCQL.

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `Issue` | CREDEBL signs a credential only when a wallet claims an offer. |
| `IssueBatch` | CREDEBL has no batch credential endpoint. |
| `Revoke` | The platform revokes an OID4VC session only with a status list host. The stack file runs none, so the status services of VCA own the status bits. |
| Every holder RPC | CREDEBL ships no wallet for a citizen. |
| Every client credential RPC | The adapter makes no client credential of an organisation yet. The admin pages offer no stack credential. |
| `CreateTenant` with a dedicated agent | The platform starts a dedicated agent through the Docker socket. The stack file mounts none, so every tenant gets the shared agent. |
| `ImportIssuerIdentity` | The agent keeps every key and takes no key reference. Set another primary DID in the platform. |
| Issuing AnonCreds or W3C JSON-LD | The platform issues those formats over DIDComm. The adapter lists them as schema formats only. |
| A revocable credential definition | The adapter writes every credential definition without a revocation registry. |
| `ProvisionIssuerIdentity` for `did:indy` and `did:web` | The agent takes the private key in the request for those methods. The adapter never holds a key, so it makes `did:key` only. |
| Every webhook RPC | The adapter sets no organisation webhook. |
| `VerifyCredential` | The adapter does not send an uploaded credential to the platform. The scanner shows no stack check. |

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

**The platform admin comes from setup.** The API gateway runs the
migrations only. `vca dpg bootstrap credebl` runs the database
initialisation of the release once. That script makes the platform
admin from `PLATFORM_ADMIN_EMAIL` of `deploy/credebl/.env`, which setup
writes from `VCA_CREDEBL_PLATFORM_ADMIN_EMAIL`. Setup also generates
`CRYPTO_PRIVATE_KEY`, `CREDEBL_PLATFORM_ADMIN_PASSWORD`,
`PLATFORM_WALLET_PASSWORD` and `PLATFORM_SEED` there. No placeholder
user exists (ADR-055 decision 4).

**No published password reaches the platform.** The script reads the
platform admin password from the master table of the platform
repository. Setup writes a master table of its own with the generated
password. The stack file mounts it over the published one. The
password travels in the CryptoJS form without quotation marks. The
script hands the plain text to Keycloak as it is. The mail key stays
empty, and the user id is random. Setup writes the same password into
`VCA_CREDEBL_PASSWORD` of each CREDEBL pair.

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

**Organisations are the tenants.** A new tenant is an organisation with
a wallet in the shared agent and a primary `did:key` that the agent
makes. The adapter creates them in that order. When the wallet or the
DID fails, it deletes the organisation again. The tenant list leaves out
the organisation `Platform-admin`, which holds the shared agent. Delete
refuses that organisation and the organisation of the adapter.

**The adapter only reads the members.** The platform lists each person of an
organisation with the roles in every organisation. The adapter keeps the
roles of the organisation it reads.

**The issuer identity is the primary DID.** The identity lists the DIDs
of the organisation of the adapter, the primary DID first. A new
identity is a `did:key` that the agent makes and marks primary. The key
stays in the Askar wallet of the agent.

**An AnonCreds schema goes on the ledger of a DID.** The publish page
offers AnonCreds on each Indy ledger where the organisation of the
adapter holds a DID. The adapter writes the schema with that DID, at
version 1.0, and then its credential definition with the tag `default`.
The configuration id is the credential definition id. The platform needs
one required claim, so a JSON Schema with no required list makes every
claim required. `GetCapabilities` reads the DIDs once a minute at
most. A platform that does not answer lists no ledger.

**A W3C JSON-LD schema goes on no ledger.** The adapter stores it with
the schema type `no_ledger`. The schema file server of the stack keeps
the document, and the configuration id is its address.

**The state of an offer is the state of its session.** The offer id
is the id of the issuance session of the agent. A session in the state
`Completed` reads as issued, and its last change is the claim time. A session
in the state `Error` failed, with the message of the agent. Every other
session is pending until its end, and expired after it.

**The issued list reads the sessions.** The adapter lists the completed
sessions of a credential type, oldest first. A session matches when its
offer carries each attribute of the query with the same value. An entry
carries the session id, the type and the issue time, and no claim value.

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
