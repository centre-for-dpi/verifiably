# CREDEBL DPG adapter

The CREDEBL DPG adapter connects Verifiable Credentials Adapters to a
CREDEBL platform. It is one of the three DPG adapters of ADR-002
decision 1. The vendor name appears in this service and nowhere else.

## Why the service exists

CREDEBL is the largest of the three DPGs. It runs about twenty services
behind one api gateway. This adapter gives the rest of VCA one small
contract instead. It issues SD-JWT credentials through the OID4VCI
pre-authorized code flow, and AnonCreds and W3C JSON-LD credentials
over DIDComm. It hands a CSV file to the bulk import of the platform.
It checks presentations with DCQL queries over OID4VP. It asks for
AnonCreds and DIF Presentation Exchange proofs over DIDComm. It keeps a
DIDComm wallet for each holder in the shared agent of the stack.

## What it serves

| Service | State |
| --- | --- |
| `CapabilityService` | Always served. |
| `IssuerBackendService` | Served. |
| `HolderBackendService` | Served with the address and the API key of the shared agent: a DIDComm wallet per holder (ADR-062). |
| `VerifierBackendService` | Served: OID4VP with DCQL, and DIDComm proof requests. |
| `CatalogBackendService` | Served. |
| `TenantBackendService` | Served for organisations, with one client credential per organisation (ADR-067) and the ecosystems (ADR-068). |
| `NotificationBackendService` | Served: the webhook of an organisation and its holder notification address (ADR-067). |
| `BulkImportBackendService` | Served when the stack names a mail provider. The platform mails each row of a file an offer. |

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
| `PUT /v1/orgs/{org}/primary-did` | Makes one DID of an organisation its primary DID. |
| `POST /v1/orgs/{org}/schemas` with the type `indy` | Writes an AnonCreds schema on a ledger. |
| `POST /v1/orgs/{org}/cred-defs` | Writes the credential definition of an AnonCreds schema. |
| `POST /v1/orgs/{org}/schemas` with the schema type `no_ledger` | Stores a W3C JSON-LD schema in the schema file server. |
| `GET /v1/orgs/{org}/schemas` | Finds a schema that an earlier registration wrote, by name. The platform answers not found for none. |
| `GET /v1/orgs/{org}/schemas/{schema}/cred-defs` | Finds the credential definition of an AnonCreds schema. The platform answers not found for none. |
| `GET /v1/platform/ledgers` | Reads the names of the ledgers. |
| `GET /v1/orgs/{org}/oid4vc/credential-offer/{id}` | Reads the issuance session of one offer. |
| `GET /v1/orgs/{org}/oid4vc/credential-offer` | Lists the issuance sessions, for the issued list. |
| `POST /v1/orgs/{org}/openid4vc/issuance-sessions/{id}/revoke` | Revokes the credentials of one issuance session in the status list of the stack. |
| `POST /v1/orgs/{org}/credentials/oob/offer` | Makes an out of band invitation that carries a DIDComm offer. |
| `POST /v1/orgs/{org}/credentials/offer` | Sends a DIDComm offer over a connection of the organisation. |
| `POST /v1/orgs/{org}/credentials/oob/email` | Has the platform mail an out of band invitation with a QR code. |
| `GET /v1/orgs/{org}/connections` | Lists the DIDComm connections. The platform answers not found for none. |
| `GET /v1/orgs/{org}/credentials/{id}` | Reads the credential exchange of one DIDComm offer. |
| `POST /v1/orgs/{org}/bulk/upload` | Hands a filled CSV file to the platform, which checks it and keeps its rows for a limited time. |
| `GET /v1/orgs/{org}/{upload}/preview` | Reads one page of the rows of an upload. |
| `POST /v1/orgs/{org}/{upload}/bulk` | Starts the issue of every row of an upload. The platform mails each row an out of band offer. |
| `GET /v1/orgs/{org}/bulk/files` | Lists the issued files with their state and counts. The platform answers not found for none. |
| `GET /v1/orgs/{org}/{file}/bulk/file-data` | Reads the rows of one issued file with the reason of each failure. |
| `POST /v1/orgs/{org}/{file}/retry/bulk` | Issues the failed rows of one file again. |
| `POST /v1/orgs/{org}/proofs/oob` | Makes an out of band invitation that carries a proof request. |
| `POST /v1/orgs/{org}/proofs` | Sends a proof request over a connection of the organisation. |
| `GET /v1/orgs/{org}/proofs` | Lists the proof requests. The platform answers not found for none. |
| `GET /v1/orgs/{org}/proofs/{id}` | Reads the proof exchange of one request. |
| `POST /v1/orgs/{org}/proofs/{id}/verify` | Verifies a presentation that waits. |
| `GET /v1/orgs/{org}/verified-proofs/{id}` | Reads the revealed values of a verified proof. |
| `GET /v1/platform/schemas` | Lists the AnonCreds schemas of the platform for the proof request builder. |
| `GET /v1/platform/cred-defs` | Lists the credential definitions of those schemas. |
| `POST /v1/orgs/{org}/oid4vp/verifier` | Creates the OID4VP verifier. |
| `POST /v1/orgs/{org}/oid4vp/presentation` | Starts an OID4VP transaction. The platform takes no nonce of the caller. The adapter returns the nonce of the signed request in the session record, so VCA checks the answer against it. |
| `GET /v1/orgs/{org}/oid4vp/verifier-presentation` | Reads the answer of a transaction. |
| `GET /v1/webhooks/orgs/webhookurl` | Reads the webhook of an organisation. The adapter reads only whether a signing secret exists. |
| `POST /v1/webhooks/orgs/{org}/register` | Sets the address of the webhook, and the signing secret when the admin names one. |
| `POST /v1/notification/register/webhook-endpoint` | Registers the holder notification address of an organisation. |
| `GET /v1/orgs/{org}/client_credentials` | Reads the client id of an organisation. The platform answers not found for none. |
| `POST /v1/orgs/{org}/client_credentials` | Makes the client credential of an organisation. The answer holds the secret once. |
| `DELETE /v1/orgs/{org}/client_credentials` | Removes the client credential and its Keycloak client. |
| `GET /v1/ecosystem/status` | Reads the ecosystem switch of the platform. |
| `PUT /v1/config/ecosystem` | Turns the ecosystems of the platform on or off. |
| `POST /v1/invitations` | Invites the platform admin to create one ecosystem, before each create. |
| `POST /v1/ecosystem?orgId={org}` | Creates an ecosystem that the organisation leads. |
| `GET /v1/ecosystem?orgId={org}` | Lists the ecosystems that an organisation leads or belongs to. |
| `GET /v1/ecosystem/members` | Lists the members of an ecosystem. The platform answers not found for none. |
| `POST /v1/ecosystem/invitation` | Adds an organisation to an ecosystem. |
| `DELETE /v1/ecosystem/member` | Removes a member organisation from an ecosystem. |
| `GET /v1/x509/{org}/{id}` | Reads the certificate row that an X.509 import names. |
| `GET /v1/x509/{org}` | Lists the active certificates of a key type. |
| `PUT /v1/x509/{org}/activate/{id}`, `PUT /v1/x509/{org}/deactivate/{id}` | Makes the imported row the active certificate of its key type, and takes the older rows out of use. |

## What the adapter can do

The answer of `GetCapabilities` reports what the platform supports.

| Item | Value |
| --- | --- |
| Formats | `dc+sd-jwt`, `vc+sd-jwt`, AnonCreds, W3C JSON-LD |
| Channels | OID4VCI pre-authorized code for SD-JWT. A DIDComm invitation for AnonCreds and W3C JSON-LD. An email from the stack for the same two, when the stack names a mail provider. |
| Protocols | OID4VCI, OID4VP, OID4VP with DCQL, DIDComm issue credential 2.0, DIDComm present proof 2.0 |
| Roles | Issuer and verifier. Holder too with the agent. |
| Features | `FEATURE_CREDENTIAL_CONFIG_API`, `FEATURE_MULTI_TENANCY`, `FEATURE_ISSUER_IDENTITY_PROVISION`, `FEATURE_ISSUER_IDENTITY_IMPORT_X509`, `FEATURE_ISSUANCE_STATUS`, `FEATURE_ISSUED_LEDGER`, `FEATURE_ANONCREDS_PROOF`, `FEATURE_WEBHOOKS`, `FEATURE_HOLDER_NOTIFICATIONS`, `FEATURE_TENANT_CLIENT_CREDENTIALS`, `FEATURE_ECOSYSTEMS`, `FEATURE_REVOCATION` with the status list host, `FEATURE_BULK_NATIVE` with a mail provider, and `FEATURE_WALLET_DIDCOMM` and `FEATURE_WALLET_DIDS` with the agent |
| Wallet DID methods | `did:key`, with the agent |
| Bulk import | With a mail provider: the email channel, AnonCreds and W3C JSON-LD, and the address column `email_identifier` |
| DID methods | None. The operator makes each DID in the platform. |
| Operator DID methods | `did:key`, `did:indy`, `did:web` |
| Key types | `Ed25519`, `secp256r1`, `secp256k1` |
| Schema formats | AnonCreds on each ledger of the organisation, and W3C JSON-LD |
| Ledgers | The Indy ledgers where the organisation holds a DID, with the names of the platform |
| Status mechanisms | None. The platform embeds no status entry of VCA. With the status list host, each SD-JWT credential carries a Token Status List entry of the stack. |
| DPG information | The platform name, `v2.2.1-alpha.4` with the digest of the api gateway, every platform service, the shared Credo agent, and Keycloak |

Each component carries its pinned version, its repository, its
documentation, and its licence. Every platform image comes from the
release line `v2.2.1`, pinned by the digest of its release tag
(ADR-066). A component shows the tag and the first twelve digits of the
digest. A test binds the adapter
to the stack file. A page shows a feature on this stack only when the
answer lists it (ADR-034).

CREDEBL is the only one of the three DPGs that reads DCQL.

## Revocation

The stack file runs the status list host of the platform, the service
`credebl-status-list` (P6-C5b).
CREDEBL publishes no image of it.
Compose builds it from the repository of its authors,
[sovio-id/status-list-server](https://github.com/sovio-id/status-list-server),
at one commit, on a base image pinned by digest.
The platform names the host `STATUS_LIST_HOST`.
The agent names it `STATUS_LIST_SERVER_URL` and writes each list with the
generated key `CREDEBL_STATUS_LIST_API_KEY`.
Setup sets `VCA_CREDEBL_STATUS_LIST` in an issuer pair.
The adapter then asks for a revocable offer, and the platform gives each
SD-JWT credential a Token Status List entry.
The agent signs each list with the DID of the issuer.
So the organisation needs a primary DID, which the operator makes.

`Revoke` takes the issuance session as the credential id.
It calls the revoke route of the platform, and the agent sets the revoked
bit and publishes the list again.
The agent writes the entry of a credential when it creates the offer.
`CreateOffer` reads the session and names that entry in its answer, with
`dpg_list` set and the session as `credential_id` (ADR-072).
The record of the offer then holds the entry of the stack.
A revoke of that record goes to `Revoke`, never to a list of VCA.
The adapter lists no status mechanism, so VCA allocates no index for it.
The issued list reads the entry of each credential from its session.
So a synced record carries its list, its index and the list address.
A verifier fetches the list at that address.
On a public host, set `CREDEBL_STATUS_LIST_URL` to the public address of
host port 17183, and publish only the `GET` requests of `/status-lists/`.
Each credential names that address, so set it before the first offer.

## Webhooks, notifications and client credentials

A tenant is an organisation of the platform (ADR-037). The platform
calls the webhook of an organisation on each event of its exchanges.
The admin can set a signing secret of 16 characters or more. The
platform then signs each call with that secret. The adapter passes the
secret on and keeps no copy. A read shows only whether a secret exists.
The platform clears no webhook, so the adapter marks each one as fixed.

The notification service of the platform posts the push notifications
of the holders of an organisation to one address. The platform keeps
the first address and reads it back through no call. The adapter keeps
the address it registered in its store. The admin portal shows the
address as kept by the adapter. The notification route of the gateway
has no guard. Keep that route on the host, as the deploy document says.

The platform keeps one client credential per organisation. The adapter
lists it by its client id, with the name of the organisation. The
answer of a create holds the secret once. Neither the adapter nor the
admin service stores it.

## Ecosystems

An ecosystem groups organisations of the platform. One organisation
leads it, and the other organisations are members (ADR-068). The platform
keeps a switch for all ecosystems, off at first. It turns ecosystems on
only when its Keycloak realm keeps the ecosystem roles of each user. The
bootstrap of the stack sets the realm up. The platform keeps each name
once.

The platform admin of the adapter creates each ecosystem. The platform
lets a user create an ecosystem only with an unused invitation of the
platform admin. So the adapter invites the platform admin before each
create. With a mail provider, the platform mails that invitation to the
address of the platform admin. The platform then writes the lead role to
the Keycloak user of the platform admin. The adapter signs in again, so
the next call carries the role.

The platform accepts a member at once when the platform admin created the
organisation. That holds for each tenant that VCA made. For another
organisation, the platform mails its creator an invitation, and the
answer says so.

## What the adapter does not do

| RPC | Reason |
| --- | --- |
| `Issue` | CREDEBL signs a credential only when a wallet claims an offer. |
| `Revoke` without `VCA_CREDEBL_STATUS_LIST` | The platform revokes an OID4VC session only with a status list host. Without one, the status services of VCA own the status bits. |
| A suspension or a reinstatement | The agent sets the revoked bit of a credential and clears none. The answer lists no `FEATURE_SUSPENSION`, so the issued page offers a revoke alone. |
| `Revoke` of a DIDComm credential | The adapter writes every credential definition without a revocation registry. |
| Every holder RPC without the agent | The holder role needs the admin address and the API key of the shared agent. `vca setup` writes both into every pair, and keeps the wallets of an issuer and a verifier pair off. |
| The cloud wallet service of the platform | The pinned cloud wallet service reads the agent with a call that the pinned agent refuses. Its proof paths hold a stray brace. Its holder account also needs a mail check. The adapter keeps each holder wallet in the shared agent instead (ADR-062). |
| `AcceptOffer` with an OID4VCI offer that has an authorization code grant only | The agent redeems a pre-authorized code only. Ask the issuer for an offer with such a code. |
| An OID4VP answer with another matching credential | The agent answers with the first credential that matches each query. The adapter refuses a pick that differs, so the answer never differs from the consent. |
| `DeleteCredential` of an AnonCreds credential | The agent has no call that removes one. The wallet portal offers no remove button for it. |
| A decline of an offer or a proof request | The agent has no decline call. The wallet portal forgets a scanned invitation, and an inbox entry waits. |
| Basic messages | The pinned agent has no basic message call. |
| `CreateKey`, `ListKeys` and `SetDefaultDid` | The agent makes the key of each DID itself and binds no credential to a default DID. |
| A second client credential of an organisation | The platform keeps one per organisation. Delete the credential, then make a new one. |
| `CreateTenant` with a dedicated agent | The platform starts a dedicated agent through the Docker socket. The stack file mounts none, so every tenant gets the shared agent. |
| `ImportIssuerIdentity` with a DID | The agent keeps the key of every DID and takes no key reference. Set another primary DID in the platform, or import an X.509 chain. |
| A revocable credential definition | The adapter writes every credential definition without a revocation registry. |
| `ProvisionIssuerIdentity` | The pinned platform makes a DID of any method only with its private key in the request. The adapter never holds a key. The operator makes the DID in the platform. |
| A clear of a webhook | The platform has no call that clears one. Set another address instead. |
| A change of the holder notification address | The platform keeps the first address and has no change call. |
| `VerifyCredential` | The adapter does not send an uploaded credential to the platform. The scanner shows no stack check. |
| A DIDComm proof request by email | The platform answers a request by email with the thread of the exchange alone. No call of the platform reads a proof by its thread, so VCA could not show the answer. Send the invitation as a QR code or a link, or over a connection. |

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

**The platform has a realm of its own.** The platform signs the platform
admin in at the realm `credebl-platform` of the Keycloak of the stack.
It uses the password grant of the client `adminClient` there. Setup
writes that realm with the client `credeblClient` for the management
calls of the platform. The secrets of both clients live in the stack
`.env`. The realms of the VCA roles stay as ADR-035 makes them.

**The platform learns each exchange from the agent.** The shared agent
posts each event to `/wh/<organisation>/<topic>` of the api gateway,
with the organisation `Platform-admin`. The gateway finds the
organisation of a tenant wallet from the context of the event. So the
platform records the state of each DIDComm and OID4VC exchange of every
organisation. `vca dpg bootstrap credebl` sets the address.

**The token comes back once and lasts.** The adapter caches the token
until one minute before its end. A call that gets the status
unauthorized signs in again once and then gives up.

**A template reads back under another name.** CREDEBL stores the body of
a template in a column named `attributes`. A read returns the body under
that name, although a write sends it under the name `template`.

**The schema of a template is a W3C schema with no ledger.** The adapter
stores a schema before each SD-JWT template. The body has the type `json`
and the schema type `no_ledger`, as the enums of the api gateway allow.
The platform refuses any other schema type. The adapter maps each claim
type onto the W3C data types of the platform. A type outside that list
becomes a string. An empty description takes the schema name.

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
a wallet in the shared agent. The adapter creates them in that order.
When the wallet fails, it deletes the organisation again. The tenant
gets no DID from the adapter. The operator makes one, as the next
section says. The tenant list leaves out
the organisation `Platform-admin`, which holds the shared agent. Delete
refuses that organisation and the organisation of the adapter.

**The adapter only reads the members.** The platform lists each person of an
organisation with the roles in every organisation. The adapter keeps the
roles of the organisation it reads.

**The issuer identity is the primary DID.** The identity lists the DIDs
of the organisation of the adapter, the primary DID first. The key
stays in the Askar wallet of the agent.

**The operator makes each DID with a key of its own.** The pinned
gateway refuses a `did:key`, a `did:indy` and a `did:web` without a
private key in the request. It names that key `seed`, 32 characters.
The agent then signs with it. The adapter never holds a key
(ADR-001 decision 3), so it makes no DID (ADR-070). The answer names the
three methods in `operator_did_methods`. The operator sends the key
straight to the platform from the host, never through VCA. The platform
admin owns the organisation of the adapter and each tenant, so its sign
in serves both. Run these steps on the host, in a shell that keeps no
history:

1. Load `PLATFORM_ADMIN_EMAIL`, `CREDEBL_PLATFORM_ADMIN_PASSWORD` and
   `CRYPTO_PRIVATE_KEY` of `deploy/credebl/.env` into the shell:
   `set -a; . deploy/credebl/.env; set +a`.
2. Encrypt the password as the sign in of the platform reads it:
   `printf '"%s"' "$CREDEBL_PLATFORM_ADMIN_PASSWORD" | openssl enc -aes-256-cbc -md md5 -salt -a -A -pass env:CRYPTO_PRIVATE_KEY`.
3. Sign in at the api gateway on host port 17181:
   `curl -s -X POST http://127.0.0.1:17181/v1/auth/signin -H 'Content-Type: application/json' -d '{"email":"<email>","password":"<encrypted password>"}'`.
   The token is `data.access_token` of the answer.
4. Write the DID request into a file of mode 0600, and post it:
   `curl -s -X POST http://127.0.0.1:17181/v1/orgs/<organisation id>/agents/did -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' -d @did.json`.
5. Delete the file.

The organisation of the adapter is `VCA_CREDEBL_ORG_ID` of the `.env`
of the pair. The admin tenant page shows the id of each tenant.
A `did:web` request holds `{"method": "web", "keyType": "ed25519", "domain": "<host>", "seed": "<32 characters>", "isPrimaryDid": true}`.
Serve the DID document of the answer at `https://<host>/.well-known/did.json`.
A `did:indy` request holds `{"method": "indy", "keyType": "ed25519", "network": "<network>", "role": "endorser", "did": "<nym>", "seed": "<32 characters>", "isPrimaryDid": true}`.
Write the nym of that key on the Indy network first, with the tools of the network.
The network is one of `VCA_CREDEBL_INDY_LEDGERS`.
A `did:key` request holds `{"method": "key", "keyType": "ed25519", "seed": "<32 characters>", "isPrimaryDid": true}`.
The organisation of the adapter needs `isPrimaryDid` true.
For a tenant, the admin tenant page offers "Make primary" too (`FEATURE_TENANT_PRIMARY_DID`).

**A ledger DID resolves through the agent.** With the agent address the
adapter lists `FEATURE_DID_RESOLVE`. `ResolveDid` asks `GET /dids/{did}`
of the shared agent, which reads the ledger. The agent records each DID
it resolves in the tenant that asks. So the adapter asks with a tenant
of its own, which it makes once. It never asks with the wallet of an
organisation. The admin service hands the document to the trust
registry, so an AnonCreds issuer can sit on a trust list. Every pair has
the agent address, so an issuer or a verifier pair resolves too. There
`VCA_CREDEBL_AGENT_RESOLVER_ONLY` keeps the holder wallets off.

**An X.509 chain binds to a certificate row of the platform.** The
platform imports a certificate only with its private key, and VCA never
holds one. So make or import the certificate in the platform first. The
agent keeps its key, and the platform keeps the certificate in a row.
Then import the chain on the identity page of VCA, with the leaf first.
The key reference names the row: `{"certificateId": "<id of the row>"}`.
The adapter checks that the chain verifies and that the leaf is the
certificate of the row. The leaf must be valid now. The adapter takes the
older active rows of the key type out of use and activates the row. The
platform signs a template with the signer option `X509_P256` or
`X509_ED25519` with that row. The `x5c` header of such a credential holds
the leaf only, so the adapter keeps the chain for the identity. The
identity lists the subject of the leaf after the DIDs while the row stays
active (ADR-068).

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

**A second registration writes nothing new (ADR-077).** The schema
registry registers every published version again at each start. Before
each write the adapter lists the schemas of its organisation by name.
It reuses an AnonCreds schema of the same name, version and ledger. It
reuses the credential definition of that schema with the tag `default`.
It reuses a W3C schema of the same name and alias. It reuses the schema
of a template of the same name. So the ledger sees one write of each. The
platform keeps one AnonCreds name and version across every organisation.
A name that another organisation holds answers `already_exists`, and
the registry stops trying it.

**The state of an offer is the state of its session.** The offer id
is the id of the issuance session of the agent. A session in the state
`Completed` reads as issued, and its last change is the claim time. A session
in the state `Error` failed, with the message of the agent. Every other
session is pending until its end, and expired after it.

**The issued list reads the sessions.** The adapter lists the completed
sessions of a credential type, oldest first. A session matches when its
offer carries each attribute of the query with the same value. An entry
carries the session id, the type and the issue time, and no claim value.

**AnonCreds and W3C JSON-LD travel over DIDComm.** The adapter lists
`CHANNEL_DIDCOMM_OOB` with the formats it carries in `channel_formats`.
An offer on that channel is an out of band invitation that carries the
offer. With a connection it goes over that connection instead.
`ListConnections` lists the connections of the platform. The platform
learns them from the webhook of the agent. The offer id is `didcomm:` and the id of the
credential exchange. `GetIssuanceStatus` reads that exchange: `done`
reads as issued, and `abandoned` or `declined` as failed. An AnonCreds
offer carries each claim as text and no validity window. A W3C JSON-LD
offer carries the credential with the context of its schema. The
primary DID of the organisation is the issuer, with Ed25519 proof
options. A DIDComm credential carries no status entry of VCA.

**The platform mails an offer only with a mail provider.** The offer by
email needs `EMAIL_PROVIDER` and the values of that provider in the stack
`.env`. Setup then sets `VCA_CREDEBL_MAIL_OFFERS`, and the adapter lists
`CHANNEL_EMAIL`. The platform keeps the invitation of the email on the
volume `credebl-files`, and the link of the email names `PLATFORM_URL`.

**The bulk import mails every row.** The platform reads a CSV file
whose first column is `email_identifier`. The other columns must match
the claims of the schema by name and by count. The platform checks every
address before it keeps the rows. It keeps an upload in Redis for a
limited time. After that, the preview asks for a new upload. The
template call of the platform answers with a link into its own UI, not
with the file. So the adapter writes the template from the
claims of the schema. `IssueBatch` writes one such file from the specs
and issues it. A row without a valid address fails alone and stays out
of the file. The platform queues one offer by email per row. The file
history reads the result of each row from the platform database.

**The adapter creates the verifier once.** It creates the OID4VP
verifier at the first request. It then stores the identifier. After a
restart the create call gets the status conflict. The adapter then looks
the verifier up by its public name.

**DIDComm proof requests go out as an invitation or over a
connection.** An AnonCreds request travels in the Indy format of the
platform. It names the attributes to reveal and the predicates to prove. Over
a connection the platform takes a list of attributes instead, with the
first restriction of each. The platform reads the revealed values one
name per referent and never reads a revealed group. So the adapter turns
a group of `names` into one referent per name, with the restrictions of
the group. A DIF PE request needs the schema of each
input descriptor. The adapter reads it from the filter of the descriptor
on `$.type`. The platform keeps only the path of each field. It reads
the first field of each descriptor only. So the adapter puts the claim
field before the type filter. It refuses a descriptor with more than one
claim, because the platform would drop the others. Ask for each claim in
its own descriptor, or ask over OID4VP. The agent
verifies each presentation as it arrives. A presentation that waits gets
the check call of the platform. The state of a request is
`didcomm-proof:` and the id of the proof exchange.

**The platform verifies the proof, and VCA reads the values.** A proof
in the state `done` with `isVerified` reads as accepted. The adapter
keeps the attribute names of each request it makes, under the id of the
proof exchange. It reads each value of the answer by one of those names.
The platform writes `schemaId`, `credDefId` and `certificateTemplate`
beside each value, so the adapter refuses to ask for an attribute of
such a name.

**The issuer of the view is the issuer the request bound.** A part of an
AnonCreds request binds its issuer with one restriction. The restriction
names a credential definition or an issuer DID. The issuer of the view is the
issuer of that credential definition, or that DID. The agent checked
that the proof meets the restriction. The adapter never takes the issuer
from the answer of the platform. With no restriction the platform names
the first credential of the proof there. Without `any_issuer` the
adapter refuses a part that binds no issuer. Over a connection it takes
a credential definition only. A value from a part that binds no issuer
gives a view with no issuer and the failed check `credebl-issuer-bound`
(ADR-064). The adapter
returns one JSON view per credential, with the revealed values under
`credentialSubject`. A predicate reads as the operator and the number,
such as `>=10`, and never as the value of the holder. The view carries
no proof, so the signature check of VCA skips it. A proof that fails the
check, and a request the holder declines, read as rejected.

**The proof request builder reads the AnonCreds schemas of the
platform.** `ListProofSchemas` lists the AnonCreds schemas of every
organisation, with the credential definitions of each.

**A DCQL query arrives in two shapes.** The adapter reads the whole
request body with its `query` member, and the bare query as well.

**Each holder has a tenant wallet in the shared agent.** `Register`
makes a tenant and a `did:key` at the first login of a holder. The store
of the adapter keeps a hash of the pairwise subject and the tenant id
alone. A holder call names a tenant that `Register` made, never the
tenant of an organisation in the same agent. The data volume keeps the
store, so a restart opens the same wallets. `Register` answers
`Internal` when the store fails or holds a damaged record. It never
makes a second wallet over a record it cannot read. The adapter makes
one wallet at a time, so two first logins of one holder share a wallet.
The record goes in with a compare and swap. When another adapter process
stored the holder first, `Register` opens that wallet.

**The agent signs the tokens.** The API key buys the token of the base
wallet, which makes the tenants and signs a token for each. The adapter
keeps the tokens in memory. After a refused token it asks for a new
token once.

**The wallet receives an invitation only after the holder accepts.**
The wallet portal reads the scanned invitation itself and shows what it
carries. On accept the adapter hands the invitation to the tenant. The
agent makes the connection and takes the message it carries. The adapter
finds the exchange by the thread of that message and accepts it. It then
waits for the credential or the answer of the verifier.

**The same wallet holds OID4VC credentials.** The tenant claims an
OID4VCI offer with a pre-authorized code through the holder API of the
agent. It answers an OID4VP request there too. The agent picks the first
credential that matches each query. The adapter reads that pick first
and refuses an answer when the holder picked another credential.
The agent takes no choice of claims. It discloses every claim of the
first claim set that the credential satisfies. So the adapter lists
`FEATURE_WALLET_WHOLE_QUERY`, and the consent screen marks every claim as
required. `Present` refuses with `FailedPrecondition` when the ticked
claims leave out a claim the agent sends. `shared_claims` name the claims
the agent sends (ADR-063 decision 1).

**The agent fetches an OID4VP request once more to answer it.** The
consent screen of the portal reads the `request_uri` first. The adapter
resolves it again to check the picks and the claims. The agent then
fetches it a third time for the answer, because it accepts a request by
its address only. A verifier could serve a narrow query on the first
fetches and a wide one on the last. Only a host on the `REQUEST_HOSTS`
allowlist of the portal gets that far, so keep the allowlist short. The
adapter closes the gap when the agent accepts a request by the id of the
resolved request (ADR-063 decision 3).

**An AnonCreds credential reads from its exchange.** The agent lists no
AnonCreds credential. The finished exchange holds the values of the
offer and the schema and the credential definition. The adapter returns
the JSON view of the DIDComm proof results. A W3C credential reads as
the agent stores it.

## Tests

The recorded set replays answers of the CREDEBL 2.x api gateway from
`testdata` through an `httptest` fake. It runs in every build.

The contract set targets a real platform. It carries the build tag
`contract_credebl`. It skips itself when the variables hold no value.

## Reference

- Service folder: `services/dpg-adapter-credebl`
- Contract: `proto/vca/backend/v1/backend.proto`
- Decisions: ADR-002 decisions 2 and 4, ADR-016 decision 6, ADR-022 decision 3, ADR-030 decision 2, ADR-059, ADR-060, ADR-061, ADR-062, ADR-063, ADR-064
