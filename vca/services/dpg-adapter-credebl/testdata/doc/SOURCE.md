# Where these answers come from

These files were written on 2026-09-26 from the sources of the CREDEBL
platform, branch `main`, not recorded from a live platform. The nightly
contract run replaces each file with a recording (plan section 0.4).
Every name, email address and description is a placeholder in square
brackets. The identifiers are random.

The api gateway wraps each answer as `statusCode`, `message` and `data`:
`apps/api-gateway/src/interfaces/IResponse` and the controllers below.

| File | Call | Source |
| --- | --- | --- |
| `org-created.json` | `POST /v1/orgs` | [organization.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/organization/organization.controller.ts) `createOrganization` |
| `org-list.json` | `GET /v1/orgs` | the same controller, and the select of `getOrganizations` in [organization.repository.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/organization/repositories/organization.repository.ts) |
| `org.json` | `GET /v1/orgs/{org}` | the same controller, and the select of `getOrganization` in the repository |
| `org-dids.json` | `GET /v1/orgs/{org}/dids` | the same controller, and `getAllOrganizationDid` in the repository |
| `org-users.json` | `GET /v1/orgs/{org}/users` | the same controller, and `findOrgUsers` in [user.repository.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/user/repositories/user.repository.ts) |
| `org-deleted.json` | `DELETE /v1/orgs/{org}` | the same controller |
| `primary-did.json` | `PUT /v1/orgs/{org}/primary-did` | the same controller, body [set-primary-did.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/organization/dtos/set-primary-did.dto.ts) |
| `wallet-created.json` | `POST /v1/orgs/{org}/agents/wallet` | [agent-service.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/agent-service.controller.ts) `createTenant`, body [create-tenant.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/dto/create-tenant.dto.ts) |
| `platform-ledgers.json` | `GET /v1/platform/ledgers` | [platform.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/platform/platform.controller.ts) `getAllLedgers`, the model `ledgers` of [schema.prisma](https://raw.githubusercontent.com/credebl/platform/main/libs/prisma-service/prisma/schema.prisma), and the ledgers of the master table |
| `indy-schema-created.json` | `POST /v1/orgs/{org}/schemas` with the type `indy` | [schema.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/schema/schema.controller.ts) `createSchema`, body [create-schema.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/dtos/create-schema.dto.ts), and `createSchema` of [schema.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/ledger/src/schema/schema.service.ts) with the model `schema` |
| `w3c-schema-created.json` | `POST /v1/orgs/{org}/schemas` with the type `json` and the schema type `no_ledger` | the same controller and service, `createW3CSchema` and `storeW3CSchemas` |
| `cred-def-created.json` | `POST /v1/orgs/{org}/cred-defs` | [credential-definition.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/credential-definition/credential-definition.controller.ts), body [create-cred-defs.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/credential-definition/dto/create-cred-defs.dto.ts), and the model `credential_definition` |
| `offer-session-pending.json`, `offer-session-completed.json`, `offer-session-error.json` | `GET /v1/orgs/{org}/oid4vc/credential-offer/{id}` | [oid4vc-issuance.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/oid4vc-issuance.controller.ts) `getCredentialOfferDetailsById`, which answers with the issuance session of the agent: `getIssuanceSessionsById` and `createCredentialOffer` of [issuance-sessions.service.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/openid4vc/issuance-sessions/issuance-sessions.service.ts), and the session fields of [oid4vc-credential-wh.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/dtos/oid4vc-credential-wh.dto.ts) |
| `offer-sessions.json` | `GET /v1/orgs/{org}/oid4vc/credential-offer` | the same controller `getAllCredentialOffers`, and `getIssuanceSessionsByQuery` of the agent service |
| `upstream-master-table.json.txt` | none: the master table that the database initialisation reads | [credebl-master-table.json](https://raw.githubusercontent.com/credebl/platform/main/libs/prisma-service/prisma/data/credebl-master-table/credebl-master-table.json), read on 2026-09-27 and kept as it is, with [seed.ts](https://raw.githubusercontent.com/credebl/platform/main/libs/prisma-service/prisma/seed.ts) `createPlatformUser` and `createKeycloakUser`. The file ends in `.txt` because it holds the placeholder text of the release in a password field, which the secret scan reads as a value. The CLI test `TestNoUpstreamCredeblCredentialSurvives` checks that none of its credentials reach a deployment. |
| `did-created.json` | `POST /v1/orgs/{org}/agents/did` | [agent-service.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/agent-service.controller.ts) `createDid`, body [create-did.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/dto/create-did.dto.ts), and `createDid` in [agent-service.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/agent-service/src/agent-service.service.ts) |

The agent makes the key of a `did:key` without a seed. The agent needs
a seed for `did:indy` and `did:web`, which is the private key
([DidController.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/did/DidController.ts)
`handleIndy`, `handleWeb`). The adapter never sends key material
(ADR-001 decision 3), so it makes `did:key` identities only.

## The schema body of an SD-JWT template

The adapter stores the schema of an SD-JWT template as a W3C schema
with no ledger. The body follows `GenericSchemaDTO` and
`CreateW3CSchemaDto` of
[create-schema.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/dtos/create-schema.dto.ts),
read on 2026-09-27. The enums come from
[enum.ts](https://raw.githubusercontent.com/credebl/platform/main/libs/enum/src/enum.ts):

| Field | Enum | Values |
| --- | --- | --- |
| `type` | `SchemaTypeEnum` | `json`, `indy` |
| `schemaPayload.schemaType` | `JSONSchemaType` | `polygon`, `no_ledger` |
| `schemaPayload.attributes[].schemaDataType` | `W3CSchemaDataType` | `number`, `integer`, `string`, `datetime-local`, `array`, `object`, `boolean` |

The payload needs a description that is not empty. The gateway strips
a member that the DTO does not name, such as `orgId`.
`TestCreateSchemaSendsTheSchemaTypeOfThePlatform` checks the body
against these values.

## DIDComm issuance

These files were written on 2026-09-27 from the same sources.

| File | Call | Source |
| --- | --- | --- |
| `oob-offer-created.json` | `POST /v1/orgs/{org}/credentials/oob/offer` | [issuance.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/issuance.controller.ts) `createOOBCredentialOffer`, body `OOBIssueCredentialDto` of [issuance.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/issuance.dto.ts), `sendCredentialOutOfBand` of [issuance.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/issuance/src/issuance.service.ts), and `createOfferOob` of the agent [CredentialController.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/didcomm/credentials/CredentialController.ts) |
| `connection-offer-created.json` | `POST /v1/orgs/{org}/credentials/offer` | the same controller `sendCredential`, body [multi-connection.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/multi-connection.dto.ts), and `sendCredentialCreateOffer` of the service |
| `oob-email-sent.json` | `POST /v1/orgs/{org}/credentials/oob/email` | the same controller `outOfBandCredentialOffer`, body `OOBCredentialDtoWithEmail`, and `sendEmailForCredentialOffer` of the service |
| `connections.json` | `GET /v1/orgs/{org}/connections` | [connection.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/connection/connection.controller.ts) `getConnections`, and `getConnections` of [connection.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/connection/src/connection.service.ts) |
| `credential-record-offer-sent.json`, `credential-record-done.json`, `credential-record-abandoned.json` | `GET /v1/orgs/{org}/credentials/{id}` | the issuance controller `getIssueCredentialsbyCredentialRecordId`, which answers with the credential exchange record of the agent |

The query parameter `credentialType` is `indy` or `jsonld`
(`IssueCredentialType` of enum.ts). The invitation of
`oob-offer-created.json` is base64url of an out of band invitation 1.1.
