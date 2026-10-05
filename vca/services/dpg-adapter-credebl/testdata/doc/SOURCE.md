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
| none: the fake keeps each schema it writes | `GET /v1/orgs/{org}/schemas` | [schema.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/schema/schema.controller.ts) `getSchemas`, query `GetAllSchemaDto` of [get-all-schema.dto.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/schema/dtos/get-all-schema.dto.ts), and `getSchemas` of [schema.repository.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ledger/src/schema/repositories/schema.repository.ts), read on 2026-10-04. The list filters on name, version, ledger id and DID with an insensitive contains, and answers the status not found for an organisation with no schema. `schemaExists` of the same repository blocks an AnonCreds schema whose name and version another AnonCreds schema of any organisation contains, and `createSchema` of [schema.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ledger/src/schema/schema.service.ts) answers it with the status conflict. A W3C schema has no such check. |
| none: the fake keeps each credential definition it writes | `GET /v1/orgs/{org}/schemas/{schemaLedgerId}/cred-defs` | the same controller `getcredDeffListBySchemaId`, and `getSchemasCredDeffList` of the same repository, read on 2026-10-04. It answers the status not found for none. `createCredentialDefinition` of [credential-definition.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ledger/src/credential-definition/credential-definition.service.ts) answers the status conflict for a second definition of the same schema and tag. |
| `offer-session-pending.json`, `offer-session-completed.json`, `offer-session-error.json` | `GET /v1/orgs/{org}/oid4vc/credential-offer/{id}` | [oid4vc-issuance.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/oid4vc-issuance.controller.ts) `getCredentialOfferDetailsById`, which answers with the issuance session of the agent: `getIssuanceSessionsById` and `createCredentialOffer` of [issuance-sessions.service.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/openid4vc/issuance-sessions/issuance-sessions.service.ts), and the session fields of [oid4vc-credential-wh.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/dtos/oid4vc-credential-wh.dto.ts) |
| `offer-session-revocable.json` | `GET /v1/orgs/{org}/oid4vc/credential-offer/{id}` | the same controller `getCredentialOfferDetailsById`, for the session of `create-offer.json` right after a revocable offer. `createCredentialOffer` and `processStatusList` of the agent write the `status` claim of the credential and the `StatusListInfo` of the metadata when they create the offer, read on 2026-09-27 at the agent tag `v2.2.1-alpha-jsonld-vc.2.1` |
| `offer-sessions.json` | `GET /v1/orgs/{org}/oid4vc/credential-offer` | the same controller `getAllCredentialOffers`, and `getIssuanceSessionsByQuery` of the agent service. The fifth session is a revocable offer: its credential carries the `status` claim and its metadata the `StatusListInfo` that `createCredentialOffer` and `processStatusList` of the agent write, read on 2026-09-27 at the agent tag `v2.2.1-alpha-jsonld-vc.2.1` |
| `session-revoked.json` | `POST /v1/orgs/{org}/openid4vc/issuance-sessions/{id}/revoke` | the same controller `revokeCredential` at the platform tag `v2.2.1-alpha.4`, `revokeCredential` of `apps/oid4vc-issuance/src/oid4vc-issuance.service.ts`, and `revokeBySessionId` of the agent issuance sessions service |
| `upstream-master-table.json.txt` | none: the master table that the database initialisation reads | [credebl-master-table.json](https://raw.githubusercontent.com/credebl/platform/main/libs/prisma-service/prisma/data/credebl-master-table/credebl-master-table.json), read on 2026-09-27 and kept as it is, with [seed.ts](https://raw.githubusercontent.com/credebl/platform/main/libs/prisma-service/prisma/seed.ts) `createPlatformUser` and `createKeycloakUser`. The file ends in `.txt` because it holds the placeholder text of the release in a password field, which the secret scan reads as a value. The CLI test `TestNoUpstreamCredeblCredentialSurvives` checks that none of its credentials reach a deployment. |

The api gateway refuses a `did:key`, a `did:indy` and a `did:web`
without a seed in the request (`Validator.validateDid` of
[validator.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/libs/common/src/validator.ts),
read on 2026-09-27). The agent takes the seed as the private key
([DidController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/did/DidController.ts)
`handleKey`, `handleIndy`, `handleWeb`). The adapter never sends key
material (ADR-001 decision 3), so it makes no DID of an organisation.
The operator makes it in the platform (ADR-070).

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

## Bulk issuance

These files were written on 2026-09-27 from the same controller, the
issuance service and repository of the platform, and the paginator of
[common.utils.ts](https://raw.githubusercontent.com/credebl/platform/main/libs/common/src/common.utils.ts).

| File | Call | Source |
| --- | --- | --- |
| `bulk-upload-created.json` | `POST /v1/orgs/{org}/bulk/upload` | [issuance.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/issuance.controller.ts) `uploadCSVTemplate`, query `TemplateQuery` and `SchemaType` of [issuance.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/issuance.dto.ts), and `uploadCSVTemplate` of [issuance.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/issuance/src/issuance.service.ts), which answers with the id of the upload |
| `bulk-upload-refused.json` | the same call with a bad address | `ResponseMessages.bulkIssuance.error.invalidEmails` of [response-messages](https://raw.githubusercontent.com/credebl/platform/main/libs/common/src/response-messages/index.ts) |
| `bulk-preview.json` | `GET /v1/orgs/{org}/{upload}/preview` | the controller `previewFileDataForIssuance`, `PreviewFileDetails`, and `previewFileDataForIssuance` of the service. The gateway calls the service through `sendNats`, which wraps the page in `response`. |
| `bulk-issue-started.json` | `POST /v1/orgs/{org}/{upload}/bulk` | the controller `issueBulkCredentials`, body `ClientDetails`, and `issueBulkCredential` of the service |
| `bulk-files.json` | `GET /v1/orgs/{org}/bulk/files` | the controller `issuedFileDetails`, `FileParameter`, `issuedFileDetails` of the service, and `getAllFileDetails` of [issuance.repository.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/issuance/src/issuance.repository.ts) with the model `file_upload` |
| `bulk-file-rows.json` | `GET /v1/orgs/{org}/{file}/bulk/file-data` | the controller `getFileDetailsByFileId`, and `getFileDetailsByFileId` of the repository with the model `file_data` |
| `bulk-retry-started.json` | `POST /v1/orgs/{org}/{file}/retry/bulk` | the controller `retryBulkCredentials`, and `retryBulkCredential` of the service |

The first column of a file is `email_identifier`
(`TemplateIdentifier.EMAIL_COLUMN` of enum.ts). The query parameter
`schemaType` is `indy` or `w3c` (`SchemaType` of enum.ts). The states of
a file are `FileUploadStatus` of `apps/api-gateway/src/enum.ts`. The
template call `POST /v1/orgs/{org}/credentials/bulk/template` answers
with a link into the UI of the platform, so the adapter does not call
it.

## DIDComm proof requests

These files were written on 2026-09-27 from the verification
controller, its DTOs and service, and the proof controller of the
agent.

| File | Call | Source |
| --- | --- | --- |
| `proof-oob-created.json` | `POST /v1/orgs/{org}/proofs/oob` | [verification.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/verification/verification.controller.ts) `sendOutOfBandPresentationRequest`, body `SendProofRequestPayload` of [request-proof.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/verification/dto/request-proof.dto.ts), `sendOutOfBandPresentationRequest` of [verification.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/verification/src/verification.service.ts), and `createRequest` of the agent [ProofController.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/didcomm/proofs/ProofController.ts), which answers with the invitation, the out of band record, and `proofRecordId` |
| `proof-connection-created.json` | `POST /v1/orgs/{org}/proofs` | the same controller `sendPresentationRequest`, body `RequestProofDtoV1`, and `sendProofRequest` of the service, which turns the attribute list into `requested_attributes` and `requested_predicates` and answers with the proof record of the agent |
| `proof-record-request-sent.json`, `proof-record-presentation-received.json`, `proof-record-done.json`, `proof-record-done-unverified.json`, `proof-record-abandoned.json` | `GET /v1/orgs/{org}/proofs/{id}` | the controller `getProofPresentationById`, which answers with the proof exchange record of the agent |
| `proof-verified.json` | `POST /v1/orgs/{org}/proofs/{id}/verify` | the controller `verifyPresentation`, and `acceptPresentation` of the agent |
| `verified-proof-indy.json`, `verified-proof-pe.json` | `GET /v1/orgs/{org}/verified-proofs/{id}` | the controller `getVerifiedProofDetails`, and `getVerifiedProofdetails` of the service, which answers with one entry per value: the attribute, the schema, and the credential definition. A predicate carries the operator and the number. |
| `verified-proof-indy-two-names.json` | `GET /v1/orgs/{org}/verified-proofs/{id}` | the same call for a request with two revealed attributes and no predicate. [verification.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/verification/src/verification.service.ts), read on 2026-09-27, lines 813 to 880: the service reads `requested_attributes[key].name` and `requested_proof.revealed_attrs[key]` only, so each name is one referent and one entry. A group with `names` gives no entry. |
| `webhook-url.json`, `webhook-url-none.json` | `GET /v1/webhooks/orgs/webhookurl?orgId={org}` | [webhook.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/webhook/webhook.controller.ts) `getWebhookUrl`, and `getWebhookUrl` of [webhook.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/webhook/src/webhook.service.ts), which reads `webhookUrl` and the encrypted `webhookSecret` of the agent row of the organisation ([webhook.repository.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/webhook/src/webhook.repository.ts)), read on 2026-09-27 |
| `webhook-registered.json` | `POST /v1/webhooks/orgs/{org}/register` | the same controller `registerWebhook`, body `webhookUrl` and an optional `webhookSecret` of at least 16 characters ([register-webhook-dto.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/webhook/dtos/register-webhook-dto.ts)). The repository updates the agent row, so a second call changes the address. No call clears it. |
| `client-credentials.json` | `GET /v1/orgs/{org}/client_credentials` | [organization.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/organization/organization.controller.ts) `fetchOrgCredentials`, and `fetchOrgCredentials` of [organization.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/organization/src/organization.service.ts), which returns the masked secret. With no credential the service answers not found. |
| `client-credentials-created.json` | `POST /v1/orgs/{org}/client_credentials` | the same controller `createOrgCredentials`, and `createOrgCredentials` of the service, which returns the secret once and keeps it masked |
| `client-credentials-deleted.json` | `DELETE /v1/orgs/{org}/client_credentials` | the same controller `deleteOrgClientCredentials`, which answers 202 |
| `notification-endpoint-registered.json` | `POST /v1/notification/register/webhook-endpoint` | [notification.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/notification/notification.controller.ts) `registerOrgWebhookEndpoint`, body `orgId` and `notificationWebhook`, and `storeOrgWebhookEndpoint` of [notification.repository.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/notification/src/notification.repository.ts), which creates one row per organisation (`orgId` is unique in `schema.prisma`). No call reads or changes it. |
| `ecosystem-status.json`, `ecosystem-status-off.json` | `GET /v1/ecosystem/status` | [platform.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/platform/platform.controller.ts) `getEcosystemEnableStatus`, and `getEcosystemEnableStatus` of [ecosystem.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ecosystem/src/ecosystem.service.ts), which reads `isEcosystemEnabled` of `platform_config`, read on 2026-09-27 |
| `ecosystem-config-updated.json` | `PUT /v1/config/ecosystem` | the same controller `updateEcosystemConfig`, platform admin only, body `isEcosystemEnabled`, and `updateEcosystemConfig` of the service, which refuses to turn ecosystems on while the user profile of the realm drops unmanaged attributes |
| `ecosystem-invitation-created.json` | `POST /v1/invitations` | the same controller `createInvitation`, body `email`, and `inviteUserToCreateEcosystem` of the service. `createEcosystemInvitation` of [ecosystem.repository.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ecosystem/repositories/ecosystem.repository.ts) makes the invitation of the type `ecosystem` with the status `accepted`. The service mails the address when the stack names a mail provider. |
| `ecosystem-created.json` | `POST /v1/ecosystem?orgId={org}` | [ecosystem.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/ecosystem/ecosystem.controller.ts) `createNewEcosystem`, owner of the organisation, body `name` of 2 to 50 characters and `description` of 2 to 255 characters ([create-ecosystem-dto.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ecosystem/dtos/create-ecosystem-dto.ts)). `createEcosystem` of the service needs an accepted invitation of the user with no ecosystem, refuses a name that exists, makes the organisation the lead, and writes the lead role to the user attribute `ecosystem_access` in Keycloak. |
| `ecosystems.json`, `ecosystems-none.json` | `GET /v1/ecosystem?orgId={org}` | the same controller `getEcosystems`, and `getEcosystemOrgs` of the service, which answers with `totalPages` and one entry per ecosystem of the organisation: `memberCount` without the lead, `role`, and `leadOrg` |
| `ecosystem-members.json` | `GET /v1/ecosystem/members?ecosystemId={id}` | the same controller `getEcosystemOrgs`, ecosystem lead only, and `getAllEcosystemOrgsByEcosystemId` of the repository, which selects the members without the lead. With no member the controller answers not found. |
| `ecosystem-member-invited.json` | `POST /v1/ecosystem/invitation` | the same controller `inviteMemberToEcosystem`, body `orgId` and `ecosystemId`. `inviteMemberToEcosystem` of the service accepts the invitation at once when the caller created the organisation, and mails the creator otherwise. It refuses the lead. |
| `ecosystem-member-deleted.json` | `DELETE /v1/ecosystem/member` | the same controller `deleteEcosystemUsers`, body `ecosystemId` and `orgIds` ([delete-ecosystem-users.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/ecosystem/dtos/delete-ecosystem-users.ts)). It answers 201 with a count, and 400 when no member matched. |
| `x509-certificate.json` | `GET /v1/x509/{org}/{id}` | [x509.controller.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/x509/x509.controller.ts) `getX509Certificate`, owner or admin of the organisation, and `findById` of [x509.repository.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/x509/src/repositories/x509.repository.ts), which answers with the row of `x509_certificates` in `schema.prisma`: the key type `P-256` or `Ed25519`, the status `Active`, `Pending activation` or `In Active` (`x5cRecordStatus` of `libs/enum/src/enum.ts`), the validity, and `certificateBase64`, read on 2026-09-27. The x509 service of the stack runs the tag `v2.2.1-alpha.3`, the newest image of the line. |
| `x509-certificates.json` | `GET /v1/x509/{org}?status=&keyType=&pageSize=` | the same controller `getAllX509ByOrgId`, `X509SearchCriteriaDto` of [x509.dto.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/x509/dtos/x509.dto.ts) with pages of 1 to 100 rows, and `findAll` of the repository, which answers with `data` and `total` |
| `x509-activated.json` | `PUT /v1/x509/{org}/activate/{id}` | the same controller `activateX509`, and `activateCertificate` of [x509.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/x509/src/x509.service.ts), which answers 409 while another active row of the same key type covers the same dates |
| `x509-deactivated.json` | `PUT /v1/x509/{org}/deactivate/{id}` | the same controller `deActivateX509`, and `deActivateCertificate` of the service, which sets the status `In Active` |
| `x509-chain.pem` | none | a leaf and an issuing CA made for the tests with the key type `P-256`. The keys were thrown away, so the files hold no private key. `x509-certificate.json` carries the leaf as `certificateBase64`. The OID4VC issuance service of the platform signs a template with the signer option `X509_P256` or `X509_ED25519` with the active row of the key type, and puts `certificateBase64` alone in `x5c` ([oid4vc-issuance.service.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/oid4vc-issuance/src/oid4vc-issuance.service.ts)). |
| `proofs.json` | `GET /v1/orgs/{org}/proofs` | the controller `getProofPresentations`, `GetAllProofRequestsDto`, and `getAllProofRequests` of [verification.repository.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/verification/src/repositories/verification.repository.ts) with the model `presentations` |
| `platform-schemas.json` | `GET /v1/platform/schemas` | [platform.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/platform/platform.controller.ts) `getAllSchema`, `GetAllSchemaByPlatformDto` of [get-all-schema.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/schema/dtos/get-all-schema.dto.ts), and `getAllSchema` of [schema.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/ledger/src/schema/schema.service.ts), which parses the attributes |
| `platform-cred-defs.json` | `GET /v1/platform/cred-defs` | the same controller `getAllCredDefs`, and `getAllPlatformCredDefsDetails` of [credential-definition.repository.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/ledger/src/credential-definition/repositories/credential-definition.repository.ts) |

The query parameter `requestType` is `indy` or `presentationExchange`
(`ProofRequestType` of verification.enum.ts). The states of a proof
exchange are those of the present proof protocol of the agent:
`request-sent`, `presentation-received`, `done`, `abandoned`, and
`declined`. The platform needs the schema of each input descriptor of a
DIF PE request (`InputDescriptors` of the DTO), and it keeps only the
path of each field.

## The holder wallet in the shared agent

These files were written on 2026-09-27 from the controllers of the
agent at the release that the stack file pins,
`v2.2.1-alpha-jsonld-vc.2.1`, and from the records of Credo 0.6.2, the
release the agent builds on. Each record is the `toJSON` form of its
class. The agent answers without the wrapper of the api gateway. Every
label and every value is a placeholder in square brackets.

| File | Call | Source |
| --- | --- | --- |
| `agent-token.json` | `POST /agent/token` | [AgentController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/agent/AgentController.ts) `getAgentToken`, and `expressAuthentication` of [authentication.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/authentication.ts), which compares the whole `Authorization` header with the API key |
| `agent-tenant-created.json`, `agent-tenant-token.json` | `POST /multi-tenancy/create-tenant`, `POST /multi-tenancy/get-token/{tenant}` | [MultiTenancyController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/multi-tenancy/MultiTenancyController.ts), which answers with the tenant record and a token |
| `agent-did-created.json`, `agent-dids.json` | `POST /dids/write`, `GET /dids` | [DidController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/did/DidController.ts) `handleKey` without a seed, and `getDids`, which lists the DID records a tenant made, a `did:peer` of each connection included |
| `agent-oob-received-offer.json`, `agent-oob-received-request.json`, `agent-oob-received-connection.json` | `POST /didcomm/oob/receive-invitation-url` | [OutOfBandController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/outofband/OutOfBandController.ts) `receiveInvitationFromUrl`, which answers with the out of band record and the connection record |
| `agent-invitations.txt` | none: the invitation URLs of the three answers above | the out of band invitation of Aries RFC 0434, with an offer of issue credential 2.0 or a request of present proof 2.0 in `requests~attach` |
| `agent-connections.json`, `agent-connection-completed.json` | `GET /didcomm/connections`, `GET /didcomm/connections/{id}` | [ConnectionController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/connections/ConnectionController.ts), and `DidCommConnectionRecord` of Credo |
| `agent-credentials-offer-received.json`, `agent-credential-offer-received.json`, `agent-credential-request-sent.json`, `agent-credential-done.json`, `agent-credential-done-jsonld.json`, `agent-credential-done-unbound.json`, `agent-credential-abandoned.json`, `agent-credentials-done.json` | `GET /didcomm/credentials`, `GET /didcomm/credentials/{id}`, `POST /didcomm/credentials/accept-offer` | [CredentialController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/credentials/CredentialController.ts), and `DidCommCredentialExchangeRecord` of Credo with the metadata keys `_anoncreds/credential` and `_anoncreds/credentialRequest` |
| `agent-credential-form-data.json` | `GET /didcomm/credentials/{id}/form-data` | the same controller, and `getFormatData` of Credo, which answers with the offer per format and `offerAttributes` |
| `agent-w3c-credentials.json` | `GET /didcomm/credentials/w3c` | the same controller `getAllW3c`, and `W3cCredentialRecord` of Credo 0.6, which keeps the credential in `credentialInstances` |
| `agent-proofs-request-received.json`, `agent-proof-request-received.json`, `agent-proof-presentation-sent.json`, `agent-proof-done.json`, `agent-proof-abandoned.json` | `GET /didcomm/proofs`, `GET /didcomm/proofs/{id}`, `POST /didcomm/proofs/{id}/accept-request` | [ProofController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/proofs/ProofController.ts), which picks the credentials of the answer itself, and `DidCommProofExchangeRecord` of Credo |
| `agent-proof-form-data.json` | `GET /didcomm/proofs/{id}/form-data` | the same controller, and `getFormatData` of Credo, which answers with the request per format |

| `agent-oid4vci-offer-resolved.json`, `agent-oid4vci-offer-authorization-code.json` | `POST /openid4vc/holder/resolve-credential-offer` | [holder.service.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/holder/holder.service.ts) `resolveCredentialOffer`, which answers with the resolved offer of Credo, with `credentialOfferPayload` |
| `agent-oid4vci-credential-stored.json`, `agent-sd-jwt-vcs.json`, `agent-mdoc-vcs.json` | `POST /openid4vc/holder/request-credential`, `GET /openid4vc/holder/sd-jwt-vcs`, `GET /openid4vc/holder/mdoc-vcs` | the same service `requestCredential`, which stores and returns the records, and `SdJwtVcRecord` and `MdocRecord` of Credo 0.6, which keep the credential in `credentialInstances` |
| `agent-oid4vp-request-resolved.json` | `POST /openid4vc/holder/resolve-proof-request` | the same service `resolveProofRequest`, and `resolveAuthorizationRequest` of the OID4VP holder service of Credo, which answers with the DCQL query result per credential query |
| `agent-oid4vp-request-resolved-plain-claims.json` | `POST /openid4vc/holder/resolve-proof-request` | the same call for a query of one claim. The stored SD-JWT keeps `contactEmail` and `residentSince` outside any disclosure, as an issuer that marks them not disclosable writes it. The SD-JWT VC draft, section 3.2.2, keeps such claims in the payload, so every presentation shows them. A key that was thrown away signs it |
| `agent-oid4vp-request-resolved-claim-sets.json` | `POST /openid4vc/holder/resolve-proof-request` | the same call for a query with `claim_sets`. The claims result follows [m-claims-result.ts](https://raw.githubusercontent.com/openwallet-foundation-labs/dcql-ts/main/dcql/src/dcql-query-result/m-claims-result.ts) of the DCQL library, read on 2026-09-27, with `valid_claim_sets`, `valid_claim_indexes` and `output`. [DcqlService.ts](https://raw.githubusercontent.com/openwallet-foundation/credo-ts/main/packages/core/src/modules/dcql/DcqlService.ts) of Credo discloses the `output` of the first valid claim set, so the agent shares both claims |
| `agent-oid4vp-request-resolved-pe.json` | `POST /openid4vc/holder/resolve-proof-request` | the same call for a request with a Presentation Exchange definition. The resolved request of Credo 0.6.2 then carries `presentationExchange` with `definition` and `credentialsForRequest`, not `dcql`: `OpenId4VpResolvedAuthorizationRequest` of [OpenId4vpHolderServiceOptions.ts](https://raw.githubusercontent.com/openwallet-foundation/credo-ts/v0.6.2/packages/openid4vc/src/openid4vc-holder/OpenId4vpHolderServiceOptions.ts), and the requirements, `submissionEntry`, `verifiableCredentials`, `claimFormat`, `credentialRecord` and `disclosedPayload` of [DifPexCredentialsForRequest.ts](https://raw.githubusercontent.com/openwallet-foundation/credo-ts/v0.6.2/packages/core/src/modules/dif-presentation-exchange/models/DifPexCredentialsForRequest.ts), read on 2026-10-05. `selectCredentialsForRequest` of [DifPresentationExchangeService.ts](https://raw.githubusercontent.com/openwallet-foundation/credo-ts/v0.6.2/packages/core/src/modules/dif-presentation-exchange/DifPresentationExchangeService.ts) answers with the first `needsCount` entries of each requirement and the first credential of each |
| `agent-oid4vp-request-accepted.json`, `agent-oid4vp-request-refused.json` | `POST /openid4vc/holder/accept-proof-request` | the same service `acceptPresentationRequest`, which picks the first valid credential of each query with `selectCredentialsForDcqlRequest` and answers with the status and the body of the verifier |

The removal of a W3C credential goes through `DELETE
/openid4vc/holder/credential` of
[holder.service.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/holder/holder.service.ts),
with the type `w3c-vc`, and of an SD-JWT or an mdoc credential with
`sd-jwt-vc` or `mso_mdoc`. The agent has no call that removes an AnonCreds
credential, no decline call, and no basic message call.

## The nonce of an OID4VP request

The pinned platform takes no nonce of the caller. `PresentationRequestDto`
of
[oid4vc-verifier-presentation.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-verification/dtos/oid4vc-verifier-presentation.dto.ts),
read on 2026-10-04, has `requestSigner`, `presentationExchange`, `dcql`,
`responseMode`, `expectedOrigins` and `version` only. The agent picks the
nonce and keeps it in the verification session record.

| File | Call | Source |
| --- | --- | --- |
| `presentation-created.json` | `POST /v1/orgs/{org}/oid4vp/presentation` | `createVerificationPresentation` of [oid4vc-verification.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-verification/oid4vc-verification.controller.ts), which answers with `createAuthorizationRequest` of the agent [verification-sessions.service.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/verifier-sessions/verification-sessions.service.ts): the request URL and the record `OpenId4VcVerificationSessionRecord` of [Credo](https://raw.githubusercontent.com/openwallet-foundation/credo-ts/main/packages/openid4vc/src/openid4vc-verifier/repository/OpenId4VcVerificationSessionRecord.ts). A request signed with a DID sits in `authorizationRequestJwt`, whose payload carries the nonce. An unsigned request sits in `authorizationRequestPayload`. Read on 2026-10-04. The body takes exactly one of `dcql` and `presentationExchange`. The class `PresentationRequestDto` of [oid4vc-verifier-presentation.dto.ts](https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/oid4vc-verification/dtos/oid4vc-verifier-presentation.dto.ts) checks it, and `PexFieldConstraintDto` needs an `id` on each field. Read on 2026-10-05 |

## The DID resolution of the agent

| File | Call | Source |
| --- | --- | --- |
| `agent-did-resolved-indy.json` | `GET /dids/{did}` | `getDidRecordByDid` of [DidController.ts](https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/did/DidController.ts), read on 2026-10-04. It answers with the resolution result of the DID resolver of the agent, with `didDocument` as JSON. The indy VDR resolver of Credo gives a ledger DID the key `#verkey` and the key agreement key `#key-agreement-1`. The call also imports the DID into the tenant that asks, so the adapter asks with a tenant of its own |

## The display of a credential template

The adapter sends the display of the schema as `appearance.display`
and a label per claim as `template.attributes[].display`. The body
follows `CreateCredentialTemplateDto`, `AppearanceDto`,
`CredentialDisplayDto`, `CredentialAttributeDto` and
`CredentialAttributeDisplayDto` of
[oid4vc-issuer-template.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/dtos/oid4vc-issuer-template.dto.ts),
read on 2026-10-05. A display entry needs a name. Its locale,
description and colours are optional. A claim label has a name and an
optional locale. The issuer metadata of the platform puts both under
`credential_metadata` of each configuration:
`buildCredentialConfigurationsSupported` and `buildClaimsFromTemplate`
of
[issuer.metadata.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/oid4vc-issuance/libs/helpers/issuer.metadata.ts),
read on the same day. The first template of `templates.json` carries
both, as the template listing returns them.
