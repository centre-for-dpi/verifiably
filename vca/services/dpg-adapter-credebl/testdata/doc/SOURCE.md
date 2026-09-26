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
| `did-created.json` | `POST /v1/orgs/{org}/agents/did` | [agent-service.controller.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/agent-service.controller.ts) `createDid`, body [create-did.dto.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/dto/create-did.dto.ts), and `createDid` in [agent-service.service.ts](https://raw.githubusercontent.com/credebl/platform/main/apps/agent-service/src/agent-service.service.ts) |

The agent makes the key of a `did:key` without a seed. The agent needs
a seed for `did:indy` and `did:web`, which is the private key
([DidController.ts](https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/did/DidController.ts)
`handleIndy`, `handleWeb`). The adapter never sends key material
(ADR-001 decision 3), so it makes `did:key` identities only.
