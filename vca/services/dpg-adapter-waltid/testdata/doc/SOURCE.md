# Fixtures written from the upstream documentation

The files in this directory follow the walt.id Community Stack 0.18.2
API documentation. No live stack recorded them. The nightly contract
run replaces each file with a recording.

| File | Endpoint | Source | Date |
| --- | --- | --- | --- |
| `onboard-issuer-ed25519.json` | `POST /onboard/issuer` with `keyType` `Ed25519` and `method` `key` | https://docs.walt.id/community-stack/issuer/api/onboarding | 2026-09-25 |
| `onboard-issuer-tse.json` | `POST /onboard/issuer` with `backend` `tse` and its `config` | https://docs.walt.id/community-stack/issuer/key-management/hashicorp-vault and https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/crypto/waltid-crypto/src/commonMain/kotlin/id/walt/crypto/keys/tse/TSEKey.kt | 2026-09-25 |
| `wallet-keys.json` | Wallet API `GET /wallet-api/wallet/{wallet}/keys` | https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-wallet-api/src/main/kotlin/id/walt/webwallet/web/controllers/KeyController.kt and service/keys/SingleKeyResponse.kt | 2026-09-26 |
| `wallet-key-generate.txt` | Wallet API `POST .../keys/generate`, the key id | KeyController.kt, as above | 2026-09-26 |
| `wallet-dids.json` | Wallet API `GET .../dids` | https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-wallet-api/src/main/kotlin/id/walt/webwallet/web/controllers/DidController.kt and db/models/WalletDids.kt | 2026-09-26 |
| `wallet-did-create.txt` | Wallet API `POST .../dids/create/{method}`, the DID | web/controllers/DidCreation.kt at the same tag | 2026-09-26 |
| `wallet-pending.json` | Wallet API `POST .../exchange/useOfferRequest?requireUserInput=true` | web/controllers/exchange/ExchangeController.kt and web/controllers/CredentialController.kt (`reject` with a note) at the same tag | 2026-09-26 |
| `wallet-events.json` | Wallet API `GET .../eventlog` | web/controllers/EventLogController.kt, usecase/event/EventFilterUseCase.kt, and service/events/Event.kt at the same tag | 2026-09-26 |
| `resolve-offer-authcode.json` | Wallet API `resolveCredentialOffer` of an offer with the authorization code grant only | The OID4VCI offer shape; service/exchange/IssuanceService.kt shows the wallet redeems the pre-authorized code only | 2026-09-26 |
| `callback-jwt-issue.json` | Issuer API callback `jwt_issue` to the `statusCallbackUri` of an issue request | https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-issuer-api/src/main/kotlin/id/walt/issuer/issuance/CIProvider.kt (`sendCallback`) and issuance/IssuerApi.kt (`getCallbackUriHeader`) | 2026-09-26 |
| `callback-status-unsuccessful.json` | Callback `issuance_status` with `UNSUCCESSFUL` | CIProvider.kt (`emitIssuanceStatus`) and issuance/OidcApi.kt, as above | 2026-09-26 |
| `callback-status-expired.json` | Callback `issuance_status` with `EXPIRED` | CIProvider.kt (`getVerifiedSession`), as above | 2026-09-26 |
| `callback-resolved-offer.json` | Callback `resolved_credential_offer` | issuance/OidcApi.kt, as above | 2026-09-26 |
| `verifier2-create.json` | Verifier API 2 `POST /verification-session/create` with `flow_type` `cross_device` | https://docs.walt.id/community-stack/verifier2/credential-verification/sd-jwt-vc-oid4vp and https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/protocols/waltid-openid4vp-verifier/src/commonMain/kotlin/id/walt/verifier2/handlers/sessioncreation/VerificationSessionCreationResponse.kt | 2026-09-25 |
| `verifier2-session-active.json` | Verifier API 2 `GET /verification-session/{id}/info`, status `ACTIVE` | https://docs.walt.id/community-stack/verifier2/credential-verification/sd-jwt-vc-oid4vp and https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/protocols/waltid-openid4vp-verifier/src/commonMain/kotlin/id/walt/verifier2/data/Verification2Session.kt | 2026-09-25 |
| `verifier2-session-successful.json` | The same, status `SUCCESSFUL`, with `presented_raw_data` and `policy_results` | as above, plus https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/protocols/waltid-openid4vp-verifier/src/commonMain/kotlin/id/walt/verifier2/verification2/Verifier2PolicyResults.kt | 2026-09-25 |
| `verifier2-session-failed.json` | The same, status `FAILED`, with a failed check | as above | 2026-09-25 |
| `verifier2-create-dcapi.json` | Verifier API 2 `POST /verification-session/create` with `flow_type` `dc_api_openid4vp` and `expectedOrigins` | https://docs.walt.id/community-stack/verifier2/credential-verification/dc-api and the OpenAPI examples of https://verifier2.demo.walt.id/api.json | 2026-09-25 |
| `verifier2-response.json` | Verifier API 2 `POST /verification-session/{id}/response` with the JSON answer of the browser | https://docs.walt.id/community-stack/verifier2/credential-verification/dc-api | 2026-09-25 |
| `verifier2-session-expired.json` | The same, status `EXPIRED` | as above | 2026-09-25 |

The answer has the shape of `onboard-issuer.json`: the key as a walt.id
JWK key object, and the DID. The test key is fixed, so the did:key in
the file matches the public key in it.

Verifier API 2 notes (release 0.18.2):

- The service and its endpoints: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-verifier-api2/README.md
- The settings `clientId`, `clientMetadata`, `urlPrefix`, and `urlHost`: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-verifier-api2/src/main/kotlin/id/walt/verifier2/OSSVerifier2ServiceConfig.kt
- The settings come from files and from command line flags: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-services/waltid-service-commons/src/main/kotlin/id/walt/commons/config/ConfigManager.kt
- The port 7004 of the stack: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/docker-compose/verifier-api2/config/web.conf
- The policy names `signature`, `expiration`, `not-before`, `webhook`: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/credentials/waltid-verification-policies2/src/commonMain/kotlin/id/walt/policies2/vc/policies/ (one file per policy)

The session status values are the enum `VerificationSessionStatus` of
`Verification2Session.kt`. The field `vpToken` of `presented_raw_data`
has no serial name, so it keeps its camel case.

The flow type name `dc_api_openid4vp` comes from the OpenAPI examples of
the live demo verifier, which runs a later release. Release 0.18.2 has
the request mode `DC_API` in `Verification2Session.kt`. The contract
case `TestContractDcApiSession` confirms the name against 0.18.2.

Issuer identity notes (release 0.18.2):

- The key store settings `server`, `auth` with `accessKey` or `roleId` and `secretId`, and `namespace`: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/crypto/waltid-crypto/src/commonMain/kotlin/id/walt/crypto/keys/tse/TSEKeyMetadata.kt and TSEAuth.kt in the same folder
- The transit engine refuses `secp256k1`: `keyTypeToTseKeyMapping` in TSEKey.kt
- A did:cheqd takes `{"network": ...}` and an Ed25519 key through the public registrar: https://raw.githubusercontent.com/walt-id/waltid-identity/v0.18.2/waltid-libraries/waltid-did/src/commonMain/kotlin/id/walt/did/dids/registrar/dids/DidCheqdCreateOptions.kt and registrar/local/cheqd/DidCheqdRegistrar.kt
