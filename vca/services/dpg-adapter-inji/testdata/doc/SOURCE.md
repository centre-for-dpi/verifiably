# Sources of the documented fixtures

The files in this folder are written from the upstream sources of the
pinned releases, not recorded from a running stack. The nightly
contract run (`hack/contract-tests.sh`, build tag `contract_inji`)
replaces each file with a recording when it differs.

Pinned releases: Inji Certify 0.14.0, Inji Verify 0.16.0, eSignet
1.5.1 (`deploy/vca/dpg/inji.yaml`). Every source was read on
2026-09-26.

## Credential configuration API (Certify 0.14.0)

| File | Source |
| --- | --- |
| `config-created.json` | `CredentialConfigResponse` (`id`, `status`) returned by `POST /credential-configurations` and `PUT /credential-configurations/{id}`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/CredentialConfigController.java and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/CredentialConfigResponse.java |
| `config-farmer.json` | `CredentialConfigurationDTO` returned by `GET /credential-configurations/{id}`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/CredentialConfigurationDTO.java, with the values of the sample row in https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify_init.sql |
| `config-not-found.json` | Error body of an internal controller (HTTP 200, `errors` array) from https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/advice/ExceptionHandlerAdvice.java, code `config_not_found_by_id` from https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/constants/ErrorConstants.java |
| `config-exists.json` | Same error body with the code `ldp_vc_config_exists`, thrown by the duplicate check of https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CredentialConfigurationServiceImpl.java |

Facts the adapter relies on:

- The servlet path is `/v1/certify` (`server.servlet.path`), and the
  stack configuration opens `/credential-configurations/**` without a
  token and without a CSRF check:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-default.properties
- The API accepts the formats `ldp_vc`, `mso_mdoc`, and `vc+sd-jwt`
  only (`VCFormats` and the switch of `validateCredentialConfiguration`):
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/constants/VCFormats.java
- `ldp_vc` needs `contextURLs`, `credentialTypes`, and
  `signatureCryptoSuite`. `vc+sd-jwt` needs `sdJwtVct` and
  `signatureAlgo`. `mso_mdoc` needs `doctype` and
  `signatureCryptoSuite`. The key manager application and reference ids
  must match `mosip.certify.signature-algo.key-alias-mapper` for the
  signature algorithm, for example `EdDSA` with
  `CERTIFY_VC_SIGN_ED25519` and `ED25519_SIGN`.
- The `DataProvider` plugin mode of the stack needs a `vcTemplate`: a
  Velocity template, base64 encoded. The template reads `_issuer`,
  `_holderId`, `validFrom`, `validUntil`, and one variable per claim.
- `credentialStatusPurposes` holds at most one purpose, and the stack
  allows `revocation` only
  (`mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes`).
- The pre-authorized data API rejects a claim that the configuration
  does not declare (`unknown_claims`), from
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/PreAuthorizedCodeService.java

## Ledger, credential status, and DID document (Certify 0.14.0)

| File | Source |
| --- | --- |
| `ledger-search.json` | The list of `CredentialStatusResponse` that `POST /v2/ledger-search` returns: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/CredentialLedgerController.java and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/CredentialStatusResponse.java |
| `ledger-search-invalid.json` | The error body with the code `invalid_search_criteria`, thrown when no indexed attribute has a value: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CredentialLedgerServiceImpl.java |
| `status-update.json` | The `CredentialStatusResponse` of `POST /credentials/status`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/CredentialStatusController.java and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/UpdateCredentialStatusRequest.java |
| `did.json` | The DID document of `GET /.well-known/did.json`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/WellKnownController.java and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/utils/DIDDocumentUtil.java |

Facts the adapter relies on:

- The ledger search needs `issuerId` and `credentialType`, and at least
  one entry of `indexedAttributesEquals` with a value. It answers 204
  when nothing matches. It has no paging.
- The ledger stores the issuer DID URL as `issuerId`, and the credential
  types sorted and joined with commas as `credentialType`
  (`LedgerUtils.extractCredentialType`):
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/utils/LedgerUtils.java
- A time is a `LocalDateTime` in the pattern `yyyy-MM-dd'T'HH:mm:ss`.
- The first version of the status update finds the credential by
  `credentialId` in the ledger and sets `status` for the purpose. An
  unknown id answers 404. A scheduled job then writes the status list:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CredentialStatusServiceImpl.java
- The stack opens `/ledger-search/**` and `/credentials/**` without a
  token (`certify-default.properties`, as above).

## mDoc and rendering templates (Certify 0.14.0)

| File | Source |
| --- | --- |
| `credential-mdoc.json` | The credential answer of an `mso_mdoc` request: the IssuerSigned CBOR, base64url without padding, from https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/credential/MDocCredential.java. The fixture holds three elements of the `org.iso.18013.5.1` namespace and an unsigned MSO. |
| `rendering-template.svg` | The body of `GET /rendering-template/{id}` (`image/svg+xml`), from https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/RenderingTemplateController.java. The drawing is a sample card. |

Facts the adapter relies on:

- The mDoc template names `docType`, `validityInfo` with `${_validFrom}`
  and `${_validUntil}`, and `namespaces`: one list of elements per
  namespace, each with `digestId`, `elementIdentifier`, and
  `elementValue` (`MDocProcessor.processTemplatedJson`):
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/utils/MDocProcessor.java
- Certify 0.14.0 skips the claim check of an mDoc staging call (release
  note INJICERT-1282): https://docs.inji.io/inji-certify/releases/version-0.14.0
- The Linked Data proof suites of the release are in
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/constants/SignatureAlg.java
- The deployment names one rendering template in
  `mosip.certify.data-provider-plugin.rendering-template-id`
  (`CertifyIssuanceServiceImpl`), and the stack opens
  `/rendering-template/**` without a token.
- The features page lists JSON-LD, JWS, SD-JWT, mDoc, and mDL, and SVG
  rendering: https://docs.inji.io/inji-certify/overview/features

## Credential check (Verify 0.16.0)

| File | Source |
| --- | --- |
| `vc-verification-success.json`, `-expired.json`, `-revoked.json`, `-invalid.json` | `VCVerificationStatusDto` of `POST /vc-verification`: https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/java/io/inji/verify/controller/VCVerificationController.java and https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/java/io/inji/verify/dto/verification/VCVerificationStatusDto.java, with the values of `VerificationStatus` from https://raw.githubusercontent.com/mosip/vc-verifier/master/vc-verifier/kotlin/vcverifier/src/main/java/io/mosip/vercred/vcverifier/data/Data.kt |

Facts the adapter relies on:

- The body is the credential text. `application/vc+sd-jwt` and
  `application/dc+sd-jwt` select SD-JWT; every other Content-Type
  selects `ldp_vc`, and the check reads the revocation purpose:
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/java/io/inji/verify/services/impl/VCVerificationServiceImpl.java
- A revoked credential answers `REVOKED` whatever the other checks say
  (`Utils.getVcVerificationStatus`):
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/java/io/inji/verify/utils/Utils.java

## Key manager (Certify 0.14.0)

| File | Source |
| --- | --- |
| `key-certificate.json` | `ResponseWrapper<KeyPairGenerateResponseDto>` of `GET /system-info/certificate`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/SystemInfoController.java, fields from https://raw.githubusercontent.com/mosip/keymanager/master/kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/keymanagerservice/service/impl/KeymanagerServiceImpl.java. The certificate is a self signed test certificate with the default subject of the key manager. |
| `upload-certificate.json`, `upload-ca-certificate.json` | `ResponseWrapper` of `POST /system-info/uploadCertificate` and `POST /system-info/upload-ca-certificate` with a status. |
| `key-not-matching.json` | The error `KER-KMS-014` of a certificate of another key: https://raw.githubusercontent.com/mosip/keymanager/master/kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/keymanagerservice/constant/KeymanagerErrorConstant.java |
| `x509-chain.pem`, `x509-other.pem` | Test chains: a leaf on the key of `key-certificate.json` with its CA, and a certificate of another key. No private key is kept. |

Facts the adapter relies on:

- `getCertificate` makes the key pair when none exists for the
  application id and the reference id, and returns the certificate in
  PEM. `generateCSR` reuses the key. `uploadCertificate` checks that
  the certificate holds the stored public key (KeymanagerServiceImpl
  above).
- The stack allows the partner domain `DEVICE`
  (`mosip.kernel.partner.allowed.domains` in `certify-default.properties`
  above), and opens `/system-info/**` without a token.
- The key alias mapper of the stack names the keys of `RS256`, `EdDSA`,
  `ES256K`, and `ES256` (`certify-default.properties` above).
- The stack sample runs `MockCSVDataProviderPlugin` and
  `LoggerAuditService` in the `DataProvider` plugin mode:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-csvdp-farmer.properties

## Presentation during issuance (Certify 0.14.0)

| File | Source |
| --- | --- |
| `oauth-authorization-server.json` | `OAuthAuthorizationServerMetadataDTO` of `GET /.well-known/oauth-authorization-server`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/controller/OAuthController.java and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/OAuthAuthorizationServerMetadataDTO.java |
| `iar-require-interaction.json` | `IarPresentationResponse` of the first `POST /oauth/iar`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/IarPresentationResponse.java, with the request of `IarVpRequestService.convertToOpenId4VpRequest` and the definition of https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/vp_request_config.json |
| `iar-ok.json` | `IarAuthorizationResponse` of the second call: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/IarAuthorizationResponse.java |
| `iar-error.json` | The status `error` of `IarStatus` with the code `invalid_vp` of `IarPresentationService`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/IarPresentationService.java |
| `token-iar.json` | `OAuthTokenResponse` of the authorization code grant of `IarServiceImpl.processTokenRequest`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/IarServiceImpl.java |

Facts the adapter relies on:

- `POST /oauth/iar` takes a form. The first call needs `response_type`
  `code`, `client_id`, `code_challenge`, `code_challenge_method` `S256`,
  `interaction_types_supported` with `openid4vp_presentation`, and
  `authorization_details` of type `openid_credential` with a
  `credential_configuration_id`. The second call carries `auth_session`
  and `openid4vp_response`, a JSON object with `vp_token` and
  `presentation_submission`.
- Certify posts the presentation to the `response_uri` of Inji Verify
  with the `state`, then reads `vp-result`. The response mode
  `direct_post` of Inji Verify becomes `iar-post` for the wallet.
- The token endpoint takes `grant_type` `authorization_code`, a code
  that starts with `iar_auth_`, and the PKCE `code_verifier`.
- The stack properties name the endpoint in
  `mosip.certify.oauth.interactive-authorization-endpoint` and the
  definition file in `mosip.certify.vp-request.config-file-url`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-default.properties
- The error body of a refused presentation is not in the DTOs. The
  fixture uses the OAuth fields `error` and `error_description`. The
  nightly contract run confirms it.

## Mimoto 0.21.0, the backend of Inji Web 0.16.0

The spike P6-I7a read these sources.

- The wallet API and its session attributes:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/controller/WalletsController.java
- The held credentials, the PDF, the delete, and the download body:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/controller/WalletCredentialsController.java,
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/dto/VerifiableCredentialRequestDTO.java,
  and https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/dto/mimoto/VerifiableCredentialResponseDTO.java
- The presentation calls:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/controller/WalletPresentationsController.java
- The token login and its provider beans:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/controller/TokenAuthController.java,
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/service/TokenServiceFactory.java,
  and https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/service/impl/GoogleTokenService.java
- The session store, the Google registration, and the PIN rule:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/resources/application-default.properties

The holder role of P6-I7b replays these answers.

| File | Source |
| --- | --- |
| `mimoto-wallet.json` | The answer of `POST /wallets`, a `WalletResponseDto` with the `walletId`. `WalletsController.java` above. |
| `mimoto-credentials.json` | The answer of `GET /wallets/{id}/credentials`, a list of `VerifiableCredentialResponseDTO` with names, logos, and ids. The names are those of the Farmer and National ID samples of the stack. `WalletCredentialsController.java` above. |
| `mimoto-presentation.json` | The answer of `POST /wallets/{id}/presentations`, with the `presentationId` and the verifier of the request. `WalletPresentationsController.java` above. |
| `mimoto-credential.pdf` | A one page PDF in place of the rendered credential, which Mimoto returns for `Accept: application/pdf`. Its content is a stand in. The wallet reads only the media type and the bytes. |

The fake answers the token login with a `Set-Cookie` header, as the
session filter of Mimoto does. It answers `401` for a refused token and
for an ended session. The PATCH answer carries `redirectUri` when the
verifier gave one.

## eSignet 1.5.1 as the authorization server and a login provider

The eSignet facts steer `vca dpg bootstrap` and the authorization code
offer. The CLI test answers the client API from these shapes.

- The client API is `POST /v1/esignet/client-mgmt/oauth-client` with
  `RequestWrapper<ClientDetailCreateRequestV2>` and
  `PUT /v1/esignet/client-mgmt/oauth-client/{client_id}` with
  `ClientDetailUpdateRequestV2`:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/java/io/mosip/esignet/controllers/ClientManagementController.java
- The create request needs `clientName`, `publicKey`, `userClaims`,
  `authContextRefs`, `logoUri`, `redirectUris` (at most 5),
  `grantTypes`, `clientAuthMethods`, and `clientNameLangMap`:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-core/src/main/java/io/mosip/esignet/core/dto/ClientDetailCreateRequest.java
- The public key is an RSA JWK (`RsaJsonWebKey` in
  `IdentityProviderUtil.getJWKString`). A known client id answers
  `duplicate_client_id`:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-core/src/main/java/io/mosip/esignet/core/util/IdentityProviderUtil.java
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/client-management-service-impl/src/main/java/io/mosip/esignet/services/ClientManagementServiceImpl.java
- The token endpoint takes `private_key_jwt` only, and discovery names
  `RS256` in `token_endpoint_auth_signing_alg_values_supported`. The
  client API needs the scope `add_oidc_client`, except in the `local`
  profile of the eSignet compose file, which clears the rule:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-default.properties
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-local.properties
- The issuer metadata of Certify names its authorization server in
  `authorization_servers` (`mosip.certify.authorization.url`,
  `certify-default.properties` above).

## Identity QR code (Certify 0.14.0, QR code specification 1.1.0)

| File | Source |
| --- | --- |
| `credential-ldp-claim169.json` | The credential answer of an `ldp_vc` configuration with `qrSettings`. The template the adapter registers puts the first entry of `claim_169_values` in `credentialSubject.identityQR`: https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CertifyIssuanceServiceImpl.java. The code is a COSE_Sign1 CWT with claim 169, zlib, and base45. A key that was thrown away signed it. |

Facts the adapter relies on:

- `CredentialConfigurationDTO` carries `qrSettings`, a list of objects,
  and `qrSignatureAlgo`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-core/src/main/java/io/mosip/certify/core/dto/CredentialConfigurationDTO.java
- Certify evaluates `qrSettings` as a Velocity template, maps each key
  with `CLAIM_169_KEY_MAPPER` and `CLAIM_169_VALUE_MAPPER`, signs the
  CWT with `qrSignatureAlgo` or else the proof algorithm, and puts the
  base45 texts in `claim_169_values` for every format
  (`CertifyIssuanceServiceImpl`, `Credential.signQRData`, and
  `VelocityTemplatingEngineImpl.formatQRData` of the tag).
- The stack sample row has `qr_settings` with `Full Name`,
  `Phone Number`, and `Date Of Birth`, and `qr_signature_algo` `EdDSA`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify_init.sql
- The key mapper names `ID`, `Version`, `Language`, `Full Name`,
  `First Name`, `Middle Name`, `Last Name`, `Date of Birth`, `Gender`,
  `Address`, `Email ID`, `Phone Number`, `Nationality`,
  `Marital Status`, and `Guardian`. The value mapper turns `Male`,
  `Female`, and `Others` into 1, 2, and 3:
  https://raw.githubusercontent.com/inji/pixelpass/develop/kotlin/PixelPass/src/commonMain/kotlin/io/mosip/pixelpass/shared/Constants.kt
- The attribute table of claim 169 and the CWT layout:
  https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification
