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
