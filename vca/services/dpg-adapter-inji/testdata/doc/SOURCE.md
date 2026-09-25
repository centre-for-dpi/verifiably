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
