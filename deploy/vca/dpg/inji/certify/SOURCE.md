# Sources of the Certify and Inji Verify files

The issuer profile of `deploy/vca/dpg/inji.yaml` runs Inji Certify
0.14.0 as the injistack compose file of the release does (P6-I0), and
Certify reaches Inji Verify 0.16.0 for a presentation during issuance
(P6-I4b). Every source was read on 2026-09-26. The upstream files carry
the MPL-2.0 licence, and so do the files derived from them.

| File | Source | Change |
| --- | --- | --- |
| `certify-default.properties` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-default.properties | The database, the key store password, Inji Verify, and the nginx of the stack, and the readiness probe of the health check. Each change carries a `VCA:` comment. |
| `certify-csvdp-farmer.properties` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-csvdp-farmer.properties | The address of `inji-certify-esignet`, eSignet of the stack as the authorization server, the audiences of the Mimoto and VCA client `vca-inji`, the mock identity of the stack, and the DID of the stack. Each change carries a `VCA:` comment. |
| `certify-preauth.properties` | The block "Use below properties to use certify as authorization server" and the `PreAuthDataProviderPlugin` line of https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/resources/application-local.properties, with the plugin block of `certify-csvdp-farmer.properties` above | VCA wrote the file from those lines. |
| `certify_init.sql` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify_init.sql | None |
| `farmer_identity_data.csv` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/farmer_identity_data.csv | None |
| `certify-nginx.conf` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify-nginx.conf | One server per Certify container, names resolved per request, and the presentation definition at the root. |
| `vca_certify_did.sql` | none | VCA wrote it. It names the DID of the stack in the sample configuration. |
| `vp_request_config.json` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/vp_request_config.json | None |
| `../verify/init.sql` | https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/docker-compose/db-init/init.sql | None |

## Facts the Certify containers rely on

- The compose file of the release runs the image
  `injistack/inji-certify-with-plugins:0.14.0` as root with
  `container_user=mosip`, `SPRING_CONFIG_NAME=certify`,
  `SPRING_CONFIG_LOCATION=/home/mosip/config/`,
  `active_profile_env=default, csvdp-farmer`, and the key store under
  `/home/mosip/CERTIFY_PKCS12`. Its Postgres runs `certify_init.sql`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/docker-compose.yaml
- The access token filter checks one issuer
  (`mosip.certify.authn.issuer-uri`), one key set
  (`mosip.certify.authn.jwk-set-uri`), and the audiences of
  `mosip.certify.authn.allowed-audiences`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/filter/AccessTokenValidationFilter.java
- A pre-authorized token carries the issuer of `mosip.certify.oauth.issuer`,
  the audience of `mosip.certify.oauth.access-token.audience`, and the
  staged claims as its subject. Certify signs it with its own key:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/PreAuthorizedCodeService.java
  and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/utils/AccessTokenJwtUtil.java
- The credential comes from the one data provider of the deployment,
  which reads the claims of the token:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CertifyIssuanceServiceImpl.java
- The CSV data provider looks the subject up in the identifier column:
  https://raw.githubusercontent.com/inji/digital-credential-plugins/release-0.5.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java
- The issuer metadata names `mosip.certify.authorization.url` in
  `authorization_servers` and `mosip.certify.domain.url` as the
  credential issuer:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/CredentialConfigurationServiceImpl.java
- The key setup of the start makes the RSA, Ed25519, secp256k1, and
  secp256r1 keys in the `DataProvider` plugin mode:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/config/AppConfig.java
- eSignet sets the audience of an access token to the client id, or to
  the resource of a credential scope
  (`mosip.esignet.credential.scope-resource-mapping`):
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-service-impl/src/main/java/io/mosip/esignet/services/TokenServiceImpl.java
- Mimoto reads `<credential_issuer_host>/.well-known/openid-credential-issuer`
  and `<authorization server>/.well-known/oauth-authorization-server`:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/util/IssuerConfigUtil.java

## Facts the presentation during issuance relies on

- The "Verify Service Configuration" of Certify names
  `mosip.certify.verify.service.base-url`, the `vp-request` and
  `vp-result` endpoints, the verifier client id, and
  `mosip.certify.vp-request.config-file-url`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-default.properties
- Certify reads the definition with a `RestTemplate`, so the file needs
  an HTTP server. The injistack compose file serves it from
  `certify-nginx`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/docker-compose.yaml
- Inji Verify listens on 8080 and its UI on 8000. Its settings are
  `DATABASE_*` and `INJI_*`:
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/docker-compose/docker-compose.yml,
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/Dockerfile,
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-ui/nginx.conf, and
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/resources/application.properties
