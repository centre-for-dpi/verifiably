# Sources of the Certify and Inji Verify files

The issuer profile of `deploy/vca/dpg/inji.yaml` runs Inji Certify
0.14.0 as the injistack compose file of the release does (P6-I0), and
Certify reaches Inji Verify 0.16.0 for a presentation during issuance
(P6-I4b). Every source was read on 2026-09-26. The upstream files carry
the MPL-2.0 licence, and so do the files derived from them.

| File | Source | Change |
| --- | --- | --- |
| `certify-default.properties` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/certify-default.properties | The database, the key store password, Inji Verify, the definition URL of the adapter, and the readiness probe of the health check. No authorization server in the base, no Redis password, and a key certificate subject from `vca setup` (ADR-055). Each change carries a `VCA:` comment. |
| `certify-vca-store.properties` | The plugin block of https://raw.githubusercontent.com/inji/inji-config/release-0.14.x/certify-postgres-landregistry.properties and the block "Use below properties to use certify as authorization server" of https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/resources/application-local.properties | VCA wrote the file from those lines. The query reads the VCA claims store, and the scope is `vca_credential` (ADR-051). |
| `certify-authcode.properties` | none | VCA wrote it. The address of `inji-certify-authcode` and the holder authorization server of the adapter (ADR-052). |
| `certify_init.sql` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify_init.sql | The insert of the credential configuration of the release is gone. The schema and the key policies stay (ADR-050). |
| `certify-nginx.conf` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/certify-nginx.conf | One server per Certify container, and names resolved per request. |
| `vca_claims.sql` | none | VCA wrote it. It makes the foreign table of the VCA claims store (ADR-051). |
| `../verify/init.sql` | https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/docker-compose/db-init/init.sql | None |

## Facts the Certify containers rely on

- The compose file of the release runs the image
  `injistack/inji-certify-with-plugins:0.14.0` as root with
  `container_user=mosip`, `SPRING_CONFIG_NAME=certify`,
  `SPRING_CONFIG_LOCATION=/home/mosip/config/`,
  a profile of its own after `default`, and the key store under
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
- The image bundles the digital credential plugins 0.6.0, among them
  `postgres-dataprovider-plugin.jar`:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service-with-plugins/pom.xml
- `PostgresDataProviderPlugin` loads when
  `mosip.certify.integration.data-provider-plugin` names it. It reads
  `sub` and `scope` of the token, takes the query of the scope from
  `mosip.certify.data-provider-plugin.postgres.scope-query-mapping`, runs
  it as a native query with `:id` set to `sub`, and returns the first row
  with the column names as keys. No row is an error:
  https://raw.githubusercontent.com/inji/digital-credential-plugins/v0.6.0/postgres-dataprovider-plugin/src/main/java/io/mosip/certify/postgresdataprovider/integration/service/PostgresDataProviderPlugin.java
  and https://raw.githubusercontent.com/inji/digital-credential-plugins/v0.6.0/postgres-dataprovider-plugin/src/main/java/io/mosip/certify/postgresdataprovider/integration/repository/DataProviderRepositoryImpl.java
- The scan package of the plugin is
  `io.mosip.certify.postgresdataprovider.integration`, and the table sits
  in the database of Certify:
  https://raw.githubusercontent.com/inji/inji-config/release-0.14.x/certify-postgres-landregistry.properties
  and https://raw.githubusercontent.com/inji/digital-credential-plugins/v0.6.0/postgres-dataprovider-plugin/README.md
- The staging call checks every staged claim against the claims of the
  configuration. A claim with no `mandatory` member is optional:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/PreAuthorizedCodeService.java
  (lines 134 to 208).
- The Postgres image `postgres:15.8` ships the contrib module
  `file_fdw`. Its `program` option reads the output of a command as a
  table: https://www.postgresql.org/docs/15/file-fdw.html
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
  an HTTP server. The injistack compose file serves a fixed file from
  `certify-nginx`. VCA serves the definition that the issuer set from
  the Inji adapter instead (ADR-051 decision 6). Its shape follows the
  file of the release, a `presentation_definition` object:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/docker-compose.yaml
  and https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/vp_request_config.json
- Certify takes the subject of the token of a presentation during
  issuance from the first claim of the presented credential that
  `mosip.certify.iar.identity-data` names:
  https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/certify-service/src/main/java/io/mosip/certify/services/IarPresentationService.java
- Inji Verify listens on 8080 and its UI on 8000. Its settings are
  `DATABASE_*` and `INJI_*`:
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/docker-compose/docker-compose.yml,
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/Dockerfile,
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-ui/nginx.conf, and
  https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/verify-service/src/main/resources/application.properties

## Facts the key certificate subject relies on

Read on 2026-09-26.

- The key manager reads the subject from
  `mosip.kernel.keymanager.certificate.default.*` with no default, so
  every key must exist:
  https://raw.githubusercontent.com/mosip/keymanager/release-1.3.x/kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/keymanagerservice/util/KeymanagerUtil.java
  (lines 128 to 158).
- The certificate builder leaves an empty part out of the subject:
  https://raw.githubusercontent.com/mosip/keymanager/release-1.3.x/kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/keymanager/hsm/util/CertificateUtility.java
  (lines 214 to 231).
- Mimoto uses the same key manager, so the same facts apply to
  `mimoto-default.properties`.
