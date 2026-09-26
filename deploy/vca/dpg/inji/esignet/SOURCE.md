# Sources of the eSignet files

The issuer and holder profiles of `deploy/vca/dpg/inji.yaml` run eSignet
1.5.1, the mock identity system 0.10.1, and the eSignet login page,
oidc-ui 1.5.1 (P6-I7f). The files of this folder come from the
deployment files of the eSignet release. Every source was read on
2026-09-26. The upstream files carry the MPL-2.0 licence, and so do the
files derived from them.

| File | Source | Change |
| --- | --- | --- |
| `init.sql` | https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/init.sql | None |
| `nginx.conf` | https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/nginx.conf | The files of the page under `/esignet-ui`, the configuration it reads at the root, names resolved per request, and no route for the key set and the credential issuer metadata of eSignet. |

## Facts the stack file relies on

- The compose file of the release runs eSignet with
  `active_profile_env=default,local`, `plugin_name_env=esignet-mock-plugin.jar`,
  the database URL, `MOSIP_ESIGNET_MOCK_DOMAIN_URL`,
  `MOSIP_ESIGNET_INTEGRATION_KEY_BINDER`, and a Redis. It runs the mock
  identity system with `active_profile_env=default,local` on the same
  Postgres, and oidc-ui with its own nginx file:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/docker-compose.yml
- The local profile clears the scope rule of the client API and the
  captcha:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-local.properties
- eSignet builds its issuer, its token endpoint, and its authorization
  endpoint from `mosip.esignet.domain.url`. The authorization endpoint is
  `/authorize` of that address, which the login page serves.
  `mosip.esignet.jwks-uri` names the key set, and a deployment without the
  login page names the path under `/v1/esignet/oauth`. A credential scope
  must sit in `mosip.esignet.supported.credential.scopes`, and
  `mosip.esignet.credential.scope-resource-mapping` names the audience of
  its token:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-default.properties
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-service-impl/src/main/java/io/mosip/esignet/services/TokenServiceImpl.java
- The login page calls the eSignet API at `/v1/esignet` of its own
  origin, reads `/theme/config.json` and `/locales/default.json` at the
  root, and draws `/authorize`, `/login`, `/consent`, `/claim-details`,
  `/something-went-wrong`, and `/page-not-found`:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/src/services/api.service.js,
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/src/services/configService.js,
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/src/services/langConfigService.js,
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/src/constants/routes.js
- `OIDC_UI_PUBLIC_URL` moves the files of the page under that path at
  the start, and the start script fails when the path exists. A restart
  of the same container therefore starts nginx only:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/configure_start.sh
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/oidc-ui/Dockerfile
- The mock identity system takes one identity per
  `POST /v1/mock-identity-system/identity`, needs every field of its
  schema, answers `duplicate_individual_id` for a known id, and takes the
  one time code `111111`. `mosip.mock.ida.kyc.psut.field` names the field
  that becomes the subject of the eSignet token:
  https://raw.githubusercontent.com/mosip/esignet-mock-services/v0.10.1/mock-identity-system/src/main/java/io/mosip/esignet/mock/identitysystem/controller/IdentityController.java,
  https://raw.githubusercontent.com/mosip/esignet-mock-services/v0.10.1/mock-identity-system/src/main/resources/mock-identity-schema.json,
  https://raw.githubusercontent.com/mosip/esignet-mock-services/v0.10.1/mock-identity-system/src/main/java/io/mosip/esignet/mock/identitysystem/service/impl/IdentityServiceImpl.java,
  and https://raw.githubusercontent.com/mosip/esignet-mock-services/v0.10.1/mock-identity-system/src/main/java/io/mosip/esignet/mock/identitysystem/service/impl/AuthenticationServiceImpl.java
