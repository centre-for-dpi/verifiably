# Sources of the eSignet files

eSignet 1.5.1 and its login page, oidc-ui 1.5.1, run in the Inji stack
only under the profile `esignet-inji`. `vca deploy` adds the profile when
the operator names a real authenticator at setup (ADR-053). The files of
this folder come from the deployment files of the eSignet release. Every
source was read on 2026-09-26. The upstream files carry the MPL-2.0
licence, and so do the files derived from them.

| File | Source | Change |
| --- | --- | --- |
| `init.sql` | https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/init.sql | The eSignet database only. The second database of the release and its key policy for a test key binder are gone. |
| `nginx.conf` | https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/nginx.conf | The files of the page under `/esignet-ui`, the configuration it reads at the root, names resolved per request, and no route for the key set and the credential issuer metadata of eSignet. |

## Facts the stack file relies on

- The image `mosipid/esignet-with-plugins:1.5.1` bundles the plugins of
  `esignet-plugins` 1.3.1. `plugin_name_env` picks the jar that eSignet
  loads from `/home/mosip/plugins`. A jar under a folder of that path
  loads with its relative name:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-with-plugins/pom.xml
  and https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-with-plugins/README.md
- The MOSIP identity plugin, `mosip-identity-plugin.jar`, needs MOSIP
  IDA, IdRepo, the auth manager, the audit manager, a MISP licence key,
  and `mosip.ida.client.secret`. Its properties name
  `mosip.esignet.integration.authenticator=IdaAuthenticatorImpl` and the
  `ida.*` addresses:
  https://raw.githubusercontent.com/mosip/esignet-plugins/v1.3.1/mosip-identity-plugin/README.md
- The Sunbird RC plugin, `sunbird-rc-plugin.jar`, needs a Sunbird RC
  1.0.0 registry. Its properties name
  `mosip.esignet.integration.authenticator=SunbirdRCAuthenticationService`,
  the fields of the knowledge based check, and the search address of the
  registry:
  https://raw.githubusercontent.com/mosip/esignet-plugins/v1.3.1/sunbird-rc-plugin/README.md
- eSignet reads the properties of each active profile from
  `/home/mosip/config`. The stack file adds the profile `integration`, so
  the file `esignet-integration.properties` of the operator applies last.
- The local profile clears the scope rule of the client API and the
  captcha:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-local.properties
- eSignet builds its issuer, its token endpoint, and its authorization
  endpoint from `mosip.esignet.domain.url`. The authorization endpoint is
  `/authorize` of that address, which the login page serves.
  `mosip.esignet.jwks-uri` names the key set, and a deployment without the
  login page names the path under `/v1/esignet/oauth`:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/esignet-service/src/main/resources/application-default.properties
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
- The docker compose file of the release is not for production use:
  https://raw.githubusercontent.com/mosip/esignet/v1.5.1/docker-compose/README.md
