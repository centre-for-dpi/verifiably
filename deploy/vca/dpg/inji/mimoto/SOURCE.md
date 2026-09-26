# Sources of the Mimoto and Inji Web files

The holder part of `deploy/vca/dpg/inji.yaml` runs Mimoto 0.21.0 and
Inji Web 0.16.0. The files of this folder come from the deployment
files of those releases. Every source was read on 2026-09-26. The
upstream files carry the MPL-2.0 licence, and so do the files derived
from them.

| File | Source | Change |
| --- | --- | --- |
| `mimoto-default.properties` | https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/config/mimoto-default.properties | Redis sessions, the token login provider `google` on the holder realm, the eSignet and Inji Web of the stack, and the key store of the key manager on a volume. Each change carries a `VCA:` comment or names a container of the stack. |
| `mimoto-bootstrap.properties` | https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/config/mimoto-bootstrap.properties | The configuration server is `http://inji-web:3004/`, as in https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/docker-compose/config/mimoto-bootstrap.properties |
| `mimoto_init.sql` | https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/mimoto_init.sql | None |
| `credential-template.html` | https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/config/credential-template.html | The three links to the Google Fonts CDN are gone, because no deployment file loads from a CDN. The PDF uses a local font. |
| `mimoto-issuers-config.json` | The structure of the "Mimoto Issuers Configuration" section of https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/docker-compose/README.md | One issuer: the Inji Certify of the stack, with eSignet as the authorization server and the VCA client `vca-inji`. |
| `mimoto-trusted-verifiers.json` | https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/config/mimoto-trusted-verifiers.json | The Inji Verify of the stack on its host ports. |

## Facts the stack file relies on

- The compose file of Mimoto runs Postgres with `mimoto_init.sql`,
  mounts the properties under `/home/mosip/`, and sets
  `SPRING_CONFIG_LOCATION`, `SPRING_CONFIG_NAME`, and
  `SPRING_CLOUD_BOOTSTRAP_LOCATION`:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/docker-compose/docker-compose.yml
- The compose file of Inji Web runs the image on port 3004 with
  `MIMOTO_URL` and serves the issuer list, the trusted verifiers, and
  the credential template from `/home/mosip`:
  https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/docker-compose/docker-compose.yml
- The nginx file of Inji Web sends `/v1/mimoto/` to
  `mimoto-service:8099` and serves `*.json` and `*-template.html` from
  `/home/mosip`:
  https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/inji-web/nginx.conf
- The start script of Inji Web writes `MIMOTO_URL` into the page
  configuration: https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/inji-web/configure_start.sh
  and https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/inji-web/Dockerfile
- Inji Web sends the browser back to `<origin>/redirect` after the
  authorization at the issuer:
  https://raw.githubusercontent.com/mosip/inji-web/v0.16.0/inji-web/src/utils/api.ts
- The release keeps sessions in Redis with `spring.session.store-type`
  and `spring.data.redis.*`:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/resources/application-default.properties
  The Redis section of the Inji Web compose README says the same.
- The token login provider is the bean `google`. It checks the issuer
  of `google.issuer`, the first audience against the client id of the
  `google` registration, and the `email` claim:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/service/impl/GoogleTokenService.java
- It reads the key set of
  `spring.security.oauth2.client.provider.google.jwk-set-uri`:
  https://raw.githubusercontent.com/mosip/mimoto/v0.21.0/src/main/java/io/mosip/mimoto/config/JwtConfig.java
- The key manager 1.3.0 makes its PKCS12 key store when the file is
  missing:
  https://raw.githubusercontent.com/mosip/keymanager/v1.3.0/kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/keymanager/hsm/impl/pkcs/PKCS12KeyStoreImpl.java
- Mimoto reads the client key of an issuer from
  `mosip.oidc.p12.path` and `mosip.oidc.p12.filename` under the
  `client_alias` of the issuer list (Inji Web compose README, step 6).
