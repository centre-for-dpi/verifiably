# Sources of the Certify and Inji Verify files

Presentation during issuance (P6-I4b) needs Certify 0.14.0 to reach
Inji Verify 0.16.0 and to read one presentation definition over HTTP.
Every source was read on 2026-09-26. The upstream files carry the
MPL-2.0 licence.

| File | Source | Change |
| --- | --- | --- |
| `vp_request_config.json` | https://raw.githubusercontent.com/mosip/inji-certify/v0.14.0/docker-compose/docker-compose-injistack/config/vp_request_config.json | None |
| `../verify/init.sql` | https://raw.githubusercontent.com/mosip/inji-verify/v0.16.0/docker-compose/db-init/init.sql | None |

## Facts the stack file relies on

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
