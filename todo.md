# Independent Module Deployments — Todo

Plan completo: `docs/superpowers/plans/2026-06-11-independent-module-deployments.md`
Spec: `docs/superpowers/specs/2026-06-11-independent-module-deployments-design.md`

---

## Task 1: Test harness para funciones de rol
- [ ] Crear `verifiably-go/tests/test_roles.sh` con assertions para `resolve_role`, `validate_roles`, `role_services`, `infra_services`
- [ ] Ejecutar tests — verificar que fallan (funciones no existen aún)
- [ ] Commit: `test: add failing tests for role-based deploy helper functions`

## Task 2: Arrays y funciones de rol en `common.sh`
- [ ] Reemplazar arrays monolíticos (`WALTID_SERVICES`, `INJI_CORE_SERVICES`, `CREDEBL_SERVICES`) con arrays por rol
- [ ] Agregar `resolve_role()`, `validate_roles()`, `role_services()`, `infra_services()`
- [ ] Refactorizar `scenario_services()` para usar las nuevas funciones
- [ ] Ejecutar tests — verificar que pasan
- [ ] Commit: `feat(deploy): role-based service arrays and helper functions in common.sh`

## Task 3: Flag `--role` en `deploy.sh`
- [ ] Parsear `--role` en `cmd_up()` → exportar `CLI_ROLE`
- [ ] Llamar `validate_roles` antes de `scenario_services`
- [ ] Actualizar RAM check para considerar cantidad de roles activos
- [ ] Smoke test del flag
- [ ] Commit: `feat(deploy): add --role flag to deploy.sh up; validate roles before compose`

## Task 4: Actualizar archivos `.env.example`
- [ ] Agregar `VERIFIABLY_ROLES=` documentado en `verifiably-go/.env.example`
- [ ] Agregar `VERIFIABLY_ROLES=verifier`, `HUB_VERIFIER_PORT`, `HUB_VERIFIER_BASE_URL`, `WALTID_VERSION` en `deploy/compose/hub/.env.example`
- [ ] Commit: `docs(deploy): add VERIFIABLY_ROLES to .env.example files`

## Task 5: Hub `verifier-api` — compose + config + Caddyfile
- [ ] Crear `deploy/compose/hub/config/verifier/web.conf`
- [ ] Crear `deploy/compose/hub/config/verifier/verifier-service.conf`
- [ ] Agregar servicio `hub-verifier-api` (profile: verifier) en `hub/docker-compose.yml`
- [ ] Agregar ruta `/verify*` en `Caddyfile.hub`
- [ ] Verificar `docker compose --profile verifier config --services` incluye `hub-verifier-api`
- [ ] Commit: `feat(hub): add hub-verifier-api service (profile: verifier) for independent VC verification`

## Task 6: Campo `verifier_url` en `gen-backends.sh`
- [ ] Agregar variables `_walt_verifier_advertised`, `_inji_verify_advertised`, `_credebl_verify_advertised` en `backends_for()`
- [ ] Agregar `"verifier_url"` a `waltid_stanza`, `inji_verify_stanza`, `credebl_stanza`
- [ ] Smoke test: `CLI_ROLE=issuer` → `verifier_url: ""`, `CLI_ROLE=issuer,verifier,holder` → URL poblada
- [ ] Commit: `feat(backends): add verifier_url field per backend stanza based on active roles`

## Task 7: Smoke tests finales
- [ ] `bash verifiably-go/tests/test_roles.sh` → 0 failed
- [ ] `CLI_ROLE=issuer scenario_services waltid` → sin `verifier-api`, sin `wallet-api`, sin `wso2is`
- [ ] Default sin `VERIFIABLY_ROLES` → comportamiento idéntico al actual
- [ ] `docker compose --profile verifier config --services` (hub) → incluye `hub-verifier-api`
- [ ] Commit final

---

## Fuera de scope (spec separado requerido)
- Hub Phase 2: lógica de orquestación en `verifiably-go` para delegar verificación a nodos federados cuando tienen `verifier_url` activo
