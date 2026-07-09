# Independent Module Deployments — Todo

Plan completo: `docs/superpowers/plans/2026-06-11-independent-module-deployments.md`
Spec: `docs/superpowers/specs/2026-06-11-independent-module-deployments-design.md`

**Estado: COMPLETO** (implementado vía subagent-driven-development en el worktree
`worktree-independent-module-deployments`, tareas 1-7 + 2 desviaciones de diseño
respecto al plan original, documentadas abajo).

---

## Task 1: Test harness para funciones de rol
- [x] Crear `verifiably-go/tests/test_roles.sh` con assertions para `resolve_role`, `validate_roles`, `role_services`, `infra_services`
- [x] Ejecutar tests — verificar que fallan (funciones no existen aún)
- [x] Commit: `test: add failing tests for role-based deploy helper functions`

## Task 2: Arrays y funciones de rol en `common.sh`
- [x] Reemplazar arrays monolíticos (`WALTID_SERVICES`, `INJI_CORE_SERVICES`, `CREDEBL_SERVICES`) con arrays por rol
- [x] Agregar `resolve_role()`, `validate_roles()`, `role_services()`, `infra_services()`
- [x] Refactorizar `scenario_services()` para usar las nuevas funciones
- [x] Ejecutar tests — verificar que pasan (36/36)
- [x] Commit: `feat(deploy): role-based service arrays and helper functions in common.sh`
- [x] Fix post-review: `infra_services()` re-derivaba el skip de wso2is por conteo de roles,
      ignorando silenciosamente wso2is en deploys parciales (ej. `--role issuer`) aunque
      `VERIFIABLY_SKIP_WSO2IS` no estuviera seteado. Corregido para respetar `IDP_WSO2IS`
      directamente — wso2is es opt-out por esa variable, no por cantidad de roles.

## Task 3: Flag `--role` en `deploy.sh`
- [x] Parsear `--role` en `cmd_up()` → exportar `CLI_ROLE`
- [x] Llamar `validate_roles` antes de `scenario_services`
- [x] Actualizar RAM check para considerar cantidad de roles activos
- [x] Smoke test del flag
- [x] Commit: `feat(deploy): add --role flag to deploy.sh up; validate roles before compose`
- [x] Fix post-review: `.env.example` ya usaba `VERIFIABLY_ROLES=issuer,verifier,schemas`
      (variable compartida con `internal/roles/roles.go`, el sistema de roles de la app Go
      que gatea rutas HTTP: issuer/holder/verifier/trust/schemas/hub). `validate_roles()`/
      `role_services()` ahora aceptan el superset de 6 roles del app Go — `trust`/`schemas`/
      `hub` son no-ops válidos para la capa bash (no afectan qué contenedores arrancan).

## Task 4: Actualizar archivos `.env.example`
- [x] Documentar `VERIFIABLY_ROLES` en `verifiably-go/.env.example` (consolidado en la línea
      preexistente sin comentario, no un bloque duplicado — explica ambas capas: app Go y bash)
- [x] Agregar `VERIFIABLY_ROLES=verifier`, `HUB_VERIFIER_PORT`, `HUB_VERIFIER_BASE_URL`, `WALTID_VERSION` en `deploy/compose/hub/.env.example`
- [x] Commit: `docs(deploy): consolidate and document VERIFIABLY_ROLES across app and deploy layers`

## Task 5: Hub `verifier-api` — compose + config + Caddyfile
- [x] Crear `deploy/compose/hub/config/verifier/web.conf`
- [x] Crear `deploy/compose/hub/config/verifier/verifier-service.conf`
- [x] Agregar servicio `hub-verifier-api` (profile: verifier) en `hub/docker-compose.yml`
- [x] **Desviación del plan:** la ruta se montó en `/verifier-api/*` (no `/verify*`). El plan
      original (2026-06-11) predata la Fase 2 de `federated-emission.md` (portal público de
      verificación), que ya registra `/verify`, `/verify/build`, `/verify/request`,
      `/verify/result/{state}` en el propio binario `verifiably-go:8080`. Enrutar `/verify*`
      al `hub-verifier-api` crudo habría roto ese portal en producción.
- [x] Verificar `docker compose --profile verifier config --services` incluye `hub-verifier-api`
- [x] Commit: `feat(hub): add hub-verifier-api service (profile: verifier) for independent VC verification`

## Task 6: Campo `verifier_url` en `gen-backends.sh`
- [x] Agregar variables `_walt_verifier_advertised`, `_inji_verify_advertised`, `_credebl_verify_advertised` en `backends_for()`
- [x] Agregar `"verifier_url"` a `waltid_stanza`, `inji_verify_stanza`, `credebl_stanza`
- [x] Smoke test: `CLI_ROLE=issuer` → `verifier_url: ""`, `CLI_ROLE=issuer,verifier,holder` → URL poblada
- [x] Commit: `feat(backends): add verifier_url field per backend stanza based on active roles`

## Task 7: Smoke tests finales
- [x] `bash verifiably-go/tests/test_roles.sh` → 36 passed, 0 failed
- [x] `CLI_ROLE=issuer scenario_services waltid` → sin `verifier-api`, sin `wallet-api`
      (wso2is SÍ presente por diseño tras el fix de Task 2 — ver arriba)
- [x] Default sin `VERIFIABLY_ROLES` → comportamiento idéntico al actual
- [x] `docker compose --profile verifier config --services` (hub) → incluye `hub-verifier-api`
- [x] **Deploy real:** `./deploy.sh up waltid --role issuer` levantado end-to-end (Docker Desktop
      local) — confirmado que solo arrancan `postgres`, `caddy`, `keycloak`, `wso2is`,
      `libretranslate`, `issuer-api` (sin `verifier-api` ni `wallet-api`); `issuer-api` respondiendo
      en `:7002`; `verifiably-go:8080` healthy. Stack bajado tras la verificación.
- [x] Commit final

---

## Fuera de scope (spec separado requerido)
- Hub Phase 2: lógica de orquestación en `verifiably-go` para delegar verificación a nodos federados cuando tienen `verifier_url` activo
