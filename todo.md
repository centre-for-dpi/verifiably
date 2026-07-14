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

## Post-merge: pruebas reales de inji y credebl (2026-07-10)

Tras el merge, se probaron en vivo los stacks `inji` y `credebl` (solo `waltid` se
había probado antes del merge). Se encontraron y corrigieron 2 bugs reales; se
documenta 1 hallazgo de diseño de CREDEBL sin arreglar (fuera de alcance del
filtrado de roles).

### Bug 1 — CRLF en scripts .sh/.sql rompía el init de Postgres (corregido)
`deploy/compose/stack/inji/certify/init.sh` / `init-preauth.sh` (y otros 15
scripts `.sh` + 7 `.sql` en todo el repo) tenían terminadores CRLF por
`core.autocrlf=true` en Windows sin `.gitattributes` que forzara LF. Al montar
esos scripts como `docker-entrypoint-initdb.d` dentro de un contenedor Linux,
el shebang `#!/bin/bash\r` no es válido → `cannot execute: required file not
found` → postgres nunca corría el init → `inji --role issuer` fallaba en seco.
**Fix:** normalizados todos a LF + agregado `.gitattributes` (`*.sh`/`*.sql`/
`Dockerfile`/`Caddyfile` → `eol=lf`) para que nunca vuelva a pasar en un
checkout Windows. Commit: `1248c76`.

### Bug 2 — SIGPIPE hacía que scenario_needs_credebl/injiweb devolvieran "no" (corregido)
`scenario_needs_credebl()`/`scenario_needs_injiweb()` (añadidas en Task 2)
canalizaban `scenario_services "$1" | grep -q '^credebl-'` directo. Como
`scenario_services()` corre `role_services` + `infra_services` como comandos
secuenciales (no un solo `printf`), `grep -q` puede cerrar el pipe apenas
encuentra el primer match mientras el segundo comando sigue escribiendo —
ese comando muere por SIGPIPE, y bajo `set -e` eso hace que toda la función
parezca haber fallado, devolviendo "no" en vez de "yes". Efecto real: cualquier
`deploy.sh up credebl --role <lo-que-sea>` fallaba con "CREDEBL not configured"
aunque `role_services` calculaba bien los servicios `credebl-*`. **Fix:**
capturar el output en variable antes de grepearlo, evitando el pipe. Agregados
4 tests de regresión (reproducidos con TDD: fallan sin el fix, pasan con él).
Commit: `273a4a8`. Tests: 40/40 pasando.

### Bug 3 — CREDEBL: `depends_on` cruzados filtraban servicios de rol equivocado (corregido)
`credebl-verification` y `credebl-organization` declaraban `depends_on:
credebl-issuance`/`credebl-ledger`, y `credebl-agent-provisioning` (compartido
por todos los roles) declaraba `depends_on: credebl-verification`. Docker
Compose resuelve dependencias transitivas aunque no estén en la lista
explícita de `docker compose up -d <servicios>`, así que **cualquier rol de
CREDEBL levantaba de más los servicios de otros roles**: `--role
verifier`/`--role holder` arrastraban `credebl-issuance`/`credebl-ledger`
(exclusivos de issuer), y `--role holder` arrastraba también
`credebl-verification`.

**Investigación antes de tocar el compose file** (a pedido explícito, no se
asumió que el fix era seguro): se auditó el código fuente real de
`github.com/credebl/platform` (el monorepo oficial de CREDEBL). Conclusión con
alta confianza — estas dependencias NO son un requisito real de runtime:
- El flujo core de `verification` (proof-request/verify) va por NATS directo a
  `agent-service`, que llama al agente ACA-Py/Credo por su propio endpoint
  REST — el agente resuelve schema/cred-def contra el ledger, sin pasar por el
  microservicio `ledger` de CREDEBL. La única llamada real de `verification` a
  `ledger` es cosmética (nombres de schema en una lista, con manejo de
  excepción ya existente).
- `organization` solo referencia `issuance`/`verification` en un endpoint
  opcional de estadísticas de dashboard, no en la creación/setup de org.
- El propio `docker-compose.yml` oficial de CREDEBL tiene el mismo grafo de
  dependencias, pero es una cadena de arranque en cascada ("esperá a que
  exista todo lo definido antes"), no un mapa real de llamadas — CREDEBL nunca
  documentó ni soportó un modo de despliegue parcial (issuer-only/verifier-only).

**Fix:** se quitaron las 4 aristas (`verification→issuance`,
`verification→ledger`, `verification→organization`, `organization→issuance`,
`organization→ledger`, `agent-provisioning→verification`) con comentarios en
el compose file explicando por qué, citando la investigación. Commit: `08c139a`.

**Verificación end-to-end tras el fix** (los 3 roles de CREDEBL, deploy real):
- `--role verifier`: `credebl-verification`/`credebl-oid4vc-verification`
  arrancan y quedan escuchando en NATS, SIN `credebl-issuance` ni
  `credebl-ledger`. ✅
- `--role holder`: `credebl-cloud-wallet` arranca y queda escuchando en NATS,
  SIN `credebl-issuance`, `credebl-ledger` ni `credebl-verification`. ✅
- `--role issuer`: regresión verificada — sigue arrancando
  `credebl-issuance`/`credebl-ledger` correctamente (las aristas quitadas eran
  entrantes hacia verification/organization, no salientes desde issuance/ledger). ✅

### Resultado final — matriz completa de 9 combinaciones (3 stacks × 3 roles), todas en deploy real (2026-07-10)

| Stack | issuer | verifier | holder |
|---|---|---|---|
| waltid | ✅ | ✅ | ✅ |
| inji | ✅ | ✅ | ✅ |
| credebl | ✅ | ✅ (tras fix Bug 3) | ✅ (tras fix Bug 3) |

Todas las combinaciones confirmadas en Docker real (no solo dry-run), con
healthchecks nativos o logs de aplicación confirmando arranque sano, y sin
fuga de servicios de otro rol en ningún caso.

Nota aparte (no bloqueante): en este entorno específico, el provisioning del
agente Aries de CREDEBL (`credebl-agent-service`) intentó conectar a una IP
pública (`.env` con `VERIFIABLY_PUBLIC_HOST` apuntando a
`verifiably.ysalabs.work`) que rechazó la conexión — problema de red/entorno
del `.env` de producción usado para la prueba, no del filtrado de roles; no
impidió confirmar qué contenedores arrancan por rol. También se observó un
`unbound variable` preexistente en `scripts/bootstrap-credebl.sh:426` (`local
did_doc` sin inicializar, bajo `set -u`) — no bloqueante, la función tiene
manejo defensivo, no arreglado en esta sesión.

---

## Fuera de scope (spec separado requerido)
- Hub Phase 2: lógica de orquestación en `verifiably-go` para delegar verificación a nodos federados cuando tienen `verifier_url` activo
- `scripts/bootstrap-credebl.sh:401` — inicializar `local did_doc=""` explícitamente para eliminar el riesgo de `unbound variable` bajo `set -u` cuando el camino de asignación no corre
