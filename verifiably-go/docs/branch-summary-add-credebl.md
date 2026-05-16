# Branch Summary: `add-credebl`

> **Base:** `main` → **Head:** `add-credebl`
> **Commits:** 55 · **Files changed:** 75 · **Lines:** +13 371 / −1 357
> **Última actualización:** 2026-05-16

---

## Objetivo del branch

Integrar **CREDEBL** como tercer DPG (Digital Public Good) en verifiably-go,
junto con la infraestructura de producción necesaria para correr los tres
backends (walt.id, Inji Certify, CREDEBL) bajo un mismo dominio con TLS,
subdominios automáticos y deploy reproducible desde un solo comando.

---

## 1. Nuevo adaptador: CREDEBL

### Paquete `internal/adapters/credebl/`

| Archivo | Responsabilidad |
|---------|----------------|
| `adapter.go` | Bootstrap del cliente HTTP; gestión de sesión CREDEBL; `isTransient` con protección anti-doble-emisión; `sfGroup` singleflight. |
| `config.go` | Resolución de config OID4VCI (issuer ID, credential template ID, DID). |
| `issuer.go` | Issuance OID4VCI vía CREDEBL API: creación de credencial, offer URL, polling de aceptación. Singleflight en `resolveTemplateID` para evitar escrituras duplicadas bajo carga. |
| `verifier.go` | OID4VP vía CREDEBL: creación de verification request, extracción de campos SD-JWT del `vp_token`, routing determinista por estado. |
| `adapter_test.go` | Suite de tests: extracción SD-JWT, lógica `isTransient`, routing OID4VP. |

### Highlights técnicos

- **Singleflight** (`sfGroup`/`sfCall`): implementación stdlib-only (sin `golang.org/x/sync`) que colapsa llamadas concurrentes a `resolveTemplateID`. Evita race conditions bajo burst de issuance.
- **`isTransient`**: `context.DeadlineExceeded` y `context.Canceled` NO son retryables (riesgo de doble emisión). `net.OpError` SÍ lo es. HTTP 5xx también.
- **DPoP**: domain URL extraído de `VERIFIABLY_PUBLIC_URL` para que los tokens DPoP sean válidos externamente.
- **SD-JWT extraction**: soporte para `vp_token` como string y como array JSON; extracción de claims de disclosures tilde-separados.

---

## 2. Multi-vendor routing

### `internal/adapters/registry/`

- `registry.go`: tabla de routing `schemaID → adapter`; soporta walt.id, Inji Certify, Inji Certify Pre-auth, y CREDEBL en el mismo servidor.
- `registry_test.go`: test suite para OID4VP multi-vendor (misma request, backends distintos).

---

## 3. API REST y handlers

### Endpoints nuevos

| Método | Path | Descripción |
|--------|------|-------------|
| `POST` | `/api/v1/issue` | Issuance (todos los backends) |
| `POST` | `/api/v1/bulk/issue` | Bulk issuance CSV |
| `GET`  | `/api/v1/bulk/status/:id` | Estado de job bulk |
| `GET`  | `/api/v1/bulk/progress/:id` | SSE de progreso en tiempo real |
| `GET`  | `/api/v1/credentials` | Listado con filtros |
| `POST` | `/api/v1/credentials/:id/revoke` | Revocación |
| `POST` | `/api/v1/credentials/:id/reinstate` | Reinstauración |
| `POST` | `/api/v1/verify` | Inicio de OID4VP |
| `GET`  | `/api/v1/verify/:state` | Poll resultado verificación |
| `GET`  | `/metrics` | Prometheus text (protegido por API key) |
| `GET`  | `/openapi` | Spec OpenAPI 3.0 + Scalar UI |

### `internal/handlers/ratelimit.go` (nuevo)

Rate limiter per-IP con whitelist de proxies confiables. `VERIFIABLY_TRUSTED_PROXIES` (lista de CIDRs) controla cuándo se usa `X-Forwarded-For`. Sin lista, se usa IP directa (backward compatible). Previene IP spoofing en rate limiting.

### `internal/handlers/session.go`

Exporta `SessionEncrypt` / `SessionDecrypt` (AES-256-GCM) para que los backends PG y Redis reutilicen exactamente el mismo cifrado que el store de archivos. Agrega interfaz `SessionStore` para desacoplar el store del handler.

---

## 4. Paquetes nuevos

### `internal/jobs/` — Queue de bulk issuance

```
queue.go       Async job queue; Submit no bloqueante; worker pool configurable
queue_test.go  6 tests (happy path, errores, SSE, cancel, full, shutdown abort)
```

- Submit devuelve inmediatamente (`HTTP 202`); si el buffer de 256 slots está lleno, limpia el registro y retorna error.
- Workers reciben el `context.Context` de shutdown: en SIGTERM, marcan el job como error con `"server shutdown"`.
- Cleanup loop: borra filas `bulk_jobs` con `status IN ('done','error')` de más de 7 días, cada hora.
- Backend dual: PostgreSQL cuando hay pool disponible; in-memory para dev/test.

### `internal/metrics/` — Prometheus text-format

```
metrics.go       Registry; Counter, Gauge, Histogram; labStr con escape anti-inyección
metrics_test.go  Tests de escaping de labels (\n \r " \)
```

Los valores de labels escapan `\n`, `\r`, `"` y `\` para prevenir inyección de líneas falsas en el endpoint `/metrics`.

### `internal/tracing/` — Trazabilidad W3C

```
tracer.go       Span, SpanContext, Sampler; SpanFromContext / ContextWithSpan
exporter.go     OTLPJSONExporter (HTTP POST a Grafana Tempo/Jaeger); SlogExporter
propagation.go  Extract/Inject W3C traceparent (RFC 9180)
middleware.go   HTTP middleware que inicia spans y propaga trace_id al logger
global.go       Tracer global; safe para usar desde handlers sin inyección
```

- `Inject` propaga `traceparent` con `flags=00` para spans no sampleados — downstream services mantienen el mismo `trace_id` para correlación de logs.
- `Shutdown` usa `sync.Once` para ser idempotente (seguro en multiple call).
- Exporters stackables: OTLP activo cuando `VERIFIABLY_OTEL_ENDPOINT` está seteado; SlogExporter siempre activo (una línea estructurada por span).

### `internal/storage/` — Backends persistentes

```
pg/db.go          Open pool + runMigrations (DDL auto-aplicado)
pg/sessions.go    SessionStore PG con AES-256-GCM
pg/issuance.go    IssuanceLog PG; hash chain integridad; PII excluido
pg/statuslist.go  Token Status List store en PG
redis/client.go   Client wrapper con TLS y timeout configurables
redis/sessions.go SessionStore Redis con AES-256-GCM
```

Clave AES derivada via `sha256.Sum256([]byte(VERIFIABLY_SESSION_SECRET))[:]` — mismo algoritmo en los tres backends (file, PG, Redis).

---

## 5. Infraestructura de deploy

### `deploy.sh` → modular `scripts/`

| Script | Responsabilidad |
|--------|----------------|
| `scripts/common.sh` | Carga de `.env`; helpers `url_for`, `bold/green/red/yellow`; defaults de todas las variables. |
| `scripts/gen-backends.sh` | Genera `config/backends.json` y `auth-providers.*.json` según el escenario. |
| `scripts/start-container.sh` | Build + run de `verifiably-go` como contenedor Docker. |
| `scripts/bootstrap-credebl.sh` | Bootstrap completo de CREDEBL: Keycloak realm, plataforma-admin, DID, OID4VCI issuer, credential template, patches de contenedores. |
| `scripts/gen-caddy.sh` | Generación de `Caddyfile.public` para modo subdominios. |

`deploy.sh` funciona como dispatcher puro que source los scripts y delega.

### Setup wizard (`./deploy.sh setup`)

Wizard interactivo de primera configuración. Escribe `.env` con:
- IP del servidor
- Dominio base (e.g. `verifiably.ysalabs.work`)
- Let's Encrypt email
- Password de admin Keycloak
- Email de plataforma-admin CREDEBL

### Escenarios de deploy

```bash
./deploy.sh up all      # Walt.id + Inji + CREDEBL + WSO2IS + LibreTranslate
./deploy.sh up waltid   # Solo walt.id + Keycloak
./deploy.sh up inji     # Inji Certify + Verify + Web + WSO2IS
./deploy.sh up credebl  # Solo CREDEBL
./deploy.sh status      # Resumen de qué está corriendo
```

### Compose stack

- **`deploy/compose/stack/docker-compose.yml`**: añade `verifiably-pg`, `verifiably-redis`, `citizens-postgres`, perfiles `injiweb`, `subdomain` y `credebl`.
- **`deploy/compose/credebl/docker-compose.yml`**: stack completo de 18 microservicios CREDEBL con volúmenes `credebl_*` aislados.
- **`Caddyfile.public`**: TLS automático vía Let's Encrypt para todos los subdominios (`*.verifiably.ysalabs.work`).

### Variables de entorno clave (nuevas)

| Variable | Descripción |
|----------|-------------|
| `VERIFIABLY_PUBLIC_DOMAIN` | Dominio base para modo subdominios |
| `VERIFIABLY_HOSTS_PATTERN` | Pattern `https://%s.domain` para URLs de servicios |
| `VERIFIABLY_LE_EMAIL` | Email para certificados Let's Encrypt |
| `VERIFIABLY_DATABASE_URL` | DSN PostgreSQL de verifiably-go |
| `VERIFIABLY_REDIS_URL` | URL Redis para sesiones multi-réplica |
| `VERIFIABLY_SESSION_SECRET` | Secreto para derivar clave AES-256-GCM |
| `VERIFIABLY_TRUSTED_PROXIES` | CIDRs de proxies confiables (para XFF) |
| `VERIFIABLY_OTEL_ENDPOINT` | Endpoint OTLP para Grafana Tempo/Jaeger |
| `VERIFIABLY_BULK_WORKERS` | Workers del job queue (default: 4) |
| `CREDEBL_EMAIL` | Email de la cuenta CREDEBL platform-admin |
| `CREDEBL_PASSWORD` | Password CREDEBL (auto-generado si vacío) |

---

## 6. Hardening de seguridad (review 2026-05-16)

| Severidad | Item | Fix |
|-----------|------|-----|
| P0 | PII en DB | `SubjectFields` tagged `json:"-"`; `subjectJSON` nulled en INSERT PG |
| P0 | Sesiones sin cifrar en PG/Redis | AES-256-GCM en ambos backends |
| P1 | Race condition en `resolveTemplateID` | Singleflight stdlib-only |
| P1 | Queue bloqueante (goroutine leak) | `select/default` con cleanup |
| P1 | Inyección en métricas Prometheus | Escape `\n \r " \` en labels |
| P1 | XFF spoofing en rate limiter | Whitelist CIDR de proxies confiables |
| P2 | Job queue sin graceful shutdown | Workers respetan `shutCtx` |
| P2 | TCP error como no-retriable | `net.OpError` → retriable; `DeadlineExceeded` → no |
| P2 | `OTLPJSONExporter.Shutdown` panic en double-call | `sync.Once` |
| P2 | `chainHashOf` duplicado | Exportado como `issuance.ChainHashOf` |
| P3 | bulk_jobs sin TTL | Cleanup loop: filas >7 días eliminadas hourly |
| P3 | traceparent no propagado en spans no-sampleados | `flags=00` per W3C spec |

---

## 7. Documentación añadida

| Archivo | Contenido |
|---------|-----------|
| `TODO.md` | Review de 2026-05-16: 13 ítems P0–P3 resueltos + long-tail pendiente (Vault/SSM, mTLS, backup Docker, revocación push, VERIFIABLY_MODE) |
| `docs/haip-conformance.md` | Gap analysis de HAIP (High Assurance Interop Profile) para OID4VCI/OID4VP |
| `docs/spec-versions.md` | Versiones pinadas de OID4VCI, OID4VP, SD-JWT VC, W3C VC 2.0, HAIP |
| `docs/branch-summary-add-credebl.md` | Este archivo |

---

## 8. Fixes operacionales notables

- **`ctx → shutCtx`** en `main.go`: el job queue recibía `ctx` (no definido en ese scope); corregido a `shutCtx`.
- **`python3` → `grep`** en `bootstrap-credebl.sh`: `python3 open('/c/...')` no funciona en Windows/Git Bash porque el path bash no es un path Windows válido.
- **`bootstrap-keycloak.sh`**: soporta `--skip-tls-verify` cuando Let's Encrypt aún no propagó.
- **`.env` removido de git**: fue accidentalmente trackeado; la eliminación está en commit `761a620`. El archivo ya estaba en `.gitignore`.

---

## 9. Estado del stack al final del branch

```
Contenedores (docker compose ls):
  waltid: 52 servicios (walt.id + Inji + CREDEBL + verifiably-go)

Acceso público (subdomain mode):
  https://verifiably.verifiably.ysalabs.work   ← verifiably-go
  https://keycloak.verifiably.ysalabs.work     ← Keycloak
  https://credebl.verifiably.ysalabs.work      ← CREDEBL API gateway + agente
  https://walt-issuer.verifiably.ysalabs.work  ← walt.id issuer-api
  https://walt-wallet.verifiably.ysalabs.work  ← walt.id wallet-api
  https://walt-verifier.verifiably.ysalabs.work ← walt.id verifier-api
  https://inji-web.verifiably.ysalabs.work     ← Inji Web UI
  https://esignet.verifiably.ysalabs.work      ← eSignet OIDC
  https://wso2.verifiably.ysalabs.work         ← WSO2IS
```

---

## 10. Long-tail pendiente (no en este branch)

| Tag | Item |
|-----|------|
| `[SEC]` | Integrar con Vault KV v2 / AWS SSM para CREDEBL credentials y API keys |
| `[OPS]` | mTLS entre verifiably-go y backends DPG |
| `[OPS]` | Backup automático de volúmenes Docker a S3/GCS |
| `[ARCH]` | Notificación push de revocación al holder (webhook / OID4VC Notification) |
| `[ARCH]` | Resolver Docker socket risk de CREDEBL (static agents) |
| `[ARCH]` | Separar UI y API: `VERIFIABLY_MODE=ui\|api\|all` |
