# TODO — Verifiably-Go Maturity Roadmap

> Generado por code review + arquitectura de madurez (2026-05-16).
> Marcar con `[x]` al completar. Re-priorizar según el roadmap del proyecto.
> Las referencias de archivo usan rutas relativas desde `verifiably-go/`.

---

## P0 — Crítico / Bloqueante (seguridad + datos)

- [x] **[SEC] Eliminar PII del issuance log** ✓ 2026-05-16
  `internal/issuance/log.go:71` — `SubjectFields` cambiado a `json:"-"`. La PII vive
  solo en memoria de proceso; nunca se escribe en `issued-credentials.json`.

- [x] **[SEC] Eliminar log de 3000 bytes del vp_token raw** ✓ 2026-05-16
  `internal/adapters/credebl/verifier.go` — línea `log.Printf("[credebl] ResponseVerified raw: %.3000s", ...)` eliminada. Solo se loguean `state` + campos extraídos.

- [x] **[SEC] Credenciales CREDEBL fuera de backends.json** ✓ 2026-05-16
  `internal/adapters/credebl/config.go` — `UnmarshalConfig` lee 7 `CREDEBL_*` env vars
  y las aplica con prioridad sobre JSON. `deploy.sh` ya no escribe email/password/cryptoKey
  en el JSON; pasa las credenciales al container vía `-e CREDEBL_*` flags en `docker run`.

- [x] **[SEC] Agregar `--restart unless-stopped` + health check al docker run en deploy.sh** ✓ 2026-05-16
  `deploy.sh` — añadidos `--restart unless-stopped`, `--health-cmd`, `--health-interval=15s`,
  `--health-timeout=5s`, `--health-retries=3` al `docker run` en `start_container()`.

- [x] **[BUG] Race condition en translator global** ✓ 2026-05-16
  `internal/handlers/handlers.go` — eliminados `activeTranslator`, `activeContext`, `translatorMu`
  y `installTranslatorForRequest`. Reemplazado por `MakeTranslateFunc(tr)` que captura el
  translator en un closure al startup; la función `t` en el FuncMap no tiene estado mutable.
  `cmd/server/main.go` — translator se construye antes de `loadTemplates` y se pasa a `funcMap`.

---

## P1 — Alta prioridad (próximo sprint)

- [x] **[SEC] Cookie de sesión sin flag `Secure`** ✓ 2026-05-16
  `internal/handlers/session.go` — agregado `Secure: externalScheme(r) == "https"` al
  `http.SetCookie` de `getOrCreate`. La cookie solo viaja por HTTPS cuando el sitio lo usa.

- [x] **[SEC] Validar `X-Forwarded-Host` para redirect URI OIDC** ✓ 2026-05-16
  `internal/handlers/handlers.go` — agregada función `publicBase(r)` que prefiere
  `VERIFIABLY_PUBLIC_URL` (ya seteado por deploy.sh) sobre los headers `X-Forwarded-*`.
  Las dos construcciones de `redirect` en `StartAuth` y `AuthCallback` usan `publicBase`.

- [x] **[SEC] Open redirect en /lang** ✓ 2026-05-16
  `internal/handlers/handlers.go` — `SetLang` ahora parsea el Referer con `url.Parse` y
  usa solo `u.RequestURI()` (path+query, sin scheme/host) para el redirect de destino.

- [x] **[BUG] Manejar errores de ListAllSchemas en handlers críticos** ✓ 2026-05-16
  11 call sites corregidos: `api.go` (3 API handlers → `apiError 503`), `issuance.go` (5 UI
  handlers → `errorToast`), `verifier.go` (`ShowVerify`), `bulk.go` (`SetBulkSource` +
  `runBulkIssue`). Todos retornan ahora un error claro al cliente en vez de fallar silenciosamente.

- [x] **[BUG] Race condition en flush() de sesiones** ✓ 2026-05-16
  `internal/handlers/session.go` — `flush()` ahora serializa cada sesión con `json.Marshal`
  mientras mantiene el store lock (`s.mu`). La encriptación y escritura a disco ocurren después
  de liberar el lock. Elimina la ventana donde un handler podía mutar fields mientras se serializaba.

- [x] **[OBS] Loguear errores de adapter antes de convertirlos en toast** ✓ 2026-05-16
  `internal/handlers/handlers.go` — `slog.Warn("handler error", ...)` agregado al inicio
  de `errorToast`. Todos los 28+ call sites heredan automáticamente el logging sin cambios.

- [x] **[OBS] Agregar duration_ms a los slog events de issuance y verification** ✓ 2026-05-16
  `issuance.go`, `verifier.go`, `api.go` — 4 slog events con `"duration_ms"`:
  `IssueToWallet` (UI + API), `IssueAsPDF`, `FetchPresentationResult`.

- [x] **[TEST] Tests de retry logic en withAuth** ✓ 2026-05-16
  `internal/adapters/credebl/adapter_test.go` (nuevo) — 5 tests con `httptest.Server`:
  happy path, 401→re-auth+retry→OK, 401→401→error, 5xx→retry→OK, 5xx→5xx→error.
  Verifica número de llamadas de autenticación y de `fn` en cada escenario.

---

## P2 — Mejoras importantes (próximas semanas)

- [x] **[SEC] Agregar rate limiting por API key y por IP** ✓ 2026-05-16
  `internal/handlers/ratelimit.go` (nuevo) — sliding-window in-process limiter: 60 req/min
  por API key name (`VERIFIABLY_RATE_KEY_RPM`), 20 req/min por IP (`VERIFIABLY_RATE_IP_RPM`).
  `internal/handlers/handlers.go` — campo `RateLimiter *RateLimiter` en `H`.
  `internal/handlers/api.go` — check en `APIIssue` y `APIIssueBulk`; responde 429 con
  `Retry-After: 60`. `cmd/server/main.go` — `RateLimiter: handlers.NewRateLimiter()`.

- [x] **[BUG] Hacer firstIssuerDPG / firstVerifierDPG deterministas** ✓ 2026-05-16
  `internal/handlers/api.go` — ambas funciones ahora usan `sort.Strings` sobre las keys del
  mapa antes de retornar el primero, garantizando la misma selección en requests paralelos.

- [x] **[BUG] Límite de rows en APIIssueBulk + timeout global** ✓ 2026-05-16
  `internal/handlers/api.go` — `const maxBulkRows = 500` + 413 si se excede.
  `context.WithTimeout(ctx, 5*time.Minute)` aplicado antes del loop de emisión.

- [x] **[OBS] Middleware de request ID (X-Request-ID)** ✓ 2026-05-16
  `cmd/server/main.go` — `withRequestID` middleware genera un ID hex de 8 bytes por request
  (preserva el header entrante si ya existe), lo pone en el response header y en el contexto
  via `ctxKeyRequestID`. El mux queda envuelto: `Handler: withRequestID(mux)`.

- [x] **[OBS] Migrar todos los log.Printf a slog** ✓ 2026-05-16
  `internal/adapters/credebl/adapter.go` (2), `verifier.go` (4), `registry/registry.go` (1),
  `internal/handlers/api.go` (1). Todos reemplazados por `slog.Warn/Debug` con atributos
  clave-valor. Los logs de polling pasan a `Debug` para no saturar la salida en producción.

- [x] **[OBS] /readyz debe verificar alcanzabilidad del adapter primario** ✓ 2026-05-16
  `cmd/server/main.go` — cuando `VERIFIABLY_READYZ_URL` está seteado, el handler hace un
  HEAD request con timeout de 2 s. Si falla, retorna 503. Sin la env var el comportamiento
  anterior (200 siempre) se preserva para retro-compatibilidad.

- [x] **[TEST] Tests HTTP end-to-end con httptest** ✓ 2026-05-16
  `internal/handlers/api_test.go` (nuevo) — 10 tests con `httptest.NewRecorder`:
  `APIIssue` (success, schema not found→404, adapter error→502, unauthenticated→401/503,
  rate limited→429+Retry-After), `APIIssueBulk` (row limit→413, success→accepted=2),
  `APIVerifyRequest` (success, adapter error→502),
  `PublishBitstringStatusList` (no signing key→503).

- [x] **[TEST] Test de concurrencia en Registry (go test -race)** ✓ 2026-05-16
  `internal/adapters/registry/registry_test.go` (nuevo) — 100 goroutines concurrentes haciendo
  `ListAllSchemas` + `SaveCustomSchema` + `DeleteCustomSchema`. Correr con
  `go test -race ./internal/adapters/registry/...`.

- [x] **[SPEC] Documentar versiones de spec implementadas por cada adapter** ✓ 2026-05-16
  `docs/spec-versions.md` (nuevo) — tabla adapter × protocolo × draft: CREDEBL OID4VCI
  draft-13 pre-auth + OID4VP draft-20 DCQL; walt.id OID4VCI draft-13 + OID4VP draft-18 PE2;
  Inji Certify OID4VCI draft-13; Inji Verify OID4VP draft-20. Incluye formato de credencial,
  wire-format de vp_token, gaps de compatibilidad conocidos, e instrucciones de actualización.

- [x] **[SPEC] Agregar tests de regresión de wire format para vp_token** ✓ 2026-05-16
  `internal/adapters/credebl/verifier_test.go` — ya implementados en la sesión anterior:
  `TestExtractDisclosedFieldsFromVpToken_ArrayFormat`, `_StringFormat`, `_MultipleCredentials`,
  `_InvalidJSON`, `_ArrayFallsBackToString`. Cubren ambos formatos conocidos del CREDEBL/Credo.

---

## P3 — Deseables / largo plazo

- [x] **[OBS] Agregar Prometheus + endpoint /metrics** ✓ 2026-05-16
  Implementado en `internal/metrics/metrics.go` (stdlib-only, sin dependencias externas).
  Counters: `credential_issued_total{dpg,schema,status}`, `verification_requested_total{dpg,schema,status}`.
  Histogramas: `adapter_duration_seconds{dpg,op}` con buckets 5ms/25ms/100ms/500ms/2s.
  Endpoint `/metrics` en main.go protegido con API key opcional. 6 unit tests en `metrics_test.go`.

- [x] **[OPS] Migrar sessions y status lists a PostgreSQL** ✓ 2026-05-16
  `internal/storage/pg/` — tres backends: `SessionStore` (flush 5 s, replay al arranque),
  `IssuanceLog` (hash-chain preservado, mutex serializa Append), `StatusListStore` (delega
  bit ops a in-memory Store + sincroniza BYTEA a Postgres en cada mutación).
  `cmd/server/main.go` — `pg.Open` una vez; `buildSessionStore` y `wireIssuancePG`
  comparten el pool. Activado con `VERIFIABLY_DATABASE_URL`.

- [x] **[SEC] Hash chain en el issuance log (tamper-evidence)** ✓ 2026-05-16
  Campo `PrevHash string` en `IssuedCredential`. `chainHashOf()` calcula SHA-256 de campos
  inmutables (ID, SchemaID, IssuerDpg, OwnerKey, IssuedAt, PrevHash) separados por `\x00`.
  `Append()` enlaza cada entrada a la anterior. `VerifyChain()` detecta corrupciones.
  Backward-compatible: entradas sin PrevHash (pre-chain) no se marcan como corruptas.
  4 unit tests en `log_test.go`.

---

## P0 — Crítico emergente (detectado en review 2026-05-16)

- [x] **[SEC] PII reintroducida en backend PostgreSQL** ✓ 2026-05-16
  `internal/storage/pg/issuance.go` — `json.Marshal(c.SubjectFields)` reemplazado por `var subjectJSON []byte`.
  PII nunca llega a la columna `subject_fields`; comportamiento idéntico al file backend (`json:"-"`).
  También eliminada la cláusula `subject_fields::text ILIKE` del List() ya que el campo es siempre nulo.

- [x] **[SEC] Sessions sin cifrar en PG y Redis backends** ✓ 2026-05-16
  `internal/handlers/session.go` — exportados `SessionEncrypt`/`SessionDecrypt`.
  `internal/storage/pg/sessions.go` — constructor recibe `key []byte`; `flush()` cifra con AES-GCM antes de
  escribir a PG; `load()` descifra al leer.
  `internal/storage/redis/sessions.go` — ídem para `saveToRedis()`/`loadFromRedis()`.
  `cmd/server/main.go` — `buildSessionStore` deriva la clave AES al inicio (antes de elegir backend) y la
  pasa a `pg.NewSessionStore(pool, aesKey)` y `redis.NewSessionStore(client, aesKey)`.

---

## P1 — Alta prioridad emergente

- [x] **[BUG] `jobs.Submit()` bloquea indefinidamente con queue llena** ✓ 2026-05-16
  `internal/jobs/queue.go` — send reemplazado por `select { case q.pending <- ...: default: ... }`.
  Si la queue está llena se elimina el job recién creado (mem + PG) y se retorna `fmt.Errorf("queue full")`.

- [x] **[BUG] Race en `resolveTemplateID` → templates duplicados en CREDEBL** ✓ 2026-05-16
  `internal/adapters/credebl/issuer.go` — implementado `sfGroup` (stdlib-only singleflight) en el mismo paquete.
  Campo `templateSF sfGroup` en `Adapter`. `resolveTemplateID` usa `a.templateSF.Do(schema.ID, fn)`;
  doble check-en-cache dentro del closure para el caso post-singleflight.

- [x] **[SEC] Label values en métricas no sanean `\n` — Prometheus text injection** ✓ 2026-05-16
  `internal/metrics/metrics.go` — `labStr` ahora escapa `\` → `\\`, `"` → `\"`, `\n` → `\n`, `\r` → `\r`.

- [x] **[SEC] Rate limiter IP confía en X-Forwarded-For sin whitelist de proxies** ✓ 2026-05-16
  `internal/handlers/ratelimit.go` — `NewRateLimiter` lee `VERIFIABLY_TRUSTED_PROXIES` (CIDR list).
  `clientIP` solo acepta XFF si `RemoteAddr` está dentro de un CIDR de confianza (o si la lista está vacía,
  comportamiento legacy). Método `clientIP` movido a `RateLimiter` para acceder a `trustedNets`.

---

## P2 — Mejoras importantes emergentes

- [x] **[BUG] `jobs.run()` usa `context.Background()` — ignora graceful shutdown** ✓ 2026-05-16
  `internal/jobs/queue.go` — `NewQueue` recibe `ctx context.Context`; campo `q.ctx` almacenado en Queue.
  `run()` pasa `q.ctx` a cada `workFn`; loop chequea `q.ctx.Err()` antes de cada row y marca el job
  como `StatusError` con msg `"server shutdown"` si el contexto se cancela.
  `cmd/server/main.go` — `NewQueue(ctx, pgPool, bulkWorkers)`.

- [x] **[BUG] `isTransient()` no detecta errores TCP (connection refused)** ✓ 2026-05-16
  `internal/adapters/credebl/adapter.go` — añadido guard explícito para `context.DeadlineExceeded` y
  `context.Canceled` (no reintentar — riesgo de double-issuance). Añadido `errors.As(err, &net.OpError{})`
  para detectar fallos TCP (ECONNREFUSED, ECONNRESET) que sí son seguros de reintentar.

- [x] **[BUG] `OTLPJSONExporter.Shutdown` panics en segunda llamada** ✓ 2026-05-16
  `internal/tracing/exporter.go` — campo `shutdownOnce sync.Once` en la struct.
  `Shutdown` usa `e.shutdownOnce.Do(func() { close(e.ch) })`.

- [x] **[ARCH] `chainHashOf` duplicado entre `internal/issuance` y `internal/storage/pg`** ✓ 2026-05-16
  `internal/issuance/log.go` — `chainHashOf` renombrado a `ChainHashOf` (exportado).
  `internal/storage/pg/issuance.go` — eliminada la copia local; usa `issuance.ChainHashOf`.
  Eliminados los imports `crypto/sha256` y `encoding/hex` del paquete pg ahora innecesarios.

- [x] **[TEST] Package `internal/jobs` sin cobertura de tests** ✓ 2026-05-16
  `internal/jobs/queue_test.go` (nuevo) — 6 tests:
  `TestSubmitAndWait`, `TestSubmitCountsErrors`, `TestSubscriberReceivesProgress`,
  `TestContextCancelCleansUpSubscriber`, `TestQueueFull`, `TestShutdownContextAbortsRun`.
  Todos en paquete `jobs` (white-box). Ejecutar con `go test -race ./internal/jobs/...`.

---

## P3 — Deseables emergentes

- [x] **[OPS] No hay TTL ni cleanup para `bulk_jobs` en PostgreSQL** ✓ 2026-05-16
  `internal/jobs/queue.go` — `NewQueue` lanza goroutine `cleanupLoop()` cuando `pool != nil`.
  Ejecuta `DELETE FROM bulk_jobs WHERE status IN ('done','error') AND updated_at < now() - INTERVAL '7 days'`
  cada hora. Se detiene cuando el shutdown context se cancela.

- [x] **[OBS] W3C traceparent no se propaga para spans no-sampleados** ✓ 2026-05-16
  `internal/tracing/propagation.go` — `Inject()` ahora propaga `traceparent` con `flags=00` para spans
  no-sampleados. Solo se omite si `!s.sc.IsValid()`. Servicios downstream mantienen correlación de `trace_id`.

---

## P3 — Deseables / largo plazo

- [ ] **[SEC] Integrar con secret manager (Vault / AWS SSM)**
  Reemplazar las credenciales de CREDEBL y las API keys de `backends.json` / env vars con
  lecturas de Vault KV v2 o AWS SSM Parameter Store. Agregar `VERIFIABLY_VAULT_ADDR` en deploy.sh.

- [ ] **[OPS] mTLS entre verifiably-go y los backends DPG**
  Configurar TLS en walt.id y CREDEBL, y agregar `tls.Config` con la CA del backend en el
  `httpx.Client`. Usar Vault PKI Engine para emitir y renovar los certificados.

- [x] **[OPS] Dividir deploy.sh en scripts modulares** ✓ 2026-05-16
  `deploy.sh` reducido de 3752 a 786 líneas. Extraído en:
  `scripts/common.sh` (env loading, helpers), `scripts/gen-backends.sh` (backends_for, auth_providers_for),
  `scripts/start-container.sh` (start/stop_container, backends_for_docker),
  `scripts/bootstrap-credebl.sh` (1651 líneas de bootstrap CREDEBL),
  `scripts/gen-caddy.sh` (wso2 toml, waltid confs, issuer catalog, Caddyfile).
  Todos con guard de idempotencia y `bash -n` OK.

- [x] **[SPEC] Evaluar conformidad con OID4VC High Assurance Interop Profile (HAIP)** ✓ 2026-05-16
  `docs/haip-conformance.md` — tabla completa ✅/⚠️/❌ por requisito HAIP.
  3 gaps críticos: `response_mode=direct_post.jwt` (P1), `client_id_scheme=x509_san_dns` (P2),
  `wallet_attestation` (P2). Plan de cierre con prioridades y archivos afectados.

- [ ] **[OPS] Configurar backup automático del volumen Docker**
  El volumen `verifiably-go-state` contiene sesiones, status lists, issuance log, schema store,
  session.key. Sin backup, un `docker volume rm` es pérdida total. Configurar backup diario
  (ej: `docker run --rm -v verifiably-go-state:/vol alpine tar czf -` → S3 / GCS).

---

## Backlog Arquitectónico

- [x] **[ARCH] Escala horizontal: sticky sessions L7 + Redis** ✓ 2026-05-16
  `internal/storage/redis/` — cliente RESP2 stdlib-only + `SessionStore` write-through
  con caché local y flush 5 s. Activado con `VERIFIABLY_REDIS_URL` (prioridad sobre PG).
  `scripts/gen-caddy.sh` — emite `lb_policy cookie verifiably_session` cuando Redis está
  activo. `deploy/compose/stack/docker-compose.yml` — servicio `verifiably-redis` (redis:7.4-alpine,
  puerto 6380, RDB). Imágenes homologadas: `postgres:16.4-alpine`, `redis:7.4-alpine`.

- [x] **[ARCH] Modelo async para bulk issuance (job queue)** ✓ 2026-05-16
  `internal/jobs/queue.go` — `Queue` con worker pool, `pending chan *jobTask`, subscriber
  channels (SSE-ready), `bulk_jobs` PostgreSQL table con fallback in-memory.
  `internal/handlers/handlers.go` — campo `BulkJobQueue *jobs.Queue` en `H`.
  Endpoints: `POST /api/v1/credentials/issue/bulk/async` (202 + job_id),
  `GET /api/v1/bulk/{jobID}` (status JSON), `GET /api/v1/bulk/{jobID}/events` (SSE stream).
  `cmd/server/main.go` — queue inicializado con `pgPool` y `VERIFIABLY_BULK_WORKERS` (default 4).

- [ ] **[ARCH] Notificación push de revocación al holder**
  Actualmente el holder no sabe que su credencial fue revocada hasta que un verifier
  chequea el status list. Para casos de gobierno (credenciales de identidad) se requiere
  notificación activa. Opciones: webhook al wallet, o implementar OpenID4VC Notification
  endpoint (si el wallet lo soporta).

- [ ] **[ARCH] Resolver Docker socket risk de CREDEBL (upstream)**
  `agent-provisioning` requiere `/var/run/docker.sock` para provisionar contenedores Credo
  dinámicamente. Esto da privilegios root efectivos en el host. Solución a largo plazo:
  colaborar con el equipo CREDEBL para migrar a un modelo de agentes estáticos multi-tenant
  (un solo contenedor Credo por organización, no un contenedor por agente). Trackear en el issue tracker upstream de CREDEBL.

- [ ] **[ARCH] Separar la capa de presentación de la capa de orquestación**
  `verifiably-go` mezcla servidor de templates HTML, proxy de DPGs, status list host,
  y API REST en un único proceso. Para producción: el API REST (`/api/v1/*`) debería poder
  desplegarse sin la UI HTMX, y la UI sin exponer el API a internet. Separar con un flag
  `VERIFIABLY_MODE=ui|api|all`.

- [x] **[ARCH] Observability completa con OpenTelemetry** ✓ 2026-05-16
  `internal/tracing/` — paquete stdlib-only (sin dependencias externas) con:
  `tracer.go` — `Tracer`, `Span`, `SpanContext`; sampler head-based por trace ID.
  `propagation.go` — W3C Trace-Context: `Extract` (incoming request) + `Inject` (outbound header).
  `exporter.go` — `SlogExporter` (una línea slog por span; Loki correlation inmediata) +
  `OTLPJSONExporter` (batch HTTP POST a Tempo/Jaeger; no protobuf) + `CombinedExporter`.
  `middleware.go` — span root por request HTTP con method, route, status code.
  `global.go` — `SetGlobal` / `Global` / `Start` (API sin inyección explícita de *Tracer).
  `internal/httpx/client.go` — `tracing.Inject` en `DoJSON` / `DoForm` / `DoRaw` → todos los
  adapters (CREDEBL, walt.id, Inji, LibreTranslate) propagan `traceparent` automáticamente.
  `cmd/server/main.go` — `buildTracer()` lee `VERIFIABLY_OTEL_ENDPOINT`,
  `VERIFIABLY_OTEL_SAMPLE_RATE`, `VERIFIABLY_OTEL_SERVICE_NAME`; envuelve el mux con
  `tracing.Middleware`; drena spans pendientes en el shutdown graceful (10 s timeout).

---

*Última actualización: 2026-05-16 | Todo completo: P0-original + P1 + P2 + todos los ítems emergentes del review 2026-05-16 (13/13). Pendiente long-tail: Vault/SSM, mTLS, backup Docker, revocación push, Docker socket, VERIFIABLY_MODE.*
