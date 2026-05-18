# Federated Emission — Arquitectura y Progreso

**Branch:** `federated-issuance`
**Último update:** 2026-05-17 (Fases 2 + 10 + 3 + 6 + 7 + 8 + 9 completadas)

---

## Objetivo

Extender verifiably-go para soportar un ecosistema federado de emisores de
credenciales verificables con:

- N instancias independientes de verifiably-go (una por organización emisora)
- Un Hub central (CDPI) con Trust Registry, Schema Registry y portal de
  verificación público (sin login)
- Cada instancia corre solo los módulos que necesita (`VERIFIABLY_ROLES`)
- Cualquier wallet OID4VC-compatible puede presentar credenciales de cualquier emisor
- Trust framework unificado bajo autoridad central con upgrade path a OpenID Federation 1.0

---

## Estado real del codebase en `federated-issuance` (base: `add-credebl`)

> Branch creado desde `add-credebl`, que incluye CREDEBL adapter, Trust Registry,
> métricas Prometheus, Grafana y admin_metrics. Esta sección refleja la realidad
> verificada leyendo los archivos directamente.

### Lo que SÍ existe

| Componente | Ubicación | Notas |
|-----------|-----------|-------|
| Adapter interface | `backend/adapter.go` | Interfaz completa con todos los métodos |
| Registry (fan-out) | `internal/adapters/registry/registry.go` | Multi-adapter, `Register()`, fan-out correcto |
| BackendEntry/Config | `internal/adapters/registry/config.go` | Lee `backends.json` |
| SchemaStore | `internal/adapters/registry/schema_store.go` | Persistencia JSON de schemas custom |
| Factory | `internal/adapters/factory/factory.go` | Builds: waltid, credebl, injicertify, injiverify, injiweb |
| Walt.id adapter | `internal/adapters/waltid/` | Issuer + holder + verifier |
| **CREDEBL adapter** | `internal/adapters/credebl/` | Issuer + verifier (OID4VP + DCQL) |
| Inji Certify adapter | `internal/adapters/injicertify/` | Issuer (auth-code + pre-auth) |
| Inji Verify adapter | `internal/adapters/injiverify/` | Verifier only |
| Inji Web adapter | `internal/adapters/injiweb/` | Holder only |
| LibreTranslate | `internal/adapters/libretranslate/` | Traducción |
| Auth OIDC | `internal/auth/` | Providers, registry, user store |
| **Trust Registry** | `internal/trust/` | `registry.go` (interfaz) + `store.go` (pg + mem) + `jwt.go` |
| **Trust handler** | `internal/handlers/trust.go` | `GET /trust-registry` JWT público |
| **Métricas Prometheus** | `internal/metrics/metrics.go` | Counters + histograms |
| **Admin metrics UI** | `internal/handlers/admin_metrics.go` | `/admin/metrics` |
| **API REST** | `internal/handlers/api.go` | Endpoints headless de emisión |
| **PostgreSQL storage** | `internal/storage/pg/` | Sessions, issued_credentials, trusted_issuers |
| **Redis storage** | `internal/storage/redis/` | Sessions cache opcional |
| **Rate limiter** | `internal/handlers/ratelimit.go` | Por API key (60/min) + por IP (20/min, `VERIFIABLY_RATE_IP_RPM`) |
| Handlers | `internal/handlers/` | Todos los handlers actuales |
| Issuance log | `internal/issuance/log.go` | JSON-backed + pg, con `OwnerKey` scoping |
| Status list stores | `internal/statuslist/` | Bitstring (W3C) + Token (IETF) |
| Domain types | `vctypes/vctypes.go` | Schema, DPG, Credential, OID4VPTemplate |
| Main / router | `cmd/server/main.go` | Todas las rutas registradas flat, sin condicionales |
| DID proxy (Inji) | `internal/handlers/inji_proxy.go` | Proxy específico para DID docs de Inji — NO es resolver genérico |
| Config | `config/backends.json` | Config actual de adapters |
| **Grafana dashboard** | `deploy/compose/monitoring/grafana/` | Dashboard de métricas existente |
| **Prometheus config** | `deploy/compose/monitoring/prometheus.yml` | Scrape de la instancia local |
| **did:web deploy automation (Inji)** | `deploy/compose/stack/inji/certify/init.sh` | `ISSUER_DID_DOMAIN` → `did:web:{domain}` automático en init postgres |
| **did:web deploy automation (preauth)** | `deploy/compose/stack/inji/certify/init-preauth.sh` | Mismo DID que primary en prod; `inji_proxy` fusiona claves |
| **`ISSUER_DID_DOMAIN` en .env** | `deploy/compose/stack/.env.example` | Variable única para activar did:web en todo el stack Inji |

### Lo que NO existe (hay que construir)

| Componente | Fase | Notas |
|-----------|------|-------|
| `internal/didresolver/` | Fase 1.5 | Resolver `did:web` genérico — el proxy Inji no sirve aquí |
| ES256 signing key + JWKS endpoint | Fase 1.5 | Upgrade de HS256 a ES256 en Trust Registry JWT |
| `VERIFIABLY_ROLES` routing | Fase 1 | Activación condicional de módulos |
| Portal público `/verify` | Fase 2 | Sin login, para ciudadanos |
| `/api/schemas` público | Fase 3 | CORS + cache TTL, con SourceIssuerDID |
| Schema aggregation cache | Fase 3 | Cache in-memory TTL 5-10 min; sin esto N+1 HTTP en cada `/verify` |
| `config/federation.json` | Fase 4 | Seed inicial del Hub — DB es master |
| State prefix routing en Registry | Fase 4 | TODO pendiente en `FetchPresentationResult` — bloquea Fase 2 |
| Admin CRUD de emisores | Fase 5 | `/admin/federation/members` |
| `ServiceEndpoint` en TrustedIssuer | Fase 5 | Extensión del struct existente |
| ALTER TABLE `trusted_issuers` | Fase 5 | Nuevas columnas vía `ADD COLUMN IF NOT EXISTS` en `runMigrations()` |
| `verification_events` log | Fase 6 | PostgreSQL desde día 1 (no JSON — Hub es punto de agregación) |
| Issuer Analytics API | Fase 7 | `/api/ecosystem/issuers/{did}/stats` |
| API key lifecycle definido | Fase 7 | One-time display, hashed in DB, rotación via admin UI |
| Prometheus Federation | Fase 8 | Hub agrega métricas de emisores registrados |
| Trust Registry Health monitoring | Fase 9 | Gauges expiración + endpoint health |
| Status List Cache | Fase 10 | Cache con verificación de firma JWT — debe ir con Fase 2 |
| CREDEBL did:web automation | Post-Fase 5 | CREDEBL usa Aries agent con Indy ledger; did:web requiere re-provisioning manual del agente (pasos documentados en `credebl.env`) |
| Walt.id did:web compose config | Post-Fase 5 | Walt.id soporta did:web pero no hay env var en compose actual; pendiente |

---

## Decisiones arquitectónicas (fijas, no debatir)

| Decisión | Elección |
|----------|----------|
| Modelo de despliegue | Instancias separadas de verifiably-go por emisor |
| Gobernanza del trust | Autoridad central única (CDPI) — JWT firmado |
| Algoritmo de firma del Trust Registry JWT | ES256 (ECDSA P-256) — HS256 es solo baseline de dev |
| Fuente de verdad de miembros | DB (`trusted_issuers`) es master; `federation.json` = seed inicial y exportación |
| Upgrade path del trust | OpenID Federation 1.0 — interfaz `trust.Registry` no cambia |
| Portal de verificación | Público, sin login (`/verify` en el Hub) |
| Wallets objetivo | Cualquier wallet OID4VC-compatible (sin lock-in) |
| DID method requerido | `did:web` con dominio propio — requisito de acreditación |
| Política de status list | Configurable por schema: `fail-open` o `fail-closed` |
| Schema federation | Activada automáticamente al registrar un emisor (via ServiceEndpoint) |
| Backend del events log | PostgreSQL desde día 1 (JSON-backed no escala para Hub) |
| Backwards compat | Sin `VERIFIABLY_ROLES` → comportamiento idéntico al actual |
| `did:web` es requisito de acreditación, no de runtime | Deployments sin `ISSUER_DID_DOMAIN` funcionan con `did:web` Docker-interno (dev) o `did:key`; solo se exige `did:web` público para entrar al Hub |
| Variable única para federation-ready Inji | `ISSUER_DID_DOMAIN=dominio.gov` activa `did:web` en toda la stack Inji automáticamente (postgres init + Spring Boot); no requiere otros cambios |
| DID primario y preauth comparten dominio en prod | En producción ambas instancias Inji usan `did:web:{ISSUER_DID_DOMAIN}`; `inji_proxy` fusiona sus claves en un solo DID Document — sin colisión de kids |
| Re-init de volumen requerido al cambiar dominio | Los scripts `init.sh` corren solo en la primera inicialización del volumen PostgreSQL; cambiar `ISSUER_DID_DOMAIN` en un deploy existente requiere `docker volume rm certify-db certify-preauth-db` |
| CREDEBL did:web no automatizado | CREDEBL usa Aries agent con ledger Indy/Sovrin; did:web requiere re-provisioning manual documentado en `credebl.env` — no bloquea las demás fases |

---

## Prerequisitos del Hub (verify.cdpi.dev)

Antes de operar en modo `hub`, el host debe tener:

1. `did:web:verify.cdpi.dev` resolvible en `https://verify.cdpi.dev/.well-known/did.json`
2. Par de claves ECDSA P-256 para firmar el Trust Registry JWT (ES256), configurado en
   `VERIFIABLY_TRUST_SIGNING_KEY` (PEM de clave privada)
3. `GET /.well-known/jwks.json` — expone la clave pública; verifiers externos la usan para
   validar el JWT sin secreto compartido

Sin estos tres requisitos los verifiers externos no pueden validar el Trust Registry JWT
y el upgrade path a OpenID Federation 1.0 no es posible.

---

## Extensión al modelo TrustedIssuer

```go
// internal/trust/registry.go
type TrustedIssuer struct {
    DID                 string
    DisplayName         string
    Schemas             []string
    ServiceEndpoint     string    // URL base: "https://issuer-a.gov"
    StatusListEndpoints []string  // URLs públicos de sus status lists
    StatusListPolicy    string    // "fail-open" | "fail-closed" (default: "fail-closed")
    AccreditedAt        time.Time
    ValidUntil          time.Time
}
```

---

## Diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────┐
│           HUB  (verifiably-go --role=hub)                │
│  verify.cdpi.dev                                         │
│                                                          │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  Trust Registry │  │Schema Registry│  │  /verify   │  │
│  │  /trust-registry│  │  /schemas    │  │  (público) │  │
│  │  JWT ES256      │  │  (federado)  │  │  sin login │  │
│  └─────────────────┘  └──────────────┘  └────────────┘  │
│                                                          │
│  /.well-known/jwks.json → clave pública ES256            │
│  Admin: /admin/federation/members (CRUD emisores)        │
│  federation.json → seed inicial; DB es master            │
└──────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Emisor A    │    │  Emisor B    │    │  Emisor C    │
│  ROLES=issuer│    │ ROLES=issuer │    │ ROLES=issuer │
│  DPG: walt.id│    │ DPG: CREDEBL │    │  DPG: Inji   │
│  did:web:a…  │    │ did:web:b…   │    │  did:web:c…  │
│              │    │              │    │              │
│  /api/schemas│    │ /api/schemas │    │ /api/schemas │
│  /status-list│    │ /status-list │    │ /status-list │
│  /healthz    │    │ /healthz     │    │ /healthz     │
└──────────────┘    └──────────────┘    └──────────────┘
```

---

## Flujo de verificación en el Hub

```
Ciudadano visita /verify
    │
    ├── Selecciona schema (agregado cacheado de todos los emisores, TTL 5 min)
    │
    ├── Hub genera OID4VP request via adapter del emisor correspondiente
    │        (verifier adapter configurado en federation.json / DB)
    │        (state prefix identifica el adapter de vuelta en FetchPresentationResult)
    │
    ├── Ciudadano presenta con su wallet OID4VC
    │
    ├── Hub recibe presentación → FetchPresentationResult() (routed by state prefix)
    │
    ├── Status list check (Fase 10 — requerido para que Fase 2 sea completa):
    │     → fetch live desde issuer.gov/status-list/...  (timeout 3s)
    │     → verificar firma JWT contra did:web del emisor (DID resolver genérico)
    │     → fallback a cache (Redis/JSON)
    │     → policy: fail-closed o fail-open si no hay cache
    │
    ├── Trust Registry check: IsTrusted(issuerDID, schemaID)
    │
    └── Resultado: badge "Verificado por CDPI" si TrustStatus == "trusted"
```

---

## Flujo de status list en ecosistema federado

```
Credencial emitida por Emisor A contiene:
  "status": {
    "status_list": {
      "uri": "https://issuer-a.gov/status-list/token/v1",  ← URL embebida
      "idx": 42
    }
  }

Hub verifica:
  1. DPG adapter fetcha el URL del status list (embebido en la credencial)
  2. Verifica firma JWT del status list contra did:web:issuer-a.gov
     → internal/didresolver: GET https://issuer-a.gov/.well-known/did.json
     → cache DIDDocument 10 min para evitar resolver en cada verificación
  3. Lee bit en índice 42
  4. Si falla → usa cache del Hub → si no hay cache → aplica policy

Privacidad: W3C Bitstring / IETF Token Status List son listas de miles
de posiciones → Emisor A solo sabe que alguien fetcha la lista,
no qué credencial específica se verificó.
```

---

## Métricas por actor

### Emisor A — su `/admin/metrics`
- Credenciales emitidas (por schema, por fecha) — ya existe en log
- Credenciales activas / revocadas — ya existe en log
- Verificaciones de sus credenciales (por schema) → datos del Hub vía
  `GET /api/ecosystem/issuers/{did}/stats`

### Hub / CDPI — `/admin/ecosystem`
- Total ecosistema: emitidas, verificadas, emisores activos
- Por emisor: emitidas, verificadas, error rate, estado de acreditación
- Trust Registry health: semáforo por emisor (días hasta expiración)
- Status list availability: uptime de status lists

---

## Requisitos de acreditación para emisores

Al registrarse en el Hub, cada emisor DEBE tener:

1. `did:web:{domain}` — resolvible en `https://{domain}/.well-known/did.json`
   - **Para stacks Inji:** setear `ISSUER_DID_DOMAIN={domain}` en `.env` antes del
     primer `docker compose up` (o borrar volúmenes y reiniciar si ya existe el stack)
   - **Para CREDEBL:** requiere re-provisioning manual del agente (ver `credebl.env`)
   - **Para Walt.id:** pendiente de automatización en compose
2. Status lists públicas en `{serviceEndpoint}/status-list/{type}/v1`
   - Sin auth requerida
   - JWTs firmados con la clave del DID declarado
3. `GET {serviceEndpoint}/api/schemas` — schemas sin auth, con CORS
4. `GET {serviceEndpoint}/healthz` — retorna HTTP 200
5. `VERIFIABLY_ROLES=issuer` (o roles que incluyan `issuer`)

---

## Fases de implementación

### ✅ Fase 0 — Baseline (existente desde `add-credebl`)

CREDEBL adapter, Trust Registry (JWT + pg + mem), métricas Prometheus,
admin_metrics UI, Grafana dashboard, PostgreSQL/Redis storage, API REST headless.
Sin cambios requeridos — es la base de partida.

---

### ✅ Fase 0.5 — DID:web Deployment Automation (Inji Certify)

**Objetivo:** Permitir que cualquier deployment de Inji Certify use `did:web` público
para ser elegible al Hub's Trust Registry, con una sola variable de entorno.

**Decisiones de diseño tomadas:**
- `did:web` es requisito de **acreditación** (Hub membership), no de runtime
- Sin `ISSUER_DID_DOMAIN`: el stack sigue funcionando con `did:web:certify-nginx`
  (Docker-interno, dev only) — zero regression
- Con `ISSUER_DID_DOMAIN=issuer.gov`: ambas instancias Inji (primary + preauth) usan
  `did:web:issuer.gov`; `inji_proxy` ya fusiona sus claves en el DID Document
- Los init scripts solo corren en la primera inicialización del volumen — cambiar de
  dominio requiere `docker volume rm certify-db certify-preauth-db`

**Archivos creados/modificados:**
- [x] `deploy/compose/stack/inji/certify/init.sh` — inicializa certify-postgres con DID correcto
- [x] `deploy/compose/stack/inji/certify/init-preauth.sh` — ídem para preauth; lógica bash para dominio compartido en prod vs. hostnames separados en dev
- [x] `deploy/compose/stack/.env.example` — `ISSUER_DID_DOMAIN=` con documentación completa
- [x] `deploy/compose/stack/inji/certify/certify-csvdp-farmer.properties` — `${CERTIFY_ISSUER_DID:did:web:certify-nginx}` (Spring Boot resolves from env)
- [x] `deploy/compose/stack/inji/certify/certify-csvdp-farmer-preauth.properties` — ídem con fallback `did:web:certify-preauth-nginx`
- [x] `deploy/compose/stack/docker-compose.yml` — 4 servicios actualizados: volumes + `CERTIFY_ISSUER_DID` env var en inji-certify y inji-certify-preauth-backend
- [x] `deploy/compose/credebl/config/credebl.env` — pasos documentados para did:web manual (CREDEBL requiere re-provisioning de agente Aries)

**Pendiente (no bloquea otras fases):**
- Walt.id did:web en compose (soportado por el DPG, falta env var en compose)
- CREDEBL did:web automation (requiere refactor del agent provisioning)

---

### ✅ Fase 1 — Deployment Roles

**Objetivo:** Activar/desactivar módulos por instancia con `VERIFIABLY_ROLES`.

**Archivos creados/modificados:**
- [x] `internal/roles/roles.go` — nuevo package: `Set` type, `Parse()`, `FromEnv()`, `Has()`, `Log()`
- [x] `cmd/server/main.go` — importa `roles`, llama `roles.FromEnv()` + `activeRoles.Log()` al inicio; rutas reorganizadas en bloques etiquetados con guards `activeRoles.Has(...)`
- [x] Lógica de routing condicional implementada:
  - `issuer`: `/issuer/*`, `/status-list/*`, `/api/v1/credentials/*`, `/api/v1/bulk/*`
  - `holder`: `/holder/*`
  - `verifier`: `/verifier/*`, `/api/v1/verify/*`
  - `trust`: `GET /trust-registry`, `/admin/trust/*` (hub implica trust automáticamente)
  - `schemas`: placeholder — rutas se añaden en Fase 3
  - `hub`: `/verify/*` placeholder — rutas se añaden en Fase 2; `hub` implica `trust` + `schemas` en `Parse()`
- [x] Log en startup: `slog.Info("roles activos", "roles", activeRoles.names())`
- [x] Rutas core (healthz, auth, static, lang, docs) siempre activas — zero regression

**Decisiones de diseño:**
- `nil` Set = todos los roles activos (env var ausente → comportamiento idéntico al actual)
- `hub` implica `trust` y `schemas` en `Parse()` — no hay que setearlos por separado
- Admin shared (`/admin/auth-providers`, `/admin/metrics`) gateado por `issuer || verifier`
- Inji proxy routes siempre registradas (backward compat — no hay adapter check)

**Criterio de éxito verificado:**
- `VERIFIABLY_ROLES=issuer` → solo rutas de issuance activas
- `VERIFIABLY_ROLES=hub` → solo `/trust-registry` (+ `/verify/*` en Fase 2)
- Sin variable → todo activo (regression-free)

---

### ✅ Fase 1.5 — DID Resolver + Trust Registry Key Upgrade

**Objetivo:** Habilitar verificación de firmas de `did:web` arbitrarios y migrar
el Trust Registry JWT a ES256 con JWKS endpoint público.

**Archivos creados/modificados:**
- [x] `internal/didresolver/resolver.go` — interfaz `Resolver`, tipos `DIDDocument`, `VerificationMethod`
- [x] `internal/didresolver/web.go` — `WebResolver`: parsea `did:web:{domain}[:{path}]`, GET HTTPS, cache in-memory TTL 10 min, thread-safe con sync.Mutex
- [x] `internal/trust/jwt.go` — añadidos `BuildJWTES256` (ECDSA P-256, R||S padding 32 bytes), `PublicKeyToJWK`; `BuildJWT` (HS256) se mantiene para dev/fallback
- [x] `internal/handlers/trust.go` — `ServeTrustRegistry` usa ES256 cuando `TrustSigningKey != nil`, HS256 en fallback; añadido `ServeJWKS` → `GET /.well-known/jwks.json`
- [x] `internal/handlers/handlers.go` — H struct: `TrustSigningKey *ecdsa.PrivateKey`, `DIDResolver didresolver.Resolver`
- [x] `cmd/server/main.go` — `loadTrustSigningKey()`: carga PEM (SEC1 o PKCS8), genera efímera si ausente con warning; `trustAlg()` para logging; `h.DIDResolver = didresolver.NewWebResolver()`; registro de `GET /.well-known/jwks.json` en bloque trust

**Decisiones de diseño:**
- Sin `VERIFIABLY_TRUST_SIGNING_KEY` → clave efímera ES256 generada al inicio (dev safe, public key cambia en restart)
- `did:web:example.com` → `https://example.com/.well-known/did.json`; `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
- `FillBytes` para el padding R||S del JWT ES256 (P-256 = 32 bytes por componente)
- PKCS8 fallback en `loadTrustSigningKey` para claves generadas con `openssl genpkey`

**Criterio de éxito:**
- `GET /.well-known/jwks.json` retorna JWK set `{kty:EC, crv:P-256, alg:ES256}`
- Trust Registry JWT usa ES256 verificable sin secreto compartido
- `Resolve("did:web:issuer-a.gov")` retorna DIDDocument con `VerificationMethods`
- Segunda llamada al mismo DID no hace HTTP (cache hit)

---

### ✅ Fase 2 — Hub: Portal de Verificación Público

**Objetivo:** Portal `/verify` sin login para ciudadanos.

**Archivos creados/modificados:**
- [x] `internal/handlers/public_verify.go` — handlers sin auth:
  - `GET /verify` → `ShowPublicVerify` — lista schemas custom del adapter
  - `POST /verify/request` → `PublicVerifyRequest` — genera OID4VP; rate-limit IP via `"public-verify"` key; retorna `fragment_public_qr` con QR + polling setup
  - `GET /verify/result/{state}` → `PublicVerifyResult` — poll HTMX every 3s; adjunta `TrustStatus` + `StatusListSource`; retorna `fragment_public_result`
  - `checkStatusListAvailability()` helper: consulta TrustRegistry + StatusListCache para determinar Source
  - `renderPublicPage()` helper: usa `layout_public` sin nav de auth
- [x] `templates/public/layout_public.html` — layout mínimo: header CDPI + main + footer sin nav de roles
- [x] `templates/public/verify.html` — `content_public_verify` (schema picker grid) + `fragment_public_qr` (QR + polling bootstrap) + `fragment_public_result` (badge ✅/❌ con TrustStatus, StatusListSource, DisclosedFields)
- [x] `internal/handlers/handlers.go` — H struct: añadido `StatusListCache statuslistcache.Cache`
- [x] `backend/adapter.go` — `VerificationResult` extendido con `StatusListSource string` y `StatusListCachedAt *time.Time`
- [x] `cmd/server/main.go` — rutas `/verify`, `/verify/request`, `/verify/result/{state}` bajo `activeRoles.Has(roles.Hub)`

**Decisiones de diseño:**
- Polling HTMX every 3s (mismo patrón que el verifier de operador) — SSE es mejora futura
- `resolveFields()` no invocada en portal público (pre-filling de defaults no necesario para VP request)
- DPG selector: primer verifier DPG disponible (Fase 3 añade `SourceIssuerDID` para routing por schema→emisor)
- IP rate limit usa `"public-verify"` como key bucket (60 req/min global + 20/min por IP)
- `StatusListSource` fallback: si el cache no tiene datos pero `res.CheckedRevocation=true`, se reporta "live" (el adapter lo chequeó)

**Criterio de éxito:**
- Ciudadano visita `/verify`, selecciona schema, escanea QR, ve badge CDPI
- Badge muestra TrustStatus, emisor, StatusListSource
- Resultado muestra `StatusListSource: "live" | "cached" | "unknown"` al ciudadano

---

### ✅ Fase 3 — Schema Federation

**Objetivo:** Cada emisor expone schemas públicamente; Hub los agrega con caché.

> **Nota:** Sin caché, cada load de `/verify` en el Hub hace N HTTP requests
> a los issuers (uno por miembro del ecosistema). Caída de un issuer bloquea
> la carga. El caché es parte integrante de esta fase, no un opcional.

**Archivos creados/modificados:**
- [x] `vctypes/vctypes.go` — añadido a `Schema`:
  ```go
  SourceIssuerDID  string `json:"sourceIssuerDid,omitempty"`
  SourceDeployment string `json:"sourceDeployment,omitempty"`
  ```
- [x] `internal/schemacache/aggregator.go` — nuevo package:
  - `Aggregator` struct: in-memory `map[string]issuerEntry` por DID + `memberIDs` (DID→adapterKey)
  - `NewAggregator(ttl time.Duration, memberIDs map[string]string) *Aggregator`
  - `Start(ctx, trust.Registry)`: goroutine — poll inmediato al inicio + ticker cada TTL
  - `Schemas() []vctypes.Schema`: retorna merge de todas las entradas cacheadas (lectura rápida)
  - `refresh()`: itera `TrustedIssuers()`, llama `fetchIssuer()` por cada issuer con `ServiceEndpoint`
  - `fetchIssuer()`: GET `{ServiceEndpoint}/api/schemas` (timeout 5s, cap 1 MiB); en fallo preserva cache; override `SourceIssuerDID` + `SourceDeployment` con valores conocidos por el Hub
- [x] `internal/handlers/public_schemas.go` — nuevo:
  - `ServePublicSchemas`: `GET /api/schemas` — CORS, retorna schemas custom con `SourceIssuerDID` desde `VERIFIABLY_ISSUER_DID` y `SourceDeployment` desde `VERIFIABLY_PUBLIC_URL`
  - `ServeHubSchemas`: `GET /schemas` — CORS, retorna `h.SchemaCache.Schemas()` (Hub mode)
  - `setCORSHeaders()`: helper para `Access-Control-Allow-Origin: *`
- [x] `internal/handlers/handlers.go` — H struct: añadido `SchemaCache *schemacache.Aggregator`
- [x] `internal/handlers/public_verify.go`:
  - `ShowPublicVerify`: usa `h.SchemaCache.Schemas()` cuando disponible; fallback a adapter local
  - `PublicVerifyRequest`: usa `picked.SourceDeployment` como `dpgKey` para routing correcto; fallback a primer verifier si no matchea
- [x] `cmd/server/main.go`:
  - Importa `schemacache`
  - Bajo `activeRoles.Has(roles.Schemas)`: `GET /api/schemas` + `OPTIONS /api/schemas`
  - Bajo `activeRoles.Has(roles.Hub)`: wiring del aggregator (lee `federation.json` para DID→memberID map), `agg.Start(shutCtx, h.TrustRegistry)`, `GET /schemas` + `OPTIONS /schemas`

**Decisiones de diseño:**
- TTL 5 min: balanceo entre frescura y carga en issuers; refresh en background para zero-latency en reads
- Hub overrides `SourceIssuerDID` + `SourceDeployment` desde su propio trust registry — no confía en los valores que el issuer auto-reporta
- `SourceDeployment` = `member.ID` de `federation.json` = clave del adapter en el Registry → routing directo sin joins extra
- `OPTIONS` registrado explícitamente (Go 1.22 mux matchea por método)
- `nil` schemas → `[]vctypes.Schema{}` (JSON array vacío, nunca `null`)

**Criterio de éxito:**
- Emisor A en `https://issuer-a.gov/api/schemas` retorna sus schemas
- Hub en `/schemas` retorna schemas de todos los emisores registrados
- Segunda carga de `/verify` (dentro de TTL) no hace HTTP a issuers
- Si Emisor B cae, Hub sigue mostrando sus schemas desde caché

---

### ✅ Fase 4 — Federation Config

**Objetivo:** Hub mantiene `config/federation.json` como seed inicial y construye
el Registry dinámicamente desde DB al startup.

**Nota:** El state prefix routing de `FetchPresentationResult` ya estaba
implementado en `registry.go` (formato `"dpg:<vendor>:<inner-state>"`). No requirió
cambios — la fase confirmó que el bloqueante estaba resuelto.

**Archivos creados/modificados:**
- [x] `internal/federation/config.go` — nuevo package: `Config`, `EcosystemInfo`, `Member`
- [x] `config/federation.json` — archivo de ejemplo con un miembro (`issuer-a` → `did:web:issuer-a.gov`)
- [x] `internal/federation/loader.go` — `LoadConfig(path string)` + `(*Config).ToBackendEntries()`
  que convierte miembros en `registry.BackendEntry` (verifier-only, vendor=member.ID)
- [x] `cmd/server/main.go` — `bootstrapHub()` function + llamada en `main()` bajo
  `activeRoles.Has(roles.Hub)`:
  1. Carga `config/federation.json` (o `VERIFIABLY_FEDERATION_CONFIG`)
  2. Registra adaptador verifier por cada miembro con `VerifierBackendType`
  3. Siembra trust registry desde `federation.json` solo si DB está vacía

**Decisiones de diseño:**
- `federation.json` seed es idempotente: si DB ya tiene entradas, no re-siembra
- Miembros sin `verifierBackendType` son skipped en `ToBackendEntries()` — solo participan como issuers
- `VERIFIABLY_FEDERATION_CONFIG` env var permite override del path
- `bootstrapHub` no-op silencioso si `federation.json` no existe — zero regression en deployments sin hub

**Criterio de éxito:**
- Hub con members en federation.json → Registry tiene verifier adapters por member
- `FetchPresentationResult` enruta correctamente por state prefix (ya funcionaba)
- Trust registry se siembra automáticamente en primera boot con hub vacío

---

### ✅ Fase 5 — Extensión del Trust Registry + Issuer Registration CRUD

**Objetivo:** Extender el Trust Registry existente con `ServiceEndpoint` y
construir el CRUD admin de emisores en Hub.

> Trust Registry ya existe en `internal/trust/` con interfaz completa
> (`IsTrusted`, `TrustedIssuers`, `Add`, `Remove`), store PostgreSQL + memStore,
> y endpoint `GET /trust-registry` JWT. Solo necesita ser extendido.

**Archivos creados/modificados:**
- [x] `internal/trust/registry.go` — `TrustedIssuer` extendido con `ServiceEndpoint`, `StatusListEndpoints`, `StatusListPolicy`
- [x] `internal/trust/store.go` — `pgStore.Add()` y `pgStore.refresh()` actualizados para los 3 nuevos campos
- [x] `internal/storage/pg/db.go` — `runMigrations()` añade:
  ```sql
  ALTER TABLE trusted_issuers
    ADD COLUMN IF NOT EXISTS service_endpoint      TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS status_list_endpoints TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS status_list_policy    TEXT   NOT NULL DEFAULT 'fail-closed';
  ```
- [x] `internal/trust/jwt.go` — no requirió cambios: `BuildJWTES256` marshala el slice `[]TrustedIssuer` completo vía JSON; los nuevos campos aparecen automáticamente en el payload
- [x] `internal/handlers/admin_federation.go` — nuevo:
  - `GET /admin/federation/members` → `ShowFederationMembers`
  - `POST /admin/federation/members` → `RegisterFederationMember` (JSON o form)
  - `POST /admin/federation/members/{did}/delete` → `DeleteFederationMember`
  - Validaciones: DID debe ser `did:web:*`; healthz check si `service_endpoint` presente; DID resolution con warn-only (no bloquea)
  - HTMX: re-renderiza `fragment_federation_list` en lugar de redirigir
- [x] `templates/pages/admin_federation.html` — tabla con form inline + `fragment_federation_list`
- [x] `cmd/server/main.go` — rutas bajo `activeRoles.Has(roles.Hub)`

**Decisiones de diseño:**
- `trust.Registry` existente se reusa como backend — sin nueva tabla
- DID resolution al registrar es warn-only (dev environments no tienen DID doc público)
- Healthz check es hard-fail solo si `service_endpoint` está presente
- `jwt.go` no necesitó cambios — los nuevos campos fluyen por JSON marshaling automático
- Formulario en la misma página (no página separada) — HTMX swap reemplaza la lista

**Criterio de éxito:**
- `GET /trust-registry` retorna JWT ES256 con `service_endpoint`, `status_list_endpoints`, `status_list_policy` por emisor
- Admin puede agregar/ver/eliminar emisores desde `/admin/federation/members`
- Migración idempotente: `ADD COLUMN IF NOT EXISTS` no rompe DB existente

---

### ✅ Fase 6 — Verification Events Log

**Objetivo:** Persistir cada verificación completada para analytics.

> **PostgreSQL desde día 1.** El Hub es el punto de agregación del ecosistema completo.
> El patrón JSON-backed de `issuance/log.go` funciona bien para un solo emisor,
> pero en el Hub todos los eventos de todos los schemas e issuers convergen aquí.
> JSON con mutex es un bottleneck bajo carga concurrente y no soporta queries
> eficientes para `/api/ecosystem/issuers/{did}/stats`. El patrón `pg/` ya existe.

**Archivos creados/modificados:**
- [x] `internal/verification/events.go` — nuevo package: `Event` struct, `Log` interface, `NewID()`
- [x] `internal/verification/pg_log.go` — PostgreSQL-backed: `NewPGLog(pool)`, `Append()` (ON CONFLICT DO NOTHING), `QueryByIssuer()` (uses ve_issuer_did_idx)
- [x] `internal/storage/pg/db.go` — DDL añadido a `runMigrations()`:
  ```sql
  CREATE TABLE IF NOT EXISTS verification_events (...)
  CREATE INDEX IF NOT EXISTS ve_issuer_did_idx ON verification_events (issuer_did, verified_at DESC);
  ```
- [x] `internal/handlers/handlers.go` — H struct: `VerificationLog verification.Log`
- [x] `internal/handlers/public_verify.go` — `PublicVerifyResult`: goroutine fire-and-forget tras resultado terminal; emite `Event{IssuerDID, SchemaName, Status, TrustStatus, StatusListSrc}`
- [x] `internal/handlers/verifier.go` — `SimulateResponse`: goroutine fire-and-forget; emite `Event{IssuerDID, SchemaID, SchemaName, VerifierDPG, Status, TrustStatus}`
- [x] `cmd/server/main.go` — `verification.NewPGLog(pgPool)` wired cuando `pgPool != nil`; nil en deployments sin DB (feature deshabilitada silenciosamente)

**Decisiones de diseño:**
- PostgreSQL-only: no hay implementación JSON-backed — `h.VerificationLog = nil` en deployments sin DB, feature disabled con zero regression
- Fire-and-forget goroutine con `context.WithTimeout(5s)` por evento — la respuesta HTTP nunca espera al DB
- `ON CONFLICT (id) DO NOTHING` en Append: idempotente si el goroutine reintenta
- Sin PII: `Event` no tiene campo de holder; `DisclosedFields` jamás se escribe
- `DeploymentID = VERIFIABLY_PUBLIC_URL` para correlación entre instancias

**Criterio de éxito:**
- Cada verificación completada genera un registro en PostgreSQL
- Sin PII del holder en ningún registro
- `QueryByIssuer` retorna resultados en <100ms con índice

---

### ✅ Fase 7 — Issuer Analytics API

**Objetivo:** Cada emisor puede ver estadísticas de sus credenciales verificadas.

**Archivos creados/modificados:**
- [x] `internal/trust/apikeys.go` — nuevo package:
  - `APIKeyStore` interface: `Issue`, `Validate`, `Revoke`, `HasKey`
  - `pgAPIKeyStore`: UPSERT en Issue (rotación atómica), SHA-256 en Validate, DELETE en Revoke
  - `NewPGAPIKeyStore(pool)` + `ErrInvalidAPIKey` sentinel error
- [x] `internal/storage/pg/db.go` — DDL añadido a `runMigrations()`:
  ```sql
  CREATE TABLE IF NOT EXISTS issuer_api_keys (
      did        TEXT        PRIMARY KEY,
      key_hash   TEXT        NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  ```
- [x] `internal/handlers/ecosystem_api.go` — nuevo handler:
  - `GET /api/ecosystem/issuers/{did}/stats` con `Authorization: Bearer`
  - Valida key → DID; verifica que DID coincide con `{did}` en el path (401/403)
  - Agrega `verification_events` de los últimos 30 días: total/valid/invalid/bySchema
  - JSON response: `{issuer_did, period_days, verified:{total,valid,invalid,by_schema}}`
- [x] `internal/handlers/handlers.go` — H struct: `IssuerAPIKeyStore trust.APIKeyStore`
- [x] `internal/handlers/admin_federation.go`:
  - `IssueAPIKey`: `POST /admin/federation/members/{did}/api-key` — genera key, renderiza `fragment_api_key_display` con plaintext visible una sola vez
  - `RevokeAPIKey`: `POST /admin/federation/members/{did}/api-key/revoke` — revoca, re-renderiza member list
  - `memberKeyMap()`: helper que construye `map[DID]bool` para el template
  - `ShowFederationMembers`, `RegisterFederationMember`, `DeleteFederationMember` — actualizados para pasar `MemberKeys` y `HasAPIKeyStore`
- [x] `templates/pages/admin_federation.html`:
  - `#api-key-display` slot vacío, se llena vía HTMX con `fragment_api_key_display`
  - `fragment_api_key_display`: muestra token, botón copiar al portapapeles; slot vacío cuando no hay key
  - `fragment_federation_list`: columna "API key" con `active/none` pill + botones Generate/Rotate/Revoke (solo cuando `HasAPIKeyStore`)
- [x] `cmd/server/main.go`:
  - `trust.NewPGAPIKeyStore(pgPool)` wired cuando `pgPool != nil`
  - Rutas bajo Hub: `POST .../api-key`, `POST .../api-key/revoke`, `GET /api/ecosystem/issuers/{did}/stats`

**Decisiones de diseño:**
- One-time display: plaintext nunca almacenado; SHA-256 del token en DB; UPSERT en Issue (rotación invalida anterior atómicamente)
- `HasKey` para el template: N SELECT EXISTS por miembro en ShowFederationMembers (aceptable: pocas decenas de miembros)
- Verificaciones solo (no emisiones): el Hub no emite credenciales — la analytics API expone únicamente datos del `verification_events` del Hub
- `ErrInvalidAPIKey` sentinel: caller distingue "bad key" de I/O error sin inspeccionar strings

**Criterio de éxito:**
- Emisor A llama `/api/ecosystem/issuers/{did}/stats` con su API key → breakdown de verificaciones por schema en 30 días
- Clave inválida → 401; clave de otro DID → 403
- Admin genera clave desde `/admin/federation/members` → se muestra una sola vez con botón "Copy"
- Admin revoca clave → lista se actualiza en tiempo real, "none" pill

---

### ✅ Fase 8 — Prometheus Federation en el Hub

**Objetivo:** Hub agrega métricas de todos los emisores.

**Archivos creados:**
- [x] `deploy/compose/monitoring/prometheus-hub.yml` — config Prometheus específica del Hub:
  - Job `verifiably-hub`: scrape del propio Hub en `/metrics` (15s)
  - Job `verifiably-federation`: usa `file_sd_configs` apuntando a `federation-targets.json` (hot-reload automático cada 5 min)
  - Preserva labels `issuer_did` e `issuer_name` de los targets
- [x] `deploy/compose/monitoring/generate-federation-prometheus.sh` — script bash + jq:
  - Lee `config/federation.json` (o path por argumento)
  - Genera `federation-targets.json` en formato Prometheus file_sd con `__scheme__`, `issuer_did`, `issuer_name`
  - Filtra miembros sin `service_endpoint`
  - Escribe a archivo (default: `deploy/compose/monitoring/federation-targets.json`) o stdout (`-`)
  - Output: mensaje de recarga para el operador
- [x] `deploy/compose/monitoring/grafana/dashboards/verifiably-ecosystem-v1.json`:
  - **Row Ecosystem Totals**: 5 stat panels — Active Issuers, Issued (24h), Verified at Hub, Valid Rate, Unreachable Issuers
  - **Row Verification Trends**: 2 time series — Verification Rate by Issuer + Issuance Rate by Member
  - **Row Per-Issuer Breakdown**: tabla con issued/verified/valid/status por emisor (transformaciones merge + organize)
  - **Row Trust Registry Health**: bar gauge days-until-expiry (con umbrales 30/90 días), 2 stat panels, tabla de salud — todos esperando métricas de Fase 9
  - Variables de template: `$issuer` (multi-select desde label_values) + `$interval`
- [x] `deploy/compose/hub/docker-compose.yml` — stack Hub independiente:
  - Servicios: postgres, verifiably-go (ROLES=hub), prometheus (usa prometheus-hub.yml), grafana
  - Prometheus monta `federation-targets.json` como `:ro` (actualizable sin restart por file_sd)
  - Grafana: home dashboard = ecosystem overview
- [x] `deploy/compose/hub/federation-targets.json` — array vacío inicial (Prometheus no falla en primera boot)
- [x] `deploy/compose/hub/.env.example` — variables requeridas documentadas

**Decisiones de diseño:**
- file_sd en lugar de static_configs: Prometheus hot-reload automático al detectar cambio en el archivo JSON — no requiere restart del container
- El generate script solo escribe el targets file (no regenera todo el prometheus.yml) — la config base es estable
- `honor_labels: true` en el job federation: preserva labels del issuer sin colisión con labels del Hub
- El dashboard incluye paneles de Fase 9 (Trust Registry Health) como placeholders — no muestran datos hasta que Fase 9 emita los gauges
- `$__range` para totales de período seleccionado; `$interval` para rates

**Workflow operacional:**
```bash
# 1. Editar/actualizar members en el Hub admin o federation.json
# 2. Regenerar targets:
./deploy/compose/monitoring/generate-federation-prometheus.sh \
    config/federation.json \
    deploy/compose/hub/federation-targets.json
# 3. Prometheus hot-reloads automáticamente (sin restart necesario)
# 4. Verificar targets en http://localhost:9090/targets
```

**Criterio de éxito:**
- `GET http://localhost:9090/targets` muestra todos los miembros del federation
- Grafana en `http://localhost:3100` abre el Ecosystem Overview dashboard por defecto
- Paneles de issuance (scraped de issuers) y verificación (Hub) muestran datos reales
- Paneles de Trust Registry Health muestran "no data" hasta Fase 9

---

### ✅ Fase 9 — Trust Registry Health Monitoring

**Objetivo:** Detectar proactivamente emisores con acreditación por vencer o caídos.

**Archivos creados/modificados:**
- [x] `internal/metrics/metrics.go` — extendido con tipo gauge:
  - `gge` struct: `{name, ls string, val atomic.Int64}`
  - `gauges map[string]*gge` en `registry`; inicializado en `newRegistry()`
  - `SetGauge(name string, v int64, labels ...string)`: upsert bajo lock
  - `DeleteGauge(name string, labels ...string)`: elimina entrada bajo lock (stale cleanup)
  - `snapshot()` actualizado a 3 valores de retorno `([]*ctr, []*histo, []*gge)`
  - `writeTo()` emite gauges con `# TYPE xxx gauge` header, ordenados por name+ls
  - Funciones package-level `SetGauge` / `DeleteGauge` añadidas
- [x] `internal/trust/health.go` — nuevo package:
  - `EndpointStatus{Up, Checked bool, At time.Time}` — estado en memoria sin DB
  - `Monitor` struct: `status map[string]EndpointStatus`, `knownDIDs map[string]struct{}`, `http.Client` (5s timeout)
  - `NewMonitor()`: inicializa con client de 5s
  - `Start(ctx, Registry)`: lanza 2 goroutines — `runExpiry()` + `runEndpoint()`
  - `runExpiry()`: ticker hourly → `emitExpiry()` — gauge `trusted_issuer_days_until_expiry{did,name}`; limpia gauges de DIDs eliminados via `knownDIDs` diff
  - `runEndpoint()`: ticker 5 min → `probeEndpoints()` — GET `{ServiceEndpoint}/healthz`, gauge `trusted_issuer_endpoint_up{did,name}` (1/0), actualiza `status` map
  - `EndpointStatus(did string)`: lectura thread-safe del status en memoria
- [x] `deploy/compose/monitoring/alerts.yml` — 3 reglas de alerta:
  - `IssuerAccreditationExpiringSoon`: `trusted_issuer_days_until_expiry < 30`, severity: warning, for: 0m
  - `IssuerEndpointDown`: `trusted_issuer_endpoint_up == 0`, severity: critical, for: 10m
  - `FederationAllMembersDown`: `count(up{job="verifiably-federation"} == 1) == 0`, severity: critical, for: 15m
- [x] `deploy/compose/monitoring/prometheus-hub.yml` — `rule_files` descomentado:
  ```yaml
  rule_files:
    - /etc/prometheus/alerts.yml
  ```
- [x] `internal/handlers/handlers.go` — H struct: `TrustHealthMonitor *trust.Monitor`
- [x] `internal/handlers/admin_federation.go`:
  - `memberHealthMap(members)`: construye `map[DID]trust.EndpointStatus` desde `TrustHealthMonitor`
  - Todos los renders de fragmentos actualizados para incluir `MemberHealth`
- [x] `templates/pages/admin_federation.html` — columna "Health" con semáforo dot:
  - Gris: `not $health.Checked` (aún no sondeado)
  - Rojo: endpoint down (`not $health.Up`) O expirado O `< 30 días`
  - Amarillo: 30–90 días
  - Verde: `>= 90 días` o sin expiración
  - Usa `daysUntil` template function (sentinel 99999 para no-expiry → siempre verde)
- [x] `cmd/server/main.go`:
  - Monitor wired bajo `activeRoles.Has(roles.Hub) && h.TrustRegistry != nil`
  - `daysUntil` añadido a `funcMap`: retorna `int(time.Until(t).Hours()/24)`; `t.IsZero()` → `99999`

**Decisiones de diseño:**
- Gauges en memoria con `atomic.Int64`: sin dependencias externas, thread-safe, compatible con el metrics.go stdlib-only existente
- `knownDIDs` para stale gauge cleanup: cuando se elimina un emisor del trust registry, su gauge desaparece del `/metrics` en la próxima ronda del ticker (sin restart)
- `EndpointStatus` en memoria (no DB): es estado efímero — no necesita persistencia; se recalcula en cada probe cycle; sirve solo para renderizar el semáforo en el admin UI
- Sentinel `99999` en `daysUntil` para `ValidUntil.IsZero()`: el template usa comparaciones numéricas directas (`lt $days 30`, `lt $days 90`) sin branch especial para "sin expiración"

**Criterio de éxito:**
- `GET /metrics` expone `trusted_issuer_days_until_expiry` y `trusted_issuer_endpoint_up` por emisor
- Alerta `IssuerAccreditationExpiringSoon` se dispara cuando emisor tiene <30 días
- Alerta `IssuerEndpointDown` se dispara tras 10 min de endpoint caído
- Panel admin `/admin/federation/members` muestra semáforo de salud por emisor en tiempo real
- Eliminar un emisor limpia su gauge en el próximo ciclo del ticker (no persiste en `/metrics`)

---

### ✅ Fase 10 — Status List Cache con Verificación de Firma

**Objetivo:** Hub mantiene copias cacheadas de status lists para disponibilidad e integridad.

**Archivos creados:**
- [x] `internal/statuslistcache/cache.go` — `Cache` interface + `Result{RawJWT, Source, CachedAt, ExpiresAt}`
- [x] `internal/statuslistcache/json_cache.go` — `jsonStore`: in-memory map + disk (`state/status-list-cache/{sha256(url)[:16]}.json`); thread-safe con `sync.RWMutex`
- [x] `internal/statuslistcache/fetcher.go` — `Fetcher` implements `Cache`:
  1. `fetchLive()`: GET con timeout 3s; soporta JWT crudo y JSON con `token`/`jwt`/`verifiableCredential`
  2. `verifyJWT()`: extrae `iss` del payload → DID resolve → ES256 verify contra `publicKeyJWK` del DID doc; fallo de resolución es warn-only; mismatch de firma retorna error
  3. `verifyES256JWT()`: stdlib pura (ecdsa, elliptic, sha256, big.Int) — sin dependencias externas
  4. Fallback a `jsonStore.load()` si fetch falla; `Source: "unknown"` si tampoco hay cache
  5. TTL default: 6 horas por entrada
- [x] `internal/statuslistcache/poller.go` — `Poller`: goroutine; poll inmediato al `Start()` + ticker cada hora; itera `TrustedIssuers()` + `StatusListEndpoints`
- [x] `backend/adapter.go` — `VerificationResult` extendido con `StatusListSource string`, `StatusListCachedAt *time.Time`
- [x] `cmd/server/main.go` — `statuslistcache.NewFetcher()` wired in all roles; `NewPoller().Start()` solo en Hub mode

**Decisiones de diseño:**
- TTL 6 horas: balanceo entre frescura y disponibilidad (emisor down < 6h → cache válido)
- Verificación ES256 pura stdlib: sin `golang.org/x/crypto` ni `lestrrat-go/jwx`; la curva es P-256 (el algoritmo del Trust Registry JWT propio)
- JWK como `map[string]any` (tipo que usa el DIDDocument del resolver existente)
- Fail-closed por DID resolution: si el resolver falla, no se bloquea la caché (warn-only) — evita que un DID temporalmente irresolvible haga unavailable el endpoint

**Criterio de éxito:**
- Si Emisor A cae, el Hub usa cache y muestra `StatusListSource: "cached"`
- Status list con firma inválida ES256 → `Source: "unknown"` + error retornado
- Poller warms cache al startup y cada hora

---

## Restricciones de diseño (no negociables)

1. **Backwards-compatible 100%**: sin `VERIFIABLY_ROLES` → comportamiento actual idéntico
2. **Interfaz `trust.Registry` estable**: `IsTrusted`, `TrustedIssuers`, `Add`, `Remove`
   no cambian una vez creados (upgrade path a OpenID Federation sin cambios de interfaz)
3. **Adapters existentes sin modificar**: cambios solo en capa de servidor y nuevos packages
4. **Sin nuevas dependencias externas** salvo justificación explícita
5. **Sin PII en tablas de analytics**: `verification_events` nunca almacena datos del holder
6. **Sin correlación de verificaciones**: no almacenar campos que permitan identificar
   que dos verificaciones corresponden al mismo holder
7. **Firma asimétrica obligatoria en producción**: HS256 es solo para dev/test local;
   producción requiere `VERIFIABLY_TRUST_SIGNING_KEY` configurada

---

## Secuencia de implementación recomendada

```
Fase 1 (Roles) → Fase 1.5 (DID Resolver + ES256) → Fase 4 (Federation Config)
      ↓
Fase 5 (Trust Registry + CRUD)
      ↓
Fase 2 (Hub Portal Público) + Fase 10 (Status List Cache)  ← van juntas
      ↓
Fase 3 (Schema Federation con caché)
      ↓
Fase 6 (Verification Events Log — PostgreSQL)
      ↓
Fase 7 (Issuer Analytics API) → Fase 8 (Prometheus Federation)
      ↓
Fase 9 (Trust Registry Health)
```

Las fases 1, 1.5, 4, 5 son el núcleo de la federación.
Las fases 2 + 10 son el portal público (siempre juntas).
Las fases 6–9 son el plano de observabilidad.

---

## Archivos clave de referencia

```
backend/adapter.go                           ← interfaz principal + VerificationResult
internal/adapters/registry/registry.go       ← fan-out, Register(), AllAdapters()
internal/adapters/registry/config.go         ← BackendEntry, LoadConfig()
internal/adapters/factory/factory.go         ← construye adapters desde config
internal/handlers/handlers.go                ← struct H, render(), pageData()
internal/handlers/verifier.go                ← flujo de verificación actual
internal/handlers/trust.go                   ← GET /trust-registry handler
internal/handlers/ratelimit.go               ← rate limiter (IP + API key, ya implementado)
internal/trust/registry.go                   ← interfaz + TrustedIssuer
internal/trust/jwt.go                        ← BuildJWT (HS256 → ES256 en Fase 1.5)
internal/issuance/log.go                     ← patrón del audit log (seguir para events)
internal/statuslist/store.go                 ← patrón del status list store
internal/storage/pg/db.go                    ← runMigrations() — aquí van los ALTER TABLE
cmd/server/main.go                           ← startup, wiring, registro de rutas
config/backends.json                         ← formato de config de adapters
vctypes/vctypes.go                           ← tipos de dominio
```

---

## Progreso general

- [x] Fase 0 — Baseline (add-credebl)
- [x] Fase 0.5 — DID:web Deployment Automation (Inji Certify)
- [x] Fase 1 — Deployment Roles (`VERIFIABLY_ROLES`)
- [x] Fase 1.5 — DID Resolver + Trust Registry Key Upgrade (ES256 + JWKS)
- [x] Fase 4 — Federation Config (`federation.json` + hub bootstrap + state prefix routing confirmado)
- [x] Fase 5 — Trust Registry Extension + Federation Member CRUD Admin
- [x] Fase 2 — Hub Portal Público (`/verify` ciudadano + HTMX polling)
- [x] Fase 10 — Status List Cache (fetcher + JSON store + poller + ES256 verify)
- [x] Fase 3 — Schema Federation
- [x] Fase 6 — Verification Events Log
- [x] Fase 7 — Issuer Analytics API
- [x] Fase 8 — Prometheus Federation
- [x] Fase 9 — Trust Registry Health Monitoring
