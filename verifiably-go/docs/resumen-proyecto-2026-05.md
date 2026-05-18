# Resumen del Proyecto — Ecosistema de Credenciales Verificables
*verifiably-go · Presentación de estado · 18 de mayo de 2026*

---

## Resumen ejecutivo

Se construyó una plataforma completa de emisión y verificación de credenciales
verificables (W3C VC / OID4VC) orientada a ecosistemas de gobierno digital.
La plataforma va desde una instancia standalone hasta un **ecosistema federado
de N ministerios** con un Hub central que opera la infraestructura de confianza
y el portal de verificación para ciudadanos — sin lock-in de vendor, sin wallet
propietaria, con privacidad por diseño.

El proyecto se implementó en tres etapas sobre la rama `federated-issuance`
(99 commits, ~7 000 líneas de código Go y ~3 000 de configuración/infraestructura).

---

## 1. Punto de partida — baseline `main`

La base de código en `main` ya tenía:

| Componente | Estado |
|---|---|
| Adaptadores DPG | walt.id, Inji Certify, Inji Verify, Inji Web |
| Interfaz unificada `backend.Adapter` | Completa — swap de vendor sin tocar la UI |
| OIDC sign-in | Keycloak + WSO2 IS |
| Traducción | LibreTranslate (inglés / francés / español) |
| Deploy | `deploy.sh` — wizard interactivo, subdominio TLS via Caddy |

Lo que **no existía**: CREDEBL, Trust Registry, métricas, persistencia PG, API
headless, ni ningún componente de federación.

---

## 2. Etapa 1 — Integración CREDEBL + Madurez del codebase (`add-credebl`)

### CREDEBL adapter
- Emisión OID4VCI pre-auth + verificación OID4VP con DCQL
- Bootstrap automático completo: realm Keycloak, platform-admin, DID, issuer,
  credencial template — sin pasos manuales
- 18 microservicios orquestados con un solo comando: `./deploy.sh up credebl`

### Trust Registry (Opción A — JWT ES256)
- `GET /trust-registry` → JWT firmado ES256 con lista de emisores confiables
- `GET /.well-known/jwks.json` → clave pública para verificación externa
- Almacenamiento: PostgreSQL (+ fallback in-memory para dev)
- Upgrade path a OpenID Federation 1.0 sin cambios de interfaz

### Observabilidad y calidad
- **Prometheus + Grafana**: counters de emisión/verificación, histogramas de
  latencia por adaptador, 6 paneles de métricas en tiempo real
- **OpenTelemetry stdlib-only**: trazas W3C traceparent propagadas a todos los
  adaptadores; exportadores Slog (Loki) + OTLP JSON (Tempo/Jaeger)
- **PostgreSQL backend**: sessions (AES-GCM cifradas), issuance log (hash chain
  SHA-256 tamper-evident), status lists
- **Redis**: sessions distribuidas para escala horizontal con sticky sessions L7

### Seguridad y confiabilidad (revisión P0–P3)
Se resolvieron **26 items** de seguridad, bugs y observabilidad clasificados en
cuatro prioridades. Los críticos incluyen:
- PII eliminado del log de emisión y del backend PostgreSQL
- Credenciales CREDEBL movidas de `backends.json` a variables de entorno
- Race conditions en sesiones, traductor global y `resolveTemplateID` corregidos
- Rate limiting por API key (60 req/min) + por IP con whitelist de proxies
- Modo de sesión seguro: cookie `Secure`, redirect URI validado, open redirect `/lang` cerrado
- Hash chain tamper-evident en el issuance log

---

## 3. Etapa 2 — Ecosistema Federado (`federated-issuance`)

### Arquitectura del ecosistema

```
┌──────────────────────── HUB (verify.cdpi.dev) ──────────────────────────┐
│  Trust Registry    — JWT ES256, JWKS público                            │
│  Schema Registry   — agregado + cacheado de todos los emisores          │
│  Portal /verify    — sin login, para ciudadanos                         │
│  Admin             — CRUD de miembros, API keys, semáforo de salud      │
│  Grafana           — dashboard de ecosistema completo                   │
└───────────────┬───────────────────────────┬─────────────────────────────┘
                │                           │
        Ministerio de Educación      Ministerio de Trabajo
        ROLES=issuer · DPG: walt.id  ROLES=issuer · DPG: CREDEBL
        did:web:minerd.gob.do        did:web:mt.gob.do
```

### Las 13 fases implementadas

| # | Fase | Descripción |
|---|------|-------------|
| 0 | Baseline | CREDEBL, Trust Registry, Prometheus/Grafana, PG/Redis |
| 0.5 | did:web Inji | `ISSUER_DID_DOMAIN` activa did:web en todo el stack Inji automáticamente |
| 1 | Roles | `VERIFIABLY_ROLES` — activación condicional de módulos por instancia |
| 1.5 | DID Resolver + ES256 | Resolver `did:web` genérico con cache 10 min; migración JWT a ES256 |
| 4 | Federation Config | `federation.json` como seed; DB como master; state prefix routing |
| 5 | Trust Registry CRUD | Extensión con `ServiceEndpoint`, admin `/admin/federation/members` |
| 2 | Portal Público | `/verify` ciudadano sin login — schema picker + QR + badge confianza |
| 10 | Status List Cache | Cache de status lists con verificación ES256 y política fail-closed |
| 3 | Schema Federation | Agregador con cache TTL 5 min — cero latencia extra en `/verify` |
| 6 | Events Log | `verification_events` PostgreSQL — privacidad: sin PII del holder |
| 7 | Analytics API | `GET /api/ecosystem/issuers/{did}/stats` — emisores acceden a sus stats |
| 8 | Prometheus Federation | Hub agrega métricas de todos los miembros via file_sd hot-reload |
| 9 | Trust Health Monitor | Gauges de días hasta expiración + endpoint up/down; 3 alertas Prometheus |

### Componentes adicionales construidos en producción

Durante el deployment real con MINERD y MT se identificaron y resolvieron:

- **Adaptador `verifiably`**: permite que el Hub delegue verificación OID4VP a
  otra instancia de verifiably-go via API key — sin exponer el backend DPG
- **Template completo en `/api/v1/verify/request`**: el Hub puede enviar el
  template OID4VP completo (campos, formato, disclosure) al emisor
- **Hub admin landing page**: pantalla de entrada post-login para operadores del Hub
- **fix: `VERIFIABLY_API_KEYS` en container** — passthrough correcto al contenedor Docker
- **fix: `host.docker.internal` en Linux** — `credebl-oid4vci-rewriter` usaba el
  bridge `172.17.0.1` que no alcanza al agente Credo en la red de compose;
  `_credebl_configure_oid4vci_rewriter` detecta la IP real del contenedor
- **fix: recuperación de wallet ya provisionada** — CREDEBL retorna 409 al re-provisionar;
  el bootstrap ahora recupera el wallet existente en lugar de fallar
- **i18n en portal público** — `renderPublicPage` ejecuta el mismo pipeline de
  traducción que el portal admin

---

## 4. Estado actual en producción

| Instancia | URL | DPG | Estado |
|---|---|---|---|
| **Hub** | `verify.cdpi.dev` | — | ✅ operativo |
| **MINERD** | `verifiably.minerd.credenciales.ysalabs.work` | walt.id | ✅ operativo |
| **MT** | `verifiably.mt.credenciales.ysalabs.work` | CREDEBL | ✅ operativo |

**Flujo end-to-end verificado en producción:**
1. Ciudadano visita `verify.cdpi.dev/verify`
2. Selecciona un tipo de documento (schemas de MINERD o MT)
3. Escanea el QR con una wallet OID4VC compatible
4. La wallet obtiene el authorization request JWT desde el agente del emisor correspondiente
5. Presenta la credencial
6. El Hub muestra el badge: ✅ **Verificado** con emisor, nivel de confianza y estado del status list

---

## 5. Diseño de privacidad y confianza

| Principio | Implementación |
|---|---|
| Sin PII del holder | `verification_events` nunca escribe datos del ciudadano |
| Sin correlación de verificaciones | El Hub no puede saber si dos verificaciones son del mismo holder |
| Status list privacidad | Bitstring / Token Status List — el emisor solo sabe que alguien fetcha la lista, no qué credencial |
| Firma asimétrica | Trust Registry JWT firmado ES256; clave pública en `/.well-known/jwks.json` |
| Sin vendor lock-in | Cualquier wallet OID4VC-compatible funciona (probado con Inji Web, wallets CREDEBL) |

---

## 6. Infraestructura del Hub

```yaml
# docker-compose.yml — hub stack
hub-postgres:     PostgreSQL 16 — Trust Registry, events, API keys
verifiably-go:    Hub app (VERIFIABLY_ROLES=hub)
hub-prometheus:   Scrape propio + federation scrape de emisores (file_sd)
hub-grafana:      Dashboard ecosistema — emisiones, verificaciones, health
```

**Variables de entorno clave del Hub:**

| Variable | Propósito |
|---|---|
| `VERIFIABLY_ROLES=hub` | Activa solo módulos de hub (trust + schemas + portal) |
| `VERIFIABLY_TRUST_SIGNING_KEY` | Clave PEM ES256 para firmar el Trust Registry JWT |
| `VERIFIABLY_DATABASE_URL` | PostgreSQL DSN — Trust Registry, eventos, API keys |
| `VERIFIABLY_PUBLIC_URL` | URL pública del Hub (embed en events log) |
| `VERIFIABLY_ADMIN_PASSWORD` | Contraseña del admin del Hub |

---

## 7. Alertas de monitoreo configuradas

| Alerta | Condición | Severidad |
|---|---|---|
| `IssuerAccreditationExpiringSoon` | `days_until_expiry < 30` | warning |
| `IssuerEndpointDown` | endpoint `/healthz` caído > 10 min | critical |
| `FederationAllMembersDown` | ningún miembro scrapeado | critical |

---

## 8. Pendientes (largo plazo)

Todos los items críticos y de alta prioridad están completos. Lo que queda son
mejoras de infraestructura de producción a largo plazo:

| Item | Prioridad | Descripción |
|---|---|---|
| Vault / AWS SSM | P3 | Reemplazar credenciales en env vars con secret manager |
| mTLS backends | P3 | TLS mutuo entre verifiably-go y los DPGs |
| Backup de volúmenes | P3 | Backup diario del volumen `verifiably-go-state` |
| Push revocation | Backlog | Notificar al holder cuando su credencial es revocada |
| Docker socket (CREDEBL) | Backlog | `agent-provisioning` necesita socket — riesgo de privilegios |
| `VERIFIABLY_MODE=ui\|api` | Backlog | Separar la API REST del frontend HTMX |
| `did:web` Walt.id automation | Post-Fase 5 | Falta env var en el compose de walt.id |

---

## 9. Números del proyecto

| Métrica | Valor |
|---|---|
| Commits en `federated-issuance` | 99 |
| Fases de federación implementadas | 13 / 13 (100%) |
| Items de seguridad/bugs resueltos (TODO.md) | 26 / 31 (84%) — los 5 restantes son long-tail |
| DPGs soportados | 5 (walt.id, CREDEBL, Inji Certify, Inji Verify, Inji Web) |
| Instancias en producción | 3 (Hub + MINERD + MT) |
| Dependencias externas añadidas | 0 (stdlib Go en toda la implementación) |

---

*Documento generado desde `TODO.md` + `federated-emission.md` + git log del branch `federated-issuance`.*
*Próxima versión recomendada: post-onboarding de nuevos miembros del ecosistema.*
