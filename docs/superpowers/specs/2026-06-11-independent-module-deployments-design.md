# Independent Module Deployments

**Date:** 2026-06-11  
**Status:** Approved  
**Scope:** `verifiably-go/` — deploy scripts, compose files, backends generation

---

## Objetivo

Permitir desplegar cada DPG (Walt ID, CREDEBL, Inji) con solo los servicios necesarios para el rol deseado (emisor, verificador, holder/wallet), sin levantar contenedores innecesarios. El hub de verificación debe poder operar de forma completamente independiente de que los nodos federados tengan o no un módulo de verificación activo.

---

## Arquitectura general

El deploy introduce una segunda dimensión: **DPG × Rol**.

```
./deploy.sh up <dpg> [--role <roles>]
           ↓
   resolve_role() → lee CLI_ROLE > VERIFIABLY_ROLES > default (issuer,verifier,holder)
           ↓
   role_services(<dpg>, <role>)   → servicios del DPG para ese rol
   infra_services(<role>)         → servicios compartidos mínimos para ese rol
           ↓
   docker compose up <servicios combinados>
```

**Roles soportados:** `issuer`, `verifier`, `holder` (comma-separated, cualquier combinación)

**Default preserva comportamiento actual:** si `VERIFIABLY_ROLES` no está definido, se usa `issuer,verifier,holder`.

---

## Infra mínima por rol

| Rol | Infra requerida | Omitida por defecto |
|-----|----------------|---------------------|
| `issuer` | postgres, caddy, keycloak | wso2is |
| `verifier` | caddy, keycloak | postgres (si DPG no lo necesita), wso2is |
| `holder` | postgres, caddy | keycloak, wso2is |
| `issuer,verifier,holder` | postgres, caddy, keycloak | wso2is (opt-in vía `VERIFIABLY_SKIP_WSO2IS=0`) |

`wso2is` sigue siendo opt-in mediante la variable existente `VERIFIABLY_SKIP_WSO2IS`.  
Keycloak y postgres siguen siendo externalizables con variables existentes (`VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL`, etc.).

---

## Arrays de servicios por DPG × rol

### Walt ID

| Rol | Servicios |
|-----|-----------|
| `issuer` | postgres, caddy, issuer-api |
| `verifier` | postgres, caddy, verifier-api |
| `holder` | postgres, caddy, wallet-api |
| `issuer,holder` | postgres, caddy, issuer-api, wallet-api |
| `issuer,verifier` | postgres, caddy, issuer-api, verifier-api |
| `issuer,verifier,holder` | postgres, caddy, issuer-api, verifier-api, wallet-api *(comportamiento actual)* |

### CREDEBL

| Rol | Servicios incluidos | Servicios omitidos |
|-----|--------------------|--------------------|
| `issuer` | infra (postgres, redis, nats, minio, mailpit), user, utility, connection, issuance, ledger, organization, agent-provisioning, agent-service, oid4vc-issuance, oid4vci-rewriter | verification, oid4vc-verification |
| `verifier` | infra parcial (postgres, redis, nats), user, utility, connection, verification, agent-provisioning, agent-service, oid4vc-verification | issuance, ledger, minio, mailpit, oid4vc-issuance, oid4vci-rewriter |
| `holder` | infra parcial (postgres, redis), cloud-wallet | issuance, verification, ledger, nats, minio |
| `issuer,verifier,holder` | todos *(comportamiento actual)* | — |

### Inji

| Rol | Servicios incluidos | Servicios omitidos |
|-----|--------------------|--------------------|
| `issuer` | certify-postgres, inji-certify, certify-preauth-postgres, inji-certify-preauth-backend, certify-preauth-proxy, certify-nginx, certify-preauth-nginx, citizens-postgres | inji-verify-*, vc-adapter, injiweb-* |
| `verifier` | inji-verify-postgres, inji-verify-service, inji-verify-ui, vc-adapter | inji-certify, certify-*, citizens-postgres, injiweb-* |
| `holder` | todos los injiweb-* (8 servicios: postgres, redis, mock-identity, esignet, oidc-ui, minio, datashare, mimoto, ui) | inji-certify, certify-*, inji-verify-*, vc-adapter |
| `issuer,verifier,holder` | todos *(comportamiento actual)* | — |

---

## Interfaz CLI/env

### `.env` — fuente de verdad persistente

```bash
# Roles a desplegar para el DPG seleccionado.
# Valores: issuer, verifier, holder (comma-separated)
# Default si no se define: issuer,verifier,holder (comportamiento completo)
# Ejemplo solo-emisión:  VERIFIABLY_ROLES=issuer
# Ejemplo demo típico:   VERIFIABLY_ROLES=issuer,holder
VERIFIABLY_ROLES=issuer,verifier,holder
```

### `deploy.sh` — flag `--role` como override

```bash
# Sintaxis
./deploy.sh up <dpg> [--role <roles>]

# Ejemplos
./deploy.sh up waltid                               # usa VERIFIABLY_ROLES del .env
./deploy.sh up waltid --role issuer                 # solo emisión, ignora .env
./deploy.sh up credebl --role issuer,holder         # emisión + wallet
./deploy.sh up inji --role verifier                 # solo verificación
./deploy.sh up all --role issuer,verifier,holder    # comportamiento actual explícito
```

### Lógica de resolución en `common.sh`

```bash
resolve_role() {
  # Precedencia: CLI_ROLE > VERIFIABLY_ROLES > default
  echo "${CLI_ROLE:-${VERIFIABLY_ROLES:-issuer,verifier,holder}}"
}
```

`CLI_ROLE` se setea en `deploy.sh` al parsear el flag `--role`.

### Validaciones

| Caso | Comportamiento |
|------|---------------|
| `--role holder` sin `issuer` en Walt ID / CREDEBL / Inji | Warning interactivo: "wallet sin issuer no puede recibir credenciales. Continuar? [y/N]" |
| `VERIFIABLY_ROLES` vacío | Error: "VERIFIABLY_ROLES no puede estar vacío. Valores válidos: issuer, verifier, holder" |
| Rol desconocido (ej. `admin`) | Error: "rol 'admin' no reconocido. Valores válidos: issuer, verifier, holder" |

---

## Hub: verificación independiente

### Fase 1 — Hub con verifier propio (este sprint — en scope)

El hub es un deploy separado con su propio `.env` en `deploy/compose/hub/`. Se agrega `VERIFIABLY_ROLES` al hub `.env.example` con default `verifier` (el hub raramente necesita emitir o ser holder).

Se agrega `hub-verifier-api` al compose del hub (`deploy/compose/hub/docker-compose.yml`):

```yaml
hub-verifier-api:
  image: docker.io/waltid/verifier-api:${WALTID_VERSION:-latest}
  networks: [verifiably-hub]
  volumes:
    - ./config/verifier:/waltid-work/config
  restart: unless-stopped
  profiles: ["verifier"]
```

El hub activa el profile `verifier` cuando `VERIFIABLY_ROLES` en `deploy/compose/hub/.env` incluye `verifier` (default). Caddy del hub agrega una ruta `/verify` que apunta a `hub-verifier-api`. El hub verifica cualquier credencial de emisores federados sin depender de que esos nodos tengan verifier activo.

### Fase 2 — Orquestación inteligente (fuera de scope de este plan — spec separado requerido)

`verifiably-go` lee `backends.json` por petición de verificación:

```
¿El issuer del VC está en backends.json?
  ├─ No  → rechaza (emisor no federado)
  └─ Sí  → ¿ese backend tiene verifier_url definida?
             ├─ Sí → delega a verifier_url del nodo
             └─ No → verifica localmente con hub-verifier-api
```

### Cambios a `backends.json`

Campo opcional `verifier_url` por backend. Vacío = hub verifica localmente.

```json
{
  "backends": [
    {
      "id": "credebl-nodo-A",
      "issuer_url": "https://nodo-a.example.com/issuer",
      "verifier_url": "https://nodo-a.example.com/verifier",
      "roles": ["issuer", "verifier"]
    },
    {
      "id": "waltid-nodo-B",
      "issuer_url": "https://nodo-b.example.com/issuer",
      "verifier_url": "",
      "roles": ["issuer"]
    }
  ]
}
```

`gen-backends.sh` se extiende para leer `VERIFIABLY_ROLES` de cada nodo y omitir `verifier_url` cuando el rol `verifier` no está activo en ese nodo.

---

## Archivos afectados

| Archivo | Cambio |
|---------|--------|
| `verifiably-go/.env.example` | Agregar `VERIFIABLY_ROLES` documentado |
| `verifiably-go/scripts/common.sh` | Agregar `resolve_role()`, `role_services()`, `infra_services()` |
| `verifiably-go/deploy.sh` | Parsear flag `--role`, pasar `CLI_ROLE` a common.sh, agregar validaciones |
| `verifiably-go/scripts/gen-backends.sh` | Leer roles por nodo, poblar `verifier_url` condicionalmente |
| `verifiably-go/deploy/compose/hub/docker-compose.yml` | Agregar servicio `hub-verifier-api` con profile `verifier` |
| `verifiably-go/deploy/compose/hub/Caddyfile.hub` | Ruta `/verify` → `hub-verifier-api` |
| `verifiably-go/deploy/compose/hub/config/verifier/` | Config inicial del verifier (walt.id config files) |

---

## Compatibilidad hacia atrás

- Deploys existentes sin `VERIFIABLY_ROLES` en `.env` mantienen comportamiento completo (`issuer,verifier,holder`).
- El flag `--role` es completamente opcional.
- No se eliminan escenarios existentes (`waltid`, `inji`, `credebl`, `all`). Los roles se aplican dentro de cada escenario.
- El hub existente sin `hub-verifier-api` sigue funcionando; el servicio solo aparece con profile `verifier`.
