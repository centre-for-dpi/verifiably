# Inji Mobile como holder (guía de interoperabilidad)

**Date:** 2026-07-14
**Status:** Approved
**Scope:** `verifiably-go/docs/` — documentación de interoperabilidad, sin cambios de código

---

## Objetivo

Documentar cómo una wallet **Inji Mobile** ya instalada por el usuario (que resuelve
esquemas contra Mimoto y trae el **Inji Verify SDK** embebido) puede actuar como
holder end-to-end en `verifiably-go`: recibir credenciales del rol Issuer y
presentarlas al rol Verifier — sin necesidad de un `backend.Adapter` nuevo,
porque Inji Mobile consume los estándares OID4VCI/OID4VP directamente vía
QR/deep-link, igual que cualquier wallet conforme.

## Contexto ya confirmado en el código

- `internal/adapters/injiweb/adapter.go` es un **stub de redirect** — Inji Web
  es una SPA de navegador sin API de lectura, así que todo método de holder
  devuelve `backend.ErrNotLinked`. Esto **no aplica** a Inji Mobile.
- `internal/adapters/injicertify/issuer.go` (`IssueToWallet`) genera el offer
  OID4VCI (`openid-credential-offer://...`) en dos modos:
  - `pre_auth`: `POST /v1/certify/pre-authorized-data` → offer con
    `pre-authorized_code`, redimible sin login.
  - `auth_code`: offer manual con grant `authorization_code` +
    `issuer_state` + `authorization_server` (eSignet u otro OIDC), hosteado en
    `/offers/{slug}/{id}`. El holder hace login en `authorization_server`, la
    wallet redime el `code`.
  - En ambos modos, el offer trae un `credential_configuration_id` explícito
    (`req.Schema.ID`) — no hay descubrimiento activo por parte de la wallet;
    cada credencial requiere su propio offer generado y entregado fuera de
    banda (QR, link). Esto es igual para Inji Mobile que para Inji Web o
    walt.id wallet.
- `internal/adapters/injiverify/adapter.go` (`RequestPresentation`) genera un
  `openid4vp://authorize?client_id=...&request_uri=...` apuntando al Inji
  Verify service real (`POST /v1/verify/vp-request` + `GET
  /vp-request/{id}`). Como Inji Mobile trae el Inji Verify SDK embebido,
  en teoría resuelve y responde a este JAR de forma nativa sin adaptación.
- El adapter walt.id (`walt_community`) genera sus propios offers/requests vía
  `openid4vc/jwt/issue` y `openid4vc/verify` — formato distinto, ya
  documentado como fuente de fricción cross-stack con otras wallets (ver
  `dpg-matrix.md` § walt.id, notas sobre `formatRank` y JsonArray).

## Qué se entrega

**Nota de alcance:** todo el contenido de compatibilidad se redacta a partir de
análisis estático del código y de los bugs ya catalogados para wallets
Inji-based (Inji Web) — **no** se ejecuta ninguna prueba en vivo con un
teléfono real en este trabajo. Cada fila de la matriz nueva se marca
explícitamente `⏳ pendiente de verificación en vivo` hasta que alguien corra
el checklist manual contra un deploy real.

### 1. Nueva sección en `docs/dpg-matrix.md`: "Inji Mobile (holder)"

Tabla de compatibilidad cubriendo las 4 combinaciones:

| Issuer ↓ / Verifier → | Inji Verify | walt.id verifier |
|---|---|---|
| Inji Certify (pre-auth) | ⏳ | ⏳ |
| Inji Certify (auth-code) | ⏳ | ⏳ |
| walt.id issuer | ⏳ | ⏳ (ya cubierto por walt.id wallet, no por Inji Mobile) |

Cada celda documenta, basándose en el código y en los bugs ya conocidos:
- Qué formato de credencial es más probable que funcione sin fricción
  (ej. SD-JWT para el mismo motivo que ya aplica a Inji Web: la librería
  `vc-verifier` de MOSIP tiene bugs de canonicalización URDNA2015 con LDP/VCDM
  2.0 — ver `dpg-matrix.md` § Inji Web Wallet, punto 4).
- Riesgos conocidos heredados de Inji Certify (kid mismatch primary vs
  preauth, key rotation desync) que afectarían a *cualquier* wallet,
  incluida Inji Mobile.
- Riesgos conocidos del lado walt.id (formato `jwt_vc_json` vs `vc+sd-jwt`,
  JsonArray assertion) si se usa como issuer o verifier cruzado.
- Marcador `⏳` explícito + instrucción de correr el checklist (sección 2)
  para reemplazarlo con `✅` / `❌` real.

### 2. Checklist de verificación manual (nueva subsección, no ejecutada aún)

Pasos concretos para cuando alguien tenga el deploy + teléfono a mano:

1. Generar offer desde el issuer de verifiably-go (pre-auth y auth-code por
   separado) y capturar la URI exacta / QR.
2. Escanear con Inji Mobile, registrar: ¿se resuelve el `credential_offer_uri`?
   ¿el login eSignet funciona (auth-code)? ¿la credencial se renderiza?
3. Generar un `request_uri` OID4VP desde el verifier (Inji Verify y luego
   walt.id) y registrar si el Inji Verify SDK embebido lo resuelve y si la
   presentación llega a `FetchPresentationResult`.
4. Plantilla de reporte de hallazgo (mismo formato forense que ya usa
   `dpg-matrix.md`: síntoma, causa raíz, reproducción, workaround) para que
   cualquier bug encontrado se documente con el mismo nivel de detalle que
   los ya existentes.

### 3. Actualización de `docs/integration.md`

Añadir una nota junto a la sección "Inji Web Wallet's 'adapter' is a stub"
aclarando que **Inji Mobile no necesita adapter ni entrada en
`backends.json` como holder** — no hay integración de código posible ni
necesaria del lado de verifiably-go; el único requisito es que el offer/
request_uri emitido sea válido OID4VCI/OID4VP estándar. Esto evita que un
futuro colaborador intente escribir un `internal/adapters/injimobile/`.

## Fuera de alcance

- Cualquier cambio de código en `injicertify` o `injiverify`. Si el checklist
  manual (ejecutado después, por el usuario) revela una incompatibilidad real,
  se abre como hallazgo nuevo en `dpg-matrix.md` siguiendo el patrón existente
  — no se anticipa ni implementa una corrección especulativa aquí.
- Pruebas automatizadas / e2e con Inji Mobile (no es automatizable sin un
  emulador Android/iOS con la app instalada; fuera del harness de Puppeteer
  existente en `e2e/`).
