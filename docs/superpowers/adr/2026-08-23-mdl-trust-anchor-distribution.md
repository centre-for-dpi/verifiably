# Decisión: distribución del trust anchor mdoc — endpoint dinámico ahora (POC), VICAL del Hub como camino de producción

Status: **decidido e implementado.** Cierra la pregunta que
`2026-08-20-mdl-production-path-analysis.md` (Part 5, "How would a wallet
ever come to trust a *real* verifiably-issued IACA?") dejó explícitamente
abierta: no existía, en ninguna forma, un mecanismo para que la wallet
confiara en el IACA real de un despliegue sin recompilar el certificado
dentro de la app. Ese mecanismo ya existe, está desplegado en
`mtc.credenciales.ysalabs.work`, y fue verificado extremo a extremo contra
un IACA regenerado en vivo.

## El problema que forzó esta decisión

Cada corrida de `./deploy.sh up waltid` que no encuentra un `dsc.pem`
existente genera un IACA + DSC **nuevos** (`provision_issuer2_certificates`
en `scripts/gen-caddy.sh`). Antes de este cambio, la wallet solo confiaba en
un certificado **compilado como constante** en
`src/agent/setup.ts::MDOC_TRUSTED_CERTIFICATES`. El resultado: cada
redeploy limpio rompía la aceptación de credenciales con
`"No trusted certificate was found"` hasta recompilar y republicar la app
con el nuevo certificado — inviable como flujo operativo real, y
completamente opuesto al objetivo explícito de que un despliegue nuevo
"quede listo" sin pasos manuales de por medio.

## Las tres opciones consideradas

1. **Fijar el IACA una sola vez y no regenerarlo nunca más** — elimina el
   síntoma pero no el problema: sigue exigiendo que TODA wallet que alguna
   vez deba confiar en un despliegue distinto (otro país, otro ambiente)
   recompile con un certificado nuevo. No escala más allá de un único
   emisor fijo.
2. **La wallet resuelve el trust anchor dinámicamente desde el propio
   emisor** — el `credential_issuer` de la oferta OID4VCI ya identifica el
   origen; ese origen puede publicar su propio IACA vigente por HTTP, y la
   wallet lo consulta en el momento de verificar, con un fallback estático
   para no romper credenciales ya emitidas bajo el certificado anterior.
3. **Un VICAL (ISO 18013-5, Annex C) operado por una autoridad distinta del
   emisor** — una lista de emisores legítimos, firmada por alguien que NO es
   el propio emisor, de forma que un emisor comprometido no puede
   autocertificarse. Es el modelo que usan despliegues reales (AAMVA opera
   uno; `multipaz-identity-reader` ya tiene el *cliente* VICAL en su modelo
   de datos, aunque no opera un servidor VICAL — ver
   `2026-08-20-mdl-production-path-analysis.md` línea ~427).

## Decisión tomada

> "como esto es un POC vamos con el endpoint, pero me parece que el camino
> final con esto en un pais es usar el hub como lista VICAL para todas las
> credenciales de un gobierno, debemos dejas eso explictamente
> documentando"

Se implementó la **opción 2 ahora** (endpoint dinámico, POC) con la
**opción 3 explícitamente registrada como el reemplazo de producción**, no
como una idea futura vaga sino como un plan de migración concreto contra
código que ya existe.

### Por qué el endpoint dinámico es honesto como POC y no como producción

El endpoint que el emisor publica (`GET /trust/mdoc-anchors`, ver más abajo)
está **deliberadamente sin firmar**. La razón no es pereza — firmarlo con
una clave del propio emisor no añade seguridad real: un atacante capaz de
falsificar la respuesta del endpoint es, por definición, capaz de falsificar
también la firma sobre esa respuesta, porque ambas autoridades son la misma.
El límite de confianza real en este POC es TLS + mismo origen que la oferta
OID4VCI ya resolvió — nunca más fuerte que "el propio emisor lo dice".

Un VICAL cambia exactamente ese punto: la lista la firma una autoridad
**distinta** del emisor (el Hub, en el caso de CDPI), así que un emisor
comprometido no puede simplemente publicar su propio certificado falso en
su propio endpoint y hacerlo pasar por confiable. Es un cambio de
**autoridad firmante**, no la adición de una firma donde antes no había
ninguna — de ahí que el POC no sea "VICAL sin firmar", sino un mecanismo
categóricamente distinto que este documento no debe confundir con un VICAL
real.

## Lo que se construyó (POC, ambos repos)

### Lado emisor — `verifiably-go`

- **`GET /trust/mdoc-anchors`**
  (`internal/handlers/mdoc_anchors.go`) — público, sin autenticar, cacheado
  30s, lee `iaca.pem` desde el directorio de certs de issuer2
  (`VERIFIABLY_MDOC_CERTS_DIR`, por defecto
  `/app/issuer-api2-config/certs` dentro del contenedor). Responde
  `{ anchors: string[], updatedAt, poc: true }` — el campo `poc` es un
  contrato permanente, no decoración: un futuro cliente VICAL-aware puede
  ramificar sobre él.
- **Allowlist explícito de archivos** (`mdocAnchorFilenames = []string{"iaca.pem"}`)
  — nunca `dsc.pem` (porta material de clave privada) ni `issuer2.env`
  (coordenadas de la clave privada del DSC). Verificado con archivos reales
  extraídos del VPS, no solo revisado por lectura.
- **Ruteo Caddy** — el emisor real (`issuer-api2`, alias público
  `walt-issuer2.<dominio>`) y el servicio que expone este endpoint
  (`verifiably-go`) son **contenedores distintos**. `walt-issuer2` tiene un
  allowlist deliberadamente angosto en `scripts/gen-caddy.sh` (solo
  `/openid4vci/*` y `/.well-known/*`, todo lo demás 404) porque
  `issuer-api2` no tiene ninguna autenticación en su API de gestión. Este
  cambio añade una tercera regla, `handle /trust/mdoc-anchors { reverse_proxy
  verifiably-go:8080 }`, antes del catch-all — el único path nuevo abierto,
  sin debilitar el resto del allowlist. **Este fue el bug real encontrado
  durante la verificación de esta misma sesión**: el endpoint funcionaba
  perfectamente en el dominio de `verifiably-go`, pero la wallet lo consulta
  contra el origen del `credential_issuer` (`walt-issuer2`), que devolvía
  404 hasta este fix — commit `2afe956`.

### Lado wallet — `cdpi-wallet`

- **`src/agent/mdocTrustAnchors.ts`** — resolver dinámico para
  `X509Module.getTrustedCertificatesForVerification`. Puntos de diseño que
  importan operacionalmente:
  - Cachea 5 minutos por origen de emisor, con colapso de solicitudes en
    vuelo.
  - **Stale-on-failure**: si el fetch falla pero hay un valor cacheado
    previo, se devuelve ese valor viejo en vez de fallar — "un ancla vieja
    sigue siendo un ancla que este emisor sirvió alguna vez por TLS; el TTL
    solo significa que pudo haber rotado desde entonces". Sin nada
    cacheado, sí falla (cae al fallback estático).
  - **Nunca deriva la URL de fetch de la cadena de certificados que está
    verificando** — eso permitiría que una credencial hostil nominara a su
    propio auditor. La URL viene exclusivamente del `credential_issuer` de
    la oferta OID4VCI, el mismo valor ya usado para construir el `aud` del
    JWT de prueba de posesión.
  - Solo se activa cuando `verification.type === 'credential'` — nunca en
    rutas de presentación offline ni en otros tipos de verificación
    (oauth2, key-attestation). Cubierto por tests que confirman `fetch`
    nunca se llama en esos casos.
  - El resultado se **une** (no reemplaza) con el fallback estático
    compilado, así que credenciales ya emitidas bajo un IACA anterior
    siguen verificando después de que el emisor rote su root.

## El camino de producción — explícitamente documentado, no solo prometido

El Hub (`internal/trust/registry.go`) ya tiene la forma correcta para esto:
`TrustedIssuer` (hoy solo `DID string`, sin campo X.509) y
`GET /trust-registry` (ya firmado ES256 por el Hub, no por el emisor
vouched-for). La migración es:

1. Añadir un campo `X5c []string` (o equivalente PEM) a `TrustedIssuer`.
2. El Hub firma y sirve la lista completa de IACAs de todos los emisores
   registrados de un gobierno vía `GET /trust-registry` — el mismo endpoint
   que hoy ya sirve el trust registry DID-based, extendido, no duplicado.
3. La wallet cambia su fuente de fetch: en vez de
   `{issuerOrigin}/trust/mdoc-anchors`, consulta el `trust-registry` del Hub
   y busca la entrada correspondiente al emisor de la oferta.
4. **Se elimina `GET /trust/mdoc-anchors`** — es el sustituto interino de
   un solo emisor, documentado como tal desde su propio comentario de
   cabecera en `mdoc_anchors.go`, no como una característica permanente.

Nada de esto está implementado — es la ruta señalada, no código pendiente
de review. Se registra aquí porque el usuario pidió explícitamente que
quedara documentado, no solo decidido de palabra.

## Verificación realizada

- Suite Go completa (`go test ./internal/...`) verde.
- Allowlist de `iaca.pem` mutation-testeado con archivos reales del VPS
  (copiando también un `dsc.pem` real y confirmando que sigue devolviendo
  exactamente 1 ancla).
- Suite Jest de la wallet (`mdocTrustAnchors.test.ts`), 12/12, corrida
  directamente — incluyendo los dos tests de seguridad más importantes:
  "nunca hace fetch sin emisor registrado" (ruta de presentación offline) y
  "nunca hace fetch para tipos de verificación distintos de credential".
- Verificación end-to-end real, no solo de componentes aislados: tras
  redesplegar (lo cual regeneró un IACA nuevo, `CN=VERIFIABLY POC IACA`,
  distinto del `CN=INTRANT POC IACA` compilado en la wallet), se confirmó
  por curl que `walt-issuer2.mtc.credenciales.ysalabs.work/trust/mdoc-anchors`
  responde 200 con el certificado nuevo, que `verifiably-go`'s propio
  dominio sigue respondiendo 200, y que `walt-issuer2.../issuer2/sessions`
  (API de gestión sin autenticar) sigue en 404 — el allowlist no se
  debilitó. Pendiente de confirmación por el usuario: que una aceptación
  real en dispositivo, contra este IACA nuevo y sin recompilar la wallet,
  funciona.

## Ver también

- `2026-08-20-mdl-production-path-analysis.md` — Part 5 planteó la pregunta
  que este documento resuelve.
- `internal/handlers/mdoc_anchors.go` — comentario de cabecera con el
  razonamiento de seguridad completo, verbatim consistente con este ADR.
- `src/agent/mdocTrustAnchors.ts` (cdpi-wallet) — comentario de cabecera
  equivalente del lado wallet.
- `internal/trust/registry.go` — el modelo `TrustedIssuer` que la migración
  a VICAL extiende.
