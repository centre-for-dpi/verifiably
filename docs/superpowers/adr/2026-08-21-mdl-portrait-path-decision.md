# Decisión: `issuer-api2` de walt.id sigue siendo el emisor de mDL — `internal/mdl/` no se usa en producción como firmador embebido

Status: **decidido — revierte la decisión inicial de este mismo documento,
tomada horas antes en la misma fecha.** Ver "Por qué se revirtió" abajo antes
de leer el resto; es la parte que importa.

Resuelve la pregunta que `2026-08-20-mdl-production-path-analysis.md` dejó
explícitamente abierta en su tabla comparativa — cuál de los tres caminos a
un mDL conforme (legacy `issuer-api` parcheado, `issuer-api2` de walt.id, o
el emisor nativo Go) absorbe a los otros. Este documento no repite ese
análisis; lo asume leído.

## Decisión (versión final)

**`issuer-api2` de walt.id sigue siendo el emisor de mDL en producción.**
`internal/mdl/` (rama `feat/mdl-issuer`) no se conecta al flujo de emisión
real de `verifiably-go` como firmador embebido — su código, tests y
vectores de conformidad siguen siendo valiosos (siguiente sección), pero no
como "el servicio que firma el mDL de un ciudadano real".

Lo que sí sigue en pie: los dos bloqueadores de seguridad de `issuer-api2`
identificados en el ADR de análisis (API de gestión sin autenticar, claves
privadas de ejemplo públicas en el repo de walt.id) deben resolverse antes
de cualquier tráfico real — eso no cambió. Lo que cambió es que la respuesta
a esos bloqueadores es **arreglar `issuer-api2`**, no reemplazarlo.

## Por qué se revirtió

La primera versión de este documento (misma fecha, horas antes) eligió
`internal/mdl/` razonando solo sobre seguridad y consistencia de código —
sin verificar contra el principio arquitectónico real del proyecto, que el
propio responsable del sistema aclaró de forma directa al revisar el plan
de implementación:

> "aquí esta aplicación es más que otra cosa un mediador, los DPGs son los
> encargados de emitir y no quiero romper ese patrón, porque si hay algo en
> el futuro que falle yo sería el responsable de mantener eso"

Verificado contra el código real, no solo contra la afirmación: cada
adapter (`internal/adapters/{waltid,credebl,injicertify}/issuer.go`)
implementa `IssueToWallet` construyendo un request y llamándolo contra un
servicio HTTP externo — el DPG en cuestión (walt.id, CREDEBL, Inji Certify)
es quien firma, `verifiably-go` media. `internal/mdl/` rompe esto de raíz:
`mdl.Issue()` firma **dentro del mismo proceso Go** que sirve el resto de
`verifiably-go` (confirmado: `APIMdlIssue` en `feat/mdl-issuer` llama
`mdl.Issue(...)` directamente, sin ningún salto de red — el endpoint
`POST /api/v1/credentials/mdl/issue` nunca se separó en un servicio propio).
Adoptarlo como está habría hecho que `verifiably` fuera, para mDL
específicamente, el emisor — exactamente el rol que el resto de la
plataforma existe para no tener.

La objeción de seguridad que motivó la primera decisión (API sin
autenticar, claves de ejemplo públicas) es real, pero es un problema
**operacional de `issuer-api2` tal como se configuró en esta sesión de
pruebas** — resoluble sin cambiar de arquitectura (gateway de
autenticación, rotar las claves). No es una razón para que `verifiably`
empiece a firmar credenciales él mismo.

## `internal/mdl/` no se desperdicia — para qué sigue sirviendo

- **Verificación independiente de conformidad ISO/IEC 18013-5.** Sus
  vectores de prueba (`internal/mdl/testdata/vectors/`) y el verificador
  Node.js independiente (`testdata/verify/verify.mjs`) ya sirvieron para
  confirmar, contra una implementación ajena, que el mdoc que `issuer-api2`
  produce (portrait, tags CBOR, cadena de certificados) es realmente
  conforme — ese trabajo cruzado ya pagó su costo y sigue siendo la
  referencia para futuras verificaciones.
- **Candidato real si algún día se necesita un DPG propio**, no como atajo
  para evitar arreglar uno existente. Si en el futuro CDPI decide operar su
  propio servicio de emisión de mDL — un servicio HTTP separado, con su
  propio ciclo de vida, corriendo como cualquier otro DPG que `verifiably`
  media — `internal/mdl/` es la base de código que ya sabe hacer la parte
  criptográfica correctamente. Eso es un proyecto distinto (desplegar,
  operar y mantener un servicio nuevo), no una tarea de "conectar un
  endpoint interno".

## Consecuencia inmediata

**Los cuatro pasos que este documento proponía originalmente (datos reales,
persistencia IACA/DSC, integración a catálogo, auditoría) para
`internal/mdl/` no proceden como trabajo de producción.** El trabajo real
que falta es el que el ADR de análisis ya había identificado para
`issuer-api2` en su Parte 2, sección "Hard blockers found in the shipped
configuration": autenticar `POST /issuer2/credential-offers` y
`GET /issuer2/sessions`, y rotar las claves de ejemplo públicas
(`defaultIssuerKey`, `ciTokenKey`, `credentialEncryptionKey`) por material
real y privado.

## Fuentes

- `2026-08-20-mdl-production-path-analysis.md` — el análisis completo;
  tabla comparativa, verdicts por parte, todo citado a archivo/línea real.
  Su Parte 2 ("Hard blockers found in the shipped configuration") es ahora
  el trabajo pendiente real.
- `2026-08-20-mdl-tramo-c-status-and-next-steps.md` — mapa de estado; su
  paso "1. Decidir cuál de los dos caminos a portrait es el definitivo"
  queda resuelto por este documento, en su versión final, no la inicial.
- Conversación de brainstorming de esta sesión (2026-08-21) donde se
  detectó y corrigió el error de razonamiento — el registro completo del
  intercambio que llevó a esta corrección vive en el historial de la
  sesión, no reproducido aquí.
