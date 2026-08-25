# Inji Certify como segundo emisor de mdoc — diseño

**Status:** Aprobado para plan. **Fecha:** 2026-08-25.

## Contexto

`verifiably-go` emite mDL (ISO/IEC 18013-5, formato `mso_mdoc`) exclusivamente vía walt.id `issuer-api2` hoy — ver `docs/superpowers/adr/2026-08-18-mdl-issuer-walletid-not-standalone.md` y `docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md`, que fijan el principio arquitectónico del proyecto: *"esta aplicación es más que otra cosa un mediador, los DPGs son los encargados de emitir y no quiero romper ese patrón, porque si hay algo en el futuro que falle yo sería el responsable de mantener eso."*

El plan `2026-08-24-mdl-driving-privileges-variable-count` resolvió, del lado de walt.id, el problema de que `driving_privileges` se rellenaba a un tamaño fijo — la solución (4 perfiles walt.id por conteo de categorías) es necesaria porque walt.id's `arrayConfig` exige coincidencia exacta de longitud, sin mecanismo de longitud variable (confirmado empíricamente).

Este spec incorpora **Inji Certify** (MOSIP) como un **segundo emisor de mDL**, en modo **redundancia/alternativa**: walt.id sigue siendo el emisor principal; Inji se agrega como opción que el operador elige explícitamente por emisión — no hay fallback automático ni configuración fija de deployment.

## Investigación previa (evidencia, no asunción)

Una investigación de código real (`mosip/inji-certify`, ahora movido a `inji/inji-certify`) confirmó que Inji Certify implementa `mso_mdoc` nativamente — CBOR/COSE propio (`co.nstant.in:cbor`), MSO completo, firma delegada al Keymanager MOSIP — en el camino de emisión de producción (DataProvider), no detrás de un mock-gate, contradiciendo documentación desactualizada del propio repo (`AGENTS.md` dice "mock only").

Un **spike de validación** (2026-08-25, worktree aislado, Docker local, código descartable) ejecutó el flujo OpenID4VCI completo contra Inji Certify **v0.14.0 real** (imagen `injistack/inji-certify-with-plugins:0.14.0`) y confirmó:

- El mdoc emitido es genuino y criptográficamente válido: CBOR con `IssuerSignedItem` etiquetados (Tag 24), salts de 24 bytes, digests MSO correctos, **firma COSE_Sign1 ECDSA P-256/SHA-256 válida** contra el certificado del `x5chain`, fechas como CBOR tag 1004.
- **Inji NO tiene el problema de arrays de tamaño fijo de walt.id.** Con un único perfil, sin modificar, se emitieron mDLs con 2, 3 y 4 categorías de conducción reales, cada uno un array CBOR genuino de longitud variable (`MDocProcessor.preprocessForCBOR` recorre List/Map genéricamente). Esta es la ventaja concreta que justifica la integración: Inji no necesita el patrón "N perfiles por conteo" que walt.id sí requirió.
- De los 3 issues abiertos de no-conformidad OpenID4VCI 1.0 identificados en la investigación previa (#949, #954, #999): **dos no bloquean nada en la práctica** — #954 (algoritmo de firma anunciado como string "ES256" en el metadata) es solo una inconsistencia de metadata, el header COSE real lleva el entero `-7` correcto; #999 (falta de binding `cose_key`) no se reprodujo, un proof JWT con `jwk` normal fue aceptado (HTTP 200).
- **El tercer issue (#949) sí es real y bloquea la interoperabilidad con Credo-TS**, pero no por la razón originalmente descrita (el envoltorio JSON de la respuesta `{"credential": "..."}` es aceptado tal cual por Credo-TS). El bloqueo real está un nivel más abajo: `MDocCredential.addProof` (en Inji) envuelve el mapa `IssuerSigned` ya firmado dentro de un objeto contenedor `{"docType": "...", "issuerSigned": <mapa firmado>}` — la forma de un `Document` de *DeviceResponse*, no de una credencial standalone. Credo-TS (`@animo-id/mdoc` 0.5.2, la librería exacta usada por `@credo-ts/core` 0.6.3 de `cdpi-wallet`) espera el mapa `IssuerSigned` directo. Confirmado en el spike: quitando manualmente ese contenedor exterior — sin tocar un solo byte del mapa `IssuerSigned` interno, donde vive la firma — la misma credencial parsea perfectamente contra `@animo-id/mdoc`.

**Decisión sobre el bloqueante**: no se reporta upstream a Inji. Se corrige exclusivamente como workaround en `cdpi-wallet` (ver más abajo). Esto es deuda técnica nuestra, deliberada, no una dependencia de que Inji publique un fix.

Dos defectos operativos adicionales del spike, relevantes para el plan de despliegue: `credentialOfferCache` falta en el `certify-default.properties` distribuido (se arregla con un override de config); `MDocMockVCIssuancePlugin` hardcodea `driving_privileges` como mapa de una entrada, no sirve como fuente de datos real — el perfil de producción debe usar el modo DataProvider con template real, no el mock plugin.

## Decisión de diseño

### Selección de emisor

**No se necesita ningún mecanismo nuevo de selección.** Confirmado en el código real (`internal/handlers/schema.go`, `ShowSchemaBrowser`): el operador ya elige el DPG PRIMERO (`sess.IssuerDpg`, fijado en `/issuer/dpg`), y luego `schemaBrowserData` muestra únicamente los schemas/tipos de credencial disponibles bajo ese DPG. La navegación es DPG → schema, no al revés — exactamente como ya sucede hoy entre walt.id, CREDEBL e Inji para los formatos no-mdoc existentes.

Por lo tanto, "el operador elige walt.id o Inji para emitir mDL" se resuelve enteramente por el hecho de que exista un schema/tipo de credencial mDL catalogado bajo AMBOS DPGs: el que ya existe bajo walt.id (sin cambios) y uno nuevo bajo Inji (lo que este spec agrega). El operador elige Inji primero en `/issuer/dpg`, y entonces ve "mDL" entre los tipos disponibles de ese DPG — mismo flujo, cero código nuevo de selección, cero campo de formulario nuevo. No hay fallback automático entre DPGs ni configuración fija por deployment porque la elección de DPG-primero ya cumple ese rol.

### Ubicación del código

Se extiende el adapter **`internal/adapters/injicertify/`** existente (ya en producción, usado hoy para credenciales no-mdoc emitidas vía Inji Certify) — no se crea un paquete separado. `injicertify.Adapter.IssueToWallet` gana un caso para `Std == "mso_mdoc"`, siguiendo el mismo patrón por el que `waltid.Adapter.IssueToWallet` ya distingue mdoc de otros formatos dentro del mismo paquete (`internal/adapters/waltid/catalog.go:41`: *"IssueToWallet dispatches Std=='mso_mdoc' straight to issueMdocViaIssuer2"*).

No se abstrae una interfaz Go común "mdoc issuer" entre walt.id e Inji en esta iteración — ambos adapters siguen implementando `backend.Adapter.IssueToWallet` de forma independiente, sin código compartido nuevo. El riesgo de tocar la lógica de walt.id ya probada en producción supera el beneficio de deduplicar dos implementaciones que, en la práctica, difieren en casi todo (modelo de perfiles, protocolo de auth, forma de la respuesta).

### Modelo de perfil mdoc en Inji

Inji no necesita el patrón "N perfiles por conteo de categorías" — un único perfil mdoc (`doctype = "org.iso.18013.5.1.mDL"`, con `mso_mdoc_claims` declarando `driving_privileges` como array genérico) cubre 1 a N categorías sin modificación, confirmado en el spike. La configuración de este perfil (fila en `certify.credential_config`, o el mecanismo de seed que el plan de implementación determine) sigue el mismo patrón operativo que ya usa la config de walt.id: baseline versionado en el repo, runtime gitignored, seedeado en el primer `up` y preservado en despliegues subsecuentes.

El límite operativo de 4 categorías máximo, y el rechazo de 0 categorías, se mantienen **iguales para Inji que para walt.id** — no porque Inji lo requiera técnicamente (no lo requiere), sino por consistencia de producto: el operador no debe ver comportamiento distinto según el emisor elegido para el mismo tipo de validación de negocio.

### El bloqueante del envoltorio CBOR — dónde se corrige

**`verifiably-go` solo crea la oferta de credencial (`credentialOffer` URI) y no interviene en la redención.** La wallet redime la oferta directamente contra el DPG elegido (walt.id o Inji) — confirmado que este es el patrón real ya en producción con walt.id: `issuer2.go` solo hace `POST /issuer2/credential-offers` y devuelve la URI; el intercambio token→nonce→proof→credential ocurre wallet↔DPG, sin pasar por `verifiably-go`.

Esto significa que `verifiably-go` **nunca ve** el CBOR final que Inji entrega a la wallet, y por lo tanto no puede corregir el envoltorio ahí. La corrección se implementa **en `cdpi-wallet`**: al recibir una credencial `mso_mdoc`, la wallet detecta si viene envuelta en `{docType, issuerSigned}` (forma específica de Inji) y, de ser así, extrae el mapa `issuerSigned` interno — sin modificar ni re-serializar ese mapa — antes de pasarlo a `agent.mdoc.store`/Credo-TS. Inmediatamente después de la extracción, la wallet **verifica el COSE_Sign1** contra el certificado del `x5chain` como salvaguarda activa: si la verificación falla, la credencial se rechaza y no se persiste, en vez de guardarse silenciosamente en un estado potencialmente corrupto.

Un CBOR que NO viene envuelto (el caso de walt.id, y el caso de una futura versión de Inji que ya no envuelva) debe pasar por esta detección sin ser modificado — la detección es condicional sobre la forma real de los bytes recibidos, nunca asume incondicionalmente cuál DPG los produjo.

**Alcance explícito de esta limitación**: mientras el workaround viva en `cdpi-wallet`, Inji-como-emisor-de-mdoc solo funciona correctamente con `cdpi-wallet`. Una wallet de terceros que se conectara a este sistema y eligiera Inji como emisor recibiría el CBOR con el envoltorio sin corregir. Esto se acepta deliberadamente como aceptable para el alcance actual del proyecto (cdpi-wallet es la única wallet real hoy), siguiendo el mismo precedente que el ADR de 2026-08-21 ya estableció al descartar `internal/mdl` como issuer nativo: si en el futuro se necesita soportar otra wallet con Inji, es una decisión nueva tomada con ese requisito en mano, no una extensión automática de este diseño.

## Flujo de datos

1. El operador elige el DPG en `/issuer/dpg` (walt.id o Inji, flujo ya existente, sin cambios) y luego el tipo de credencial mDL, ahora disponible bajo ambos.
2. `SubmitIssue` (`internal/handlers/issuance.go`) recolecta y valida `driving_privileges` exactamente igual que hoy — 0 categorías es error duro, más de 4 se rechaza. Esta validación es independiente del DPG elegido; vive en `internal/mdoc`/el handler, no en ningún adapter.
3. El registry/`factory.Build` ya resuelve, por la sesión/schema elegidos, cuál `backend.Adapter` concreto invocar (mismo mecanismo ya en producción) — `IssueToWallet` despacha a `waltid.issueMdocViaIssuer2` (sin cambios) o al nuevo caso `mso_mdoc` dentro de `injicertify.Adapter.IssueToWallet`, sin lógica de despacho condicional nueva en el handler.
4. El nuevo camino de Inji construye la oferta OID4VCI usando el perfil mdoc único (sin selección por conteo), reusando el cliente HTTP/auth ya existente en `injicertify/`, y devuelve la `credentialOffer` URI — igual forma de resultado que el camino walt.id.
5. La wallet (`cdpi-wallet`) redime la oferta directamente contra el DPG elegido. Si es Inji, tras recibir la respuesta, detecta y corrige el envoltorio `{docType, issuerSigned}` si está presente, verifica el COSE_Sign1 post-extracción, y solo entonces persiste vía `agent.mdoc.store`.
6. De ahí en adelante, indistinguible del flujo ya existente con walt.id: catálogo, elegibilidad, métricas de emisión, revocación por status list — todo sin cambios, en ambos DPGs.

## Manejo de errores

- **0/>4 categorías**: sin cambios, ver arriba — validación previa al adapter, independiente del DPG.
- **Perfil mdoc de Inji no provisionado o mal configurado**: el nuevo camino de `injicertify` falla con un error explícito en español antes de intentar construir la oferta (p. ej. "inji: no hay perfil mdoc provisionado — contacta al operador de la plataforma"), mismo tono que el resto del proyecto.
- **Fallo de Inji al crear la oferta** (HTTP error, respuesta malformada): se propaga el mensaje de Inji verbatim, mismo patrón que `waltid` ya usa hoy para su propio fallo de creación de oferta.
- **En `cdpi-wallet`**: si la extracción del envoltorio o la verificación COSE_Sign1 post-extracción falla, la wallet rechaza la credencial con un error claro y no la persiste — "fail closed", mismo principio que el resto de esta línea de trabajo (ver el plan de `driving_privileges` variable-count).

## Testing

- **`verifiably-go`**: tests unitarios para el nuevo camino `mso_mdoc` dentro de `injicertify.Adapter.IssueToWallet` (construcción de oferta: docType, namespace, subject data), usando un servidor HTTP de prueba que simule Inji Certify — mismo patrón `httptest` ya usado en los tests existentes de `waltid`. No requiere una instancia real de Inji para CI; la validación empírica contra el servicio real ya la cubrió el spike.
- **`cdpi-wallet`**: test unitario para la función de detección/extracción del envoltorio, usando como fixture uno de los CBOR reales capturados durante el spike (`C:\tmp\spike\run\mdl_4categories.json` u otro archivo del mismo directorio), más un test que confirme que un CBOR SIN envoltorio (el caso walt.id) pasa **sin modificarse** — para que la corrección de Inji nunca corrompa una credencial que ya viene en la forma correcta.
- **End-to-end en VPS** (tarea final del plan de implementación, mismo patrón que el plan de `driving_privileges`): levantar Inji Certify real en la VPS junto a walt.id, emitir un mDL real por cada emisor desde el formulario real, decodificar y verificar ambos, y confirmar que el operador puede elegir entre los dos emisores end-to-end, incluyendo la corrección del envoltorio verificada contra una wallet real.

## Fuera de alcance de este spec

- No se toca la lógica de perfiles-por-conteo de walt.id (`isoMdl_1cat`..`isoMdl_4cat`) — permanece exactamente como quedó tras el plan anterior.
- No se reporta ni se depende de un fix upstream en `inji/inji-certify` para el envoltorio del CBOR.
- No se abstrae una interfaz Go común entre adapters de mdoc.
- No se diseña soporte para una wallet de terceros con Inji como emisor — ver "Alcance explícito de esta limitación" arriba.
- No se atienden los defectos operativos menores del spike (`credentialOfferCache` faltante, `MDocMockVCIssuancePlugin` inservible para producción) como código de este repo — son configuración de despliegue de Inji Certify, se documentan como pasos de la tarea de provisión en el plan de implementación, no como código Go/TypeScript.
