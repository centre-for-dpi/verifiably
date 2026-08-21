# Tramo C (POC de emisión mDL) — estado real verificado y próximos pasos

Status: **mapa de estado, no un plan nuevo.** Escrito porque el trabajo técnico de
las últimas sesiones avanzó fases reales del plan
(`docs/superpowers/plans/2026-08-17-mdl-issuer-go.md`) sin marcar sus checkboxes ni
abrir los PRs que el propio plan prescribía — así que antes de decidir qué sigue,
esto confirma qué existe, qué está probado, y qué falta, verificado contra código y
tests reales corridos hoy, no contra lo que el plan dice que *debería* existir.

**Gate de negocio:** destrabado (`2026-08-20-mdl-iso18013-5-poc-design.md`, §Origen y
demanda) — INTRANT y MTC confirmados como solicitantes, ambos pidiendo emisión y
verificación. Detalle administrativo (interlocutor, fecha, plazo, sponsor) sigue sin
registrar, pero ya no bloquea el trabajo.

## Cómo leer la tabla

Cuatro estados, no dos:
- ✅ **Hecho y verificado** — código existe, tests corridos hoy, pasan.
- 🟡 **Hecho, verificación parcial** — código existe y probablemente funciona, pero
  el criterio de aceptación exacto del plan no se comprobó formalmente.
- ⚠️ **Empezado, incompleto** — parte del alcance existe, falta una porción real.
- ❌ **No empezado** — cero código, confirmado por búsqueda exhaustiva.

## C.7.0 — Fase 0, spike bloqueante de hardware

**🟡 Hecho, verificación parcial.**

Ejecutado en sesión previa: reader de Multipaz compilado e instalado, device
engagement completado con la wallet en foreground, presentación BLE end-to-end
confirmada dos veces (con portrait real la segunda vez), confirmado con WiFi apagado.

**Lo que el plan pedía como entregable y no existe:** `docs/mdl-fase0-report.md`
— el informe formal con modelo/fabricante de los dos teléfonos, resultado de
chunking con tiempos medidos, y el veredicto binario de seguridad de clave
(StrongBox/TEE/software vía Askar). Se hicieron pruebas equivalentes de facto, pero
nunca se documentaron como el entregable que el plan exige, y **el criterio de los
dos fabricantes distintos no está confirmado** — no hay registro de haber probado en
un segundo teléfono Android de fabricante distinto.

**✅ Verificado — 2026-08-20**, vía HCI snoop log de Android en vez de sniffer nRF
(el spec ya listaba ambos métodos como equivalentes). Captura real de una
presentación completa con portrait: cero PII del mDL en texto plano en 88.9KB /
1010 registros HCI; los únicos fragmentos legibles son el framing no-sensible de
`SessionEstablishment` (`eReaderKey`, que va sin cifrar por diseño). Detalle
completo en `docs/mdl-s2-btsnoop-analysis.md`, incluyendo qué no queda probado por
este método (correctitud interna del KDF/IV, solo la propiedad observable de que
un eavesdropper no aprende nada del contenido).

## C.7.1 — Issuer mdoc en Go

**✅ Hecho y verificado — confirmado corriendo los tests hoy, no solo leyendo código.**

Rama `feat/mdl-issuer`, 12 commits, nunca fusionada ni con PR abierto. Verificado en
esta sesión:

```
docker run --rm -v "$PWD":/app -w /app golang:1.25-alpine \
  go test ./internal/mdl/... ./internal/signer/... -v
```
→ **26 tests, todos PASS.** Cubre: tags CBOR correctos (tag 0 vs 1004, distinción que
el plan marca como el error más común), `IssuerSignedItem`/`valueDigests`, MSO con
`deviceKeyInfo`, `COSE_Sign1` con `x5chain`, PKI IACA→DSC con los límites del Annex B
(457 días, no exceder la vigencia de la IACA), `ValidityInfo` con las restricciones
normativas.

```
cd internal/mdl/testdata/verify && npm run verify
```
→ **"All checks passed."** Un verificador independiente (`@owf/mdoc`, no código
nuestro) acepta la firma, la cadena de certificados, y los 12 digests. Este es
literalmente el criterio de aceptación de C.7.1 según el plan, y pasa.

**Lo que falta de C.7.1 tal como está escrito:** Task 9 (correr `go vet`/`gofmt`,
abrir el PR) nunca se ejecutó — el trabajo técnico está completo pero no
"cerrado" en el sentido del plan. `proof_types_supported.cwt` vs `jwt` (decisión
técnica pendiente #4 del spec) sí se resolvió en la práctica — el código usa `jwt`
(commit `1ac0c7d` en esta misma rama, "use jwt proof type for mso_mdoc, not the
removed cwt type") — pero nunca se marcó como decidido en el documento.

**Limitación declarada por el propio plan, no un hallazgo nuevo:** portrait
diferido a C.7.5 a propósito. El ADR de hoy (`2026-08-20-mdl-issuer-api2-portrait-fix.md`)
resolvió ese mismo problema, pero **por la vía de walt.id `issuer-api2`, no por la
vía que este plan trazaba** (que era añadir `portrait` al `LicenceData` nativo y
volver a pasar por Fase 0 con el payload real). Las dos rutas no son la misma
credencial ni el mismo camino de código — ver la sección de reconciliación abajo.

## C.7.2 — Dataset

**✅ Hecho y verificado.** 12 elementos, tags correctos, round-trip CBOR sin
pérdida — cubierto por los mismos tests de C.7.1. `age_over_NN` calculado contra
`validFrom` del MSO, no `time.Now()` — confirmado leyendo `ageAtLeast()` en
`internal/mdl/issue.go`, exactamente como el plan lo exige.

## C.7.3 — Holder (`cdpi-wallet`)

**⚠️ Empezado, sustancialmente avanzado, sin cerrar.**

Confirmado en el historial de `cdpi-wallet`: presentación BLE real (`9da9063`),
pantalla de consentimiento (`8e0fdb2`, y referenciada explícitamente contra el
criterio §S-3 en `app/present-mdl.tsx`), cierre de sesión BLE en fallo (`97a84a0`,
`e2d62e0`), filtrado por `DeviceRequest` (`presentMdoc.ts`).

**No verificado formalmente:** el criterio de aceptación (d) del plan — "una captura
BLE de la sesión no muestra PII en claro" — no tiene evidencia de sniffer, igual que
en C.7.0. Es el mismo gap, no uno nuevo.

**Bug de arquitectura descubierto y corregido esta sesión, no anticipado por el
plan original:** `holder.requestCredentials()` (el path estándar de Credo) llama
`Mdoc.verify()` automáticamente, y el wallet nunca tuvo `X509Module` configurado con
ningún trust anchor — bug preexistente que solo se manifestó al cambiar de emisor
(de legacy `issuer-api`, que usa un path manual que evita esa verificación, a
`issuer-api2`, que usa el path estándar). Ya corregido y documentado en el ADR de
certificados de hoy.

## C.7.3b — Registro en Android Credential Manager

**❌ Bloqueado — no por hardware (esa hipótesis quedó descartada), sino por
una causa raíz sin identificar tras investigación exhaustiva.**

Implementado sobre `@animo-id/expo-digital-credentials-api` (paquete publicado,
v0.4.0) en vez de un módulo nativo propio — decisión tomada explícitamente en
sesión, no un cambio de alcance silencioso. Confirmado en el repo:
`registerMdlDigitalCredentials()`/`toCredentialItem()`
(`src/agent/mdl/registerDigitalCredentials.ts`), llamado desde la pantalla de
Credenciales (`app/(tabs)/credentials/index.tsx`) sólo en `Platform.OS ===
'android'`; entry point custom (`index.js`) con
`registerGetCredentialComponent`; guard en `app/_layout.tsx`
(`isGetCredentialActivity()`) para no montar la app completa detrás del
overlay del sistema; `DigitalCredentialsRequestOverlay.tsx` con **sólo
"Denegar" cableado** — "Aprobar" (firmar y devolver el vp_token) queda fuera
de alcance a propósito, porque requiere el trabajo de ISO 18013-7/OpenID4VP
que el spec ya excluye (decisión #9). Commit `389705a` (implementación
original), `7da12df` (fixes de esta sesión), ambos en `main` de cdpi-wallet.

**El bloqueo de hardware de la sesión anterior (Android 10 en el único
equipo disponible) quedó descartado — 2026-08-21.** El backport
`androidx.credentials.registry:registry-provider-play-services` sí funciona
en Android 10/API 29 vía Google Play Services (confirmado: el picker nativo
de Android se abre correctamente, y **CMWallet** — la wallet de referencia
de `github.com/digitalcredentialsdev/CMWallet`, side-instalada en el mismo
equipo para esta investigación — aparece y completa presentaciones
exitosas contra el mismo `dcql_query`, mismo Chrome 151, mismo dispositivo).
El límite real no era la versión de Android; era una configuración de
prueba anterior (debug build sin Metro corriendo) que nunca cargó el JS
real de la app.

**Investigación exhaustiva de por qué cdpi-wallet nunca aparece en el
picker, con evidencia directa en cada paso, sin resolver la causa raíz:**

Tres bugs reales confirmados y corregidos (commit `7da12df` en
cdpi-wallet), ninguno resolvió el problema por sí solo:
1. `encodeCredentials.js` nunca escribía `supported_protocols` en el JSON
   registrado — confirmado vía decompilación del struct Rust real del
   matcher (`Registry.supported_protocols: Vec<String>` con
   `#[nserde(default)]`): ausente → lista vacía → el loop de matching del
   matcher corre cero iteraciones, sin error. Parcheado.
2. El registro nativo llamaba dos veces con el mismo `id` bajo dos `type`
   distintos (uno legacy `"com.credman.IdentityCredential"`, otro el
   estándar `DigitalCredential.TYPE_DIGITAL_CREDENTIAL` — confirmado
   byte-idéntico al que `DigitalCredentialRegistry` fija internamente vía
   decompilación del `.aar`). CMWallet solo registra una vez. Parcheado,
   eliminada la llamada legacy.
3. El paquete fija `androidx.credentials.registry:*:1.0.0-alpha01` —
   `supportedProtocols` en la propia API de registro recién se agregó en
   `alpha05` (confirmado contra el índice de Google Maven y el historial de
   releases). Forzado a `alpha05` vía nuevo plugin
   `plugins/withCredentialsRegistryVersion.js`.

Con los tres fixes aplicados, **el picker sigue sin mostrar cdpi-wallet**
(confirmado repetidas veces, con capturas de pantalla). Se probó además,
como control definitivo: un registro nativo Kotlin directo usando las
clases oficiales `MdocEntry`/`OpenId4VpRegistry`
(`androidx.credentials.registry.digitalcredentials.*`) — el mismo patrón
exacto que usa CMWallet, evitando por completo el encoding manual del
paquete de terceros. **Tampoco aparece.** Se probó igualar `targetSdkVersion`
a un valor cercano al de CMWallet (33 vs 36 nuestro, 28 el de CMWallet — no
se pudo bajar a 28 exacto porque el lint de Google Play lo bloquea en
release builds). **Tampoco cambió el resultado.**

Comparación de manifests/firmas instalados (`adb shell dumpsys package`):
estructuralmente equivalentes en los intent-filters de `GET_CREDENTIAL`
(mismas acciones, misma categoría). Diferencia real no explicada: CMWallet
tiene el flag `DEBUGGABLE` (es un `app-debug.apk` real), cdpi-wallet es
`app-release.apk` — no se investigó si esto importa.

**Conclusión de la sesión:** cada hipótesis verificable por lectura de
código/bytecode fue confirmada y corregida donde aplicaba, pero ninguna
explica el síntoma completo. La causa raíz sigue sin identificar. Candidato
más probable para la próxima sesión: inspeccionar el `bugreport` completo
de Android (no solo `logcat`, que no expone nada del lado de Play
Services/GMS para este flujo) para ver si GMS descarta el registro de
`org.cdpi.wallet` por algún criterio no visible por las vías ya agotadas
(firma release vs. debug, algún allowlist interno, estado de sesiones
previas de prueba con distintos matchers/`id`s acumulado del lado del
sistema).

## C.7.4 — Reader de la POC

**✅ Cumplido tal como el plan lo definía para la POC — no confundir con el SDK
del Tramo D.**

El plan es explícito: para la POC se usa `multipaz-identity-reader` sin forkear,
importando la IACA por su UI. Eso es exactamente lo que se hizo, confirmado en vivo
esta sesión: verificación exitosa con portrait real, después de importar el
certificado por `TrustedIssuersScreen`. El "germen del SDK del Tramo D" que el plan
menciona (arquitectura core/transporte reutilizable) **no se ha empezado** — no
existe código propio de reader, solo el uso del reader ajeno.

## C.7.5 — Ampliación a mDL conforme (portrait + opcionales)

**⚠️ Resuelto, pero por una ruta distinta a la que el plan trazaba — ver
reconciliación abajo.** Portrait real, JPEG, funciona end-to-end y fue verificado
visualmente en el reader. Pero es walt.id `issuer-api2` quien lo produce, no
`internal/mdl/` (que sigue sin campo `portrait` en su struct `LicenceData`).

## C.7.6 — Testing y CI

**⚠️ Parcial.** Los tests Go de `internal/mdl/` pasan (confirmado corriéndolos hoy).
`.github/workflows/image.yml` corre `go test ./...` en cualquier push que toque
`internal/**`, así que `internal/mdl/` quedaría cubierto automáticamente en cuanto
la rama se abra como PR — pero **nunca se ha disparado contra este código**, porque
`feat/mdl-issuer` nunca se pusheó como PR. El harness cruzado Node pasa. **No
existe** `docs/mdl-manual-checklist.md` — confirmado, no está en el repo.

## C.7.7 — Demo

**❌ No ejecutada como demo formal de principio a fin con los 9 pasos que el plan
especifica** (incluyendo el caso negativo de mdoc manipulado, y la demostración
explícita de que `birth_date` no viaja cuando solo se pide `age_over_18`). Los
componentes individuales que la demo encadenaría sí funcionan por separado
(emisión, presentación, verificación, portrait) — pero nunca se corrió como un guion
único, y el caso negativo nunca se probó.

## Tramo D — SDK RN embebible

**❌ No empezado**, ni un archivo. Correcto que así sea: el plan es explícito en que
D solo arranca "tras gate C", y C no ha cerrado.

---

## La pieza que el plan no anticipó: dos caminos a un mdoc conforme, no uno

Esto es la reconciliación real, y es la decisión que importa más que cualquier
checkbox de arriba.

El plan asumía **un solo emisor mdoc**: `internal/mdl/`, nativo en Go, creciendo de
"10 de 11 mandatory" (C.7.1/C.7.2) a "11 de 11, conforme" (C.7.5) añadiendo
`portrait` al mismo struct tipado y volviendo a correr Fase 0 con el payload real de
~20KB para confirmar que el chunking BLE lo soporta.

Lo que pasó en la práctica: el portrait se resolvió por una vía completamente
distinta y no planeada — `issuer-api2` de walt.id, descubierto y adoptado en la
sesión de hoy, sin relación con `internal/mdl/`. Produce una credencial
igualmente conforme (confirmado: bstr real, tag 1004, verificada por el mismo tipo
de reader), pero:

- Es una credencial **de prueba con datos de muestra austriacos**, no datos reales
  de un solicitante — el ADR de hoy ya documenta esto como limitación.
- Depende de un servicio de walt.id con dos bloqueadores de seguridad duros sin
  resolver (API de gestión sin autenticar, claves privadas de ejemplo en el repo
  público de walt.id) — también ya documentado.
- No pasa por `internal/mdl/` en absoluto — es un código completamente distinto, un
  PKI distinto (el de walt.id vs. el `internal/mdl/pki/` que sí pasa los tests
  Annex B), y una cadena IACA→DSC distinta a la que el emisor nativo ya genera y
  verifica correctamente.

**Ahora hay, de facto, dos emisores mdoc parcialmente funcionando en paralelo**, sin
que ninguno de los dos sea el mDL conforme completo con datos reales que el plan
original perseguía. Ninguno de los ADR de hoy ni este documento decide cuál de los
dos absorbe al otro — eso es exactamente la decisión pendiente más importante que
sigue abierta.

---

## Próximos pasos — en orden, con lo que cada uno depende

Esto es una secuencia, no una lista de opciones — cada paso asume que el anterior se
resolvió.

### 1. Decidir cuál de los dos caminos a portrait es el definitivo

No es una pregunta técnica nueva — ya está analizada en
`2026-08-20-mdl-production-path-analysis.md` (Partes 2 y 3 de ese ADR). Lo que
falta es la decisión explícita, porque hoy el repo tiene ambos caminos avanzando
sin que ninguno esté descartado:

- **Terminar `internal/mdl/`**: añadir `portrait` al struct, exponerlo en
  `mdl_issue.go`, volver a correr Fase 0 con el payload real de ~20KB (el criterio
  de C.7.0 ya lo anticipaba con un payload sintético — falta con el real). Esto
  mantiene todo dentro de un solo emisor propio, sin depender de un segundo
  servicio de terceros con los bloqueadores de seguridad ya documentados.
- **Formalizar `issuer-api2`** como backend de producción: resolver los dos
  bloqueadores de seguridad (gateway de autenticación, rotar las claves de
  ejemplo), y construir el adaptador Go correspondiente detrás de la interfaz
  `backend.Adapter` — como se discutió en la conversación previa a este documento.

Estos dos caminos no son mutuamente excluyentes técnicamente (el `Adapter` los
soporta a ambos), pero **mantener los dos en paralelo indefinidamente es el peor
resultado**: duplica la superficie de PKI, de trust anchors en el wallet, y de
código a mantener, sin que ninguno llegue a producción.

### 2. Cerrar C.7.1 formalmente

Independiente de la decisión del paso 1: `feat/mdl-issuer` tiene 26 tests en verde
y un verificador independiente que lo acepta. Correr `go vet`/`gofmt` (Task 9,
Step 3 del plan, nunca ejecutado) y abrir el PR que el propio plan ya redactó
(Task 9, Step 5) es trabajo de horas, no de días — y deja el trabajo ya hecho
protegido por CI en vez de viviendo sin PR desde hace días.

### 3. Completar el informe de Fase 0 con los criterios que faltan

`docs/mdl-fase0-report.md` nunca se escribió. Antes de escribirlo, falta una
verificación real, no solo redactar lo ya hecho:
- **Segundo teléfono Android de fabricante distinto** — el plan es explícito en
  que un solo fabricante no cumple el criterio de aceptación. Sigue pendiente
  deliberadamente: la configuración probada usa Android solo como reader (nunca
  como holder en BLE peripheral mode, que es donde la inconsistencia entre
  fabricantes históricamente aparece), así que el riesgo que el criterio
  buscaba mitigar no se ejerció — ver la nota de estado en el spec, §C.7.0.
- ~~Captura BLE con sniffer confirmando ausencia de PII en claro~~ — **hecho
  2026-08-20** vía HCI snoop log de Android (el spec ya listaba esa vía como
  equivalente al sniffer nRF). Cero PII en 88.9KB de captura real con portrait.
  Detalle: `docs/mdl-s2-btsnoop-analysis.md`.

### 4. C.7.3b — bloqueo de causa desconocida, no de hardware ni de código conocido

**Actualizado 2026-08-21 — el bloqueo de hardware se descartó, pero apareció
uno más profundo sin resolver.** El Galaxy S9+ (Android 10) sí puede ejercer
la API vía el backport de Play Services — confirmado con una wallet de
referencia (CMWallet) funcionando correctamente en el mismo equipo, misma
sesión. cdpi-wallet, en cambio, nunca aparece en el picker pese a que su
registro es válido por toda medida verificable (dos matchers WASM distintos
lo procesan sin error de formato) y pese a que se probó con un registro
nativo Kotlin directo, código por código idéntico al de CMWallet. Detalle
completo de las tres correcciones reales encontradas y de todo lo descartado
en la sección de estado de arriba. Siguiente acción concreta: capturar un
`adb bugreport` completo (no solo `logcat`) durante un intento fallido, para
buscar del lado de Google Play Services alguna señal de por qué descarta el
registro de `org.cdpi.wallet` específicamente — nadie ha mirado ese nivel
todavía.

### 5. La demo formal (C.7.7) al final, no antes

Con los 4 pasos anteriores resueltos, correr el guion completo de 9 pasos del
plan — incluyendo el caso negativo (mdoc manipulado → error) y la prueba de
privacidad explícita (pedir solo `age_over_18`, confirmar que `birth_date` nunca
viaja) — es lo que cierra C.7 y habilita evaluar el gate hacia el Tramo D.

### Lo que NO recomiendo hacer ahora

**No empezar el Tramo D** (SDK RN, 3-4 meses) hasta que el paso 1 esté decidido.
Construir un SDK de verificación reutilizable sobre un emisor cuyo camino de
producción todavía está en disputa es exactamente el tipo de inversión que el gate
C→D existe para evitar.

**No dejar caer silenciosamente ninguno de los dos caminos a portrait sin
decisión explícita** — ahora mismo eso es lo que está pasando de facto, y es más
barato decidir esta semana que descubrir en tres meses que se mantuvieron dos PKIs
paralelas sin que nadie lo decidiera a propósito.

## Fuentes

- `docs/superpowers/plans/2026-08-17-mdl-issuer-go.md` (plan original, Tasks 0-9)
- `docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md` (spec maestro,
  Tramos A-D)
- `docs/superpowers/adr/2026-08-20-mdl-cbor-type-limits.md`,
  `2026-08-20-mdl-issuer-api2-portrait-fix.md`,
  `2026-08-20-mdl-production-path-analysis.md` (ADRs de esta sesión)
- `verifiably-go` rama `feat/mdl-issuer`: tests corridos en vivo hoy vía
  `docker run golang:1.25-alpine go test ./internal/mdl/... ./internal/signer/... -v`
  y `cd internal/mdl/testdata/verify && npm run verify`
- `cdpi-wallet`: `git log` completo de commits `mdl`/`mDL`/`18013`,
  `app/present-mdl.tsx`, `src/agent/mdl/{presentMdoc,signDeviceResponse}.ts`
- Búsquedas exhaustivas confirmando ausencia: `docs/mdl-fase0-report.md`,
  `docs/mdl-manual-checklist.md`, cualquier referencia a
  `androidx.credentials`/Credential Manager, cualquier paquete `@cdpi/mdl-*`
