# Diseño: `driving_privileges` con número real de categorías, sin relleno duplicado

Status: **aprobado, listo para implementación.**

## El problema

`issuer-api2` (walt.id) exige que el array `driving_privileges` de cada mDL
tenga **exactamente** el número de entradas que su perfil declara en
`mDocNameSpacesDataMappingConfig`'s `arrayConfig` — confirmado empíricamente,
no supuesto, contra un `issuer-api2:0.23.1` real desplegado en el VPS:

- Con `arrayConfig` de 2 entradas: 1, 3 y 4 categorías reales fallan con
  `Json array sizes (input & config) are not equal`; solo 2 funciona.
- Con `arrayConfig` ampliado a 3: 1, 2 y 4 fallan; solo 3 funciona.
- Con `arrayConfig` ampliado a 6: 1 a 5 fallan; solo 6 funciona.

No existe, dentro del modelo de configuración de walt.id, ningún mecanismo
para un array de tamaño variable (mínimo/máximo, opcional, etc.) —
`JsonArrayToCborMappingConfig.executeMapping` (decompilado de
`waltid-mdoc-credentials-jvm-0.23.1.jar`) compara longitudes con
igualdad estricta.

Por eso el código actual (`internal/mdoc/drivingprivileges.go`'s
`PadDrivingPrivileges`) **duplica** la última categoría real del operador
hasta llegar a 2 entradas — nunca inventa ni deja vacío, pero el resultado
visible es una credencial con la misma categoría repetida dos veces cuando
el titular solo tiene una. El usuario reportó esto correctamente como
confuso, y preguntó si se puede lograr que el array lleve solo las
categorías reales.

## La solución: un perfil walt.id por cada tamaño de array

Cada perfil walt.id (`isoMdl_1cat`, `isoMdl_2cat`, `isoMdl_3cat`,
`isoMdl_4cat`) declara su propio `arrayConfig` de tamaño fijo (1, 2, 3, 4
entradas respectivamente) — pero **todos declaran el mismo
`credentialConfigurationId = "org.iso.18013.5.1.mDL"`**.

Confirmado empíricamente que esto no produce colisión: `profileId` se fija
en el servidor al crear la oferta (`POST /issuer2/credential-offers`), antes
de que la wallet vea nada. La wallet resuelve la oferta por `offerId`, que
ya está internamente amarrado al `profileId` correcto — nunca consulta
`credentialConfigurationId` para decidir qué perfil usar. Dos ofertas
creadas con perfiles distintos (`isoMdl_1cat` con 1 categoría real,
`isoMdl_2cat` con 2) redimieron exitosamente en la misma sesión de prueba,
ambas anunciando `org.iso.18013.5.1.mDL` en su `credential_offer`, sin
ambigüedad ni error.

Esto significa: el operador con 1 sola categoría real obtiene una
credencial con exactamente 1 entrada en `driving_privileges` — nunca
duplicada, nunca rellenada.

### Por qué 4 es el máximo elegido

Cubre holgadamente los casos reales de la mayoría de licencias sin generar
un número excesivo de perfiles HOCON casi idénticos. Un operador que
necesite más de 4 categorías reales en una sola credencial recibe un error
explícito en el formulario (comportamiento ya existente, solo el número
cambia de 2 a 4).

### Por qué 0 categorías es un error, no un caso soportado

`driving_privileges` es un elemento **obligatorio** de ISO 18013-5 Table 3
para el docType mDL. Aceptar 0 categorías violaría el propio estándar y
reintroduciría el problema que este cambio existe para eliminar: datos que
no representan la realidad del titular.

El formulario marca la primera fila con un asterisco (`templates/pages/
issuer_issue.html:155`), pero es **puramente visual** — verificado que el
`<input>` correspondiente (línea 156) no lleva el atributo HTML
`required`, así que un navegador no bloquea el envío con 0 filas
llenadas. Esto significa que el mensaje de error explícito propuesto más
abajo (en `internal/handlers/issuance.go`) es la **única** defensa real
contra 0 categorías, no una capa adicional sobre una validación de
cliente ya existente.

### Por qué no ampliar un solo `arrayConfig` a un techo mayor

Fue la primera hipótesis, descartada tras verificación empírica: ampliar
`arrayConfig` a un techo (probado con 3 y 6) solo mueve el número mágico de
padding — sigue exigiendo coincidencia exacta con ESE nuevo número, así que
el operador seguiría viendo relleno duplicado, ahora potencialmente hasta 5
filas idénticas en vez de 1. No resuelve el problema real.

### Por qué no usar el emisor nativo Go (`internal/mdl`)

Existe en el repo un firmador mdoc nativo sin esta limitación (construye el
CBOR directamente). Pero el equipo ya decidió explícitamente en
`docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md` que
`issuer-api2` de walt.id sigue siendo el emisor de mDL en producción, para
no romper el patrón arquitectónico "los DPGs emiten, verifiably-go media".
Reabrir esa decisión solo para este campo introduciría exactamente el
riesgo de mantenimiento paralelo que la decisión original buscaba evitar, y
no fue lo que el usuario pidió explorar en esta sesión.

## Alcance de los cambios

### `deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf`

- El bloque `isoMdl` actual se convierte en 4 bloques: `isoMdl_1cat`,
  `isoMdl_2cat`, `isoMdl_3cat`, `isoMdl_4cat`. Cada uno es una copia
  completa del `isoMdl` actual (mismo `credentialData`, mismo
  `idTokenClaimsMapping`), difiriendo únicamente en el número de bloques
  dentro de `driving_privileges.arrayConfig`.
- **Crítico para la seguridad de la firma — verificado, no opcional:**
  cada uno de los 4 bloques nuevos debe conservar
  `issuerKey = ${defaultIssuerKey}` y `x5Chain = ${defaultIssuerX5chain}`
  exactamente como **referencias por sustitución HOCON** (idénticas al
  `isoMdl` actual), nunca como el valor resuelto pegado literalmente en
  cada bloque. `defaultIssuerKey` (línea 36) y `defaultIssuerX5chain`
  (línea 94) son variables definidas UNA SOLA VEZ a nivel de archivo, y
  `scripts/gen-caddy.sh`'s `provision_issuer2_certificates` las
  reescribe con un regex de `count=1` — solo toca esa única definición
  top-level, nunca busca dentro de los bloques de perfil. Si el
  certificado/clave real se pegara como valor literal en 3 de los 4
  perfiles nuevos (en vez de la referencia `${...}`), esos 3 perfiles
  seguirían anunciando el certificado de ejemplo de walt.id (el propio
  "HARD GATE" de seguridad al inicio del archivo) mientras firman con la
  clave real — exactamente la discrepancia clave/certificado que ese
  HARD GATE existe para prevenir, y de forma silenciosa: la oferta
  seguiría devolviendo 201, la credencial se emitiría, y solo un
  conformant reader la rechazaría. Confirmado contra el archivo real que
  ambas variables son top-level y compartidas — clonar el bloque
  `isoMdl {...}` completo preservando sus dos líneas `${...}` intactas
  es automáticamente seguro; escribir el bloque a mano sin copiar esas
  dos líneas literalmente no lo es.
- Todos los 4 perfiles declaran
  `credentialConfigurationId = "org.iso.18013.5.1.mDL"` — idéntico al
  valor que el `isoMdl` original ya usaba, así que el catálogo/wellknown
  (`credential-issuer-metadata.baseline.conf`) **no necesita cambios**.
  Confirmado empíricamente con los 4 perfiles cargados simultáneamente en
  un `issuer-api2` real: el wellknown sigue publicando una sola entrada
  `org.iso.18013.5.1.mDL` (no 4 duplicadas), sin ninguna advertencia de
  conflicto en el boot.
- `isoPhotoId` no se toca — no tiene `driving_privileges`.

### `internal/adapters/waltid/issuer2.go`

- Nueva función `mdlProfileForCategoryCount(n int) (mdocProfile, bool)`
  que mapea 1→`isoMdl_1cat` ... 4→`isoMdl_4cat`, y devuelve `(mdocProfile{},
  false)` para `n <= 0` o `n > 4`.
- `docTypeProfiles`/`profileIDForDocType` se mantienen intactos para Photo
  ID y para cualquier caso que necesite resolver "¿existe un perfil para
  este docType en absoluto?" sin conocer el conteo — pero para mDL,
  `docTypeProfiles["org.iso.18013.5.1.mDL"]` deja de apuntar a un
  `profileID` fijo utilizable directamente; se mantiene solo como
  entrada de allowlist (¿este docType tiene *algún* perfil mdoc
  provisto?), y `buildIssuer2Offer` bifurca: para mDL, cuenta las
  entradas reales de `driving_privileges` dentro de `structured` y llama
  `mdlProfileForCategoryCount`; para cualquier otro docType (Photo ID),
  usa `profileIDForDocType` exactamente como hoy.
- `buildIssuer2Offer` decodifica `structured["driving_privileges"]` (ya es
  un `json.RawMessage` con un array JSON real, producido por
  `EncodeDrivingPrivileges`) para contar `len(...)` antes de elegir el
  perfil. Si la clave está ausente o el array es de longitud 0, es un
  error explícito (ver más abajo el mensaje exacto).
- La clave literal `"driving_privileges"` es segura de buscar así,
  hardcodeada, porque el nombre de este campo NO es editable por el
  operador: `internal/handlers/schema.go`'s manejador de guardado de
  schema (línea ~859-861) dice explícitamente *"the standard's mandatory
  elements are preloaded and locked: the docType defines them, so an
  operator cannot omit or rename one"* — la fusión de campos usa siempre
  `m.Name` (el nombre curado de `mdoc.MandatoryFields`), nunca el nombre
  que el operador haya escrito en esa fila del formulario. Confirmado
  contra el código real, no asumido — sin esa garantía, buscar la clave
  literal habría sido frágil ante un schema custom que renombrara el
  campo.
- **Otros dos consumidores de `profileIDForDocType`/`docTypeProfiles`,
  verificados seguros y sin cambios:**
  - `internal/adapters/waltid/catalog.go:321` (`buildMDocEntry`) solo lee
    `p.baseNamespace` del resultado — nunca `p.profileID` — así que
    mantener la entrada `docTypeProfiles["org.iso.18013.5.1.mDL"]` como
    allowlist (con `baseNamespace` intacto) es suficiente para este
    sitio, sin cambios.
  - `internal/adapters/waltid/catalog_issuer2.go:37`
    (`syncIssuer2DisplayName`) solo usa el booleano `ok` de retorno
    ("¿existe algún perfil mdoc para este docType?") para decidir si
    sincronizar el nombre de display — nunca lee `.profileID` — así que
    tampoco requiere cambios.

### `internal/mdoc/drivingprivileges.go`

- `DrivingPrivilegesArrayConfigSize` se renombra a
  `DrivingPrivilegesMaxCategories = 4` — pasa de ser "el tamaño exacto que
  hay que producir" a "el techo que no se puede exceder".
- `PadDrivingPrivileges` se elimina por completo — ya no hace falta
  ningún relleno.
- `EncodeDrivingPrivileges` deja de llamar al padding. Sigue truncando
  como backstop si `len(in) > DrivingPrivilegesMaxCategories` (mismo
  comportamiento defensivo que ya tenía, solo referenciando la constante
  renombrada). Para 1 a 4 entradas reales, el array de salida es
  exactamente ese tamaño — sin relleno.

### `internal/handlers/issuance.go`

- El mensaje de error de "demasiadas categorías" (línea ~617-621) sigue
  existiendo, ahora contra `mdoc.DrivingPrivilegesMaxCategories` (4 en vez
  de 2).
- Nuevo: si el operador no llenó ninguna fila (0 categorías reales
  después de `drivingPrivilegeRows`), un error explícito, en el mismo
  idioma/tono que el mensaje ya existente de "demasiadas categorías":
  *"driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos
  una categoría de conducción antes de emitir."*

### `templates/pages/issuer_issue.html`

- Quitar la nota agregada en la sesión anterior ("el perfil de walt.id
  requiere exactamente dos categorías... se duplicará") — ya no aplica
  bajo el nuevo diseño.
- El formulario ya renderiza `maxDrivingPrivilegeRows = 4` filas — coincide
  exactamente con el nuevo máximo; no hace falta tocar `issuance.go`'s
  `maxDrivingPrivilegeRows`.

### Tests a reescribir deliberadamente

- **`internal/adapters/waltid/profiletrim_test.go`**: `namespaceBlock`
  actualmente busca el *primer* `"org.iso.18013.5.1" = {` — con 4 bloques
  de perfil, el trim guard (`TestCredentialDataCarriesOnlyTheKeptFields`)
  debe verificar TODAS las ocurrencias de `"org.iso.18013.5.1" = {`
  dentro de `credentialData` (una por perfil), no solo la primera, porque
  cada perfil clonado repite el mismo riesgo de trim accidental de forma
  independiente. `expectedConversionMappings`'s conteo total de
  `conversionType` cambia de 14 (hoy: 10 de un único perfil mDL con
  `arrayConfig` de 2 + 4 de Photo ID) a **48**: cada uno de los 4 perfiles
  de mDL lleva 6 conversiones fijas (birth_date, issue_date, expiry_date,
  portrait, portrait_capture_date, signature_usual_mark) más `2 × N` de
  driving_privileges (N=1,2,3,4) — es decir 8, 10, 12, 14 conversiones por
  perfil respectivamente, suman 44 — más las 4 de Photo ID sin cambios =
  48 en total.
- **`internal/adapters/waltid/issuer2_test.go`**:
  - `TestBuildIssuer2OfferOmitsUnsetFields` llama
    `buildIssuer2Offer(schema, subject, nil)` — con `structured = nil`,
    el nuevo diseño lo trata como **0 categorías reales**, así que este
    test completo fallaría en su `t.Fatalf` de línea 132 bajo la nueva
    regla, no solo en su aserción de `req.ProfileID != "isoMdl"` como se
    pensó en una versión anterior de este spec. Reemplazar tal cual
    perdería la cobertura original (que `nationality`/`issuing_country`/
    `birth_date`, no enviados, nunca aparecen en el payload). **Dividir
    en dos tests:**
    1. El test original, renombrado si se quiere, pero ahora enviando
       también un `structured` mínimo con 1 categoría válida de
       `driving_privileges` (vía `mdoc.EncodeDrivingPrivileges`), para
       que siga ejerciendo la omisión de los demás campos sin chocar con
       la nueva regla. Su aserción de `ProfileID` cambia a
       `"isoMdl_1cat"`.
    2. Un test nuevo, `TestBuildIssuer2OfferRejectsZeroDrivingPrivileges`
       (o nombre equivalente), que llama `buildIssuer2Offer` con
       `structured = nil` (o con `driving_privileges` vacío) y confirma
       que devuelve un error no-nil con el mensaje esperado — la
       cobertura que el caso de 0 categorías necesita, ahora explícita
       en vez de accidental.
  - `TestIssuer2OfferCarriesDrivingPrivilegesAsJSONArray` fija
    `len(arr) != mdoc.DrivingPrivilegesArrayConfigSize` (2) — se cambia a
    comparar contra el número real de entradas que el test mismo envía (2
    en ese test, pero ahora por ser lo que se pidió, no por padding), y su
    aserción de `ProfileID` (si la tuviera tras el cambio) debe esperar
    `"isoMdl_2cat"`.
  - `TestProfileIDForDocType`/`TestKnownDocTypesResolveInProfiles`/
    `TestBuilderSavedMdocSchemaResolvesProfile`: se revisan contra el
    nuevo comportamiento de `docTypeProfiles` para mDL (allowlist, no
    profileID directo).
- **`internal/handlers/issue_structured_fields_test.go`** (archivo
  completo, omitido en una versión anterior de este spec — tiene 4
  sitios que referencian `mdoc.DrivingPrivilegesArrayConfigSize`):
  - `TestSubmitIssueSendsDrivingPrivilegesAsRealJSONArray` (línea 88):
    envía 2 filas reales y afirma `len(arr) != ...ArrayConfigSize` (2) —
    se actualiza a `DrivingPrivilegesMaxCategories` solo como referencia
    de constante; la aserción de longitud sigue siendo 2 porque el test
    sigue enviando 2 filas reales (ahora por ser lo pedido, no por
    padding).
  - `TestSubmitIssueSingleDrivingPrivilegeIsPadded` (línea 146): **este
    test prueba directamente el comportamiento que se elimina** — su
    propio nombre lo dice. Se renombra (p. ej.
    `TestSubmitIssueSingleDrivingPrivilegeIsNotPadded`) y su aserción
    central (línea 159: `len(arr) != mdoc.DrivingPrivilegesArrayConfigSize`,
    esperando 2) se invierte a `len(arr) != 1` — una fila real llenada
    debe producir exactamente 1 entrada, nunca 2.
  - `TestDrivingPrivilegesOverCapWarnsOperator` (línea 419) manda 3
    categorías contra un cap de 2 y afirma truncamiento a 2 — se
    actualiza a mandar 5 categorías contra el nuevo cap de 4
    (`DrivingPrivilegesMaxCategories`), conservando la misma lógica de
    "el backstop trunca, pero `SubmitIssue` ya rechaza antes de llegar
    aquí en el flujo real".
- **`internal/mdoc/drivingprivileges_test.go`**:
  - `TestEncodeDrivingPrivilegesPadsToArrayConfigSize` se elimina —ya no
    hay padding que probar — y se reemplaza por un test que confirma
    explícitamente que 1, 2, 3 y 4 categorías reales producen exactamente
    esa cantidad de salida, nunca más.
  - `TestEncodeDrivingPrivilegesTruncatesOverlongInput` se mantiene,
    actualizando la constante referenciada y, si se quiere ejercitar el
    nuevo techo real, el número de entradas de entrada
    (`DrivingPrivilegesMaxCategories+3` en vez de un literal viejo).
- **`internal/adapters/waltid/profiledates_test.go`**
  (`TestEveryProfileDateFieldIsReachableFromTheForm`) — **verificado
  seguro, sin cambios necesarios.** Su regex dedupea por nombre de campo
  vía un mapa `seen` (línea 51-54), así que 4 bloques de perfil
  repitiendo los mismos nombres de campo (`birth_date`, `issue_date`,
  etc.) no rompen el conteo — cada nombre se verifica una sola vez sin
  importar cuántas veces aparezca en el archivo. Confirmado leyendo el
  cuerpo del test, no asumido.

## Verificación planeada

- Suite Go completa (`go test ./internal/...`) verde tras los cambios.
- Mutation testing: revertir cada fix puntual y confirmar que el test
  correspondiente falla por la razón exacta esperada (mismo estándar
  aplicado durante todo el resto de esta sesión).
- Verificación end-to-end real contra el VPS: emitir credenciales reales
  con 1, 2, 3 y 4 categorías, decodificar el CBOR resultante con la misma
  metodología usada en esta sesión (parseIssuerSigned + inspección directa
  de `driving_privileges`), confirmando en cada caso que el array tiene
  exactamente el número de entradas reales, sin ninguna duplicada.
- Confirmar que Photo ID sigue emitiendo sin cambios (no debe verse
  afectado por esta modificación en absoluto).
- **Verificación de seguridad específica**: tras clonar los 4 bloques,
  `grep -c 'x5Chain = \${defaultIssuerX5chain}'` y
  `grep -c 'issuerKey = \${defaultIssuerKey}'` contra el
  `issuer2-profiles.baseline.conf` resultante deben devolver 4 cada uno
  (uno por perfil de mDL) — no un valor literal de certificado/clave
  incrustado en ninguno de los 4 bloques. Ejecutar
  `provision_issuer2_certificates` contra el archivo nuevo en un
  contenedor de prueba (mismo patrón usado en esta sesión) y confirmar
  con `GET /issuer2/profiles` que los 4 perfiles reportan el MISMO
  `x5Chain` resuelto — no solo que booteen sin error.

## Ver también

- `internal/mdoc/drivingprivileges.go` — código actual con `PadDrivingPrivileges`.
- `TODO.md`'s sección F4 — el bug histórico que introdujo el padding como
  solución interina, ahora reemplazado por este diseño.
- `docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md` — la
  decisión de mantener `issuer-api2` como emisor de mDL, que este diseño
  respeta explícitamente en vez de reabrir.
