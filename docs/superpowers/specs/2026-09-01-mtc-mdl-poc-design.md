# PoC mDL (ISO/IEC 18013-5) sobre el despliegue Inji del MTC — diseño

**Status:** Revisado por un segundo modelo (2026-09-01) — 5 hallazgos bloqueantes, 8
importantes y 4 menores corregidos tras verificación directa contra el código real de este
repo (no solo contra el spec previo). Aprobado para plan, con la Fase 1 recortada como
único trabajo ejecutable (ver §Alcance del plan de implementación).
**Scope:** este documento de diseño vive en `verifiably-go` porque su fuente de verdad es
el código ya implementado en este repo (`internal/adapters/injicertify/db.go`,
`issuer.go`), no solo el spec `2026-08-25-inji-mdoc-issuer-design.md` que lo precedió. El
**entregable final** (documento guía + entorno de pruebas reproducible) es para el equipo
del MTC/IUGO, sobre **su propio despliegue** de Inji Certify/Mimoto/Inji Verify/InjiWallet
— no se despliega código de este repo contra la infraestructura del MTC; sí se escriben
archivos de documentación dentro de este repo (ruta exacta a fijar por el plan, p. ej.
`docs/mtc-mdl-poc/`).

---

## Contexto

El MTC (Ministerio de Transportes y Comunicaciones de Perú) opera hoy una plataforma Inji
en producción (AWS, cuenta `098355702629`, cluster EKS `mtc-prod-cluster`, `sa-east-1`) que
emite la Licencia de Conducir como credencial **SD-JWT** (`vc+sd-jwt`), en 3 clases (A/B/E).
Arquitectura confirmada contra 3 documentos aportados por el usuario
(`C:\tmp\iugo-mtc\`: `resumen-tecnico-Inji-MTC.pdf`, `MTC-KT.pptx.pdf`,
`Arquitectura-AWS-INJI-MTC-revision-as-built.pdf`):

- **Inji Certify** — emisor OpenID4VCI. Plugin de datos propio `MtcFeeDataProviderPlugin`
  (repo `inji-dataprovider`, `certify-driver-license.properties`) que autentica y consulta
  el Servicio Web FEE del MTC (`ExternalToken` → `ObtenerInformacionLicenciaPersona`),
  transforma a `credentialSubject`, Certify aplica template Velocity y firma.
- **Mimoto** — BFF/proxy de la wallet, comparte infraestructura con RENIEC. Publica el
  issuer MTC (`mimoto-issuers-config.json`) y hace proxy de token hacia **IdPeru** (CIBA)
  vía `idaas2.reniec.gob.pe`. **En despliegue activo ahora mismo** — es la arquitectura
  final objetivo del MTC, no un componente descartado (el as-built lo marcó "no
  desplegado" en un corte anterior al 10/08/2026; el usuario confirma que se está
  completando).
- **InjiVerify** — verificador OpenID4VP, `config.json` con Presentation Definition sobre
  `$.vct` para las 3 clases SD-JWT.
- **InjiWallet** — la wallet móvil, **fork propio del MTC/IUGO, modificable** (confirmado
  con el usuario). No se tiene acceso al código de ese fork en este momento.
- **Firma:** certificado CSR propio MTC/RENIEC (o default de Inji) sobre **AWS CloudHSM**
  real (`cluster-eyhqyfwhvfs`, `hsm2m.medium`, non-FIPS, región `sa-east-1`) —
  `AWSCloudHSMKeyStoreImpl`. Estos valores son los leídos del as-built (Terraform + consola
  AWS al 10/08/2026), no re-verificados por esta investigación — la disponibilidad regional
  del tipo de HSM y el modo FIPS/non-FIPS son configuración que puede cambiar.

**Objetivo de esta PoC:** producir una guía de implementación + un entorno de pruebas
reproducible para que Inji Certify del MTC pueda emitir la Licencia de Conducir también
como **mDL conformante ISO/IEC 18013-5** (`mso_mdoc`), además del SD-JWT existente —
redundancia/alternativa, sin reemplazar el flujo SD-JWT actual.

## Punto de partida: qué ya sabemos de este repo

`verifiably-go` (rama `feat/mdl`) ya **implementó** (no solo diseñó) la emisión de
`mso_mdoc` real vía Inji Certify, validado contra una instancia de prueba **v0.14.0**
(`injistack/inji-certify-with-plugins:0.14.0`). La fuente de verdad es el código, no el
spec que lo precedió: `internal/adapters/injicertify/db.go` (`saveMdocSchema`,
`mdocCredentialConfigValues`, `mdocVCTemplate`, `mdocNamespaceForDocType`) e `issuer.go`
(el manejo de `StructuredData["driving_privileges"]`), con sus comentarios empíricos
inline — ver también `docs/superpowers/specs/2026-08-25-inji-mdoc-issuer-design.md` para
el razonamiento de diseño original y los commits hasta `39a9e56`. Hallazgos que esta PoC
reutiliza directamente, citados contra el código real:

1. **Inji Certify emite mdoc genuino** (CBOR con `IssuerSignedItem` Tag 24, salts de 24
   bytes, digests MSO correctos, firma COSE_Sign1 ECDSA P-256/SHA-256 válida) desde el
   camino de producción (DataProvider), no un mock — contradiciendo documentación
   desactualizada del propio repo `inji-certify`.
2. **Inji no tiene el problema de arrays de tamaño fijo que walt.id sí tiene** — un único
   perfil, sin modificar, emite `driving_privileges` como array CBOR de longitud variable
   real (1-4 categorías). No hace falta el patrón "N perfiles por conteo" de walt.id.
3. **El template Velocity de Inji Certify exige tres condiciones simultáneas, no un simple
   "nesting"** (`db.go:mdocVCTemplate`, comentario inline extenso, cada punto confirmado
   por una prueba empírica separada):
   - Cada marcador de campo usa **notación bracket de Velocity**
     (`${rootContext['<namespace>'].<campo>}`), nunca `${campo}` bare — un marcador bare
     contra un mapa de claims anidado bajo el namespace falla en silencio (el CBOR decodifica
     literalmente `"${family_name}"`) y produce `ERROR_SIGNING_QR_DATA`.
   - El marcador de `driving_privileges` va **sin comillas** en el template (a diferencia
     de todo campo escalar, que sí lleva comillas) — con comillas, Velocity sustituye vía
     `toString()` de Java y produce texto no-JSON (`[{issue_date=..., ...}]`).
   - El valor posteado para `driving_privileges` debe ser **un string JSON ya
     pre-serializado** (`json.Marshal` sobre el array, no el array decodificado) — postear
     el array real hace que `CredentialUtils.toJsonMap` lo envuelva como `JSONArray`, cuyo
     `toString()` Java, sustituido por el marcador sin comillas, produce sintaxis
     `clave=valor` inválida para JSON.
   Solo las tres condiciones juntas producen un CBOR con `driving_privileges` como array
   real de mapas, con `issue_date`/`expiry_date` correctamente etiquetados full-date — cada
   una confirmada decodificando una credencial real emitida.
4. **Defecto conocido, no arreglable desde config ni desde el template:** desensamblado
   directo del bytecode de Inji Certify (`javap -p -c` contra
   `io.mosip.certify.utils.MDocProcessor.class` de la imagen v0.14.0 en ejecución,
   documentado en el commit `d222c33`) confirma que `preprocessForCBOR` tiene exactamente
   cuatro ramas de tipo (`byte[]`, `String` — solo revisada para el caso fecha/tag 1004 —,
   `Map`, `List`), **sin ninguna rama de detección base64/imagen**, y
   `convertToDataItem` envuelve incondicionalmente todo `String` en `UnicodeString`. Esto
   no es "no se probó arreglarlo" — es una conclusión cerrada por lectura de bytecode:
   **ningún cambio de template, nombre de campo o configuración Velocity puede alterar
   este comportamiento**, porque el punto de decisión está en el bytecode Java del propio
   Inji Certify, corriente arriba de cualquier template. El campo `portrait` queda como
   string de texto (medido en el spike original: 300KB+ en base64) donde ISO 18013-5
   exige un byte string CBOR.
5. **El bloqueante real de interoperabilidad:** `MDocCredential.addProof` en **Inji Certify
   (el emisor)** envuelve el mapa `IssuerSigned` ya firmado dentro de
   `{"docType": "...", "issuerSigned": <mapa>}` — la forma de un `Document` de
   *DeviceResponse*, no de una credencial standalone. La librería que consuma el CBOR
   (`@animo-id/mdoc` en el caso de `cdpi-wallet`) espera el mapa `IssuerSigned` directo.
   **Este repo resolvió esto con un workaround dentro de `cdpi-wallet`** (detectar la
   forma, extraer `issuerSigned`, verificar integridad post-extracción, verificar cadena
   de confianza) — código TypeScript/Credo, stack completamente distinta de InjiWallet
   (nativa MOSIP, Flutter/Kotlin). El wrapper lo produce el **emisor**; cualquier hipótesis
   sobre si sigue siendo un problema debe mirar el versionado de **Inji Certify**, no el de
   la wallet — ver la corrección de atribución más abajo.
6. **Provisión del perfil mdoc en Inji Certify** requiere código real, no solo un INSERT:
   `doctype`, claims declarados con el namespace correcto, `stdToCredentialFormat` con
   caso para `mso_mdoc`, y una configuración de firma ECDSA P-256 completa — concretamente,
   confirmado en `mdocCredentialConfigValues`, las columnas `signature_algo` /
   `key_manager_app_id` / `key_manager_ref_id` / `signature_crypto_suite` deben llevar
   exactamente `CERTIFY_VC_SIGN_EC_R1` / `EC_SECP256R1_SIGN` / `EcdsaSecp256r1Signature2019`
   (Inji trae por defecto configuración Ed25519 para sus otros formatos — el mdoc necesita
   su propia entrada de algoritmo/key manager, no una variación de la existente). **Esta
   configuración por sí sola no basta** — ver el hallazgo de provisión de key policy en
   §Fase 1, paso 1.

**Corrección de atribución (hallazgo de la revisión, no del análisis original):** una
lectura inicial de la documentación oficial de Inji
([docs.inji.io](https://docs.inji.io/inji-wallet/inji-mobile/overview), changelog v0.15.0,
entrada `INJIMOB-2778`) razonó que si el fork InjiWallet del MTC estuviera en v0.15.0+, el
problema del wrapper (hallazgo 5) "podría ya no aplicar". **Ese razonamiento confunde
emisor y consumidor.** El wrapper lo produce **Inji Certify** en `MDocCredential.addProof`
— un componente servidor con su propio versionado, independiente del changelog de
**InjiWallet** (la app móvil cliente). Que InjiWallet v0.15.0 anuncie soporte mDoc no dice
nada sobre qué forma de CBOR emite la versión de Inji Certify del MTC. La hipótesis
defendible y más estrecha es distinta: *InjiWallet podría tolerar el wrapper que Inji
Certify produce, si ambos productos MOSIP se probaron juntos internamente* — plausible,
pero no es lo mismo que "el wrapper ya no existe". Esto **no está verificado
empíricamente** en ningún sentido — ni la versión de Inji Certify del MTC, ni si InjiWallet
tolera o corrige el wrapper. Se trata con el mismo escepticismo que este repo ya aplicó una
vez en sentido contrario (`AGENTS.md` de `inji-certify` decía "mock only" para mdoc y
resultó falso — si emitía mdoc real): ninguna afirmación de documentación de Inji se da por
buena sin verificarla contra código o comportamiento real.

## Restricción operativa: sin acceso al fork de InjiWallet todavía

El usuario no tiene a mano el código del fork InjiWallet del MTC en este momento. Esto
determina el orden de trabajo: la PoC se estructura en fases donde la **Fase 1 (emisión) es
ejecutable y verificable hoy sin ninguna wallet**, y las fases que dependen de InjiWallet
quedan documentadas como procedimiento a ejecutar cuando el código esté disponible, no como
pasos ya resueltos.

## Fase 1 — Emisión: Inji Certify MTC emite `mso_mdoc` (ejecutable ahora)

Réplica adaptada del trabajo ya implementado en este repo (`internal/adapters/injicertify`,
citado en detalle en §Punto de partida), con dos diferencias de fondo respecto al código
original: (a) el MTC no usa `verifiably-go` ni su UI de schema-builder — la provisión del
`credential_config` se hace por el mismo mecanismo SQL/config que ya usan hoy para SD-JWT
(`mtc_insert.sql` alineado con `certify_init.sql`, aplicado manualmente), traduciendo a SQL
directo lo que `saveMdocSchema` hace vía Go; (b) la firma corre sobre **CloudHSM real**, no
el mock-HSM que usó el spike original.

1. **Seeding de la key policy EC, antes que nada — sin esto nada firma.** Confirmado en
   este repo que la fila de política de firma es una precondición separada de la fila de
   `credential_config`, no parte de ella: `certify.key_policy_def` necesita una entrada
   `CERTIFY_VC_SIGN_EC_R1` (ver `deploy/compose/stack/inji/certify/init.sql`,
   `init-preauth.sql`, `init-authcode.sql` de este repo para la forma exacta del INSERT), y
   `certify-default.properties` (o el equivalente de propiedades del MTC) necesita el
   mapeo `'ES256': {{'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN'}}`. El despliegue SD-JWT
   del MTC corre hoy sobre Ed25519 (`CERTIFY_VC_SIGN_ED25519`) — **no hay garantía de que
   su `key_policy_def` ya tenga la entrada EC_R1 ni que sus properties tengan el mapeo
   ES256**; confirmar esto en la base del MTC es el primer paso, no una suposición.
2. **`credential_config` nuevo por clase de licencia** (A/B/E, mismo patrón 1-fila-por-clase
   que ya existe para SD-JWT) con `credential_format = mso_mdoc`,
   `doctype = org.iso.18013.5.1.mDL`, claims declarados bajo el namespace ISO real, y las
   columnas de firma del paso 1 (`CERTIFY_VC_SIGN_EC_R1` / `EC_SECP256R1_SIGN` /
   `EcdsaSecp256r1Signature2019`) — ver hallazgo 6.
   - **Decisión de modelado a confirmar, no asumida:** en mDL, todas las categorías de
     conducción de una persona viven en un único `driving_privileges` dentro de **una sola**
     credencial — a diferencia de SD-JWT, donde el MTC emite 3 credenciales separadas (A/B/E)
     porque cada una es un `credential_config`/`scope` distinto. Replicar el patrón
     "1 fila por clase" tal cual para mdoc puede no tener sentido según cómo el MTC quiera
     modelar la emisión (¿una credencial mdoc por clase, con `driving_privileges` de una
     sola categoría cada una? ¿una sola credencial con las clases que la persona realmente
     tiene?) — esto se decide explícitamente en el plan de implementación, no se hereda del
     patrón SD-JWT sin cuestionarlo.
3. **El template Velocity del `credential_config` debe cumplir las tres condiciones del
   hallazgo 3** (marcadores bracket-notation, `driving_privileges` sin comillas en el
   template, valor posteado como string JSON pre-serializado) — este es el trabajo real
   detrás de "nestear bajo el namespace ISO", no una propiedad simple del plugin de datos.
4. **Extender `certify-driver-license.properties` / `MtcFeeDataProviderPlugin`** para que,
   cuando el `credential_config` activo sea mdoc, el valor que postea a Certify para
   `driving_privileges` sea el string JSON pre-serializado que el paso 3 exige — no el
   `credentialSubject` plano que arma hoy para SD-JWT.
   - **Riesgo de datos no verificado:** este paso asume que el Servicio Web FEE devuelve
     las categorías de conducción con la forma que ISO/IEC 18013-5 Tabla 3 exige — un array
     de objetos con `vehicle_category_code`, `issue_date`, `expiry_date` **por categoría**.
     Esto nunca se confirmó contra una respuesta real del FEE; un `credentialSubject`
     SD-JWT no impone esa estructura (podría ser, por ejemplo, un string plano tipo
     `"A-IIb"` sin fechas por categoría). Confirmar la forma real de la respuesta del FEE es
     un paso explícito antes de escribir el mapeo, no un supuesto del plan.
5. **Confirmar soporte de ECDSA P-256 en el Key Manager sobre CloudHSM real** — el spike
   original no probó HSM real, solo mock-HSM. `hsm2m.medium` non-FIPS soporta P-256 sin
   problema a nivel de hardware; el riesgo real está en la **ruta de integración**, no en la
   curva:
   - **Certificado de firma — riesgo de calendario, no solo técnico.** El as-built dice que
     el certificado puede ser "el default de Inji o uno emitido y firmado por MTC/RENIEC".
     Un mDL firmado con el certificado default de Inji **no es una credencial desplegable**
     (ninguna wallet/verificador de terceros confiará en ese emisor); obtener un
     certificado nuevo de la CA MTC/RENIEC vía el flujo `generate-csr` /
     `upload-ca-certificate` / `uploadCertificate` (§04 del resumen técnico) para una clave
     EC nueva es un proceso organizacional con plazos propios del MTC/RENIEC, no una tarea
     técnica que este plan controle. Debe señalarse como dependencia externa explícita, con
     tiempo de espera fuera del control del equipo técnico.
   - **IACA y trust anchors — pregunta no formulada hasta ahora.** El chequeo de "CBOR/COSE
     válido contra el certificado real" (paso 7) es una verificación de **integridad**, no
     de **confianza del emisor** — distinción que el spec `2026-08-25-inji-mdoc-issuer-design.md`
     ya estableció como crítica y que aplica igual aquí: cualquiera podría generar un CBOR
     autofirmado y pasar ese chequeo. Con CloudHSM y una PKI de producción real en juego,
     la pregunta real es **¿cuál es la IACA raíz del MTC, quién la emite, y contra qué
     ancla de confianza validará un verificador de terceros el DSC?** — no tiene respuesta
     en los documentos disponibles; es una brecha a cerrar antes de considerar la Fase 1
     lista para un ambiente real (no bloquea el entorno de pruebas local, que usa un
     certificado de prueba propio).
6. **Portrait:** declarar la limitación conocida (hallazgo 4, cerrado por desensamblado de
   bytecode — no es una hipótesis abierta) explícitamente en el documento guía. No se
   re-verifica como si fuera incierto: la evidencia ya dice que ningún cambio de este lado
   lo arregla. Lo único a confirmar empíricamente en el ambiente real del MTC es que la
   versión de Inji Certify que corre ahí exhibe el mismo bytecode — no si el bug "sigue
   ahí" en abstracto.
7. **Verificación de la Fase 1 sin ninguna wallet — criterio de cierre concreto:** el
   verificador standalone de este repo (`internal/mdl`/`verify.mjs`) **no es reusable tal
   cual** — está cableado a vectores de prueba fijos (rutas de archivo, certificados,
   `EXPECTED_ELEMENTS = 13`, una fecha de expiración hardcodeada deliberadamente para que el
   check no se autosatisfaga con lo que el mdoc declare). Convertirlo en un verificador que
   acepte un mdoc y un certificado arbitrarios por argumento es trabajo de implementación
   explícito de esta fase, no un reuso directo — una tarea del plan por sí sola. El criterio
   de cierre de la Fase 1 es: este verificador generalizado confirma CBOR/COSE/MSO válidos
   contra el certificado real de prueba del MTC, para al menos un mDL con `driving_privileges`
   de 1 y de 4 categorías.

**Salida de la Fase 1:** un mDL emitido por Inji Certify MTC, CBOR/COSE/MSO
criptográficamente válido, verificado independientemente por una herramienta que acepta
credenciales y certificados arbitrarios (no solo los vectores fijos de este repo). No
implica todavía que una wallet lo pueda consumir, ni que un verificador de terceros confíe
en la cadena de certificación — eso es la Fase 2 y la brecha de IACA del paso 5.

## Fase 2 — Consumo en wallet (bloqueada; procedimiento documentado, no ejecutado)

Cuando el código del fork InjiWallet esté disponible:

1. **Confirmar la versión real** del fork vs. v0.15.0 (donde Inji declara soporte nativo).
2. **Probar consumo directo primero, sin escribir código**: emitir un mDL de prueba (Fase 1
   ya funcionando) y ver si el InjiWallet del MTC lo importa y lo verifica tal cual.
3. **Si falla:** inspeccionar si el fork exhibe el mismo síntoma que este repo encontró en
   Inji Certify v0.14.0 (wrapper `{docType, issuerSigned}`) — el diagnóstico correcto exige
   verificar la versión/comportamiento real de **Inji Certify** (el emisor, quien produce el
   wrapper), no la de InjiWallet (ver la corrección de atribución en §Punto de partida: son
   productos MOSIP independientes con versionado propio). No asumir que el bug persiste, ni
   que desapareció, sin verificarlo contra la instancia real.
4. **Solo si el bug persiste y no se resuelve solo:** decidir entre dos approaches
   (documentados aquí como opciones, no como decisión tomada — se decide con el código real
   en mano):
   - **B — portar el patrón de `cdpi-wallet`** (detectar wrapper, extraer, verificar
     integridad post-extracción, verificar confianza contra un endpoint de trust anchors)
     a la stack real de InjiWallet. Requiere encontrar el punto de inserción equivalente en
     esa stack — no se asume que es el mismo tipo de archivo/capa que en `cdpi-wallet`
     (Credo/TS); InjiWallet es Flutter/Kotlin nativo de MOSIP.
   - **C — parchear Inji Certify (el fork del emisor)** para que `MDocCredential.addProof`
     no envuelva el CBOR, eliminando el problema en el origen en vez de compensarlo en cada
     wallet consumidora. Más limpio a largo plazo, pero es tocar código Java de MOSIP en el
     emisor — riesgo de deuda de mantenimiento en cada upgrade de Inji Certify upstream.

**No se elige B o C en este spec** — es la primera decisión real de la Fase 2, tomada con
el fork en mano.

## Fase 3 — InjiVerify para mdoc (a investigar)

InjiVerify hoy arma `config.json` con Presentation Definition sobre `$.vct` para SD-JWT.
El protocolo de presentación de mdoc dentro de OpenID4VP usa una forma distinta —
aproximadamente, `constraints.fields` sobre paths como
`$['org.iso.18013.5.1']['family_name']` con `limit_disclosure: required` bajo Presentation
Exchange clásico, o (con DCQL, el mecanismo de OID4VP 1.0 más reciente) un `credential` con
`format: "mso_mdoc"` y `meta.doctype_value` + `claims` con `namespace`/`claim_name`. Cuál de
los dos aplica depende de qué versión de InjiVerify corre el MTC — exactamente lo que esta
fase debe investigar; no se asume una forma concreta de antemano. Esta fase requiere:

1. Confirmar si la versión de InjiVerify que usa el MTC ya soporta ese formato de
   Presentation Definition para mdoc (mismo patrón de "verificar antes de asumir" que las
   fases anteriores — no se encontró evidencia de esto en la investigación de este spec).
2. Si sí: documentar la configuración equivalente a `config.json` pero para mdoc.
3. Si no: queda fuera de alcance de esta PoC, documentado como brecha conocida.

## Entorno de pruebas reproducible

**Corrección de ruta:** no existe un compose aislado de Inji Certify Pre-Auth en este repo
— es un subconjunto de servicios (`inji-certify-preauth`, `inji-certify-preauth-backend`,
`certify-preauth-postgres`, `certify-preauth-nginx`) definido dentro del `docker-compose.yml`
monolítico de `deploy/compose/stack/` (~1300 líneas, entrelazado con Caddy, volúmenes
compartidos, y provisión de certificados). El directorio real es
`deploy/compose/stack/inji/certify/` (config Certify) +
`deploy/compose/stack/inji/certify-preauth-nginx/` (proxy), no un `certify-preauth/`
autocontenido. **Extraer un compose aislado y reusable a partir de ese monolito es una
tarea de ingeniería en sí misma** — una tarea explícita del plan de implementación, no una
copia directa de un directorio existente.

El entorno resultante, una vez extraído, debe incluir:

- Inji Certify en la versión real confirmada del MTC (o v0.14.0 si no se puede confirmar
  aún — ver §Riesgos).
- El seeding de `key_policy_def` (paso 1 de la Fase 1) y el `credential_config` mdoc (paso
  2) pre-provisionados.
- Un **mock** del `MtcFeeDataProviderPlugin` que devuelve datos de licencia sintéticos, sin
  pegarle al Servicio Web FEE real del MTC (evita depender de credenciales/red de
  producción para iterar).
- Mock-HSM para iteración rápida.

**Alcance real de este entorno — no toda la Fase 1:** con el plugin de datos mockeado y
mock-HSM, este entorno cubre los pasos 1-4 y el criterio de verificación del paso 7 de la
Fase 1 (provisión, template, verificador standalone) — **no** cubre el paso 5 (ECDSA P-256
sobre CloudHSM real, certificado real de la CA MTC/RENIEC) ni la brecha de IACA/trust
anchors, que por definición requieren infraestructura real del MTC y quedan fuera de este
entorno local. El documento guía debe ser explícito sobre esta frontera, no presentar el
entorno como cobertura completa de la fase.

## Documento guía

Markdown, estructura:

1. **Riesgos y supuestos a verificar** (al frente, no al final): versión real de Inji
   Certify del MTC, soporte de ECDSA P-256 en CloudHSM real, estado real de portrait,
   versión y capacidades reales del fork InjiWallet, soporte de mdoc en InjiVerify.
2. Fase 1 completa (pasos, código de referencia, criterios de verificación).
3. Fase 2 como procedimiento a ejecutar (no resultado), con las opciones B/C documentadas
   sin decidir.
4. Fase 3 como investigación pendiente.
5. Entorno de pruebas reproducible (instrucciones de uso del compose).

## Riesgos y limitaciones conocidas

- **Versión de Inji Certify del MTC no confirmada.** Se asume v0.14.0 (misma que el spike
  de este repo) por decisión explícita del usuario, no por verificación — si difiere, los
  hallazgos 1-6 deben re-validarse antes de confiar en ellos.
- **CloudHSM real no probado con ECDSA P-256 en este repo** — es una verificación nueva,
  no una repetición de algo ya confirmado. Ver además el riesgo de calendario del
  certificado de firma (Fase 1, paso 5) — depende de un proceso organizacional MTC/RENIEC
  fuera del control técnico de esta PoC.
- **IACA y trust anchors del MTC no identificados en ningún documento disponible.** La
  verificación de integridad (Fase 1, paso 7) no equivale a verificación de confianza del
  emisor — falta identificar cuál es la IACA raíz real del MTC y contra qué ancla validará
  un verificador de terceros el DSC, antes de considerar un mDL del MTC desplegable fuera
  del entorno de pruebas local.
- **Portrait está roto y no es arreglable desde este proyecto** (cerrado por desensamblado
  de bytecode, hallazgo 4) — se documenta como limitación permanente del lado emisor, no
  se re-abre como pregunta ni se intenta resolver como parte de esta PoC. Lo único
  pendiente de confirmar es que la instancia real del MTC corre el mismo bytecode
  problemático — no si el defecto conceptualmente persiste.
- **Fase 2 y Fase 3 son procedimientos, no resultados** — este spec no puede completarlas
  sin acceso al fork InjiWallet y sin confirmar capacidades reales de InjiVerify. Quedan
  explícitamente abiertas; no generan tareas de plan ejecutables hoy (ver §Alcance del plan
  de implementación).
- **Estado de despliegue de Mimoto.** El as-built (corte previo al 10/08/2026) lo marcó "no
  desplegado"; el usuario confirma que está en despliegue activo como arquitectura final.
  Si Mimoto no estuviera disponible al momento de ejecutar la Fase 2, no hay camino de
  token para que una wallet obtenga el mDL — bloquea la Fase 2 por una razón distinta a la
  falta de acceso al fork de InjiWallet, y debe confirmarse por separado.
- **`use_idperu`/CIBA (autenticación) no cambia con esta PoC** — mdoc solo afecta el
  `credential_config`/formato de salida; el flujo de obtención de token (Mimoto → IdPeru)
  es idéntico al que ya usa SD-JWT hoy.

## Criterios de aceptación por fase

- **Fase 1:** el verificador standalone generalizado (paso 7) confirma CBOR/COSE/MSO
  válidos, con `driving_privileges` como array real de mapas con fechas full-date
  correctamente tageadas, para al menos dos credenciales de prueba (1 categoría y 4
  categorías), contra el certificado de prueba del entorno reproducible. Portrait puede
  fallar su propia verificación de forma (bug conocido, no bloqueante para este criterio).
- **Fase 2:** no tiene criterio de aceptación en este spec — es un procedimiento a ejecutar
  cuando el fork esté disponible; su resultado (InjiWallet consume sin cambios / requiere
  approach B / requiere approach C) se define ahí, no aquí.
- **Fase 3:** su criterio de "hecho" es la respuesta a la pregunta de investigación
  (soporta / no soporta la versión real de InjiVerify del MTC), documentada con evidencia
  — no una implementación completa si la respuesta es "no soporta" (ese caso queda fuera de
  alcance, documentado como brecha).

## Alcance del plan de implementación

El plan de implementación que sigue a este spec debe cubrir **la Fase 1 completa y la
redacción del documento guía** (incluyendo sus secciones sobre Fase 2 y Fase 3 como
contenido a escribir, con las opciones documentadas sin decidir). Fase 2 y Fase 3 **no
generan tareas de plan ejecutables** — no hay código que planificar contra un fork que no
está disponible, ni contra una versión de InjiVerify sin confirmar. Un plan que incluyera
tareas de implementación para la Fase 2 o 3 tendría pasos que nadie puede completar hoy;
el trabajo correcto ahí es redactar el procedimiento como parte del documento guía, no
ejecutarlo.

## Fuera de alcance de este spec

- Modificar el flujo SD-JWT existente del MTC — mdoc es puramente aditivo.
- Tocar infraestructura real del MTC (AWS, CloudHSM, EKS) — el entorno reproducible es
  local/aislado.
- Decidir entre approach B y C de la Fase 2 — decisión futura, con el fork en mano.
- Confirmar o arreglar el bug de portrait — se documenta, no se resuelve.
- Cualquier trabajo sobre InjiVerify más allá de la investigación de la Fase 3.
