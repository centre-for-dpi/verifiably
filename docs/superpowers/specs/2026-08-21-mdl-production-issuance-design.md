# Emisión de mDL en producción vía `issuer-api2`, con docTypes conocidos y etiquetas multi-idioma

**Fecha:** 2026-08-21
**Estado:** Diseño aprobado en conversación, pendiente de revisión antes de escribir el plan de implementación.

**Dependencia de rama:** este diseño referencia `internal/mdl/doctype.go`
(modelado de los 11 elementos de la Tabla 3) y
`internal/mdl/testdata/verify/verify.mjs` (verificador Node.js
independiente), que hoy viven en `feat/mdl-issuer` — rama sin fusionar,
PR #13 abierto. El plan de implementación debe resolver ese orden: o el PR
#13 entra primero, o este trabajo parte de esa rama.

## Contexto y problema

`verifiably-go` no puede emitir un mDL conforme hoy. El adaptador de walt.id
apunta exclusivamente al `issuer-api` legacy en v0.18.2, y ese servicio
**no puede tipar CBOR a ninguna versión** — le falta
`mDocNameSpacesDataMappingConfig`, confirmado por `git grep` en el código
fuente de walt.id en todos los tags hasta v0.23.1
(`docs/superpowers/adr/2026-08-20-mdl-production-path-analysis.md`, Parte 1).
Sin ese mapeo, `birth_date` sale como texto en vez de tag 1004, `portrait`
sale como texto en vez de bstr, y ningún reader conforme acepta la
credencial.

El servicio que sí puede — `issuer-api2` — se probó en una sesión previa
como contenedor suelto en `cdpi-vps`, no versionado ni desplegado, y
`verifiably-go` nunca le habló.

**Objetivo:** que el operador emita un mDL conforme desde el flujo normal
del sistema (elegir DPG → crear/elegir esquema → llenar datos → emitir),
sin romper el patrón arquitectónico del proyecto ni las credenciales que
hoy se emiten bien.

## Principio que gobierna el diseño

`verifiably-go` **media**; los DPGs **emiten**. Cada adaptador
(`waltid`, `credebl`, `injicertify`) implementa `IssueToWallet` construyendo
un request contra un servicio externo que posee la llave y firma.

Este principio ya descartó una alternativa: usar `internal/mdl/` (el emisor
Go nativo) como firmador de producción. Firma dentro del mismo proceso que
sirve el resto de `verifiably-go`, lo que convertiría a `verifiably` en el
emisor para ese formato — decisión revertida y documentada en
`docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md`.

`internal/mdl/` conserva un rol: **verificación independiente**. Sus vectores
de conformidad y su verificador Node.js (`internal/mdl/testdata/verify/verify.mjs`)
son implementación ajena a walt.id, y por eso sirven para comprobar que lo
que walt.id emite es realmente conforme.

## Hallazgos de investigación

### El riesgo que bloqueaba el upgrade no existe (verificado empíricamente)

El ADR de análisis marcaba un riesgo con radio de impacto sobre **todas** las
credenciales: `buildCredentialData` (`internal/adapters/waltid/issuer.go:1106`)
emite `@context` de VCDM 1.1 junto a campos `validFrom`/`validUntil` de
VCDM 2.0. walt.id v0.20.0 introdujo detección automática por `@context` con
renombrado de campos, y nadie había verificado qué hace con esa mezcla.

Se probó contra un `waltid/issuer-api:0.23.1` real, emitiendo los cuerpos
exactos que el adaptador produce hoy, en los tres caminos:

| Camino | Qué se verificó | Resultado |
|---|---|---|
| `jwt_vc_json` sin status | `@context` 1.1 + `validFrom`/`validUntil` 2.0 | Preservado verbatim; `nbf`/`exp` mapeados correctamente |
| `jwt_vc_json` con status | Lo anterior + `credentialStatus` BitstringStatusList | Todo preservado, incluido `statusListIndex` **como string** |
| `vc+sd-jwt` | `nbf`/`exp` + IETF Token Status List + SDMap | Todo preservado; 2 disclosures selectivas correctas |
| `mso_mdoc` | Cuerpo namespace-keyed, llave EC P-256 | Credencial emitida y firmada |

**El upgrade v0.18.2 → v0.23.1 no rompe nada por esta causa.** El riesgo
dominante del plan queda descartado con evidencia, no con inferencia.

Dos hallazgos incidentales del mismo spike:
- mdoc exige llave **EC P-256** tanto del emisor como del holder; Ed25519 es
  rechazado con `The key type "kty" must be EC`.
- `/draft13/credential` en v0.23.1 espera `format` (+ `credential_definition`
  / `vct` / `doctype`), no `credential_configuration_id`.

### `issuer-api2` no puede reemplazar al legacy — corre en paralelo

Se evaluó consolidar todo en `issuer-api2` para no mantener dos servicios.
No es viable hoy, por tres razones verificadas en el ADR de análisis:

1. **Se pierden los esquemas custom del operador.** Hoy `SaveCustomSchema`
   escribe la config de walt.id y reinicia el servicio; si el tipo es
   desconocido, `borrowConfigIDFor` presta un configId compatible porque el
   legacy no cruza-verifica. `issuer-api2` exige que cada `profileId`
   resuelva a un perfil pre-aprovisionado, con **dos** escrituras HOCON
   coordinadas que deben referenciarse 1:1 o el servicio lanza excepción.
2. **Persistencia con una trampa silenciosa.** `issuer-api2` solo soporta
   memoria o Redis, y si el feature flag de persistencia no está habilitado,
   la config de Redis **se ignora en silencio** y corre en memoria igual —
   perdiendo ofertas y códigos pre-autorizados en vuelo en cada reinicio.

   *Corrección respecto al ADR de análisis:* ese documento contrasta esto
   con "el legacy usa Postgres", pero verificado contra
   `deploy/compose/stack/docker-compose.yml`, el `issuer-api` legacy **no
   declara dependencia de Postgres ni variables de conexión** — solo
   `depends_on: caddy`. El Postgres del stack lo consumen `wallet-api` e
   Inji. Así que en persistencia de sesiones de emisión el legacy no es
   claramente superior; el problema real de `issuer-api2` es el modo de
   falla silencioso, no una regresión frente a lo que hay hoy.
3. **Peor aislamiento de fallas.** `listProfiles()` valida todos los perfiles
   en cada llamada: uno malformado rompe el catálogo entero.

Con la corrección de (2), la razón decisiva es **(1)**: perder los esquemas
custom del operador es una pérdida de capacidad de producto, no una
molestia operativa. (2) y (3) son agravantes, no el argumento principal. Si
alguien revisa esto y considera que los esquemas custom `mso_mdoc` no
importan para su despliegue, la conclusión del paralelo merece
reevaluarse — pero para este sistema, donde `SaveCustomSchema` es una ruta
central y probada, se sostiene.

Paralelo es además la ruta de migración segura: si walt.id cierra esas
brechas más adelante, se mueven los demás formatos cuando mDL ya lleve
tiempo corriendo sobre `issuer-api2`.

### mDL y mdoc no son lo mismo

`mso_mdoc` es el **formato contenedor** (CBOR, COSE, MSO, cadena X.509)
definido por ISO/IEC 18013-5. **mDL** es *un* tipo de documento dentro de ese
contenedor, identificado por su docType. La analogía: `mso_mdoc` es a mDL lo
que `w3c_vcdm_2` es a "Diploma Universitario".

ISO/IEC 23220 generaliza el mismo modelo a otros documentos móviles.
docTypes del ecosistema:

| docType | Documento | Perfil publicado por walt.id |
|---|---|---|
| `org.iso.18013.5.1.mDL` | Licencia de conducir | Sí |
| `org.iso.23220.photoID.1` | Identidad con foto | Sí |
| `org.iso.7367.1.mVRC` | Registro vehicular | **No** |

**El conjunto de campos obligatorios depende del docType, no del formato.**
mDL define 11 obligatorios en un solo namespace (`org.iso.18013.5.1`,
Tabla 3 del estándar, ya modelados en `internal/mdl/doctype.go`). Photo ID
define 9 obligatorios en `org.iso.23220.1`, y suma dos namespaces
completamente opcionales (`org.iso.23220.photoid.1`,
`org.iso.23220.dtc.1`).

### El `locale` hardcodeado afecta a todos los formatos, no solo a mdoc

Los cuatro constructores de catálogo de walt.id (`buildLinkedDataEntry`,
`buildSDJWTEntry`, `buildMDocEntry`, y el de W3C en `catalog.go`) escriben el
mismo bloque `display` con `locale = "en-US"` **hardcodeado**, y solo a nivel
de credencial — no por campo. Inji Certify hace lo equivalente en
`injicertify/db.go`.

Consecuencia actual: toda credencial que este sistema emite le declara a
cualquier wallet del mundo que su único idioma es inglés estadounidense, y
la wallet no tiene de dónde sacar el nombre legible de cada campo — por eso
`cdpi-wallet` muestra "Family Name" derivado del identificador técnico.

OID4VCI ya resuelve esto: cada claim puede llevar su propio array `display`
con múltiples `locale`. El mecanismo existe; nadie lo está usando.

## Arquitectura

### Cuatro tramos con dependencia estricta

**Tramo 1 — Upgrade walt.id v0.18.2 → v0.23.1.** Prerequisito duro:
`issuer-api2` no existe como módulo antes de v0.21.0 (confirmado contra los
tags publicados de la imagen).

**Fijaciones ejecutables a cambiar — 16, verificadas por grep:**
`deploy/cloud/ec2-bootstrap.sh` (3: issuer, verifier, wallet);
`deploy/compose/hub/.env.example` (`WALTID_VERSION`);
`deploy/compose/hub/docker-compose.yml` (1);
`deploy/compose/stack/docker-compose.yml` (3);
`deploy/k8s/helm/charts/walt-{issuer,verifier,wallet}/{Chart,values}.yaml`
(6); `deploy/k8s/helm/umbrella/waltid/Chart.yaml` (1);
`scripts/gen-backends.sh:73` (1 — el string de versión que el operador ve en
la tarjeta del DPG, fácil de pasar por alto).
Más `internal/adapters/waltid/integration_test.go`, que hardcodea la imagen
en dos lugares.

**No toca código de adaptador ejecutable**, pero sí deja desactualizados
~80 comentarios de documentación que citan v0.18.2 como la versión contra la
cual se verificó el comportamiento (`config.go`, `issuer.go`, `verifier.go`,
`wallet.go`, `catalog.go`, `vctypes.go`, varios handlers,
`bootstrap-waltid-did.sh`). No son bugs, pero quedan engañosos: afirman
"verificado contra el código fuente de v0.18.2" sobre un sistema que ya
corre otra versión. El plan debe decidir si se actualizan en este PR o se
anota como deuda — no dejarlo al azar.

**Tramo 2 — `issuer-api2` como servicio versionado.** Nuevo servicio en el
compose del stack y su equivalente Helm, imagen `waltid/issuer-api2:0.23.1`,
con su config bajo `deploy/k8s/config/issuer2/` — mismo patrón que las tres
cargas existentes (el compose monta el mismo directorio que respalda el
ConfigMap). Corre **en paralelo** al legacy; los demás formatos no se tocan.

Dos requisitos que el spike y el ADR dejaron establecidos:
- El feature flag de persistencia debe quedar **explícitamente** resuelto:
  Redis configurado con el flag activo, o memoria elegida a propósito y
  documentada. Nunca por omisión.
- La llave del emisor debe ser **EC P-256**.

**Tramo 3 — Enrutar `mso_mdoc` hacia `issuer-api2`.** El `case "mso_mdoc"`
que ya existe en `IssueToWallet` construye el DTO nuevo (`profileId`,
`authMethod`, `runtimeOverrides.credentialData`) y hace POST a
`/issuer2/credential-offers` contra la URL interna del nuevo servicio. La
respuesta cambia de forma: el legacy devuelve la URI de oferta como texto
plano, `issuer-api2` devuelve JSON (`{offerId, credentialOffer, ...}`). Los
demás `case` quedan intactos.

**Tramo 4 — Bloqueadores de seguridad.** `issuer-api2` no expone knob de
autenticación, así que `/issuer2/*` **no se publica** hacia fuera: sin
`ports:` en compose, `ClusterIP` sin Ingress en Kubernetes. `verifiably-go`
lo alcanza por nombre de servicio. Esto cierra de raíz el minteo no
autenticado y la fuga de llaves de `GET /issuer2/sessions` sin depender de
que walt.id agregue auth. El material privado no se versiona: sustitución
HOCON de variables de entorno, igual que las configs existentes.

### Catálogo de docTypes

Estructura versionada en el repo, una entrada por docType conocido,
declarando:

- El identificador del docType
- Sus namespaces, marcando cuál es el base
- Por cada campo: identificador, namespace, obligatoriedad, **tipo CBOR**
  (`full-date`, `bytes`, texto), y etiqueta en inglés
- El `profileId` correspondiente en `issuer-api2`

Fuente única de tres cosas hoy dispersas: qué precarga la UI, qué
`mDocNameSpacesDataMappingConfig` lleva el perfil, y qué valida el adaptador
antes de emitir. El mapeo de tipos CBOR vive hoy suelto en la config de
walt.id — el error que costó una sesión completa de depuración.

**Alcance inicial: mDL y Photo ID.** mVRC queda fuera porque walt.id no
publica perfil y su estándar (ISO 7367-1) es de pago sin fuente pública
confiable; modelarlo a ciegas es riesgo innecesario. Incluir dos docTypes
desde el inicio —con formas distintas: 1 namespace vs 3— fuerza que el
diseño sea genérico de verdad y hace mecánico agregar el tercero después.

### Etiquetas multi-idioma — transversal, no de mdoc

**Las etiquetas viven en el `Schema`, no en el catálogo de docTypes.** El
catálogo aporta las etiquetas iniciales en inglés de los campos estándar;
el mecanismo sirve a todos los formatos y a todos los DPGs que lo soporten.

- **Inglés es el idioma base obligatorio.** No es una implementación de un
  país ni de una región. Cualquier otro idioma es añadido opcional.
- **El código de idioma es texto libre.** El operador escribe `es-DO`, `ht`,
  `qu`, lo que su despliegue necesite. Ninguna lista predefinida limita algo
  que el estándar deja abierto.
- **Etiqueta vacía se deriva del identificador** (`family_name` →
  "Family Name"), que es exactamente lo que la wallet hace hoy por su
  cuenta. Sin regresión para quien no la use.
- **Cada adaptador la consume si puede.** Un método en la interfaz de
  adaptador que declare soporte de display por claim, siguiendo el patrón
  que el spec de rotación estableció con `SupportedKeyBackends()`. walt.id e
  Inji lo soportan; CREDEBL está por verificar. Un DPG sin soporte
  simplemente no las recibe y sigue como hoy: degradación silenciosa.

### UI del constructor de esquemas

Al elegir formato `mso_mdoc`, aparece un selector de docType (mDL /
Photo ID). Los campos obligatorios de ese docType se precargan con su
identificador **bloqueado** — no eliminable, no renombrable — porque el
estándar los define. Los campos opcionales conocidos se ofrecen como
sugerencias marcables, no como texto libre, para que el operador no los
escriba mal. Lo que el operador agregue por su cuenta va a un namespace
propio (ej. `do.gob.intrant.1`); meterlos en `org.iso.18013.5.1` rompería
conformidad.

Cada fila de campo gana una columna de etiqueta, con un control plegado para
añadir más idiomas:

```
[ family_name ] [ string ▾ ] [ Family Name     ] [🌐] [☑ req] [🗑]
   identificador    tipo        etiqueta (en)    idiomas
      bloqueado                   editable
   ↳ es-DO  [ Apellidos       ]
   ↳ ht     [ Siyati          ]
           + agregar idioma
```

El identificador conserva su restricción actual (`[a-zA-Z_][a-zA-Z0-9_]*`)
porque viaja al CBOR firmado y debe ser interoperable. La etiqueta es texto
libre. En los campos precargados, el identificador está bloqueado pero la
etiqueta sigue siendo editable.

## Manejo de errores

**Perfil ausente o mal configurado.** `issuer-api2` responde error si el
`profileId` no resuelve. El adaptador propaga el mensaje del servicio tal
cual, sin tragárselo. El arranque debe verificar que los perfiles declarados
existen, en vez de descubrirlo en la primera emisión de un ciudadano —
especialmente dado que un perfil malformado rompe el catálogo completo.

**Campo omitido que hereda datos de muestra.** El más peligroso: el merge de
`runtimeOverrides` es recursivo para objetos y reemplazo para escalares, así
que **cualquier campo no enviado conserva el valor del perfil**. El perfil
`isoMdl` que trae walt.id lleva datos de una persona austriaca ficticia:
omitir `nationality` emitiría una credencial válida con `nationality: "AUT"`,
en silencio. **Se cierra por diseño**: el perfil versionado en nuestro repo
lleva `credentialData` vaciado a plantilla, no los datos de muestra. Un
campo faltante sale vacío o falla la validación; nunca sale con datos de
otra persona.

**Servicio caído.** Como corre en paralelo, solo falla mDL; W3C y SD-JWT
siguen emitiendo contra el legacy. El adaptador devuelve el error de
transporte y el handler lo convierte en `502`, igual que hoy con cualquier
fallo de DPG.

## Pruebas

**Tramo 1** — `integration_test.go` levanta un contenedor efímero de walt.id
y emite de verdad, así que bumpear la imagen ahí prueba el upgrade de forma
real. **Pero hoy no corre solo:** está detrás de
`t.Skip("set WALTID_INTEGRATION=1 ...")`, y `WALTID_INTEGRATION` no se
activa en ningún workflow ni script del repo (verificado por grep). Es una
red de seguridad **potencial**, no efectiva.

El plan debe resolver esto explícitamente, y hay una decisión real que
tomar: activarlo en CI (necesita Docker en el runner, y alarga el pipeline)
o mantenerlo manual y documentar que correrlo es parte obligatoria del
procedimiento de upgrade. Lo que no es aceptable es bumpear la versión
asumiendo que el test protege el cambio cuando nadie lo ejecuta.

**Tramo 2** — que el servicio arranque, que los perfiles validen, y una
verificación explícita de que la persistencia quedó como se pretende y no
cayó a memoria por el flag olvidado.

**Tramo 3** — tests unitarios sobre construcción del DTO y parseo de la
respuesta JSON, con un caso específico para la trampa del merge:
**verificar que un campo omitido no hereda datos del perfil**. Ese test es
lo que impide que vuelva el riesgo de emitir con datos de otra persona.

**Etiquetas** — que un `Schema` con etiquetas en varios idiomas produzca
metadata OID4VCI con un `display` por locale, y que un `Schema` sin
etiquetas produzca las derivadas del identificador (sin regresión).

**Extremo a extremo** — emitir un mDL y un Photo ID contra el servicio real
y verificar los tipos CBOR con `internal/mdl/testdata/verify/verify.mjs`, el
verificador independiente. Aquí `internal/mdl/` demuestra su valor bajo la
decisión tomada: no emite, pero verifica lo que walt.id emite.

**Manual, una vez** — presentar el mDL emitido a `multipaz-identity-reader`
y confirmar que verifica, cerrando el ciclo igual que en las pruebas de la
sesión previa.

## Fuera de alcance

- **Mecanismo de llaves.** Este diseño usa una llave EC P-256 estable
  inyectada para `issuer-api2`, explícitamente provisional. El destino es
  `verifiably-go/docs/superpowers/specs/2026-07-23-issuer-key-rotation-design.md`,
  donde ya se registraron los tres requisitos que mdoc le agrega (backend
  `x509chain`, distribución del ancla IACA como análogo de
  `PublishDIDDocument`, y la ventana de transición acotada por Annex B).
- **Que `cdpi-wallet` consuma las etiquetas multi-idioma.** Es otro repo. Sin
  ese cambio todo funciona igual —la wallet sigue derivando etiquetas— solo
  que no aprovecha la mejora.
- **mVRC** (`org.iso.7367.1`), por falta de perfil de referencia y de acceso
  al texto normativo. Candidato una vez que el patrón de agregar docTypes
  esté probado con dos.
- **Portrait desde un data source real.** Ningún data source del repo tiene
  columna de foto (ADR de análisis, Parte 5). Trabajo aparte.
- **Revocación de mdoc.** `statusListKindFor` excluye `mso_mdoc` por diseño;
  `APIRevoke` devuelve 422. Gap real contra ISO 18013-5, compartido por
  todos los caminos de emisión, no introducido por este diseño.
- **C.7.3b** (registro en Android Credential Manager) sigue bloqueado por
  causa desconocida, sin relación con este trabajo.

## Riesgos a validar en la revisión

1. **Los esquemas custom `mso_mdoc` quedan limitados a docTypes conocidos.**
   Un operador no podrá crear un esquema mdoc arbitrario desde la UI y usarlo
   de inmediato, como sí puede con los otros formatos. Es consecuencia
   directa de que `issuer-api2` exige perfiles pre-aprovisionados. El diseño
   lo convierte en una lista curada en vez de un error al emitir, pero sigue
   siendo una capacidad menor que la del legacy.
2. **Dos servicios walt.id que mantener.** Mitigado porque no son dos rutas
   de código propias sino dos contenedores del mismo proveedor, y porque el
   adaptador ya bifurcaba por formato. Pero es superficie operativa real.
3. **CREDEBL casi con seguridad no soporta display por claim.** Su adaptador
   solo expone un `DisplayName` a nivel de credencial
   (`credebl/issuer.go:377`), sin nada equivalente por claim ni noción de
   `locale` (verificado por grep). No invalida el diseño —la degradación
   silenciosa está contemplada— pero conviene asumir desde ya que CREDEBL
   queda fuera del beneficio, en vez de planificar como si fuera a
   soportarlo.
4. **`profileId` pre-aprovisionado implica despliegue para agregar un
   docType.** Añadir mVRC más adelante no será solo código: requiere
   versionar su perfil y desplegarlo.
