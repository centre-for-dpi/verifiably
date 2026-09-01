# PoC mDL (ISO/IEC 18013-5) sobre el despliegue Inji del MTC — diseño

**Status:** Aprobado para plan (brainstorming architectural, 2026-09-01)
**Scope:** este documento de diseño vive en `verifiably-go` porque reutiliza directamente
la investigación de `2026-08-25-inji-mdoc-issuer-design.md`, pero el **entregable final**
(documento guía + entorno de pruebas reproducible) es para el equipo del MTC/IUGO, sobre
**su propio despliegue** de Inji Certify/Mimoto/Inji Verify/InjiWallet — independiente de
`verifiably-go` en tiempo de ejecución; no se modifica ni se despliega código de este repo
contra la infraestructura del MTC. El plan de implementación debe fijar la ruta exacta del
entregable dentro de este repo (p. ej. `docs/mtc-mdl-poc/`) como parte de sus tareas.

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
  real (`cluster-eyhqyfwhvfs`, `hsm2m.medium`, non-FIPS) — `AWSCloudHSMKeyStoreImpl`.

**Objetivo de esta PoC:** producir una guía de implementación + un entorno de pruebas
reproducible para que Inji Certify del MTC pueda emitir la Licencia de Conducir también
como **mDL conformante ISO/IEC 18013-5** (`mso_mdoc`), además del SD-JWT existente —
redundancia/alternativa, sin reemplazar el flujo SD-JWT actual.

## Punto de partida: qué ya sabemos de este repo

`verifiably-go` (rama `feat/mdl`) ya diseñó e implementó, contra una instancia de prueba de
Inji Certify **v0.14.0** (`injistack/inji-certify-with-plugins:0.14.0`), la emisión de
`mso_mdoc` real vía Inji Certify — ver
`docs/superpowers/specs/2026-08-25-inji-mdoc-issuer-design.md` (spec) y los 5 commits de
implementación hasta `39a9e56`. Hallazgos que esta PoC reutiliza directamente:

1. **Inji Certify emite mdoc genuino** (CBOR con `IssuerSignedItem` Tag 24, salts de 24
   bytes, digests MSO correctos, firma COSE_Sign1 ECDSA P-256/SHA-256 válida) desde el
   camino de producción (DataProvider), no un mock — contradiciendo documentación
   desactualizada del propio repo `inji-certify`.
2. **Inji no tiene el problema de arrays de tamaño fijo que walt.id sí tiene** — un único
   perfil, sin modificar, emite `driving_privileges` como array CBOR de longitud variable
   real (1-4 categorías). No hace falta el patrón "N perfiles por conteo" de walt.id.
3. **`driving_privileges` debe nestearse bajo el namespace ISO** (`org.iso.18013.5.1`)
   antes de que el template Velocity lo sustituya, como array JSON sin comillas (marcador
   crudo) para que `toJsonMap` produzca un array CBOR real, no un string.
4. **Defecto conocido, no arreglable desde config:** el `MDocProcessor` de Inji Certify
   (bytecode, confirmado contra la imagen v0.14.0) no bstr-encodea `portrait`
   correctamente — queda como string de texto donde ISO 18013-5 exige un byte string CBOR.
   No hay evidencia de si esto se corrigió en versiones posteriores.
5. **El bloqueante real de interoperabilidad:** `MDocCredential.addProof` en Inji envuelve
   el mapa `IssuerSigned` ya firmado dentro de `{"docType": "...", "issuerSigned": <mapa>}`
   — la forma de un `Document` de *DeviceResponse*, no de una credencial standalone. La
   librería que consuma el CBOR (`@animo-id/mdoc` en el caso de `cdpi-wallet`) espera el
   mapa `IssuerSigned` directo. **Este repo resolvió esto con un workaround dentro de
   `cdpi-wallet`** (detectar la forma, extraer `issuerSigned`, verificar integridad
   post-extracción, verificar cadena de confianza) — código TypeScript/Credo, stack
   completamente distinta de InjiWallet (nativa MOSIP, Flutter/Kotlin).
6. **Provisión del perfil mdoc en Inji Certify** requiere código real, no solo un INSERT:
   `doctype`, claims declarados con el namespace correcto, `stdToCredentialFormat` con
   caso para `mso_mdoc`, y configuración de firma ECDSA P-256 (Inji trae por defecto
   configuración Ed25519 para otros formatos — el mdoc necesita su propia entrada de
   algoritmo/key manager).

**Nuevo hallazgo de esta investigación (no estaba en el repo):** la documentación oficial
de Inji ([docs.inji.io](https://docs.inji.io/inji-wallet/inji-mobile/overview)) declara que
**InjiWallet v0.15.0 soporta mDoc/mDL/CBOR nativamente**, incluyendo verificación de
`mso_mdoc` contra su propia "VC Verifier library" (changelog v0.15.0, entrada
`INJIMOB-2778`). Esto es material porque, si el fork del MTC está en esa versión o
posterior, **el problema del wrapper (hallazgo 5) podría ya no aplicar** — Inji
verificando su propio wrapper con su propia librería es un caso distinto de una librería de
terceros (`@animo-id/mdoc`) rechazándolo. Esto **no está verificado empíricamente** — es
una declaración de changelog, y este mismo repo ya encontró un caso de documentación de
Inji equivocada en sentido contrario (`AGENTS.md` decía "mock only" para mdoc en Inji
Certify, y resultó ser falso — sí emitía mdoc real). Se trata con el mismo escepticismo:
verificar contra código/comportamiento real antes de confiar.

## Restricción operativa: sin acceso al fork de InjiWallet todavía

El usuario no tiene a mano el código del fork InjiWallet del MTC en este momento. Esto
determina el orden de trabajo: la PoC se estructura en fases donde la **Fase 1 (emisión) es
ejecutable y verificable hoy sin ninguna wallet**, y las fases que dependen de InjiWallet
quedan documentadas como procedimiento a ejecutar cuando el código esté disponible, no como
pasos ya resueltos.

## Fase 1 — Emisión: Inji Certify MTC emite `mso_mdoc` (ejecutable ahora)

Réplica adaptada del trabajo ya hecho en este repo, con dos diferencias de fondo respecto
al spike original: (a) el MTC no usa `verifiably-go` ni su UI de schema-builder — la
provisión del `credential_config` se hace por el mismo mecanismo SQL/config que ya usan
hoy para SD-JWT (`mtc_insert.sql` alineado con `certify_init.sql`, aplicado manualmente);
(b) la firma corre sobre **CloudHSM real**, no el mock-HSM que usó el spike de este repo.

1. **`credential_config` nuevo por clase de licencia** (A/B/E, mismo patrón 1-fila-por-clase
   que ya existe para SD-JWT) con `credential_format = mso_mdoc`,
   `doctype = org.iso.18013.5.1.mDL`, claims declarados bajo el namespace ISO real.
2. **Extender `certify-driver-license.properties` / `MtcFeeDataProviderPlugin`** para que,
   cuando el `credential_config` activo sea mdoc, anide `driving_privileges` (las
   categorías que hoy ya consulta del FEE) bajo `org.iso.18013.5.1` en vez del
   `credentialSubject` plano que usa para SD-JWT — mismo nesting que el hallazgo 3.
3. **Confirmar soporte de ECDSA P-256 en el Key Manager sobre CloudHSM real** — el spike de
   este repo no probó HSM real, solo mock-HSM. Es una verificación empírica nueva
   obligatoria antes de dar la Fase 1 por cerrada: `AWSCloudHSMKeyStoreImpl` debe poder
   generar/usar una clave EC P-256, no solo las curvas que SD-JWT usa hoy.
4. **Portrait:** declarar la limitación conocida (hallazgo 4) explícitamente, y
   re-verificarla empíricamente contra la versión real del MTC — no asumir que persiste
   sin comprobar, igual que el spec original de este repo exigió para su propio caso.
5. **Verificación de la Fase 1 sin ninguna wallet:** un verificador standalone (reusar el
   patrón `internal/mdl` / `verify.mjs` de este repo como conformance-checker Node) que
   confirme CBOR/COSE/MSO válidos contra el certificado real del MTC. Igual que el spike
   original de este repo, la Fase 1 se da por completa cuando este verificador standalone
   pasa — sin depender de InjiWallet.

**Salida de la Fase 1:** un mDL emitido por Inji Certify MTC, CBOR/COSE/MSO
criptográficamente válido, verificado independientemente. No implica todavía que una
wallet lo pueda consumir — eso es la Fase 2.

## Fase 2 — Consumo en wallet (bloqueada; procedimiento documentado, no ejecutado)

Cuando el código del fork InjiWallet esté disponible:

1. **Confirmar la versión real** del fork vs. v0.15.0 (donde Inji declara soporte nativo).
2. **Probar consumo directo primero, sin escribir código**: emitir un mDL de prueba (Fase 1
   ya funcionando) y ver si el InjiWallet del MTC lo importa y lo verifica tal cual.
3. **Si falla:** inspeccionar si el fork exhibe el mismo síntoma que este repo encontró en
   Inji Certify v0.14.0 (wrapper `{docType, issuerSigned}`) — puede que **no** aplique si
   la versión de Inji Certify que declara soporte nativo v0.15+ ya corrigió esto del lado
   emisor. No asumir que el bug persiste sin verificarlo.
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
El protocolo de presentación de mdoc dentro de OpenID4VP usa un esquema distinto
(`doctype` + `namespaces` en vez de `vct`+`sd_claim`/`constraints.fields`). Esta fase
requiere:

1. Confirmar si la versión de InjiVerify que usa el MTC ya soporta ese formato de
   Presentation Definition para mdoc (mismo patrón de "verificar antes de asumir" que las
   fases anteriores — no se encontró evidencia de esto en la investigación de este spec).
2. Si sí: documentar la configuración equivalente a `config.json` pero para mdoc.
3. Si no: queda fuera de alcance de esta PoC, documentado como brecha conocida.

## Entorno de pruebas reproducible

Un `docker-compose` aislado, basado directamente en
`verifiably-go/deploy/compose/stack/inji/certify-preauth/` de este repo (mismo patrón:
Inji Certify + Postgres + nginx), con:

- Inji Certify en la versión real confirmada del MTC (o v0.14.0 si no se puede confirmar
  aún — ver §Riesgos).
- El `credential_config` mdoc de la Fase 1 pre-provisionado.
- Un **mock** del `MtcFeeDataProviderPlugin` que devuelve datos de licencia sintéticos, sin
  pegarle al Servicio Web FEE real del MTC (evita depender de credenciales/red de
  producción para iterar).
- Mock-HSM para iteración rápida (CloudHSM real solo se prueba en un ambiente con acceso
  real, no en este entorno local).

Esto permite al equipo del MTC iterar la Fase 1 completa sin tocar producción ni depender
de HSM real, igual que el spike original de este repo lo hizo con Docker local.

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
  no una repetición de algo ya confirmado.
- **Portrait roto** es una limitación heredada, no resuelta aquí; se re-verifica pero no se
  arregla como parte de esta PoC (mismo alcance que el spec original de este repo, que
  tampoco lo arregló — lo mitigó del lado del holder).
- **Fase 2 y Fase 3 son procedimientos, no resultados** — este spec no puede completarlas
  sin acceso al fork InjiWallet y sin confirmar capacidades reales de InjiVerify. Quedan
  explícitamente abiertas.
- **`use_idperu`/CIBA (autenticación) no cambia con esta PoC** — mdoc solo afecta el
  `credential_config`/formato de salida; el flujo de obtención de token (Mimoto → IdPeru)
  es idéntico al que ya usa SD-JWT hoy.

## Fuera de alcance de este spec

- Modificar el flujo SD-JWT existente del MTC — mdoc es puramente aditivo.
- Tocar infraestructura real del MTC (AWS, CloudHSM, EKS) — el entorno reproducible es
  local/aislado.
- Decidir entre approach B y C de la Fase 2 — decisión futura, con el fork en mano.
- Confirmar o arreglar el bug de portrait — se documenta, no se resuelve.
- Cualquier trabajo sobre InjiVerify más allá de la investigación de la Fase 3.
