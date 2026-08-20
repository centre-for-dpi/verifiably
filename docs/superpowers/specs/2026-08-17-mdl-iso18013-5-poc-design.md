# mDL (ISO/IEC 18013-5): nota de posición, spike de verificación y POC de emisión

**Date:** 2026-08-17 (gate de negocio destrabado 2026-08-20)
**Status:** Active — gate de §Origen y demanda destrabado; detalles administrativos
de esa sección aún por confirmar (ver tabla), pero no bloquean el trabajo
**Estructura:** cuatro tramos con gate entre ellos. B, C y D requieren además gate
explícito del anterior — esos gates técnicos siguen en pie y no se tocan aquí.

| Tramo | Qué es | Duración | Código | Gate para pasar al siguiente |
|---|---|---|---|---|
| **A** | Nota de posición para gobiernos | ~1 sem | No | ¿Alguien pide más tras leerla? |
| **B** | Spike de **verificación** (app de prueba) | ~2 sem | Sí | ¿Hay petición escrita de emisión? |
| **C** | POC de **emisión** end-to-end | ~9,5-10 sem (1 persona) | Sí | ¿Se confirma el SDK como producto? |
| **D** | **SDK RN embebible** v1 (producto) | ~3-4 meses | Sí | — |

## Reparto de responsabilidades por proyecto

Decisión confirmada. Cada capacidad tiene **un solo** hogar:

| Capacidad | Proyecto | Rol ISO 18013 |
|---|---|---|
| **Emisión mdoc** | `verifiably` (Go) | Issuing Authority — genera `IssuerSigned`/MSO, firma con DSC, gestiona PKI |
| **Verificación online** | `verifiably` | Relying Party sobre **ISO/IEC 18013-7** (mdoc vía OID4VP). **Fuera de los Tramos A-D — requiere su propio spec** |
| **Holding** | `cdpi-wallet` (Expo/RN) | mdoc holder — almacena, consiente, presenta por proximidad; **registrado en Android Credential Manager** |
| **Verificación offline** | **`@cdpi/mdl-verifier`** (SDK RN) + app de referencia | mdoc reader — proximidad BLE |

**Por qué `verifiably` se queda con las dos verificaciones online:** ya tiene la
infraestructura OID4VP completa, DCQL en el adapter CREDEBL, Trust Registry con
`did:web`/JWKS, y un self-audit HAIP que documenta exactamente los gaps que 18013-7
necesita (`direct_post.jwt`/JARM, `client_id_scheme=x509_san_dns`). Construir la
verificación online en otro sitio duplicaría todo eso.

**Por qué la verificación offline NO es una app, es un SDK:** el criterio real no es
que CDPI tenga un lector, sino que **INTRANT, el MTC, la policía, bancos y aeropuertos
puedan incorporar la verificación a las apps que ya tienen**. Un lector que solo existe
como app propia no lo cumple. La app de referencia es el vehículo de prueba y demo del
SDK, no el entregable. Esto además descarta forkear `multipaz-identity-reader`: **un
fork de una app no se puede incorporar a la app de nadie.**

### Wallets nativas (¿y Google Wallet / Apple Wallet?)

Pregunta obligada de cualquier gobierno. **La credencial NO podrá vivir en las wallets
nativas, y no es una limitación de este diseño sino del ecosistema.**

**Google Wallet** tiene un programa formal (*Digital Credentials Provisioning API*,
conforme a 18013-5 / 23220-4, y **acepta OpenID4VCI**), y su texto admite emisores
gubernamentales *y privados* — pero el único camino de entrada es *"get in touch with
our team"*. **No hay API self-service.** Exige mTLS con certificado **pineado**, cipher
suites restringidos y rotación anual asistida por un representante de Google asignado:
partnership gestionada, no onboarding. La cobertura varía *"by region, based on local
government or institutional partnerships"*, sin lista pública de países elegibles.

**Apple Wallet** está más cerrado: **no publica ningún onboarding de emisor**. Por los
contratos con estados de EEUU se sabe que Apple tiene *"sole discretion"* sobre el
rollout, exige personal y presupuesto asignados, certificación propia, que el emisor
**promocione el programa**, y aprobación previa de todo el marketing. Fuera de EEUU
solo existe **Japón** (My Number Card, jun 2025). **Cero LatAm soberano, cero Europa.**
Los entitlements públicos de Apple (`in-app-identity-presentment`, Verify with Wallet)
son para **verificadores**, no emisores — para emisión no falta un permiso, falta un
contrato.

> **Dos lecturas que engañan y conviene desmontar antes de que las traiga un
> interlocutor:**
> - Google Wallet tiene "ID" en Brasil, India, UK y anunció España/Italia/Francia para
>   2026 — pero eso es el **"ID pass"**, derivado de que el usuario escanee su propio
>   pasaporte. La ayuda oficial de Google dice: *"An ID pass is **not
>   government-issued**"*. No es emisión gubernamental.
> - **Puerto Rico sí está en ambas wallets** — porque es territorio de EEUU dentro del
>   ecosistema AAMVA/TSA. Es precedente de que la maquinaria estadounidense funciona,
>   **no** de que un país extranjero pueda entrar.

**Lo que sí está abierto.** El ecosistema se abrió en 2026 de forma **asimétrica**: el
*provisioning* a wallets nativas sigue cerrado, pero la capa de **presentación** se
abrió por completo.

- **Android — Credential Manager Holder API**: cualquier app puede registrar sus
  credenciales y aparecer **en el selector del sistema, junto a Google Wallet**.
  Soporta **mdoc 18013-5** nativamente, funciona desde Android 6 (API 23), y **no hay
  allowlist ni aprobación de Google**. **Entra en alcance** (§C.7.3b).
- **iOS 26 — IdentityDocumentServices**: Apple introdujo el rol de *Identity Document
  Provider*; desde Safari 26 los sitios pueden pedir IDs a Apple Wallet **y a wallets
  de terceros**. Limitaciones: solo mdoc, orientado a presentación **web/online** (no
  al tap NFC presencial), y su entitlement es *managed capability* cuyo **criterio de
  aprobación no está documentado públicamente**. **Trabajo de seguimiento**, con el
  Capability Request iniciado pronto porque el timeline es desconocido.

**Qué hacen los demás:** apps propias, casi universalmente. **France Identité**,
**eAusweise** (Austria), **IT-Wallet** (Italia). La UE incluso publica una librería
oficial (`eu-digital-identity-wallet/av-lib-ios-w3c-dc-api`) para integrar wallets
propias con la DC API de iOS. Ningún Estado delega la emisión a Apple o Google.
**`cdpi-wallet` como holder no es un plan B: es el patrón europeo.**

**Consecuencia de diseño:** emitir por **OpenID4VCI** desde `verifiably` aunque hoy
solo sirva a `cdpi-wallet` — es el protocolo que Google acepta en su programa de
provisioning y el que Android usa nativamente. Deja la puerta abierta sin coste hoy.

**Los pasos concretos para llegar a las wallets nativas en el futuro están en
§Apéndice W.** No es trabajo de este spec, pero se documenta para que dentro de seis
meses nadie tenga que reinvestigarlo, y para no cerrar puertas hoy por descuido.

**Por qué escalonado:** una revisión de este documento verificó que **mDL, mdoc,
ISO 18013-5 y BLE no aparecen en el roadmap oficial de julio 2026** de `verifiably`
(cuyas tres prioridades son presentación multi-credencial, gestión institucional de
claves y endurecimiento operativo), ni en ningún otro documento del repo. Los
despliegues reales (MINERD, MT) corren sobre VCDM/SD-JWT/OID4VP — un stack disjunto
de mdoc/CBOR/BLE. Comprometer 7-8 semanas —~60-80% de un ciclo de release— contra
tres P1 públicas exige una demanda documentada, no inferida.

---

## Origen y demanda

> **Gate destrabado — 2026-08-20.** Confirmado explícitamente por el responsable de
> producto: la demanda existe y proviene de dos instituciones reales, cada una
> pidiendo tanto emisión como verificación. Los campos marcados _(confirmar)_ abajo
> no son huecos sin respuesta — son detalles administrativos aún no registrados, no
> una premisa sin fuente. El gate ya no bloquea el Tramo A ni el Tramo C.

| Campo | Valor |
|---|---|
| Entidad solicitante | **INTRANT (República Dominicana) y MTC (Perú)** — ambas confirmadas |
| Interlocutor (rol, no nombre si es sensible) | _(confirmar)_ |
| Fecha de la petición | _(confirmar)_ |
| Formato | _(confirmar — reunión / correo / RFP / conversación informal)_ |
| Qué pidieron **exactamente** | Emisión y verificación de mDL, ambas capacidades |
| ¿Emisión o verificación? | **Ambas** — confirma que el Tramo C (emisión, en curso) es necesario, no solo el Tramo B |
| Plazo esperado por el solicitante | _(confirmar)_ |
| Sponsor interno en CDPI | _(confirmar)_ |

**Por qué importa la distinción emisión/verificación:** son problemas de costo y
política radicalmente distintos (ver §Tesis central). Aquí ambas instituciones piden
las dos, así que ningún tramo sobra — pero conviene documentar por separado si
INTRANT y MTC piden lo mismo en el mismo plazo, o si hay una jerarquía entre ellas
que deba ordenar la secuencia de trabajo.

## Tesis central

**Verificar es unilateral, gratuito y escalable. Emitir es bilateral, caro y
político.**

Evidencia: **NZ Verify** (Nueva Zelanda) verifica mDLs de Queensland y **14
jurisdicciones de EEUU** consumiendo VICALs publicados — **sin emitir mDL propio, sin
tratado y sin reciprocidad**. Y el VICAL de AAMVA **se consume gratis y sin registro**
(verificado descargándolo y comprobando su firma), pero **ser emisor está restringido
a Norteamérica**: las entradas observadas son todas `issuingCountry: "US"`. **Perú y
RD no pueden entrar al VICAL de AAMVA**, y no existe federación entre VICALs ni raíz
de raíces.

Consecuencia estratégica: un país LatAm puede **desplegar verificación mañana** sin
permiso de nadie, mientras que emitir exige PKI propia, acuerdos bilaterales y
conformidad certificada. Esto debería ordenar cualquier recomendación a un gobierno,
y ordena estos tres tramos.

---

# TRAMO A — Nota de posición (~1 semana, sin código)

**Objetivo:** responder la pregunta que un gobierno realmente hace —*"¿debemos
adoptar mDL y qué implica?"*— en vez de la que CDPI puede responder sola —*"¿podemos
construirlo?"*, cuya respuesta el track record ya evidencia.

**Entregable:** documento de 5-10 páginas, en español, para audiencia mixta
técnica/directiva, construido sobre el análisis de §Anexo (ya escrito y pagado) más:

1. **Conversaciones reales** con INTRANT (RD), MTC/entidad competente (Perú),
   **GET Group** (vendor del mDL de Utah y del consorcio de RD), OpenWallet
   Foundation, y quien opere el mDL de Puerto Rico.
2. **La tesis central** desarrollada con el caso NZ Verify y la asimetría del VICAL.
3. **Estado real de la región**, sin concesiones (§Anexo).
4. **Recomendación explícita por país**: ¿emisor, verificador, o esperar a la 2ª
   edición ISO (Q4 2026) y a los actos de ejecución de la UE (26 nov 2026)?
5. **Qué NO recomendamos y por qué.**

**Criterio de éxito (de negocio, no técnico):** al menos un interlocutor
gubernamental responde con una petición concreta de siguiente paso. Si nadie lo hace,
**la respuesta correcta es no seguir** — y se han ahorrado 7 semanas.

**Riesgo que mitiga:** que CDPI invierta un trimestre en una capacidad que nadie pidió.

---

# TRAMO B — Spike de verificación (~2 semanas, tras gate A)

**Objetivo:** demostrar que CDPI verifica mDLs reales de producción de terceros. Es
la capacidad unilateralmente útil y la única desplegable sin tratado.

**Enfoque:** usar `openwallet-foundation/multipaz-identity-reader` (Apache-2.0)
**sin forkear**, apuntándolo a nuestros trust anchors vía la UI existente.

> **Verificado en el código del reader:** `TrustedIssuersScreen` permite importar
> certificados X.509 al `userTrustManager` (`addX509Cert`) — es la ruta para cargar
> anchors sin tocar código. `ReaderAuthMethod` ya incluye `NO_READER_AUTH`, y todas
> las llamadas al backend están envueltas en `try/catch` que solo loguean: **el
> backend es opcional por diseño** en el camino sin ReaderAuth.

**Entregables:**
- Reader corriendo en Android físico.
- Verificación exitosa de los vectores de interoperabilidad **reales** de
  `@owf/mdoc/tests/examples/{bdr,france,google,ubique}` (Alemania, Francia, Google,
  Ubique).
- Informe de lo que funciona y lo que no, con los modos de fallo observados.

**Criterio de aceptación:** el reader valida correctamente los cuatro conjuntos de
vectores y rechaza correctamente versiones manipuladas de ellos.

**Por qué esta demo sí es presentable:** *"verificamos mDLs de producción de Alemania
y Francia"* es una afirmación honesta sin asteriscos. La demo del Tramo C, en cambio,
exige declarar siete limitaciones estructurales (ver §C.2).

**Lo que NO incluye:** emisión, PKI propia, BLE de dos lados, ReaderAuth.

---

# TRAMO C — POC de emisión end-to-end (~9,5-10 semanas con 1 persona, tras gate B)

**Solo si un gobierno pide emisión por escrito.** El resto de este documento es el
material de ejecución de este tramo. Su rigor técnico está validado contra el código
de Multipaz y el texto del estándar, y no habrá que rehacerlo.

## C.0 Criterio de éxito

Un `DeviceResponse` emitido por `verifiably`, almacenado en `cdpi-wallet`,
transmitido por BLE **sobre sesión cifrada**, y validado por el reader **con el reader
en modo avión**, comprobando las dos mitades de la cláusula 9.1:

1. **Issuer data authentication** — `IssuerAuth` (`COSE_Sign1`) válido, cadena
   DSC→IACA verificada, digests de `valueDigests` coincidentes, `ValidityInfo` vigente.
2. **mdoc authentication** — `DeviceSignature` válida sobre
   `DeviceAuthenticationBytes`, con `SessionTranscript` verificado contra el que el
   reader construyó (§S-1).

Más tres propiedades verificables:

3. **Confidencialidad del canal** — captura BLE sin PII en claro.
4. **Divulgación selectiva** — el `DeviceResponse` contiene solo lo pedido.
5. **Consentimiento** — el holder aprueba antes de firmar.
6. **Presencia en el selector del sistema** — `cdpi-wallet` aparece junto a Google
   Wallet cuando una app o web pide una credencial vía Digital Credentials API
   (§C.7.3b). *Camino de presentación distinto al de proximidad, no sustituto.*

**Qué NO demuestra:** conformidad certificada, interoperabilidad cross-border,
revocación, ni resistencia a relay.

> **Advertencia de negocio:** cumplir los cinco criterios al 100% **no implica** que
> mDL sea la decisión correcta para RD o Perú. Un criterio de éxito que no puede
> producir un "no" no es un criterio de decisión — por eso el gate está en A y B.

## C.1 Modelo de amenaza

| Amenaza | Estado |
|---|---|
| **Clonación** | Mitigada **solo si** Fase 0 confirma clave hardware-backed. **Si la clave acaba en software, NO mitigada** — la credencial es clonable y hay que declararlo (§S-4) |
| **Replay** | Mitigada por `SessionTranscript`, **solo si** se cumplen las 3 condiciones de §S-1 |
| **Eavesdropping BLE** | Mitigada por session encryption (§S-2) |
| **Relay / mafia fraud** | **NO mitigada.** 18013-5:2021 no tiene distance bounding. Mitigación operativa: el operador ve al portador. Ningún despliegue desatendido |
| **Reader ilegítimo** | **NO mitigada.** `ReaderAuth` fuera de alcance — el wallet responde a cualquier reader BLE. Mitigación parcial: consentimiento del holder (§S-3) |
| **Reloj manipulado** | **NO mitigada** (§S-5) |
| **Fuga de PKI de POC a producción** | Mitigada por marcado de subject, validez de 90 días y check de arranque (§C.8) |

## C.2 Riesgo reputacional (requisito, no anexo)

CDPI asesora gobiernos: su activo es el criterio, no el código. Una demo que exhibe
una credencial con siete limitaciones estructurales puede dañar más el criterio
percibido de lo que suma la capacidad demostrada.

**Entregables obligatorios antes de cualquier demo externa:**
- **Guion de presentación** para audiencia no técnica que enmarque las limitaciones
  como decisiones de alcance de una POC, no como defectos.
- **Regla de audiencia**: la demo interna y la demo a gobiernos **no son la misma**.
  Definir quién puede asistir a cada una.
- **Posicionamiento frente a GET Group**: tienen un mDL conforme en producción en
  Utah y están en el consorcio de RD. Si INTRANT ve ambos el mismo mes, hay que tener
  respuesta a *"¿por qué esto y no aquello?"*. La respuesta honesta es que CDPI no
  compite como vendor sino como asesor — y eso hay que decirlo antes, no improvisarlo.

## C.3 Contexto confirmado en el código

Referencias **por símbolo**, verificadas contra el árbol actual.

- `verifiably-go/internal/adapters/waltid/catalog.go` → `buildMDocEntry`: entrada
  HOCON `mso_mdoc` con `doctype`, binding `cose_key`, `ES256`,
  `proof_types_supported.cwt`.
- `.../waltid/issuer.go` → `buildMdocData`. **Firma:
  `(schema vctypes.Schema, subject map[string]string)`** — solo strings (§C.7.2).
- `.../waltid/verifier.go` → `iso_mdl` en **dos** sitios: template (~L46) y
  `case "iso_mdl":` (~L950).
- `.../waltid/issuer.go` → `schemaAllowlistDefault`. El commit **`6449f96`**
  (28 abr 2026) eliminó `"Iso18013 Drivers License Credential"` — **1 línea**.
  Razón: *"more demo-noise than demo-value… harder to round-trip through MOSIP / Inji
  Verify"*.
- Cero archivos `mdoc`/`mdl`/`18013`/`mso`/`cose` en Go.
- `fxamacker/cbor/v2 v2.9.1` en `go.mod`, único uso en `injicertify/pixelpass.go`.
  **`veraison/go-cose` NO está** — dependencia nueva.
- `docs/dpg/walt-id.md` documenta `VerifyDirect unsupported`.
- `cdpi-wallet`: Credo-TS 0.6.3, OID4VCI/OID4VP, SD-JWT VC. Nada de mdoc/CBOR/BLE.
- **`cdpi-wallet` no tiene directorio `ios/`** — solo `android/` prebuildeado,
  `eas.json` solo `buildType: apk`. **El Tramo C es Android-only.**

> **Conflicto de secuenciación a resolver antes de empezar:** §C.8 propone
> `internal/signer/`, pero la abstracción de signer es **P1 en el roadmap oficial**
> (Q3, diseño aprobado 23 jul), pensada para los tres DPGs en producción. Construirla
> aquí la optimizaría para mdoc. **Decisión requerida:** o se hace como P1 por sus
> propios méritos y el Tramo C la consume, o el Tramo C usa algo local y no toca el P1.

## C.4 Especificación criptográfica normativa

Verificada contra el código de Multipaz (`SessionEncryption.kt`, `MdocDocument.kt`) y
contrastada con la implementación Rust de SpruceID.

### S-1. SessionTranscript y DeviceAuthentication

```cddl
SessionTranscript = [
  DeviceEngagementBytes,   ; #6.24(bstr .cbor DeviceEngagement) — del QR
  EReaderKeyBytes,         ; #6.24(bstr .cbor EReaderKey.Pub)  — COSE_Key efímera del READER
  Handover                 ; QRHandover = null para engagement por QR
]

DeviceAuthentication = [
  "DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes
]

DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
SessionTranscriptBytes    = #6.24(bstr .cbor SessionTranscript)
```

**`DeviceSignature` es un `COSE_Sign1` con `payload = nil`** y contenido **detached**
igual a `DeviceAuthenticationBytes`. El `SessionTranscript` es *un elemento del
array*, nunca el payload.

**Tres condiciones contra replay:**
1. `SessionTranscript` construido como el array de 3 elementos.
2. El reader genera **`EReaderKey` efímera nueva por sesión**. Reutilizarla habilita
   el replay.
3. El reader **compara el `SessionTranscript` firmado con el que él construyó**.
   ✅ *El reader de Multipaz ya lo cumple*: construye el suyo y lo pasa a
   `deviceResponse.verify(sessionTranscript = ...)`, sin reconstruirlo desde el
   `DeviceResponse`.

### S-2. Session encryption (dentro de alcance)

```
sharedSecret = ECDH(EDeviceKey.Priv, EReaderKey.Pub)
salt         = SHA-256( SessionTranscriptBytes )      ← el DIGEST, no los bytes
SKDevice     = HKDF-SHA256(sharedSecret, salt, info="SKDevice", 32 bytes)
SKReader     = HKDF-SHA256(sharedSecret, salt, info="SKReader", 32 bytes)
cifrado      = AES-256-GCM
```

**IV = 12 bytes:** `00000000` (4B ceros) ‖ identificador de dirección (4B:
`00000001` cuando cifra el mdoc, `00000000` cuando cifra el reader) ‖ **contador
big-endian de 4B que arranca en 1**.

Flujo: `SessionEstablishment` → `SessionData` → `SessionTermination`. Los contadores
por dirección son el anti-replay intra-sesión.

> Con `info = "EMacKey"` el mismo esquema deriva la clave de `DeviceMac` — relevante
> solo si `DeviceMac` deja de estar fuera de alcance.

**Verificación:** captura BLE sin PII en claro (nRF Sniffer / HCI snoop log).

### S-3. Divulgación selectiva y consentimiento

- El holder **filtra** el `DeviceResponse` a lo pedido en el `DeviceRequest`.
- El holder **muestra los atributos solicitados y requiere aprobación** antes de firmar.

### S-4. Clave de dispositivo

El nivel de seguridad **se mide en Fase 0**, no se asume:

- Fase 0 determina si el wrapper de `askar 0.6.0` en RN expone P256 hardware-backed
  (StrongBox/TEE) en los teléfonos objetivo, y **documenta el nivel alcanzado**.
- Si no lo expone: la POC opera con clave en software y **se declara que la credencial
  es clonable por un atacante con acceso al dispositivo**. Device auth demuestra el
  *mecanismo*, no la *propiedad*.
- **Key attestation** (Android Key Attestation): trabajo de seguimiento.

### S-5. Validación temporal

`ValidityInfo` se valida contra el reloj del reader, **manipulable por su operador**;
sin red no hay NTP. En un modelo sin revocación es la única defensa temporal.

**Regla del DSC — trabajo a AÑADIR al reader, no comportamiento existente:**
lo correcto es verificar que el DSC estaba vigente **en el instante `signed` del
MSO**. El reader upstream hace lo contrario (`ShowResultsScreen.kt` usa
`Clock.System.now()` para la cadena). Sin este cambio, a los ~15 meses (DSC ≤457 días)
empezaría a rechazar documentos legítimos. **Irrelevante en el Tramo C** (los
certificados de la POC son recién emitidos); **es ítem del Tramo D**, donde el SDK
implementa su propia verificación.

## C.5 Decisiones de arquitectura

### AD-1. La firma mdoc se implementa en Go

El adapter `waltid` se conserva como camino de emisión OID4VCI (reactivando
`iso_mdl`); el `IssuerSigned`/MSO se construye y firma en `verifiably-go`.

**No se adopta librería mdoc de Go.** `kokukuma/mdoc-verifier` **sin licencia**
(bloqueante legal); `georgepadayatti/mdoc` es Apache-2.0 pero se autodescarta
(*"a fun experiment; use at your peril"*, 1★). `iso18013 language:Go`: cero resultados.

Base: `fxamacker/cbor/v2` + `veraison/go-cose`.

> **`veraison/go-cose`:** tiene `Sign1` y `SignMessage`, **no `COSE_Mac0` ni
> `COSE_Encrypt0`**. Sin commits desde 2025-11-07.
> - Device auth por `DeviceSignature` (ECDSA) ⇒ `Sign1` basta. ✅
> - **El issuer Go no participa en la sesión BLE**, así que la ausencia de
>   `COSE_Encrypt0` no le afecta — pero **descarta un verificador Go completo**.
> - **Riesgo de seguridad:** 9 meses sin commits en una librería criptográfica = sin
>   ruta de parcheo ante CVE. Aceptable para POC; **descalificante para producción**.

### AD-2. Device auth y binding deviceKey↔sujeto

`MobileSecurityObject` contiene obligatoriamente `deviceKeyInfo.deviceKey`. **El
issuer no puede firmar el MSO de forma aislada.**

```
1. Wallet genera par de claves en Askar (nivel medido — §S-4)
2. Wallet → Issuer: proof de posesión, ligado al c_nonce del issuer
3. Issuer: valida el proof, construye MSO con esa deviceKey, firma IssuerAuth
4. Issuer → Wallet: IssuerSigned
5. [offline] Reader → Wallet: DeviceRequest sobre sesión cifrada
6. Wallet: consentimiento → filtra → firma DeviceAuthenticationBytes
7. Reader: valida IssuerAuth, DeviceSignature y el SessionTranscript
```

**Regla de binding (obligatoria):** el issuer usa **exclusivamente** la `deviceKey`
del proof verificado de esa misma petición, ligado al `c_nonce` y al access token de
la sesión autenticada. **No se acepta `deviceKey` por ningún otro canal.**

> **Decisión pendiente:** `proof_types_supported.cwt` está en el código, pero
> OID4VCI 1.0 se consolidó en `jwt`. Verificar contra la versión de walt.id antes de
> codificar — reactivamos una ruta que ya dio problemas de interop (`6449f96`).

### AD-3. Verificación 100% en dispositivo

Sin oráculo backend. Un endpoint que recibiera `DeviceResponse` completos sería una
base de datos de "quién mostró su mDL, dónde y cuándo" — la trazabilidad que la
verificación offline existe para evitar.

### AD-4. Librerías

**Holder (TS):** `@owf/mdoc` v0.7.0 (Apache-2.0, OpenWallet Foundation). El ecosistema
se consolidó ahí (`@auth0/mdl` archivado, `@animo-id/mdoc` congelado con redirect 301,
`mdl-js` archivado). Cripto inyectada vía `MdocContext`; se provee con
`@noble/curves` + `@noble/hashes`.

> JS puro **no garantiza resistencia a canal lateral por tiempo** en un runtime JIT.
> Las operaciones con la privada del device deben migrar a la Secure Area vía askar
> en cuanto esté disponible.

> **No se hace upgrade de Credo.** `@credo-ts/core` 0.7.0 pinea `@owf/mdoc` **^0.6.0**,
> que no resuelve a 0.7.0; además arrastra askar y rompería el `patch-package`
> existente. **`@owf/mdoc` se consume directo.**

> **Polyfill:** Expo 54 / RN 0.81.5. RN 0.81 < 0.85 ⇒ `TextDecoder` necesario.

**Transporte BLE del holder:** `expo-mdoc-data-transfer` **v0.2.0-alpha.5**
(Apache-2.0, OWF Labs) — **única versión publicada** del paquete desescopado.
**Pinear exacto** por ser alpha.

**Reader:** ver §C.7.4.

### AD-5. Trust store

Una IACA autofirmada en configuración. Se carga en el `userTrustManager` del reader
vía `addX509Cert` (`TrustedIssuersScreen`). El reader usa **`TrustManagerLocal` +
`CompositeTrustManager`** — *no* `ConfigurableTrustManager`, que existe en Multipaz
pero el reader no lo usa.

## C.5b División del trabajo entre repos

**Equipo asumido: una persona.** El trabajo es **secuencial**, y la estimación real es
por tanto **9,5-10 semanas**; el escenario de 8-9 asumiría dos personas paralelizando
Go y RN (§C.6).

### Ramas por repo, respetando la convención de cada uno

| Repo | Rama | Convención de commits | Contiene |
|---|---|---|---|
| `verifiably` | `feat/mdl-issuer` | Conventional **con scope**: `feat(mdl):`, `fix(mdl):` | C.7.1, C.7.2 + reactivar `iso_mdl` |
| `cdpi-wallet` | `mdl-holder` | Conventional **sin scope**: `feat:`, `fix:` | C.7.3, C.7.3b |
| Repo nuevo (reader POC) | `main` | Conventional sin scope | C.7.4 |

> Las convenciones difieren entre repos y **se respeta la de cada uno**, no se
> uniformiza: `verifiably` usa prefijos de rama (`feat/`, `fix/`) y scope en el commit;
> `cdpi-wallet` no usa ninguno de los dos.

### Orden de ejecución

```
1. C.7.0  Fase 0 (spike)          → los 3 repos tocados mínimamente
2. C.7.1  Issuer Go               → verifiably           [feat/mdl-issuer]
3. C.7.2  Dataset                 → verifiably           [misma rama]
   ── merge a main de verifiably: el issuer emite mdocs verificables ──
4. C.7.3  Holder                  → cdpi-wallet          [mdl-holder]
5. C.7.3b Credential Manager      → cdpi-wallet          [misma rama]
   ── merge a main de cdpi-wallet ──
6. C.7.4  Reader POC              → repo nuevo
7. C.7.5  Ampliación (portrait)   → toca los 3
8. C.7.7  Demo
```

**Regla de merge:** cada repo se mergea a `main` cuando su criterio de aceptación pasa,
sin esperar a los demás. El único acoplamiento duro es que C.7.3 necesita mdocs reales
del paso 3 — resuelto por los vectores compartidos (abajo).

### Contrato entre repos: vectores de prueba compartidos

Los tres repos deben coincidir en doctype, elementos y tags CBOR. **El contrato es
ejecutable, no documental:**

- `verifiably` genera mdocs de ejemplo y los commitea en
  **`verifiably-go/internal/mdl/testdata/vectors/`** (mdoc completo, mdoc mínimo, y
  uno con `portrait` para 1.5).
- `cdpi-wallet` y el reader los copian como **fixtures de test** y los usan en su suite.
- Si alguien cambia el formato, **los tests del otro repo fallan** — la divergencia se
  detecta sola en vez de descubrirse en la demo.
- Se versionan con el mdoc: un cambio de formato es un commit que actualiza los
  vectores en los tres sitios.

> **Con una sola persona esto no evita divergencia entre personas** (no la hay), pero
> sigue valiendo como red contra regresiones y como documentación ejecutable del
> formato para quien retome el trabajo después.

**Dependencia `deviceKey` (§AD-2):** C.7.1 no puede firmar un MSO sin la clave pública
del holder, que produce C.7.3. Se desacopla con
`internal/mdl/testdata/devicekey_test.json` (clave de prueba generada en Go); la
integración con la clave real del wallet ocurre en el paso 4.

## C.6 Fases del Tramo C

**Estimación: 9,5-10 semanas con una persona** (el escenario asumido, §C.5b);
**8-9 con dos** paralelizando Go y RN. Fase 0 incluida en ambos casos.

Suma secuencial: C.7.0 (1) + C.7.1 (2) + C.7.2 (0.6) + C.7.3 (2) + C.7.3b (1) +
C.7.4 (1.5-2) + C.7.5 (1) + C.7.7 (0.4) = **9,5-10 semanas**. C.7.6 es transversal y
no suma.

Se declara **8-9** porque hay dos paralelizaciones reales: **C.7.1 (issuer en Go) no
depende de hardware BLE** y puede avanzar durante C.7.0 y C.7.3; y **C.7.3b es
independiente del flujo de proximidad**. Con un equipo de una sola persona, contar
**9,5-10**.

**No existe un escenario de 5 semanas.**

### C.7.0 Fase 0 — Spike bloqueante (~1 semana)

**Ninguna otra tarea empieza hasta que cierre.**

**Entregables:**
1. Reader de Multipaz corriendo en Android físico — **provee el "reader de prueba"**
   que Fase 0 necesita (resuelve la dependencia circular).
2. `expo-mdoc-data-transfer` integrado en un build de `cdpi-wallet` capaz de advertir
   en BLE peripheral server mode.
3. **Informe del nivel de seguridad de claves** de askar 0.6.0 en RN por teléfono
   (StrongBox / TEE / software) — entrada obligatoria de §S-4.
4. **Prueba de MTU/chunking con payload sintético** del tamaño de un `portrait`. Se
   adelanta aquí a propósito: es el riesgo más difícil de rescatar y no puede
   descubrirse al final del presupuesto.

**Aceptación (binaria), en los dos teléfonos Android probados:**
1. El holder advierte y completa un device engagement con el reader.
2. **Chunking:** un payload sintético de **~20 KB** (tamaño realista de un `portrait`
   JPEG) se transmite completo y sin corrupción.
3. **Rendimiento:** la transacción completa —desde el escaneo del QR hasta el
   resultado— tarda **menos de 5 segundos** con ese payload.

Si algo falla en uno solo de los dos teléfonos, **Fase 0 no pasa**: se documenta el
fabricante y se decide con esa evidencia.

**Plan B si falla el holder BLE:** pivotar el transporte del *holder* — (a) usar
Multipaz en el holder vía módulo nativo (lo que reabriría la decisión del reader), o
(b) recortar a solo-verificación, que es el Tramo B. **Un reader CLI no es plan B
aquí**: si el holder no puede advertir, cambiar el reader no resuelve nada.

**Dependencias previas:** 2 Android físicos de fabricantes distintos (Motorola y
Huawei son conocidos como inconsistentes); `BLUETOOTH_ADVERTISE` (API 31+); dev client
de Expo; JDK + Android Studio; **sniffer BLE** (nRF) para la evidencia de §S-2.

### C.7.1 Issuer mdoc en Go (~2 sem)

**Entregables:** `internal/mdl/encode.go` (`IssuerSignedItem`, `valueDigests` SHA-256,
`MobileSecurityObject` con `deviceKeyInfo`), `sign.go` (`IssuerAuth` con `x5chain`),
`validity.go` (`ValidityInfo`, **emitiendo `expectedUpdate`**), `pki/` (IACA + DSC),
endpoint que valida el proof de posesión, y `testdata/devicekey_test.json` (clave de
prueba que desbloquea esta fase sin depender del holder).

**Certificados (Annex B, normativo):** DSC con EKU `1.0.18013.5.1.2`, validez
**≤457 días** y **≤ la validez de la IACA** (§C.8).

**Tags CBOR:**

| Tag | Uso |
|---|---|
| **0** (`tdate`) | `signed`, `validFrom`, `validUntil`, `expectedUpdate`. **Solo tag 0** — usar 1004 invalida el MSO |
| **1004** (full-date) | `birth_date` |
| **0 ó 1004** | `issue_date`, `expiry_date` |
| **24** (`bstr .cbor`) | `IssuerSignedItemBytes`, `ItemsRequestBytes`, `EDeviceKeyBytes`, `EReaderKeyBytes`, `DeviceAuthenticationBytes`, `SessionTranscriptBytes`, `DeviceEngagementBytes`, `DeviceNameSpacesBytes` |

**Restricción normativa:** `validFrom` ≥ `issue_date`; **`validUntil` ≤ `expiry_date`**.

**Aceptación:** un harness Node (`internal/mdl/testdata/verify/`, entregable de esta
fase) usa `@owf/mdoc` para verificar los mdocs emitidos, y el issuer **produce** mdocs
que ese verificador acepta.

> Los vectores `@owf/mdoc/tests/examples/*` son mdocs de terceros: validan un
> *verificador*, no un *emisor*. Se usan en C.7.4, no aquí.

### C.7.2 Dataset (~3 días)

**11 mandatory (Tabla 3):** `family_name`, `given_name`, `birth_date`, `issue_date`,
`expiry_date`, `issuing_country`, `issuing_authority`, `document_number`, `portrait`,
`driving_privileges`, `un_distinguishing_sign`.

**Se emiten 10 de 11 + `age_over_18` + `age_over_21`. Se difiere `portrait`** a C.7.5.

> **El documento de C.7.2-C.7.4 no es un mDL conforme**, es un mdoc de prueba. Pasa a
> conforme en C.7.5.

**Reglas de `age_over_NN`** (opcionales en el estándar, con semántica propia):
- Se calculan respecto al **`validFrom` del MSO**, no a la fecha de emisión ni a la
  actual.
- Ante una petición de `age_over_NN`, se devuelve la atestación **más cercana ≥ NN**
  presente en el mDL.
- Un valor `false` solo se devuelve si el nombre coincide exactamente con el pedido.

**Restricción descubierta:** `buildMdocData` toma `map[string]string`, pero
`driving_privileges` es un array CBOR de estructuras anidadas. **Decisión:**
`internal/mdl/` usa estructura tipada propia y no reutiliza `buildMdocData`; el offer
OID4VCI de walt.id sigue sirviendo de transporte.

**Aceptación:** los 12 elementos codifican con los tags correctos y hacen round-trip
CBOR sin pérdida; test unitario por elemento.

### C.7.3 Holder (~2 sem)

**Entregables:** par de claves en Askar + proof de posesión; `@owf/mdoc` +
`MdocContext` + polyfill; almacenamiento del `IssuerSigned`; BLE peripheral server
mode con versión pineada tras interfaz propia de transporte; **session encryption**
(§S-2); **pantalla de consentimiento**; **filtrado** por `DeviceRequest`; firma de
`DeviceAuthenticationBytes` (§S-1) — **no** del `SessionTranscript`.

**Aceptación:** el `DeviceResponse` (a) lleva `DeviceSignature` válida, (b) contiene
**solo** lo pedido, (c) no se envía sin aprobación del usuario, y **(d) una captura
BLE de la sesión no muestra PII en claro** (criterio de éxito #3).

### C.7.3b Registro en Android Credential Manager (~1 sem)

Hace que el mDL de `cdpi-wallet` aparezca **en el selector del sistema Android**, junto
a Google Wallet, cuando una app o web pida una credencial. Es la alternativa real a
estar en la wallet nativa (ver §Wallets nativas y §Apéndice W).

**Dónde vive el código:** en `cdpi-wallet`, que ya tiene `android/` prebuildeado. Las
piezas son Kotlin nativo (`androidx.credentials.registry`), así que se implementan como
**módulo Expo local** dentro del repo (`modules/credential-manager/`), con su
`expo-module.config.json` y el config plugin para el intent filter. **No** se publica
como paquete aparte; si más adelante hace falta reutilizarlo, se extrae.

**Entregables:**
- Módulo Expo local con dependencias Gradle
  `androidx.credentials.registry:registry-digitalcredentials-mdoc` y
  `registry-provider`.
- `RegistryManager.registerCredentials()` con el mdoc emitido, invocable desde TS.
- Handler del intent
  `androidx.credentials.registry.provider.action.GET_CREDENTIAL`, que reutiliza la
  pantalla de consentimiento y el filtrado de §C.7.3.
- Web de prueba que solicite la credencial por la Digital Credentials API.

**Por qué es barato y de alto retorno:** es API pública, **sin allowlist ni aprobación
de Google**, soporta mdoc 18013-5 nativamente y funciona desde Android 6 (API 23).

**Aceptación:** una web o app de prueba que solicite una credencial por la Digital
Credentials API ve `cdpi-wallet` en el selector del sistema y recibe una presentación
válida.

### C.7.4 Reader de la POC (~1,5-2 sem)

App RN de referencia que ejercita el flujo completo. **Es el germen del SDK del Tramo
D, no código desechable:** se escribe ya con la separación core/transporte de §D.2,
de modo que el Tramo D lo empaqueta en vez de reescribirlo.

**Para la POC** se usa `openwallet-foundation/multipaz-identity-reader` (Apache-2.0)
**sin forkear**, como reader de contraste — importando la IACA por su UI existente
(`TrustedIssuersScreen` → `addX509Cert`). Esto valida que nuestros mdocs son
verificables por un reader independiente, que vale más que verificarlos con código
nuestro.

> **Verificado en su código:** `ReaderModel.kt` (337 L) con el flujo
> `MdocRole.MDOC_READER → SessionEncryption → transport.open() → sendMessage →
> decryptMessage`; `DeviceResponseParser` con las dos mitades de 9.1;
> `TrustManagerLocal`, `CompositeTrustManager`, `VicalTrustManager`, `X509Crl`;
> `multipazctl` para PKI de readers. Pinea Multipaz **0.96.0** (upstream va por
> 0.100.0). La issue **#1850** (`waitForConnection` en CONNECTING) es **posterior** a
> 0.96.0 y probablemente no le afecta.
>
> **Limitación conocida:** el upstream valida la cadena contra `Clock.System.now()`
> (`ShowResultsScreen.kt`), no contra el instante `signed` del MSO (§S-5). Para la POC
> es irrelevante (certificados recién emitidos); para el SDK del Tramo D hay que
> implementarlo bien.

**Modelo de errores** (aplica a la POC y al SDK):

| # | Fallo | Significado para el operador |
|---|---|---|
| 1 | `IssuerAuth` inválido | Documento falsificado |
| 2 | Digest de un elemento no cuadra | Documento alterado |
| 3 | `ValidityInfo` fuera de rango | Documento caducado |
| 4 | DSC no vigente **en el instante `signed`** | Certificado del emisor inválido — **no** "caducado hoy" |
| 5 | Cadena a IACA rota | Emisor desconocido |
| 6 | EKU incorrecto | Certificado mal emitido |
| 7 | `DeviceSignature` inválida | El respondedor no posee la clave del MSO. **NO detecta un clon con clave extraída** (§S-4) |
| 8 | `SessionTranscript` no coincide | Replay detectado |
| 9 | Sesión BLE caída | Reintentar |

**Aceptación:** verifica los mdocs de `internal/mdl/` **y** acepta los vectores
`@owf/mdoc/tests/examples/{bdr,france,google,ubique}`.

### C.7.5 Ampliación a mDL conforme (~1 sem)

`portrait` + elementos opcionales. **Aquí la credencial pasa a ser un mDL conforme**
(los 11 mandatory). El chunking ya se validó en Fase 0 con payload sintético.

**Aceptación:** `DeviceResponse` con los 11 mandatory se transmite y verifica.

### C.7.6 Testing y CI (transversal)

- **Go:** unitarios en `internal/mdl/`. El CI (`.github/workflows/image.yml`) ya cubre
  `internal/**`.
- **TS:** Jest con `testEnvironment: node`, `testMatch src/__tests__/**/*.test.ts`.
- **Cruce issuer↔verificador:** el harness Node verifica todo mdoc emitido. Es lo que
  evita que un error de interpretación compartido pase desapercibido en ambos lados.
- **Fuera de CI:** BLE requiere hardware. Checklist manual en
  `docs/mdl-manual-checklist.md`.

**Aceptación:** vectores externos en verde; harness cruzado en verde; checklist
ejecutado una vez.

### C.7.7 Demo (~2 días)

**Aceptación del Tramo C = esta demo ejecutada de principio a fin.** Requiere el
guion de §C.2 si hay audiencia externa.

1. Emisión de un mDL desde `verifiably` al wallet.
2. **El reader se pone en modo avión** (es el reader quien verifica offline).
3. Reader escanea QR, conecta por BLE, pide atributos.
4. El holder muestra consentimiento; se aprueba.
5. Reader muestra las dos validaciones de 9.1 en verde.
6. **Caso negativo:** mdoc manipulado → error #2.
7. **Caso de privacidad:** el reader pide solo `age_over_18` → muestra "mayor de 18:
   sí" y **no recibe `birth_date`**; se verifica en el `DeviceResponse`.
8. **Evidencia de canal:** captura BLE sin PII en claro.
9. **Selector del sistema:** una web de prueba pide la credencial por la Digital
   Credentials API → Android ofrece `cdpi-wallet` en su selector → presentación válida
   (criterio de éxito #6).

**Limitación:** con el holder en background en iOS los service UUIDs pasan al
*overflow area* y un reader Android no lo ve. Irrelevante aquí (Android-only).

## C.8 PKI

```go
// internal/signer/signer.go  (ubicación sujeta al conflicto P1 de §C.3)
type Signer interface {
    Sign(ctx context.Context, payload []byte) ([]byte, error)
    // Cadena completa DSC→IACA: x5chain lo exige.
    CertificateChain() []*x509.Certificate
}
```

`SoftwareSigner` hoy; producción = `KMSSigner`/`HSMSigner` + nueva cadena en config.

**Protección del material (requisitos):**
- **Privadas de IACA/DSC nunca en el repositorio.** Fuera del árbol, permisos
  restrictivos, salida de `pki/` en `.gitignore`.
- **Marcado detectable:** subject con `O=POC-DO-NOT-TRUST`.
- **IACA de POC: 90 días** — no la vida típica de producción (~9 años, que es
  recomendación derivada, no perfil normativo del Annex B; el Annex B no impone
  mínimo). Una IACA que caduca sola es la defensa más barata contra su filtrado a
  producción.
- **DSC con validez ≤ la de la IACA**, o la cadena falla a mitad de demo.
- **Check de arranque** que rechace arrancar fuera de dev con `SoftwareSigner` o con
  una IACA marcada como POC.

## C.9 Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **Demanda no documentada** (§Origen sin completar) | **Crítico** | Gate del Tramo A |
| **Riesgo reputacional de la demo** ante gobiernos | **Alto** | §C.2 — guion, regla de audiencia, posicionamiento vs. GET Group |
| **Material de PKI de POC filtrado a producción** | **Alto** | Subject marcado, 90 días, clave fuera del repo, check de arranque |
| **Clave de dispositivo en software** ⇒ clonable pese a device auth | **Alto** | Fase 0 mide y documenta; si es software, se declara |
| **Relay attack no mitigable** por el estándar | **Alto** (residual) | Mitigación operativa; declarado |
| **Colisión con el P1 de signer** del roadmap | Medio-alto | Decidir antes de empezar (§C.3) |
| Wallet responde a cualquier reader (sin `ReaderAuth`) | Medio-alto | Consentimiento del holder; `ReaderAuth` en trabajo futuro |
| Android peripheral irregular por fabricante | Medio-alto | Fase 0 en 2 fabricantes; detectar vía `BluetoothLeAdvertiser` |
| **Validación del DSC ausente en el upstream** | Medio | Irrelevante en la POC (certs recién emitidos); ítem del Tramo D |
| Reloj del reader manipulable | Medio | Declarado; producción exige fuente de tiempo confiable |
| `veraison/go-cose` sin mantenimiento (9 meses) | Medio | Aislar tras `Signer`; **descalificante para producción** |
| Multipaz pre-1.0 (0.96.0 en el reader de contraste, upstream 0.100.0), 1.0 previsto fin 2026/inicio 2027 | Medio | Pinear exacto; el Tramo D depende de su estabilización |
| `proof_types_supported.cwt` puede no estar soportado | Medio | Verificar contra walt.id antes de codificar |
| Hardware: 2 Android + sniffer BLE | Medio | Resolver antes de Fase 0 |
| Reactivar `iso_mdl` reintroduce lo de `6449f96` | Bajo | El round-trip problemático era contra MOSIP/Inji |
| Certificación OIDF no es gratuita | Bajo | Tests gratis; certificar ~$700/$3.500. No está en alcance |

## C.10 Fuera de alcance del Tramo C

- **`ReaderAuth`** — opcional en el estándar; 7.2.1 **prohíbe** condicionar los
  elementos mandatory a ella. Consecuencia: **el wallet responde a cualquier reader
  sin identificar**. Trabajo futuro junto con la PKI de readers.
- **iOS** — `cdpi-wallet` no tiene directorio `ios/`. La POC es Android-only. **El SDK
  del Tramo D sí es iOS + Android** (§D.5).
- **Key attestation**, certificación oficial, revocación automática.
- **NFC** ⇒ el engagement es por **QR**.
- `DeviceMac` (se usa `DeviceSignature`), oráculo backend, y modificar los adapters
  para formatos no-mdoc.
- **Interoperabilidad cross-border real** — ver §Anexo: no es un problema técnico sino
  político.

---

# TRAMO D — SDK RN embebible v1 (~3-4 meses, tras gate C)

**Este es el producto.** Los Tramos B y C validan; D es lo que INTRANT, el MTC, la
policía, bancos y aeropuertos **incorporan a las apps que ya tienen**.

## D.1 Alcance de la v1 (decidido)

**v1 = solo `mdoc central client mode` + engagement por QR.** Se declara
explícitamente que **`mdoc peripheral server mode` llega en v2**.

Razón: Google exige a los lectores soportar **ambos** modos BLE, y en React Native
**no existe ninguna librería mantenida con soporte peripheral** — `ble-plx` lo lista
bajo *"It does NOT support"*, y las alternativas están muertas
(`react-native-ble-advertiser` 2022, `react-native-peripheral` 2019,
`ble-manager` central-only). Cubrir peripheral cuesta 8-12 semanas de módulo nativo y
es el 60-70% del esfuerzo total.

> **Consecuencia declarada:** una v1 solo-central **no interopera con holders que solo
> soporten peripheral server mode** (existen: el issue #728 de Multipaz documenta un
> holder de Scytáles así). Se dice en la documentación del SDK, no se descubre en
> campo.

## D.2 Arquitectura del paquete (4 capas)

```
@cdpi/mdl-core          JS puro, cero deps nativas. Testeable en Node y en CI.
                        └─ @owf/mdoc + MdocContext sobre @noble/*
                        └─ trust store, validación de cadena X.509 + EKU
@cdpi/mdl-transport-ble Módulo nativo que envuelve Multipaz (§D.3)
                        └─ app.plugin.js: permisos iOS + Android
@cdpi/mdl-verifier      Fachada: orquesta core + transport. API pública.
@cdpi/mdl-react         Hooks opcionales (useProximityVerification)
```

**Cuatro decisiones de diseño:**

1. **`mdl-core` sin dependencias nativas** — permite tests en CI sin dispositivo, uso
   en backend, y que un integrador con restricciones de build use solo el core.
2. **`@noble/*` por defecto, no `react-native-quick-crypto`** — noble cubre HKDF y
   ECDH P-256 en JS puro; quick-crypto **no tiene ECDH** y arrastra una peer-dep de
   Nitro Modules. Se deja como backend opcional inyectable vía `MdocContext`.
3. **Evitar `@peculiar/x509` en el path crítico** — requiere WebCrypto y
   `reflect-metadata` en RN. **Y ojo con el `X509Certificate` de quick-crypto: su
   getter `keyUsage` no distingue KeyUsage de ExtendedKeyUsage**, y EKU es
   precisamente lo que hay que validar en certificados mDL.
4. **Transporte tras una interfaz** — permite sustituir la implementación sin romper
   la API pública.

**API pública** (modelada sobre la de MATTR, que es el estado del arte):

```ts
initialize(config)
addTrustedIssuerCertificates(certs)   // anclas IACA
createProximityPresentationSession(deviceEngagement)
sendProximityPresentationRequest(session, docType, elements)
terminateProximityPresentationSession(session)
```

## D.3 Transporte: envolver Multipaz, no reescribir BLE

**Decisión: `@cdpi/mdl-transport-ble` envuelve Multipaz** (OWF, Apache-2.0, Kotlin
Multiplatform, Android + iOS vía SKIE) en un módulo RN.

Razones:
- Multipaz ya resuelve **ambos** modos BLE, session encryption y el estado de sesión
  18013-5. Es el motor reader que la propia Google recomienda.
- Convierte "implementar ISO 18013-5" en "escribir bindings": **~3-4 meses en vez de
  ~7-11**.
- Aunque la v1 solo exponga central client mode, **el camino a peripheral en v2 queda
  pavimentado** en vez de cerrado — Multipaz ya lo trae.
- **El binding RN no existe hoy y es contribuible upstream a OWF**, lo que da a CDPI
  presencia institucional en el ecosistema en vez de deuda de fork.

**Plantilla exacta:** `openwallet-foundation-labs/expo-mdoc-data-transfer` (Animo →
OWF Labs) es literalmente esta arquitectura del lado *holder* — Expo Module
envolviendo librerías nativas EUDI, con `plugin/src/withIos.ts` + `withAndroid.ts`
para permisos, y hasta el `pre_install` hook de CocoaPods. Nuestro SDK es su espejo
verificador.

> **Advertencia de esa plantilla:** exige `useFrameworks: "dynamic"` en iOS, una
> imposición dura sobre el build del integrador que rompe apps con dependencias que
> requieren static. **Evaluarlo antes de replicar ese patrón.**

## D.4 Empaquetado para integradores (es un requisito, no un detalle)

El SDK se juzga por lo fácil que sea meterlo en una app existente.

- **Permisos Android:** manifest merging — el `AndroidManifest.xml` de la librería
  declara `BLUETOOTH_SCAN`/`BLUETOOTH_CONNECT` y se fusiona solo, sin acción del
  integrador. (Patrón de `ble-plx`.)
- **Permisos iOS:** `app.plugin.js` inyecta `NSBluetoothAlwaysUsageDescription` con
  texto personalizable, respetando el valor existente del integrador.
- **Expo y bare RN:** ambos soportados — config plugin para Expo/CNG; manifest
  merging + autolinking de CocoaPods para bare.
- **Conflictos de versiones:** las dependencias que el integrador pueda ya tener van
  como `peerDependencies` con rango amplio, nunca como `dependencies`.
- **Rango de RN soportado:** MATTR exige RN 0.81+. Nuestro público son **apps
  existentes de bancos y ministerios, que suelen ir rezagadas** — soportar RN 0.75+
  con arquitectura nueva y vieja es ventaja competitiva real y coste de mantenimiento
  a presupuestar.

## D.5 Plataformas

**iOS y Android**, ambos. Bancos y aeropuertos necesitan iOS sí o sí.

- **Central en iOS** (`ble-plx` / Multipaz): maduro y estable.
- Las limitaciones serias de `CBPeripheralManager` en iOS son de **background**
  (service UUIDs al *overflow area*, `LocalName` ignorado). **Irrelevantes para
  verificación presencial atendida**, que es foreground por definición.
- **NFC engagement en iOS no es viable** — MATTR lo ofrece solo en Android. **v1 es
  QR-only** en ambas plataformas.

## D.6 Certificación (posicionamiento honesto)

- **AAMVA no certifica lectores** — sus *Implementation Guidelines* declaran
  explícitamente fuera de alcance *"Responsibilities of mDL verifiers"*. Su rol
  relevante es **VICAL**, para distribuir anclas IACA.
- **UL Solutions** sí opera un **mDL Reader Test Suite** (contra ISO 18013-6). Fime
  ofrece suites de identidad digital. Sin precios públicos.
- **La certificación aplica a un producto terminado con un bundle ID, no a una
  librería.** El patrón correcto (Regula, IDEMIA): **el integrador certifica su app**;
  el SDK aporta evidencia de conformidad —vectores de test, reporte de interop— para
  abaratarle el proceso.
- **No se promete "SDK certificado".** Sí se puede ejecutar el UL Reader Test Suite
  contra la app de referencia y publicar resultados.

> **El riesgo real para INTRANT o un banco no es la certificación, es la gestión del
> trust store**: VICAL, certificados IACA, revocación y rotación. Es trabajo operativo
> continuo, no de una vez, y hay que decírselo antes de que lo adopten.

## D.7 Esfuerzo

Con 1 dev senior RN + 1 con experiencia nativa/cripto:

| Componente | Esfuerzo | Riesgo |
|---|---|---|
| Core mdoc (`MdocContext` sobre noble, verificación, parsing) | 3-4 sem | Bajo — `@owf/mdoc` hace el trabajo pesado |
| Trust store + X.509 + EKU + VICAL + revocación | 3-4 sem | Medio — hueco real en `@owf/mdoc` |
| Binding RN a Multipaz, central client mode | 4-6 sem | Medio-alto |
| Device engagement por QR | 2-3 sem | Medio |
| Empaquetado y DX (config plugins, matriz Expo/bare) | 3-5 sem | Medio — **siempre se subestima** |
| Docs, app de referencia, vectores de interop | 3-4 sem | Bajo |
| **Interop real con wallets** (Apple/Google Wallet, wallets estatales) | 4-8 sem | **Alto — impredecible** |

**Total v1: ~3-4 meses.** Con peripheral server mode propio serían ~7-11.

**Lo caro no es la criptografía** —la parte que intuitivamente parece difícil es la
más resuelta— sino el transporte y la interoperabilidad real.

## D.8 Riesgos propios del Tramo D

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **v1 sin peripheral server mode** no interopera con algunos holders | **Alto** | Declarado en docs del SDK; v2 lo cubre vía Multipaz |
| **Multipaz pre-1.0** (1.0 previsto fin 2026/inicio 2027), API inestable entre minors | **Alto** | Pinear exacto; el binding aísla al integrador de sus cambios |
| Empaquetado nativo rompe builds de integradores (`useFrameworks: dynamic`) | Medio-alto | Evaluar antes de replicar el patrón de expo-mdoc-data-transfer |
| Soportar RN antiguo (bancos/ministerios rezagados) | Medio | Decidir el rango soportado desde el día uno y presupuestar el mantenimiento |
| Gestión del trust store en producción (VICAL, IACA, revocación) | Medio | Documentar como responsabilidad operativa continua del integrador |
| MATTR ya vende esto | Medio | No competimos como vendor: SDK abierto, sin contrato, para infraestructura pública |

---

# Anexo — Contexto regional y modelo de confianza

*Este análisis es el insumo principal del Tramo A y el activo más reutilizable del
documento.*

## Estado real de la región

Ningún país latinoamericano **soberano** tiene mdoc operativo. El único despliegue
ISO 18013-5 real de la geografía es **Puerto Rico** (territorio de EEUU, ecosistema
AAMVA): **83.195 mDLs a 31 mar 2026**, 2,59% de 3,2M conductores.

**RD es la señal más fuerte:** INTRANT enmarca su proyecto en ISO/IEC 18013-5:2021 —
pero las fuentes dicen *"alineado al"*, nunca *"certificado"*, y el mDL es fase 2 sin
lanzar. **GET Group** (del consorcio) es el vendor del mDL de Utah.

**Advertencia metodológica:** en esta región *"estándares internacionales"* e *"ISO"*
hacen mucho trabajo no ganado. **Colombia** referencia `ISO/IEC CD 18013-5` — un
**Committee Draft** — en el case study de IDEMIA (feb 2022; sistema lanzado nov 2020,
antes de que 18013-5:2021 existiera). **Ecuador** dice "ISO" genérico sin versión.
**Brasil CNH Digital no es ISO 18013-5** — es PDF firmado ICP-Brasil + QR.

## VICAL y por qué no hay federación

VICAL está en el **Annex C, informativo** (el Annex B, perfiles de certificado, es
normativo). Verificado descargando el VICAL de producción de AAMVA: `COSE_Sign1`
ES256, header `33` = `x5chain`, firmante con EKU `1.0.18013.5.1.8`.

**Asimetría decisiva:** consumirlo es global y gratuito; **ser emisor está restringido
a Norteamérica**. **Perú y RD no pueden entrar al VICAL de AAMVA.** No existe
federación entre VICALs ni raíz de raíces (no hay equivalente al ICAO PKD).

Para dos países, el modelo viable es **intercambio bilateral de IACAs**. Multipaz ya
trae `VicalTrustManager` si algún día se consume un VICAL ajeno.

## España y la UE

- **Directiva (UE) 2025/2205** (22 oct 2025, en vigor 25 nov 2025). **Art. 5(7):**
  *"By 26 November 2026, the Commission shall adopt implementing acts laying down
  detailed provisions concerning… the trusted lists of trusted issuers for verifying
  mobile driving licences"*. El art. 5(5) es la obligación de comunicar la lista de
  emisores. Transposición 26 nov 2028; aplicación 26 nov 2029.
- ⚠️ **La Directiva no menciona "ISO" ni "18013".** El vínculo proviene de prensa, no
  del texto legal; el formato queda **diferido a los actos de ejecución**. **No debe
  asumirse que la UE mandata mdoc.**
- **No existe puente VICAL↔eIDAS.** La UE usa ETSI TS 119 612 / 119 602 con LOTL.
- ARF de referencia: **v3.0.0 (23 jul 2026)**.
- **España no emite mDL ISO 18013-5.** miDGT y MiDNI son **QR online**. No hay a qué
  conectarse hoy. *(El instrumento real es **RD 255/2025**, Interior, DNI físico y
  digital. No existe un "RD 1/2025" sobre cartera digital.)*

## Revocación

**ISO/IEC 18013-5:2021 no define ningún mecanismo de revocación de mDL.** El reader
verifica `ValidityInfo` del MSO contra su reloj (9.3.1.f). La revocación *de
certificados* va por **CRL X.509 (RFC 5280)**, Annex B normativo; Multipaz trae
`X509Crl`.

Control de vigencia = `validUntil` + `expectedUpdate` + re-emisión periódica, acotado
por `validUntil ≤ expiry_date`. El refresco **automático** queda fuera de alcance.

**2ª edición:** estado DIS (proyecto ISO 91081), publicación prevista **Q4 2026**.
Añade revocación de MSO; los nombres concretos (ASL/ARL) **no confirmados contra
fuente primaria ISO**.

---

## Decisiones pendientes

**De negocio (ya NO bloquean — resueltas 2026-08-20, detalle administrativo pendiente):**
1. ~~Completar §Origen y demanda.~~ Demanda confirmada: INTRANT y MTC, ambas piden
   emisión y verificación. Faltan por registrar: interlocutor, fecha, formato de la
   petición, plazo, sponsor interno — ver tabla en §Origen y demanda.
2. ~~¿Lo que se pidió es emisión o verificación?~~ Ambas — el Tramo C es necesario.
3. **Sponsor interno** y **costo de oportunidad** frente a las tres P1 del roadmap —
   sigue sin confirmar explícitamente; no bloquea el trabajo técnico en curso, pero
   conviene cerrarlo antes de comprometer más tiempo del ya invertido.

**Técnicas (bloquean el inicio del Tramo C):**

| # | Decisión | Bloquea | Dueño | Fecha |
|---|---|---|---|---|
| 4 | `proof_types_supported.cwt` vs `jwt` — verificar contra la versión de walt.id en uso | C.7.1 (endpoint de proof) | _(pendiente)_ | _(pendiente)_ |
| 5 | **Colisión con el P1 de signer** (§C.3): ¿`internal/signer/` como P1 propio que el Tramo C consume, o algo local? | C.7.1 (primera línea de `sign.go`) | _(pendiente)_ | _(pendiente)_ |
| 6 | Qué dos teléfonos Android concretos (fabricantes distintos) | C.7.0 | _(pendiente)_ | _(pendiente)_ |

La #5 es la más urgente: sin dueño se resolverá tarde, y §C.3 la declara *"a resolver
antes de empezar"*.

**Del Tramo D (no bloquean C):**
7. Rango de versiones de RN a soportar en el SDK (§D.4).
8. ¿Se contribuye el binding RN de Multipaz upstream a OWF? (§D.3).

**Fuera de los Tramos A-D (spec aparte):**
9. **Verificación online 18013-7 en `verifiably`** — reutiliza la infraestructura
   OID4VP existente, pero exige cerrar los gaps HAIP ya autodocumentados
   (`direct_post.jwt`/JARM, `client_id_scheme=x509_san_dns`, wallet attestation).
   Tiene hogar asignado (§Reparto) pero **no plan**: necesita su propio spec.

---

# Apéndice W — Ruta a las wallets nativas (referencia, no alcance)

*Documentado para que no haya que reinvestigarlo. Nada de esto es trabajo de los
Tramos A-D; sirve para (a) responder a un gobierno que pregunte, y (b) no cerrar
puertas hoy por descuido.*

**Corrección respecto a lo que se creía:** Google **no** es una partnership opaca —
tiene documentación pública completa, email de intake publicado, sandbox real y test
plan. Es ingeniería con puerta conocida. **Apple sí es cerrada de verdad.** Son dos
procesos de naturaleza distinta y deben planificarse por separado.

## W.1 Google Wallet — Digital Credentials Provisioning API

**Punto de entrada real:** `wallet-vdc-issuer-intake@google.com` (publicado en la
página *Get started*). No hay formulario web. El correo debe incluir: tipo de
credencial, atributos, **doctype** (`org.iso.18013.5.1.mDL`), formato (**mdoc** o
SD-JWT), casos de uso y relying parties, **volumen de emisión proyectado** y países de
operación.

**Las 6 fases documentadas:**

1. Solicitud inicial por email.
2. Revisión de Google *(criterios de aceptación no publicados)*.
3. Intercambio de certificados **mTLS** *(la CA de origen se define aquí; no está
   documentada)*.
4. El emisor completa el **onboarding sheet**.
5. Google entrega el **Issuer ID (o Vendor ID)** → empieza el testing.
6. Test plan end-to-end → producción.

**Requisitos técnicos (documentados y verificables):**

- **mTLS bidireccional.** Google presenta certificado cliente que **el emisor debe
  pinnear**; el emisor presenta el suyo, validado contra CAs. Prohibidos ciphers NULL
  y anónimos; permitidos ECDHE-ECDSA/RSA con AES-128/256-GCM o CHACHA20-POLY1305.
  **Rotación anual** asistida por un representante de Google.
- **12 endpoints que el emisor debe exponer** (recurso `vdc`): `healthCheck`,
  `getIdentityKey`, `getHybridEncryptionKey`, `getDeviceRegistrationNonce`,
  `registerDevice`, `proofUser`, `getProofingStatus`, `cancelProofing`,
  `provisionCredential`, `provisionMobileSecurityObjects`, `getCredentialStatus`,
  `notifyCredentialDeleted`.
- **Criptografía:** HPKE base mode — KEM `DHKEM(P-256, HKDF-SHA256)`, KDF
  `HKDF-SHA256`, AEAD `AES-256-GCM`. **P-256 en todo el sistema.**
  Rotación: **Identity Key anual**, **Hybrid Encryption Key trimestral**.
- **Protocolos aceptados:** la API propietaria de Google **u OpenID4VCI** — de ahí que
  emitir por OID4VCI desde hoy sea una decisión barata con retorno futuro.
- **Regla operativa:** no liberar MSOs hasta haber verificado el `ProofOfProvisioning`.

**Requisitos no técnicos:** 5 componentes obligatorios de diseño de tarjeta (escudo
oficial, tipografía, símbolo, fondo, tema de color); **los assets van a revisión de
Google ~2 meses antes del lanzamiento** — es el único plazo numérico que Google
publica, y determina la fecha de lanzamiento hacia atrás. Obligatorio soportar borrado
por usuario y revocación por emisor.

**Sandbox:** real y disponible. Se activa en Android (Settings → cuenta Google → All
services → TapAndPay Environment → SANDBOX → reboot); si el toggle no aparece, se pide
allowlist con el *Google Pay Sandbox Access Request form*. Incluye un país ficticio de
pruebas, **"Utopia"**, con su IACA de sandbox. Google advierte explícitamente que no
tiene SLA de uptime.

**Timelines reales observados:** Montana — ley en 2023 → lanzamiento sep 2025 (**~2
años**). California — piloto 2023 → Google Wallet ago 2024. Google no publica
duraciones de fase.

## W.2 Apple Wallet — IDs in Apple Wallet

**No existe formulario, email de intake ni criterio de elegibilidad público.** La vía
es business development institucional. Apple retiene *"sole discretion"* sobre el
rollout. Su orientación a ciudadanos es "consulte con su autoridad emisora": el flujo
va Apple → gobierno, no al revés.

**Términos contractuales conocidos** (contratos de Georgia, Arizona, Kentucky y
Oklahoma obtenidos por *public records*):

- **Costos:** el emisor paga todo — emisión, mantenimiento, servicing y marketing.
  *"Neither Party shall owe the other Party any fees"*: Apple no cobra, pero tampoco
  aporta.
- **Personal:** obligación de asignar *"reasonably sufficient personnel and
  resources… on a timeline **to be determined by Apple**"*, incluyendo project managers
  dedicados.
- **Control:** Apple decide cuándo se lanza y en qué dispositivos.
- **Marketing:** el emisor debe *"prominently feature the Program in all public-facing
  communications"* y ofrecerlo proactivamente en trámites y renovaciones. Apple tiene
  **aprobación previa de todo el material**.
- **QA:** conforme a *"Apple's certification requirements"* — **no públicas**.

**Requisitos técnicos conocidos:** ISO/IEC 18013-5 para transmisión, **18013-7 Annex C**
para autenticación del lector, ICAO 9303 para chip de pasaporte, W3C DC API para web.
Par de claves generado **dentro del Secure Element**. La validación se ancla en
**CSCA** (modelo ICAO), **no en AAMVA** — relevante para un país no norteamericano.

**El precedente Japón (el único no-US) y lo que enseña:** lo negoció la **Digital
Agency** con impulso de jefe de gobierno a CEO (Kishida ↔ Tim Cook); anuncio may 2024 →
lanzamiento jun 2025 (**~13 meses** desde el anuncio, sobre negociación previa de
duración desconocida); ~100M de tenedores; y requirió **cambio normativo previo** que
habilitara el ID nacional para wallets de terceros. **Ninguno de esos cuatro factores
es técnico.**

## W.3 Prerrequisitos comunes (antes de tocar la puerta)

1. **Habilitación legal** del documento móvil y su integración en wallets de terceros.
   *(Lección Japón: va primero, no después.)*
2. **PKI operativa**: IACA + DSC con HSM y ceremonias de clave. **Un país que ya emite
   pasaporte electrónico con CSCA tiene medio problema resuelto conceptualmente.**
3. **Backend de alta disponibilidad** con los endpoints y rotaciones exigidos.
4. **Identity proofing** con liveness y decisión propia de aprobar/rechazar.
5. **Ciclo de vida completo**: update, revocación, borrado, notificaciones.
6. **Presupuesto plurianual y equipo dedicado** (contractualmente exigido por Apple).
7. **Volumen relevante** — Google lo pide en el intake; Apple lo pondera.

**Sobre VICAL de AAMVA:** **no aplica y no es posible** para RD ni Perú — el AAMVA DTS
es para jurisdicciones *"state, territorial and provincial"* de EEUU y Canadá. La ruta
no-US se ancla en la **CSCA nacional**.

**Sobre certificación (UL / Fime / ISO 18013-6):** **no es requisito publicado** por
ninguna de las dos. El test plan de Google no nombra certificador externo. Pero
certificarse es señal de credibilidad fuerte en la fase de revisión y de-riskea la
integración. **Recomendable, no obligatorio.**

**Sobre vendors:** es la **vía habitual** y acelera de verdad. IDEMIA (Iowa, Arkansas,
West Virginia), Thales (Oklahoma), GET Group (certificado UL en todos los modos de
18013-5). Ya tienen backend, mTLS, PKI, proofing, certificación — y, lo más valioso,
**relación previa con los equipos de Apple y Google**. Google asume este patrón: el
identificador que entrega es *"Issuer ID (**or Vendor ID**)"*.

## W.4 Secuencia recomendada

**Fase 0 — Fundamentos (12-24 meses, antes de contactar a nadie):** habilitación legal
→ decisión de arquitectura (mDL nacional anclado en CSCA) → PKI → **calidad de datos
del registro base** (donde más proyectos se atascan) → presupuesto y equipo.
*Procurement del vendor arranca el día 1: es el camino crítico más largo.*

**Fase 1 — Capacidad técnica** (paralelizable): backend + endpoints + mTLS + HPKE con
rotaciones; identity proofing; app/web emisora; *(opcional, alto valor)* certificación
UL o Fime.

**Fase 2 — Google primero, deliberadamente.** Es la puerta abierta, documentada, con
sandbox y sin fee. **Hacerlo primero genera el activo que abre la puerta de Apple: un
mDL real, en producción, con usuarios.** Intake → revisión → mTLS → onboarding sheet →
Issuer ID → sandbox → **assets 2 meses antes** → test plan → producción.

**Fase 3 — Apple, en paralelo desde Fase 0 pero con otra expectativa.** Iniciar el
acercamiento institucional temprano al mayor nivel posible, y/o vía vendor con relación
previa. **No poner Apple en la ruta crítica de ningún compromiso político con fecha** —
el timeline lo fija Apple.

## W.5 Qué de nuestro diseño ya prepara este camino

Decisiones ya tomadas en este spec que acercan la ruta sin coste adicional hoy:

| Decisión | Por qué ayuda |
|---|---|
| Emitir por **OpenID4VCI** (§C.5 AD-1) | Es uno de los dos protocolos que Google acepta |
| Interfaz `Signer` lista para **KMS/HSM** (§C.8) | La PKI con HSM es prerrequisito de ambos |
| PKI **IACA → DSC** conforme al Annex B (§C.7.1) | Es la base sobre la que se construye la CSCA/IACA de producción |
| **P-256 / ES256** en todo | Google exige P-256 en todo el sistema |
| Registro en **Android Credential Manager** (§C.7.3b) | Da presencia en el selector del sistema **sin** depender de ninguna de las dos empresas |

## W.6 Lo que NO está documentado públicamente

Para no inventar y para saber qué hay que preguntar por contacto directo:

- De qué CA debe provenir el certificado mTLS del emisor ante Google.
- Duración de cada fase del proceso de Google (solo se publica el plazo de assets).
- Criterios de aceptación o rechazo de Google en su fase de revisión.
- Cualquier punto de entrada formal, formulario o criterio de elegibilidad de Apple.
- El contenido de las *"Apple certification requirements"*.
- Si existe sandbox de Apple para emisores.
- Costos y SLA de ambos programas.
- **Ni RD ni Perú aparecen en ninguna lista de emisores soportados ni en anuncios de
  ninguna de las dos empresas.**

---

## Trabajo de seguimiento

- **iOS 26 — `IdentityDocumentServices`**: extensión *Identity Document Provider* para
  que `cdpi-wallet` aporte mdocs a la Digital Credentials API de Safari 26. **Iniciar
  pronto el Capability Request** del entitlement
  `com.apple.developer.identity-document-services.document-provider.mobile-document-types`:
  es *managed capability* y su criterio de aprobación **no está documentado
  públicamente**, así que el timeline es el cuello de botella.
- **Contacto exploratorio con el programa de Google Wallet** — el formulario de
  onboarding es gratis de enviar y su lenguaje admite *"private issuer"*. Contacto, no
  dependencia de roadmap. Apple realistamente exige que lo impulse un gobierno nacional.
- Key attestation para evidenciar el nivel de seguridad de la `deviceKey`.
- `ReaderAuth` + PKI de readers.
- Refresco automático vía `expectedUpdate`.
- Revisar revocación cuando publique la 2ª edición (Q4 2026).
- Vigilar los actos de ejecución de la Directiva (UE) 2025/2205 (26 nov 2026) — son
  los que definirán si la UE adopta mdoc.
- Migrar operaciones con la privada del device a la Secure Area vía askar.
