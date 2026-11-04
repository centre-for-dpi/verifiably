# Rotación centralizada de la llave de firma del emisor

**Fecha:** 2026-07-23
**Estado:** Diseño aprobado, pendiente de revisión profunda antes de escribir el plan de implementación.

## Contexto y problema

`verifiably-go` orquesta la emisión de credenciales a través de tres DPGs
(walt.id, Inji Certify, CREDEBL). Ninguno de los tres expone hoy un
mecanismo de rotación de la llave de firma del emisor diseñado desde Go —
cada uno la genera y gestiona a su manera, y verifiably-go no posee
ninguna de las tres llaves privadas hoy.

Existe ya un plan previo (memoria `project-pluggable-signer`,
`verifiably-go/TODO.md` §"PKI / HSM / KMS Integration") para introducir
`internal/signer/` — una abstracción `Provider` sobre `crypto.Signer` con
backends intercambiables (`pem`, `pkcs11`, `x509chain`, `remotekms`). Ese
plan apuntaba originalmente solo a dos llaves auxiliares: el JWT del trust
registry (`internal/trust/jwt.go`) y la firma JWS de status lists
(`internal/statuslist/jws.go`).

Este documento extiende ese mismo `internal/signer/` para cubrir una
tercera llave — la que firma las credenciales emitidas (SD-JWT VC) — y
define cómo se entrega/consume esa llave en cada uno de los tres DPGs,
dado que cada uno tiene un modelo de posesión de llave distinto.

**Objetivo:** un punto único en Go desde el cual se decide dónde y cómo
vive la llave del emisor (generada internamente, SoftHSM, CloudHSM/KMS) y
desde el cual se dispara la rotación — adaptándose al mecanismo real que
cada DPG expone, en vez de asumir un modelo uniforme.

**No-objetivo de esta fase:** migrar las llaves de trust-registry o
status-list (ya cubiertas por el plan existente); implementar los
backends `pkcs11`/`awskms`/`azurekv` reales (quedan como siguiente fase,
una vez la interfaz esté probada con el backend `pem`/`jwk`).

## Hallazgos de investigación (por qué el diseño tiene esta forma)

### Los tres DPGs no comparten modelo de llave

| DPG | Dónde vive la llave privada hoy | Método DID en este deploy |
|---|---|---|
| walt.id | `issuer-api`, generada vía `POST /onboard/issuer` (backend `jwk` por defecto) | `did:web` (script `bootstrap-waltid-did.sh`), fallback `did:jwk` |
| Inji Certify | Postgres `certify.key_store`, protegida por MOSIP Key Manager sobre SoftHSM/PKCS12 (`mosip.kernel.keymanager.hsm.*`) | `did:web` fijo por instancia (`ISSUER_DID_DOMAIN`) |
| CREDEBL | Agente Credo (`agent-controller`, sucesor activo de `credo-controller`), wallet Askar | `did:web` (`AGENT_DID_METHOD=did:web`, `AGENT_DID_DOMAIN`) |

Los tres corren sobre `did:web` en este deploy — lo cual descarta la
fricción de "rotar implica una transacción on-ledger" (esa fricción solo
existiría si CREDEBL siguiera en `did:indy`/`did:sov`, o si cualquiera de
los tres usara `did:key`/`did:jwk`, donde el identificador *es* la llave y
rotar exige cambiar el DID mismo, no solo el material de firma).

### Cada DPG expone un mecanismo distinto para traer/rotar la llave

- **walt.id** es nativamente pluggable en su gestión de llaves: además del
  backend `jwk` (generado internamente, usado hoy), soporta backends
  externos — `tse` (HashiCorp Vault Transit), `azure` (Key Vault), `oci`
  (OCI Vault) — donde walt.id **nunca posee la llave privada**, solo
  recibe una referencia + credenciales de acceso al KMS en cada request
  de emisión (`issuerKey.type/server/auth/id`). El campo `id` es
  literalmente un `kid` versionable.
  Fuente: `docs.walt.id/community-stack/issuer/api/manage-keys/*`.

- **Inji Certify** no acepta una llave externa inyectada por request — el
  HSM (SoftHSM o real) está *detrás* de su propio Key Manager
  (`kernel-keymanager-service`), intercambiable por configuración de
  Certify (`hsm.keystore-type`, `hsm.config-path`), no por Go. El único
  control real desde fuera es orquestar el ciclo de vida vía
  `key_policy_def` (expiry) o la API REST del Key Manager. Certify ya
  tolera multi-`kid` de forma parcial: `internal/injidid/observed.go` +
  `InjiProxyPrimaryDidJSON` sirven un `did.json` con la unión de todos los
  `kid`s vistos firmando, precisamente porque Certify puede rotar sin
  avisar.

- **CREDEBL** (`agent-controller`, código verificado directamente —
  `src/controllers/did/DidController.ts::handleWeb`) expone
  `POST /did/write` con `method: "web"`, que acepta un `seed` provisto por
  el caller, deriva el JWK privado (`transformPrivateKeyToPrivateJwk`), lo
  importa vía `agent.kms.importKey`, y llama
  `agent.dids.import({ did, overwrite: true, ... })`. **Llamar este mismo
  endpoint de nuevo sobre el mismo `did:web:{domain}` con un seed distinto
  rota la llave** — confirmado en el código activo del repo
  `credebl/agent-controller` (sucesor de `credebl/credo-controller`,
  archivado 2026-01-21, `size: 0`). A diferencia de walt.id/`tse`, aquí el
  material privado (`seed`) viaja por la red hacia el agente — trade-off
  de seguridad explícito, no una limitación técnica.

### El problema silencioso: snapshot estático del documento DID

Dos de los tres DPGs sirven el `did.json` como archivo estático que nadie
regenera automáticamente tras una rotación:

- **walt.id**: `bootstrap-waltid-did.sh` genera el JSON una vez al deploy;
  Caddy lo sirve verbatim (`Caddyfile.public`, `respond` estático).
- **CREDEBL**: `_credebl_export_did_document` (en `bootstrap-credebl.sh`)
  hace `GET /dids` al agente y cachea el resultado en
  `.agent-runtime/did/did.json`, servido por nginx
  (`credebl-oid4vci-rewriter`) como archivo estático — no en vivo.
- **Inji Certify** es la excepción — ya tolera multi-kid vía el merge
  activo de `inji_proxy`.

**Consecuencia de diseño:** cualquier operación de rotación debe incluir,
como paso explícito, la republicación del documento DID — no basta con
rotar la llave en el DPG. Sin esto, los verificadores seguirían viendo la
llave vieja hasta el próximo restart/redeploy manual.

## Arquitectura propuesta

### `internal/signer/` — extendido para exponer referencias, no solo firmar

```go
// Provider ya existe en el plan previo (memoria project-pluggable-signer).
// Se le añade KeyRef() para que un backend pueda describirse a sí mismo
// sin exponer material privado — es lo que un DPG "pluggable" (walt.id)
// necesita para operar contra el mismo backend que Go.
type Provider interface {
    crypto.Signer
    Certificate() *x509.Certificate // nil si no aplica (no-PKI)
    KeyRef() KeyReference
}

// KeyReference nunca contiene material privado. Describe cómo referenciar
// la llave activa ante un consumidor externo (un DPG adapter).
type KeyReference struct {
    Backend string         // "jwk" | "tse" | "azure" | "oci" | "pkcs11" | "seed-transfer"
    Config  map[string]any // específico del backend: server+auth (tse), vaultURL (azure)...
    KeyID   string         // el "kid"/versión — pieza central de la rotación
}
```

Backends de fase 1: `pem` (ya existe, comportamiento actual) y `jwk`
(equivalente lógico, para hablar con walt.id backend `jwk`/CREDEBL
seed-transfer). `pkcs11`/`tse`/`azure`/`oci` quedan diseñados en la
interfaz pero implementados en una fase posterior, cuando haya un HSM o
KMS real contra el cual probarlos.

### `ProvisionIssuerKey` — un método por adapter, tres implementaciones reales

```go
// backend/adapter.go — extensión a la interfaz de adapter existente.
type KeyConsumer interface {
    // SupportedKeyBackends declara qué backends de signer.Provider este
    // DPG puede consumir. Si el backend configurado no está en la lista,
    // el adapter cae a su modo nativo y lo loguea como degradación.
    SupportedKeyBackends() []string

    // ProvisionIssuerKey configura o rota la llave activa del emisor.
    // Debe dejar la llave anterior resoluble (multi-kid) hasta que el
    // llamador confirme que ya no hay credenciales pendientes de
    // verificar contra ella.
    ProvisionIssuerKey(ctx context.Context, ref signer.KeyReference) error

    // PublishDIDDocument fuerza la republicación del did:web document
    // tras una rotación. Ver "problema silencioso" arriba — sin esto la
    // rotación es invisible para los verificadores.
    PublishDIDDocument(ctx context.Context) error
}
```

Implementaciones:

- **`internal/adapters/waltid`**: `ProvisionIssuerKey` llama
  `POST /onboard/issuer` con `key.backend = ref.Backend` y `ref.Config`
  reenviado tal cual (Go nunca genera la llave si el backend es `tse` —
  solo la referencia). `PublishDIDDocument` re-ejecuta la lógica de
  `bootstrap-waltid-did.sh` (regenerar el JSON + recargar Caddy).

- **`internal/adapters/injicertify`**: `ProvisionIssuerKey` traduce
  `ref` a una llamada a la API del Key Manager de Certify (o ajusta
  `key_policy_def` si no hay API directa disponible); si se pide un
  backend que Certify no sabe hablar, retorna
  `signer.ErrBackendNotSupported` explícito. `PublishDIDDocument` es casi
  un no-op — el merge de `kid`s observados ya lo cubre, pero se expone
  igual por consistencia de interfaz.

- **`internal/adapters/credebl`**: `ProvisionIssuerKey` llama
  `POST /did/write` (`agent-controller`) con `method: "web"`,
  `overwrite: true`, y el `seed` que Go entrega en `ref.Config["seed"]` —
  documentando explícitamente que el material privado transita por red
  hacia el agente (a diferencia de `tse` en walt.id). `PublishDIDDocument`
  invoca el equivalente de `_credebl_export_did_document` para refrescar
  el `did.json` cacheado que sirve nginx.

### Precondición transversal: tolerancia multi-kid

Antes de que cualquier rotación sea segura en producción, el sistema debe
tolerar múltiples `kid`/DID activos por emisor durante la ventana de
transición (credenciales ya emitidas con la llave vieja deben seguir
verificando). Esto ya es parcialmente cierto en Inji Certify
(`internal/injidid/observed.go`); no está garantizado hoy en el
verificador genérico ni en walt.id/CREDEBL. `ProvisionIssuerKey` no debe
invalidar la llave anterior — solo dejar de usarla para firmar credenciales
nuevas — y `PublishDIDDocument` debe publicar ambas mientras la ventana de
transición esté abierta.

### Punto de entrada único

```
POST /admin/signer/rotate?dpg=waltid|injicertify|credebl
```

Resuelve el adapter configurado para ese DPG, genera/registra la nueva
llave en el backend de `signer.Provider` elegido, llama
`ProvisionIssuerKey` seguido de `PublishDIDDocument`, y deja un registro
auditable (qué `kid` se activó, cuándo, quién lo disparó).

## Cuarto consumidor: mDL (mdoc / ISO 18013-5) — añadido 2026-08-21

Este diseño razona en términos de DIDs y `kid`s, correcto para los tres
DPGs de arriba porque los tres corren `did:web`. **mdoc no usa DIDs en
absoluto**: la confianza va por cadena X.509 (IACA → DSC) que el
verificador valida contra un ancla instalada de antemano. Cuando este
spec pase a plan de implementación, debe absorber tres requisitos que hoy
no contempla:

1. **Backend `x509chain` como ciudadano de primera.** `KeyReference`
   describe dónde vive la llave; mdoc necesita además la cadena de
   certificados que la acompaña. `Provider.Certificate()` ya está en la
   interfaz y el plan previo ya nombra `x509chain`, pero ninguno está
   desarrollado. Un `Provider` para mdoc debe exponer la cadena completa
   (DSC + IACA), no solo el certificado hoja.

2. **Distribución del ancla IACA — el análogo de `PublishDIDDocument`.**
   Para mdoc, republicar un `did.json` no sirve de nada: lo que el
   verificador necesita es el ancla IACA, y hoy se instala **a mano**
   (confirmado en pruebas de esta sesión: hubo que importar el
   certificado por la UI de `multipaz-identity-reader` para que aceptara
   la credencial). La Parte 4 de
   `docs/superpowers/adr/2026-08-20-mdl-production-path-analysis.md` ya
   analizó la forma correcta — una lista de anclas versionada y
   **firmada**, replicando lo que el backend de `multipaz-identity-reader`
   hace con `GET /trusted-issuers?version=N` — y descartó VICAL como
   prematuro. `KeyConsumer` necesita un método equivalente para este
   caso, o `PublishDIDDocument` necesita generalizarse a "publicar el
   material de confianza que corresponda a este formato".

3. **La ventana multi-`kid` tiene una restricción dura en mdoc.** El
   equivalente de tolerar dos `kid`s activos es la superposición de
   validez de dos DSC. ISO/IEC 18013-5 Annex B lo acota: un DSC no puede
   exceder 457 días de validez ni sobrevivir a la IACA que lo firma
   (ambos límites ya implementados y con tests en
   `internal/mdl/pki/pki.go`). La ventana de transición no es libre como
   en `did:web` — está topada por la vigencia del certificado.

**No bloquea al PR de mDL en curso.** Ese PR usa una llave EC P-256
estable inyectada para `issuer-api2`, marcada explícitamente como
provisional, y no introduce mecanismo propio de claves — precisamente
para no crear un camino paralelo que luego haya que reconciliar con este
diseño.

## Fuera de alcance de esta fase

- Backends reales `pkcs11`/`tse`/`azure`/`oci`/`awskms` — la interfaz los
  contempla, pero se implementan cuando haya infraestructura real contra
  la cual probarlos.
- Migración de las llaves de trust-registry/status-list al mismo
  `signer.Provider` (ya cubierto por el plan existente, no repetido aquí).
- Automatizar la ventana de expiración/revocación de la llave vieja tras
  una rotación (por ahora es un paso manual/documentado, no un scheduler).

## Riesgos y trade-offs a validar en la revisión profunda

1. **CREDEBL transfiere material privado por red** en `POST /did/write`
   — es un trade-off de seguridad real frente al modelo `tse` de walt.id,
   no solo un detalle de implementación.
2. **No está confirmado con un test real** que Inji Certify exponga una
   API de Key Manager operable desde fuera del contenedor — el diseño
   asume que existe algo orquestable vía `key_policy_def` o REST, pero no
   se validó contra una instancia corriendo.
3. **`agent-controller` es un repo verificado por código fuente, no por
   documentación oficial estable** — al ser relativamente nuevo
   (sucesor de `credo-controller`, archivado hace apenas medio año),
   conviene revisar si hay cambios entre versiones que rompan el contrato
   de `handleWeb`.
