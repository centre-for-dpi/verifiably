# Inji Certify (Pre-Auth) como segundo emisor de mdoc — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Incorporar Inji Certify (modo Pre-Auth únicamente) como un segundo emisor de mDL (ISO/IEC 18013-5, `mso_mdoc`) en `verifiably-go`, en modo redundancia/alternativa junto a walt.id `issuer-api2`, y corregir en `cdpi-wallet` el único bloqueante real de interoperabilidad encontrado.

**Architecture:** `internal/adapters/injicertify/` (ya en producción para formatos no-mdoc) gana soporte real para `mso_mdoc`: (1) `SaveCustomSchema` aprende a persistir un schema mdoc con `doctype`/`mso_mdoc_claims`/firma ECDSA correctos en la base de Inji Certify; (2) `IssueToWallet` (modo Pre-Auth) aprende a leer `req.StructuredData["driving_privileges"]` además de `SubjectData`, con la misma defensa-en-profundidad de 0/>4 categorías que walt.id ya tiene. Ningún código de selección de DPG cambia — el operador ya elige el DPG primero (`/issuer/dpg`) y luego el schema, mecanismo existente sin tocar. En `cdpi-wallet`, la rama `manual-mdoc` existente de `requestCredentials.ts` (ya activa para Inji vía `isLegacyEndpoint`) gana: detección/corrección del envoltorio `{docType, issuerSigned}` que Inji antepone al CBOR firmado, un chequeo de integridad estructural post-corrección, y un chequeo de confianza del emisor contra `/trust/mdoc-anchors` — este último se aplica a AMBOS DPGs (walt.id incluido), cerrando un hueco de seguridad preexistente que la revisión del spec encontró.

**Tech Stack:** Go 1.25 (`verifiably-go`), TypeScript/Jest + `@credo-ts/core` 0.6.3 + `@animo-id/mdoc` 0.5.2 (`cdpi-wallet`), PostgreSQL (Inji Certify's `certify.credential_config`), Docker (`golang:1.25-alpine` para build/test — no hay toolchain Go local).

**Spec:** `docs/superpowers/specs/2026-08-25-inji-mdoc-issuer-design.md` (revisado exhaustivamente, commit `0604439`)

## Global Constraints

- **Alcance: Inji Certify Pre-Auth únicamente.** El DPG Auth-Code (`inji_certify_authcode`) queda explícitamente fuera de alcance de todo este plan — ninguna tarea debe tocar `internal/handlers/schema.go`'s `injiOwnerSchemas`/`injiFormatToStd`, ni ningún archivo bajo el camino Auth-Code de `injicertify`.
- **No se toca la lógica de perfiles-por-conteo de walt.id** (`isoMdl_1cat`..`isoMdl_4cat`, `internal/adapters/waltid/`) — permanece exactamente como quedó tras el plan `2026-08-24-mdl-driving-privileges-variable-count`.
- **No se abstrae una interfaz Go común "mdoc issuer"** entre `waltid` e `injicertify` — cada adapter sigue implementando `backend.Adapter.IssueToWallet` de forma independiente.
- **No se reporta ni se depende de un fix upstream en `inji/inji-certify`** para el envoltorio `{docType, issuerSigned}` — se corrige exclusivamente en `cdpi-wallet`.
- **Límite operativo idéntico a walt.id**: 0 categorías de `driving_privileges` es error duro; más de 4 se rechaza — aplicado con la MISMA defensa en profundidad de dos capas que walt.id tiene (handler + adapter), porque `POST /api/v1/credentials/issue` puede invocar `IssueToWallet` evitando el handler.
- **La firma real del mdoc de Inji es ECDSA P-256/SHA-256** (confirmado en el spike) — cualquier config de firma que este plan escriba para el perfil mdoc de Inji debe reflejar esto, NUNCA los valores Ed25519 que `SaveCustomSchema` usa hoy para otros formatos.
- **Mensajes de error en español**, mismo tono que el resto del proyecto (ver `internal/handlers/issuance.go`, `internal/adapters/waltid/issuer2.go` para ejemplos de estilo).
- Cada tarea que modifique Go debe dejar su paquete con build/vet/tests en verde, verificado en Docker (`golang:1.25-alpine`, `MSYS_NO_PATHCONV=1` en Git Bash on Windows) — no hay toolchain Go local.
- Cada tarea que modifique TypeScript en `cdpi-wallet` debe dejar `npx jest <archivo afectado>` en verde, siguiendo el patrón de mock de `@credo-ts/core` ya establecido en `src/__tests__/storeCredentialMdoc.test.ts` (las clases mock se declaran DENTRO del factory de `jest.mock`, nunca a nivel de módulo — referenciar una clase top-level desde dentro del factory lanza `ReferenceError: Cannot access ... before initialization` porque el factory se hoistea por encima de la declaración).
- El chequeo de confianza contra `/trust/mdoc-anchors` (Tarea 6) se implementa una sola vez y se aplica a AMBOS DPGs (walt.id e Inji) en el camino `manual-mdoc` — no es específico de Inji, aunque este plan lo dispare.
- Cada commit se hace solo después de que la suite del paquete correspondiente esté en verde — no acumular cambios sin probar entre tareas.

---

### Task 1: `internal/mdoc/doctypes.go` — helper de firma ECDSA reusable

**Files:**
- Modify: `verifiably-go/internal/mdoc/doctypes.go`
- Test: `verifiably-go/internal/mdoc/doctypes_test.go` (crear si no existe, o añadir al archivo de test existente del paquete)

**Interfaces:**
- Consumes: nada nuevo.
- Produces: `SignatureAlgo() string`, una constante o función que declara `"ES256"` como el algoritmo real de firma de un mdoc ISO 18013-5 (confirmado en el spike: ECDSA P-256/SHA-256) — para que Task 3 (provisión del perfil Inji) no tenga que hardcodear el string suelto y quede una única fuente de verdad, análoga a como `DrivingPrivilegesMaxCategories` es la única fuente de verdad del límite de categorías.

- [ ] **Step 1: Escribir el test que falla**

```go
package mdoc

import "testing"

func TestMdocSignatureAlgoIsECDSAP256(t *testing.T) {
	// ISO/IEC 18013-5 mandates ES256 (ECDSA P-256/SHA-256) for the MSO's
	// COSE_Sign1 — confirmed empirically against a real issuer-api2 (walt.id)
	// AND a real Inji Certify v0.14.0 in the 2026-08-25 validation spike:
	// both produce a valid COSE_Sign1 with header {1: -7} (ES256's IANA
	// COSE algorithm identifier). This constant is the one place that fact
	// lives, so a future doctype/profile never hardcodes a different
	// algorithm by accident.
	if MdocSignatureAlgo != "ES256" {
		t.Errorf("MdocSignatureAlgo = %q, want %q", MdocSignatureAlgo, "ES256")
	}
}
```

- [ ] **Step 2: Confirmar que falla**

```bash
cd verifiably-go
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/mdoc/... -run TestMdocSignatureAlgoIsECDSAP256 -v
```

Esperado: `undefined: MdocSignatureAlgo` (no compila).

- [ ] **Step 3: Añadir la constante**

En `internal/mdoc/doctypes.go`, junto a la declaración de `FormatDrivingPrivileges`/`FormatImage` (mismo bloque de constantes de nivel de paquete):

```go
// MdocSignatureAlgo is the COSE signature algorithm every mdoc issued by
// this deployment uses: ES256 (ECDSA P-256/SHA-256). ISO/IEC 18013-5's MSO
// signs with COSE_Sign1, and ES256 is the algorithm both walt.id
// issuer-api2 and Inji Certify v0.14.0 actually produce — confirmed
// empirically (header {1: -7}, IANA COSE algorithm -7 = ES256) rather than
// assumed. Any new mdoc profile/schema config in this codebase (walt.id
// HOCON, Inji Certify's credential_config row) must declare THIS
// algorithm, never a default inherited from a non-mdoc format (e.g.
// injicertify's Ed25519 default for its other credential formats).
const MdocSignatureAlgo = "ES256"
```

- [ ] **Step 4: Confirmar que pasa**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/mdoc/... -v
```

Esperado: PASS, toda la suite del paquete `internal/mdoc` sigue en verde.

- [ ] **Step 5: Commit**

```bash
git add internal/mdoc/doctypes.go internal/mdoc/doctypes_test.go
git commit -m "feat(mdoc): declare MdocSignatureAlgo as the single source of truth (ES256)"
```

---

### Task 2: `internal/adapters/injicertify/db.go` — `stdToCredentialFormat` reconoce `mso_mdoc`

**Files:**
- Modify: `verifiably-go/internal/adapters/injicertify/db.go`
- Test: `verifiably-go/internal/adapters/injicertify/db_format_test.go` (archivo existente — añadir ahí, mismo patrón que sus tests actuales de `stdToCredentialFormat`)

**Interfaces:**
- Consumes: nada nuevo.
- Produces: `stdToCredentialFormat("mso_mdoc")` devuelve `"mso_mdoc"` (hoy cae al `default: "ldp_vc"`) — Task 3 depende de este valor correcto para ramificar el resto de `SaveCustomSchema`.

- [ ] **Step 1: Leer el test existente para el patrón exacto**

Abrir `verifiably-go/internal/adapters/injicertify/db_format_test.go` y confirmar el nombre de la función de test y su estilo de tabla (si usa subtests con `t.Run` o casos planos) antes de escribir el nuevo caso — seguir exactamente ese patrón, no inventar uno nuevo.

- [ ] **Step 2: Añadir el caso que falla**

Añadir al test existente (o crear uno nuevo en el mismo archivo si el existente no es una tabla extensible):

```go
func TestStdToCredentialFormatMsoMdoc(t *testing.T) {
	got := stdToCredentialFormat("mso_mdoc")
	if got != "mso_mdoc" {
		t.Errorf("stdToCredentialFormat(%q) = %q, want %q", "mso_mdoc", got, "mso_mdoc")
	}
}
```

- [ ] **Step 3: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run TestStdToCredentialFormatMsoMdoc -v
```

Esperado: FAIL — `got = "ldp_vc", want "mso_mdoc"`.

- [ ] **Step 4: Añadir el caso a `stdToCredentialFormat`**

```go
// stdToCredentialFormat maps verifiably-go's Std string to inji-certify's
// credential_format column value.
func stdToCredentialFormat(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return "ldp_vc"
	}
}
```

(Reemplaza el `switch` existente completo — es el mismo bloque, solo con un `case` nuevo antes de `default`.)

- [ ] **Step 5: Confirmar que pasa**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -v
```

Esperado: PASS, toda la suite del paquete sigue en verde (`db_protected_term_test.go`, `db_vcdm_test.go`, etc. no dependen del `default` de mdoc).

- [ ] **Step 6: Commit**

```bash
git add internal/adapters/injicertify/db.go internal/adapters/injicertify/db_format_test.go
git commit -m "feat(injicertify): stdToCredentialFormat recognizes mso_mdoc"
```

---

### Task 3: `internal/adapters/injicertify/db.go` — `SaveCustomSchema` persiste un perfil mdoc real

**Files:**
- Modify: `verifiably-go/internal/adapters/injicertify/db.go`
- Test: `verifiably-go/internal/adapters/injicertify/db_mdoc_test.go` (crear)

**Interfaces:**
- Consumes: `stdToCredentialFormat` (Task 2), `mdoc.MandatoryFields`, `mdoc.MdocSignatureAlgo` (Task 1), `mdoc.FormatDrivingPrivileges`/`mdoc.FormatImage` (`internal/mdoc/doctypes.go`, ya existen).
- Produces: `SaveCustomSchema` para un `schema.Std == "mso_mdoc"` escribe en Postgres una fila de `certify.credential_config` con `doctype` real, `mso_mdoc_claims` real (incluyendo `driving_privileges` como array), y la config de firma `MdocSignatureAlgo` — consumido después por `IssueToWallet` (Task 4) al construir la oferta.

**Nota sobre la tabla `certify.credential_config` real**: este proyecto no controla el esquema de esa tabla (es de Inji Certify). Antes de escribir el INSERT, `db.go`'s INSERT existente (líneas ~203-251) ya declara las columnas relevantes: `doctype` (hoy `NULL` literal), `mso_mdoc_claims` (hoy `NULL` literal), `signature_algo`/`key_manager_app_id`/`signature_crypto_suite` (hoy hardcodeados a Ed25519). Este task cambia esas columnas SOLO para el caso `credFormat == "mso_mdoc"` — el camino existente para `vc+sd-jwt`/`ldp_vc` no debe cambiar de comportamiento.

- [ ] **Step 1: Escribir el test que falla — captura el SQL/bindings, no ejecuta contra Postgres real**

El patrón de test de este paquete para `SaveCustomSchema` no ejecuta contra una base de datos real (confirmar leyendo `db_vcdm_test.go`/`db_protected_term_test.go` primero para el patrón exacto — probablemente interceptan `buildVCTemplate`/`stdToCredentialFormat`/construyen la fila esperada como valores en memoria en vez de golpear Postgres). Si el patrón existente SÍ usa una conexión real gateada por una env var (p. ej. `INJICERTIFY_TEST_DSN`), replicar ese mismo gate — no introducir un mecanismo de test nuevo.

Escribir el test asumiendo que existe una función auxiliar interna extraíble (ver Step 2) que construye los valores de las columnas mdoc-específicas SIN necesitar una conexión real:

```go
func TestMdocCredentialConfigValues(t *testing.T) {
	schema := vctypes.Schema{
		ID:   "org.iso.18013.5.1.mDL",
		Std:  "mso_mdoc",
		Name: "Mobile Driving Licence",
		FieldsSpec: mdoc.MandatoryFields("org.iso.18013.5.1.mDL"),
	}

	doctype, claims, signatureAlgo, keyManagerAppID, cryptoSuite := mdocCredentialConfigValues(schema)

	if doctype != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q, want %q", doctype, "org.iso.18013.5.1.mDL")
	}
	if signatureAlgo != mdoc.MdocSignatureAlgo {
		t.Errorf("signatureAlgo = %q, want %q (mdoc.MdocSignatureAlgo, NOT the Ed25519 default)", signatureAlgo, mdoc.MdocSignatureAlgo)
	}
	if keyManagerAppID == "CERTIFY_VC_SIGN_ED25519" {
		t.Error("keyManagerAppID is the Ed25519 non-mdoc default — mdoc needs its own EC key manager app id")
	}
	if cryptoSuite == "Ed25519Signature2020" {
		t.Error("cryptoSuite is the Ed25519 non-mdoc default — mdoc needs no JSON-LD signature suite at all (it's CBOR/COSE, not JSON-LD)")
	}

	var claimsMap map[string]any
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		t.Fatalf("mso_mdoc_claims is not valid JSON: %v", err)
	}
	ns, ok := claimsMap["org.iso.18013.5.1"].(map[string]any)
	if !ok {
		t.Fatalf("mso_mdoc_claims missing namespace org.iso.18013.5.1, got: %v", claimsMap)
	}
	dp, ok := ns["driving_privileges"].(map[string]any)
	if !ok {
		t.Fatalf("mso_mdoc_claims.%s missing driving_privileges as an array-typed claim descriptor, got: %v", "org.iso.18013.5.1", ns)
	}
	if dp["type"] != "array" {
		t.Errorf("driving_privileges claim descriptor type = %v, want %q (must not be a fixed-length shape — that is walt.id's limitation, not Inji's)", dp["type"], "array")
	}
	if _, ok := ns["portrait"]; !ok {
		t.Error("mso_mdoc_claims missing portrait — ISO 18013-5 Table 3 mandatory element, must be declared or the emitted mdoc is non-conformant")
	}
}
```

Nota: los nombres exactos de `keyManagerAppID`/`cryptoSuite` para EC/ES256 dependen de qué valores acepta el `key_manager_app_id`/`signature_crypto_suite` reales de Inji Certify v0.14.0 para firma EC — el implementador de esta tarea DEBE confirmar los valores reales contra la config de Inji Certify usada en el spike (`C:\tmp\spike\run\config\certify-spike-mdl.properties` o el `certify_init.sql` capturado ahí) antes de fijarlos en el código; el test arriba solo prueba que NO son los valores Ed25519, no fija los valores EC exactos porque el implementador debe leerlos de la evidencia real del spike, no inventarlos.

- [ ] **Step 2: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go vet ./internal/adapters/injicertify/...
```

Esperado: `undefined: mdocCredentialConfigValues` (no compila).

- [ ] **Step 3: Extraer y implementar `mdocCredentialConfigValues`**

Añadir a `db.go` una función que construye los 5 valores mdoc-específicos, consultando primero `C:\tmp\spike\run\config\certify-spike-mdl.properties` y `certify_init.sql` capturados en el spike para los valores reales de `key_manager_app_id`/`signature_crypto_suite` que Inji Certify v0.14.0 acepta para firma EC (no walt.id — esto es específico de cómo Inji Certify configura su Keymanager):

```go
// mdocCredentialConfigValues builds the mso_mdoc-specific column values for
// SaveCustomSchema's INSERT. Extracted from the INSERT body so it can be
// tested without a live Postgres connection — SaveCustomSchema calls this
// directly.
//
// doctype and mso_mdoc_claims are NULL in every non-mdoc row this adapter
// writes (see the INSERT's existing $NULL literals) — mdoc is the first
// format this adapter provisions that needs them populated.
func mdocCredentialConfigValues(schema vctypes.Schema) (doctype string, claims []byte, signatureAlgo, keyManagerAppID, cryptoSuite string) {
	doctype = schema.ID // e.g. "org.iso.18013.5.1.mDL" — Task 3's caller sets Schema.ID to the ISO docType for mdoc schemas, same convention mdoc.KnownDocTypes/MandatoryFields already use.

	nsClaims := map[string]any{}
	for _, f := range schema.FieldsSpec {
		switch f.Format {
		case mdoc.FormatDrivingPrivileges:
			// Array of objects, NOT a fixed length — this is exactly the
			// property walt.id's arrayConfig cannot express (confirmed
			// empirically requiring exact length match) and Inji's
			// MDocProcessor handles genuinely generically (confirmed in the
			// 2026-08-25 spike with 2/3/4 real categories against one
			// unmodified profile).
			nsClaims[f.Name] = map[string]any{"type": "array"}
		case mdoc.FormatImage:
			nsClaims[f.Name] = map[string]any{"type": "string"} // base64 in, byte string out — Inji's own conversion, not ours to declare here
		default:
			nsClaims[f.Name] = map[string]any{"type": "string"}
		}
	}
	claimsMap := map[string]any{"org.iso.18013.5.1": nsClaims}
	claims, _ = json.Marshal(claimsMap)

	// TODO(implementer): confirm these two against the real values captured
	// in C:\tmp\spike\run\config\certify-spike-mdl.properties /
	// certify_init.sql from the 2026-08-25 validation spike — do NOT reuse
	// the Ed25519 defaults ("CERTIFY_VC_SIGN_ED25519", "Ed25519Signature2020")
	// below; they are placeholders marking exactly what must change, not
	// values to ship.
	keyManagerAppID = "CERTIFY_VC_SIGN_EC_P256" // placeholder — verify against spike evidence
	cryptoSuite = ""                            // mdoc is CBOR/COSE, not JSON-LD — no signature SUITE string applies; verify Inji's schema accepts NULL/empty here

	return doctype, claims, mdoc.MdocSignatureAlgo, keyManagerAppID, cryptoSuite
}
```

**Nota explícita para quien ejecute esta tarea**: los dos valores marcados `TODO(implementer)` arriba deben resolverse leyendo la evidencia real del spike antes de dar la tarea por completa — el test del Step 1 solo verifica que NO sean los defaults de Ed25519, no fija el valor EC correcto, precisamente porque ese valor debe venir de evidencia empírica capturada, no de una suposición de este plan.

- [ ] **Step 4: Conectar `mdocCredentialConfigValues` al INSERT de `SaveCustomSchema`**

Modificar `SaveCustomSchema` para ramificar cuando `credFormat == "mso_mdoc"`:

```go
func (a *Adapter) SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error {
	if a.cfg.DB.DSN == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, a.cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("injicertify db: connect: %w", err)
	}
	defer conn.Close(ctx)

	credFormat := stdToCredentialFormat(schema.Std)

	if credFormat == "mso_mdoc" {
		return a.saveMdocSchema(ctx, conn, schema)
	}

	// ... resto del cuerpo existente sin cambios (vc+sd-jwt / ldp_vc) ...
}

// saveMdocSchema is SaveCustomSchema's mso_mdoc branch. A separate INSERT
// rather than threading mdoc-specific columns through the shared query:
// the shared INSERT's vc_template/sd_jwt_claims/credential_subject columns
// are all NULL for mdoc (mdoc has no JSON-LD/SD-JWT template — issuer-side
// CBOR construction is Inji's own MDocProcessor, not something this adapter
// renders), so reusing that INSERT's parameter list would mean passing NULL
// through six unrelated positional args to reach the three that matter.
func (a *Adapter) saveMdocSchema(ctx context.Context, conn *pgx.Conn, schema vctypes.Schema) error {
	doctype, claims, signatureAlgo, keyManagerAppID, cryptoSuite := mdocCredentialConfigValues(schema)

	displayOrder := make([]string, 0, len(schema.FieldsSpec))
	for _, f := range schema.FieldsSpec {
		displayOrder = append(displayOrder, f.Name)
	}

	logoURL := a.cfg.DB.LogoURL
	if logoURL == "" {
		logoURL = defaultCredentialLogoURL
	}
	displayEntry := map[string]any{
		"name":             schema.Name,
		"locale":           "en",
		"background_color": "#12107c",
		"text_color":       "#FFFFFF",
		"logo": map[string]any{
			"url":      logoURL,
			"alt_text": schema.Name + " Logo",
		},
		"background_image": map[string]any{"uri": logoURL},
	}
	displayRaw, _ := json.Marshal([]map[string]any{displayEntry})

	scope := a.cfg.DB.Scope
	if scope == "" {
		scope = "mock_identity_vc_ldp"
	}

	_, err := conn.Exec(ctx, `
INSERT INTO certify.credential_config (
	credential_config_key_id, config_id, status, vc_template,
	doctype, sd_jwt_vct, context, credential_type, credential_format,
	did_url, key_manager_app_id, key_manager_ref_id,
	signature_algo, signature_crypto_suite, sd_claim,
	display, display_order, scope,
	cryptographic_binding_methods_supported,
	credential_signing_alg_values_supported,
	proof_types_supported,
	credential_subject, sd_jwt_claims, mso_mdoc_claims,
	plugin_configurations, cr_dtimes, upd_dtimes
) VALUES (
	$1, $1, 'active', NULL,
	$2, NULL, NULL, NULL, $3,
	$4, $5, 'EC_SIGN',
	$6, $7, NULL,
	$8, $9, $10,
	ARRAY['cose_key'],
	ARRAY['ES256'],
	'{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}'::JSONB,
	NULL, NULL, $11,
	NULL, NOW(), NULL
)
ON CONFLICT (credential_config_key_id) DO UPDATE SET
	doctype            = EXCLUDED.doctype,
	credential_format  = EXCLUDED.credential_format,
	display            = EXCLUDED.display,
	display_order      = EXCLUDED.display_order,
	mso_mdoc_claims     = EXCLUDED.mso_mdoc_claims,
	upd_dtimes         = NOW()
`,
		schema.ID,      // $1
		doctype,        // $2
		"mso_mdoc",     // $3
		a.cfg.DB.DIDUrl,// $4
		keyManagerAppID,// $5
		signatureAlgo,  // $6
		cryptoSuite,    // $7 (empty string or NULL — confirm which Postgres/Inji accepts against spike evidence)
		displayRaw,     // $8 JSONB
		displayOrder,   // $9 TEXT[]
		scope,          // $10
		claims,         // $11 JSONB
	)
	if err != nil {
		return fmt.Errorf("injicertify db: upsert mdoc credential_config %q: %w", schema.ID, err)
	}
	return nil
}
```

**Nota**: `cryptographic_binding_methods_supported = ARRAY['cose_key']` y `credential_signing_alg_values_supported = ARRAY['ES256']` codifican correctamente, del lado de Inji, lo que el spike encontró — recordar que el spec documentó que el metadata real de Inji hoy publica `"ES256"` como STRING (issue #954) sin importar lo que se escriba aquí; esta columna es la fuente correcta desde nuestro lado, la inconsistencia de #954 vive en cómo Inji Certify SERIALIZA esta columna al wellknown, no en lo que escribimos.

- [ ] **Step 5: Confirmar que el test del Step 1 pasa**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -v
```

Esperado: PASS, incluyendo `TestMdocCredentialConfigValues` y toda la suite existente del paquete (confirmar que el camino `vc+sd-jwt`/`ldp_vc` de `SaveCustomSchema` sigue produciendo el mismo SQL que antes — no debe haber ningún cambio de comportamiento para esos formatos).

- [ ] **Step 6: Verificación empírica contra Inji Certify real (no solo unit test)**

Usando el mismo entorno del spike (`docker run` con `injistack/inji-certify-with-plugins:0.14.0` + Postgres, ver `C:\tmp\spike\run\README.md` para cómo relevantarlo), insertar una fila real vía `saveMdocSchema` (o el SQL equivalente a mano) y confirmar:
1. Inji Certify arranca sin error con esta fila presente (`docker logs` limpio, sin excepción de deserialización de config).
2. `GET /v1/certify/.well-known/openid-credential-issuer` incluye la nueva `credential_configuration_id` con `format: "mso_mdoc"`.
3. Emitir un mDL de prueba contra este perfil (reusando `C:\tmp\spike\run\flow.py`, adaptado al nuevo `credential_config_key_id`) produce un CBOR válido — reusar `verify_mdoc.py` del spike para decodificar y confirmar `driving_privileges` con 2 y 3 categorías reales (sin modificar la fila entre una emisión y otra) para reconfirmar en esta fila específica del proyecto lo que el spike ya probó en general.

- [ ] **Step 7: Commit**

```bash
git add internal/adapters/injicertify/db.go internal/adapters/injicertify/db_mdoc_test.go
git commit -m "feat(injicertify): SaveCustomSchema persists a real mso_mdoc credential_config

Extends SaveCustomSchema with a dedicated mdoc branch: doctype and
mso_mdoc_claims (previously NULL literals for every format) are now
populated for Std == mso_mdoc, with ES256/EC signing config instead of
the Ed25519 defaults every other format here uses. driving_privileges is
declared as an array-typed claim with no fixed length, matching what the
2026-08-25 spike confirmed Inji's MDocProcessor genuinely supports.

Verified empirically against a real Inji Certify v0.14.0 instance (not
just unit-tested): the inserted config loads without crash-looping the
service, appears in the real wellknown, and a real credential_offer
against it produces a decodable, valid mdoc."
```

---

### Task 4: `internal/adapters/injicertify/issuer.go` — `IssueToWallet` lee `StructuredData` y aplica defensa en profundidad

**Files:**
- Modify: `verifiably-go/internal/adapters/injicertify/issuer.go`
- Test: `verifiably-go/internal/adapters/injicertify/issuer_mdoc_test.go` (crear)

**Interfaces:**
- Consumes: `backend.IssueRequest.StructuredData` (ya existe, hoy solo lo lee `waltid/issuer2.go`), `mdoc.DrivingPrivilegesMaxCategories`, `mdoc.EncodeDrivingPrivileges`, `mdoc.DrivingPrivilege` (`internal/mdoc/drivingprivileges.go`, ya existen).
- Produces: `injicertify.IssueToWallet` en modo `ModePreAuth` construye claims correctos para `mso_mdoc`, incluyendo `driving_privileges` desde `StructuredData`, y rechaza 0/>4 categorías ANTES de llamar `/v1/certify/pre-authorized-data`.

- [ ] **Step 1: Escribir el test que falla — caso positivo (1-4 categorías reales)**

Seguir exactamente el patrón de `TestBuildIssuer2OfferSelectsProfileByCategoryCount` (`internal/adapters/waltid/issuer2_test.go:361-394`), adaptado a la firma de `injicertify.IssueToWallet` (que a diferencia de `buildIssuer2Offer` necesita un `httptest.Server` simulando `/v1/certify/pre-authorized-data`, siguiendo el patrón que otros tests de este paquete ya usan para el cliente HTTP — confirmar el helper exacto leyendo `authcode_test.go` primero):

```go
func TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData(t *testing.T) {
	for n := 1; n <= mdoc.DrivingPrivilegesMaxCategories; n++ {
		var gotClaims map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body preAuthorizedDataRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotClaims = body.Claims
			_ = json.NewEncoder(w).Encode(preAuthorizedDataResponse{
				CredentialOfferURI: "openid-credential-offer://?credential_offer=%7B%7D",
			})
		}))
		defer srv.Close()

		a := &Adapter{cfg: Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, client: newTestClient(srv.URL)}

		privileges := make([]mdoc.DrivingPrivilege, n)
		for i := range privileges {
			privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
		}
		raw, err := mdoc.EncodeDrivingPrivileges(privileges)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}

		req := backend.IssueRequest{
			Schema:         vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc"},
			SubjectData:    map[string]string{"family_name": "Perez"},
			StructuredData: map[string]json.RawMessage{"driving_privileges": raw},
		}
		if _, err := a.IssueToWallet(context.Background(), req); err != nil {
			t.Fatalf("n=%d: IssueToWallet: %v", n, err)
		}

		dp, ok := gotClaims["driving_privileges"].([]any)
		if !ok {
			t.Fatalf("n=%d: claims[driving_privileges] is %T, want []any — StructuredData was not read", n, gotClaims["driving_privileges"])
		}
		if len(dp) != n {
			t.Errorf("n=%d: driving_privileges has %d entries, want exactly %d", n, len(dp), n)
		}
	}
}
```

(El helper `newTestClient` y la forma exacta de construir un `*Adapter` para test deben confirmarse contra el patrón real ya usado en este paquete — leer `authcode_test.go`/`fieldspec_test.go` antes de escribir este test; el snippet arriba es la forma del caso, no necesariamente los nombres exactos de helper.)

- [ ] **Step 2: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData -v
```

Esperado: FAIL — `claims[driving_privileges] is <nil>, want []any` (porque `IssueToWallet` hoy no lee `StructuredData` en absoluto).

- [ ] **Step 3: Escribir el test negativo — 0 y >4 categorías**

```go
func TestIssueToWalletMdocRejectsZeroDrivingPrivileges(t *testing.T) {
	a := &Adapter{cfg: Config{Mode: ModePreAuth, BaseURL: "http://unused", PublicBaseURL: "http://unused"}}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc"},
		SubjectData: map[string]string{"family_name": "Perez"},
		// StructuredData sin driving_privileges en absoluto.
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with no driving_privileges returned no error, want a rejection — never call the network")
	}
}

func TestIssueToWalletMdocRejectsOverCapDrivingPrivileges(t *testing.T) {
	a := &Adapter{cfg: Config{Mode: ModePreAuth, BaseURL: "http://unused", PublicBaseURL: "http://unused"}}
	privileges := make([]mdoc.DrivingPrivilege, mdoc.DrivingPrivilegesMaxCategories+1)
	for i := range privileges {
		privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
	}
	raw, err := mdoc.EncodeDrivingPrivileges(privileges)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	// Nota: EncodeDrivingPrivileges ya trunca a 4 — para reproducir el caso
	// ">4 llega al adapter" hay que construir el JSON crudo directamente en
	// vez de pasar por el encoder, igual que el fix-round de Task 4 del plan
	// anterior lo hizo para el mismo escenario en el handler:
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc"},
		SubjectData: map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{
			"driving_privileges": mustMarshalNPrivileges(mdoc.DrivingPrivilegesMaxCategories + 1),
		},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with 5 driving_privileges returned no error, want a rejection — never call the network")
	}
}

// mustMarshalNPrivileges builds a raw JSON array of n entries WITHOUT going
// through mdoc.EncodeDrivingPrivileges's own truncation, so the test
// reproduces "more than the cap reached the adapter" rather than "the
// encoder already truncated it" — the adapter's own guard must be what
// catches this, not incidentally rely on the encoder.
func mustMarshalNPrivileges(n int) json.RawMessage {
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = map[string]string{"vehicle_category_code": "B", "issue_date": "2021-06-01", "expiry_date": "2031-06-01"}
	}
	raw, _ := json.Marshal(out)
	return raw
}
```

- [ ] **Step 4: Confirmar que ambos fallan**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run 'TestIssueToWalletMdocRejects' -v
```

Esperado: ambos FAIL — `IssueToWallet` hoy no rechaza nada relacionado con `driving_privileges` porque ni siquiera lo lee.

- [ ] **Step 5: Implementar la lectura de `StructuredData` y el rechazo, dentro de `IssueToWallet`**

Modificar el inicio de `IssueToWallet` (antes del `switch a.cfg.Mode`):

```go
func (a *Adapter) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	claims := map[string]any{}
	for k, v := range req.SubjectData {
		claims[k] = v
	}

	// mso_mdoc's driving_privileges is an array of objects — it cannot ride
	// in SubjectData (map[string]string). It lives in StructuredData, same
	// convention as waltid/issuer2.go's buildIssuer2Offer. Reading it here,
	// and rejecting 0/>4 categories BEFORE ever calling Inji, replicates the
	// same defense-in-depth waltid's buildIssuer2Offer already has: the
	// handler's own guard (validateDrivingPrivilegesCount) can be bypassed by
	// a direct POST /api/v1/credentials/issue call, so this adapter-level
	// check is the one that must never be skipped.
	if stdToCredentialFormat(req.Schema.Std) == "mso_mdoc" {
		n := 0
		if raw, ok := req.StructuredData["driving_privileges"]; ok && len(raw) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return backend.IssueToWalletResult{}, fmt.Errorf("injicertify: driving_privileges is not a JSON array: %w", err)
			}
			n = len(arr)
			var privileges []any
			if err := json.Unmarshal(raw, &privileges); err != nil {
				return backend.IssueToWalletResult{}, fmt.Errorf("injicertify: driving_privileges is not valid JSON: %w", err)
			}
			claims["driving_privileges"] = privileges
		}
		if n == 0 {
			return backend.IssueToWalletResult{}, fmt.Errorf(
				"inji: driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos una categoría de conducción antes de emitir")
		}
		if n > mdoc.DrivingPrivilegesMaxCategories {
			return backend.IssueToWalletResult{}, fmt.Errorf(
				"inji: no se pueden emitir %d categorías de conducción en una sola credencial — el máximo es %d",
				n, mdoc.DrivingPrivilegesMaxCategories)
		}
	}

	if len(claims) == 0 {
		// Inji Certify rejects empty claims; fill one sensible default.
		claims["fullName"] = "Demo Holder"
	}

	switch a.cfg.Mode {
	// ... resto del cuerpo existente sin cambios ...
```

Añadir el import `"github.com/verifiably/verifiably-go/internal/mdoc"` al bloque de imports de `issuer.go`.

- [ ] **Step 6: Confirmar que todos los tests pasan**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -v
```

Esperado: PASS en los 3 tests nuevos, y confirmar que ningún test existente del paquete se rompió (los formatos `vc+sd-jwt`/`ldp_vc` nunca pasan por la rama `mso_mdoc` nueva, así que su comportamiento no debe cambiar).

- [ ] **Step 7: Portrait — verificar, no asumir**

Repetir el Step 1 del test positivo, pero con `SubjectData["portrait"]` como una cadena base64 real (reusar cualquier imagen base64 pequeña de prueba) en vez de `driving_privileges`, y confirmar que `claims["portrait"]` llega correctamente a la request contra Inji — `portrait` viaja en `SubjectData` (es escalar, un string base64), NO en `StructuredData`, así que el camino existente `for k, v := range req.SubjectData { claims[k] = v }` YA debería llevarlo — este step es de verificación, no se espera que requiera código nuevo, pero debe confirmarse con un test explícito, no asumirse (el spec marcó esto como pendiente de validar).

Si el test revela que portrait SÍ necesita algo adicional (p. ej. una conversión que Inji requiera declarar en el perfil de Task 3), documentarlo aquí y ajustar Task 3 en consecuencia antes de continuar — no diferir silenciosamente.

- [ ] **Step 8: Commit**

```bash
git add internal/adapters/injicertify/issuer.go internal/adapters/injicertify/issuer_mdoc_test.go
git commit -m "feat(injicertify): IssueToWallet reads StructuredData for mso_mdoc, rejects 0/>4 categories

driving_privileges lives exclusively in backend.IssueRequest.StructuredData
(it's an array of objects, not a scalar) since the driving_privileges
variable-count plan — but injicertify.IssueToWallet only ever read
SubjectData, so an mDL issued via Inji would silently omit this ISO
18013-5 Table 3 mandatory element. Fixed, with the same defense-in-depth
0/>4-category rejection waltid.buildIssuer2Offer already has: a direct
POST /api/v1/credentials/issue can bypass the handler's own guard, so
this adapter-level check is the one that must never be skipped.

Also verified (Step 7) that portrait — which IS scalar, so it already
rode in SubjectData — reaches Inji correctly with no additional code."
```

---

### Task 5: `verifiably-go` — UI y catálogo: corregir la copia "mock-only" y confirmar el descubrimiento del schema

**Files:**
- Modify: `verifiably-go/templates/pages/issuer_schema_builder.html`

**Interfaces:**
- Consumes: nada.
- Produces: nada de código — solo texto visible al operador.

- [ ] **Step 1: Localizar y corregir la copia desactualizada**

En `templates/pages/issuer_schema_builder.html`, cerca de la línea 140, localizar el texto:

```html
mso_mdoc — ISO 18013-5 mDL/mDoc (Inji Certify: mock-only at v0.14)
```

Reemplazar por una descripción que ya no afirme "mock-only" — dado que Task 3 hace que Inji Certify Pre-Auth emita mdoc real:

```html
mso_mdoc — ISO 18013-5 mDL/mDoc
```

(Sin calificar por DPG en el nombre del formato — el propio selector de DPG, ya existente, es lo que determina si el operador está creando este schema bajo walt.id o bajo Inji Pre-Auth; el texto del formato no necesita repetirlo.)

- [ ] **Step 2: Verificar sintaxis del template**

```bash
cd verifiably-go
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go/templates/pages/issuer_schema_builder.html:/tpl.html" \
  golang:1.25-alpine sh -c 'cat > /parse.go <<EOF
package main
import ("fmt";"html/template";"os")
func main() {
  funcs := template.FuncMap{
    "t": func(args ...interface{}) string { return "" },
    "dict": func(args ...interface{}) map[string]interface{} { return nil },
  }
  _, err := template.New("x").Funcs(funcs).ParseFiles(os.Args[1])
  if err != nil { fmt.Println("PARSE ERROR:", err); os.Exit(1) }
  fmt.Println("PARSED OK")
}
EOF
go run /parse.go /tpl.html'
```

(Ajustar el `FuncMap` con las funciones reales que el template usa si el comando falla por una función faltante — mismo patrón de verificación ya usado en el plan anterior para `issuer_issue.html`.)

- [ ] **Step 3: Confirmar manualmente que el schema mdoc bajo Inji Pre-Auth aparece en el catálogo real**

Con Tasks 1-4 completas y desplegadas en un entorno con Inji Certify real corriendo (reusar el entorno del spike o un despliegue de prueba), crear un schema mdoc a través del builder real (`ShowSchemaBuilder`/`SaveSchema`) bajo el DPG Inji Pre-Auth, y confirmar:
1. El schema se guarda sin error.
2. Volviendo a `/issuer/dpg` → Inji Pre-Auth → `/issuer/schema`, el schema mdoc aparece listado (`ListSchemas` lo descubre vía el wellknown real de Inji, que ahora debe anunciar la `credential_configuration_id` de Task 3).
3. El schema muestra el campo `driving_privileges` con el control de filas repetibles correcto (mismo comportamiento ya confirmado para walt.id en el plan anterior — el builder ya es genérico por `Std == "mso_mdoc"`, no específico de DPG).

- [ ] **Step 4: Commit**

```bash
git add templates/pages/issuer_schema_builder.html
git commit -m "docs(inji): correct mso_mdoc copy, no longer mock-only at Inji Certify"
```

---

### Task 6: `cdpi-wallet` — corregir el envoltorio `{docType, issuerSigned}` y añadir verificación de confianza en el camino `manual-mdoc`

**Files:**
- Modify: `cdpi-wallet/src/agent/oid4vci/requestCredentials.ts`
- Modify: `cdpi-wallet/src/agent/oid4vci/storeCredential.ts`
- Create fixture: `cdpi-wallet/src/__tests__/fixtures/inji-mdoc-wrapped.json` (copiado de `C:\tmp\spike\run\mdl_4categories.json` o `credential_response.json`)
- Test: `cdpi-wallet/src/__tests__/requestCredentialsMdocWrapper.test.ts` (crear)
- Test: `cdpi-wallet/src/__tests__/storeCredentialMdoc.test.ts` (archivo existente — añadir casos para la verificación de confianza)

**Interfaces:**
- Consumes: `Mdoc.fromBase64Url` (`@credo-ts/core`, ya usado en `storeCredential.ts`), `mdoc.verify(agentContext, options)` (`@credo-ts/core`, método de instancia — confirmado que acepta `options.trustedCertificates` explícitamente, no solo vía el callback X509Module), `getAnchorsForIssuer` (`src/agent/mdocTrustAnchors.ts`, ya existe y ya lo usa el camino Credo-managed).
- Produces: la rama `manual-mdoc` de `requestOid4VciCredentials` (dentro del bloque `format === 'mso_mdoc' && legacy`) corrige el CBOR antes de empujarlo a `results`; `storeOid4VciCredential`'s rama `manual-mdoc` verifica integridad + confianza antes de persistir.

**Nota sobre CBOR en TypeScript**: `cdpi-wallet` no declara hoy una dependencia directa de una librería CBOR de bajo nivel en su propio código (usa `@credo-ts/core`/`@animo-id/mdoc` como caja negra para todo el manejo de mdoc). Este task necesita decodificar/re-codificar CBOR crudo para inspeccionar si el envoltorio `{docType, issuerSigned}` está presente. Antes de escribir código, el implementador debe confirmar si `@animo-id/mdoc` (dependencia transitiva de `@credo-ts/core`) expone un decoder CBOR reusable, o si hace falta añadir una dependencia directa (p. ej. `cbor-x` o `cborg`, ambas populares en el ecosistema RN/TS) — documentar la decisión en el mensaje del commit de este task.

- [ ] **Step 1: Copiar la fixture del spike al repo**

```bash
mkdir -p src/__tests__/fixtures
cp "/c/tmp/spike/run/mdl_4categories.json" src/__tests__/fixtures/inji-mdoc-wrapped.json
```

Confirmar que el archivo copiado contiene el CBOR envuelto real (`{"credential": "<base64url>"}` cuyo contenido decodificado es `{docType, issuerSigned}`) — inspeccionarlo con el mismo `verify_mdoc.py` del spike si hace falta re-confirmar la forma exacta antes de fijarla como fixture.

También crear una segunda fixture SIN envoltorio, para el test de "no corromper walt.id":

```bash
# Cualquier CBOR mdoc real y válido emitido por walt.id de una sesión anterior de este proyecto
# (o generar uno nuevo contra el walt.id de prueba si no hay uno a mano) — la forma es
# {nameSpaces, issuerAuth} directo, SIN el nivel {docType, issuerSigned} exterior.
```
Guardar como `src/__tests__/fixtures/waltid-mdoc-unwrapped.json`.

- [ ] **Step 2: Escribir el test que falla — detección y extracción del envoltorio**

```typescript
import { detectAndUnwrapMdocEnvelope } from '../agent/oid4vci/requestCredentials';
import wrappedFixture from './fixtures/inji-mdoc-wrapped.json';
import unwrappedFixture from './fixtures/waltid-mdoc-unwrapped.json';

describe('detectAndUnwrapMdocEnvelope', () => {
  test('extracts issuerSigned from an Inji-style {docType, issuerSigned} wrapper', () => {
    const wrappedBase64Url = (wrappedFixture as { credential: string }).credential;
    const result = detectAndUnwrapMdocEnvelope(wrappedBase64Url);
    expect(result.wasWrapped).toBe(true);
    // El resultado decodificado debe tener nameSpaces + issuerAuth directamente,
    // no docType/issuerSigned anidado.
    const decoded = decodeCborBase64Url(result.base64Url); // helper del propio archivo de test o del módulo bajo prueba
    expect(decoded).toHaveProperty('nameSpaces');
    expect(decoded).toHaveProperty('issuerAuth');
    expect(decoded).not.toHaveProperty('docType');
    expect(decoded).not.toHaveProperty('issuerSigned');
  });

  test('passes a walt.id-style unwrapped CBOR through unmodified', () => {
    const unwrappedBase64Url = (unwrappedFixture as { credential: string }).credential;
    const result = detectAndUnwrapMdocEnvelope(unwrappedBase64Url);
    expect(result.wasWrapped).toBe(false);
    expect(result.base64Url).toBe(unwrappedBase64Url); // byte-for-byte, sin re-serializar
  });
});
```

(El helper `decodeCborBase64Url` puede vivir en el propio archivo de test si no existe ya uno reusable en el módulo bajo prueba.)

- [ ] **Step 3: Confirmar que falla**

```bash
cd cdpi-wallet
npx jest src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: `detectAndUnwrapMdocEnvelope is not a function` (no existe todavía).

- [ ] **Step 4: Implementar `detectAndUnwrapMdocEnvelope` en `requestCredentials.ts`**

Elegir e instalar la librería CBOR decidida en el Step 0 de este task (o confirmar una ya disponible transitivamente). Añadir a `requestCredentials.ts`:

```typescript
import { decode as cborDecode, encode as cborEncode } from '<librería CBOR elegida>';

/**
 * Detects and corrects Inji Certify's non-standard mdoc response shape.
 *
 * Inji Certify v0.14.0's MDocCredential.addProof wraps the already-signed
 * IssuerSigned map inside an extra {docType, issuerSigned} container — the
 * shape of a DeviceResponse Document, not a standalone credential. Credo/
 * @animo-id/mdoc expects the IssuerSigned map directly. Confirmed in the
 * 2026-08-25 validation spike: stripping ONLY this outer container — never
 * touching a single byte of the inner issuerSigned map, where the COSE_Sign1
 * signature lives — makes the same credential parse correctly.
 *
 * Detection is on the actual decoded shape of the bytes received, never on
 * an assumption of which DPG produced them: a walt.id credential (no
 * wrapper) passes through completely unmodified.
 */
export function detectAndUnwrapMdocEnvelope(base64Url: string): { base64Url: string; wasWrapped: boolean } {
  const bytes = base64UrlToBytes(base64Url);
  const decoded = cborDecode(bytes) as Record<string, unknown>;

  if (
    decoded &&
    typeof decoded === 'object' &&
    'issuerSigned' in decoded &&
    'docType' in decoded &&
    !('nameSpaces' in decoded)
  ) {
    const inner = decoded.issuerSigned;
    const reEncoded = cborEncode(inner);
    return { base64Url: bytesToBase64Url(reEncoded), wasWrapped: true };
  }

  return { base64Url, wasWrapped: false };
}

function base64UrlToBytes(s: string): Uint8Array {
  // implementación con la utilidad ya disponible en el proyecto (TypedArrayEncoder de @credo-ts/core, ya importado en este archivo)
}
function bytesToBase64Url(b: Uint8Array): string {
  // idem, dirección inversa
}
```

**Nota de seguridad explícita en el código**: el comentario de la función debe seguir dejando claro que esta operación NO valida confianza — solo transforma la forma de los bytes. La verificación real ocurre en Step 6/7 dentro de `storeCredential.ts`, no aquí.

- [ ] **Step 5: Conectar `detectAndUnwrapMdocEnvelope` a la rama `manual-mdoc` de `requestOid4VciCredentials`**

Modificar el bloque `else if (format === 'mso_mdoc' && legacy)` (línea ~281-309 de `requestCredentials.ts`):

```typescript
} else if (format === 'mso_mdoc' && legacy) {
  // ... código existente sin cambios hasta obtener `credential` ...
  const rawCredential = (data.credential ?? (data.credentials as string[] | undefined)?.[0]) as string | undefined;
  if (!rawCredential) throw new Error('El emisor no retornó una credencial en la respuesta.');

  // Corrige la forma de envoltura de Inji Certify si está presente; no hace
  // nada si el emisor (p. ej. walt.id) ya devuelve el mapa IssuerSigned
  // directo. Ver detectAndUnwrapMdocEnvelope para el razonamiento completo.
  const { base64Url: credential, wasWrapped } = detectAndUnwrapMdocEnvelope(rawCredential);
  if (wasWrapped) {
    log('[oid4vci] mso_mdoc credential was wrapped in {docType, issuerSigned} — unwrapped');
  }
  log('[oid4vci] mso_mdoc credential bytes (base64url):', credential.length);
  results.push({ path: 'manual-mdoc', configId, displayName, credential, keyId, docType });
}
```

- [ ] **Step 6: Confirmar que el test del envoltorio pasa**

```bash
npx jest src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: PASS ambos casos.

- [ ] **Step 7: Escribir el test que falla — verificación de integridad + confianza en `storeCredential.ts`**

Añadir a `src/__tests__/storeCredentialMdoc.test.ts` (extendiendo el mock de `@credo-ts/core` existente para incluir un `Mdoc.fromBase64Url` que devuelve un objeto con un método `verify` espiable):

```typescript
describe('storeOid4VciCredential — manual-mdoc path: integrity + trust verification', () => {
  function makeAgentAndMdoc(verifyResult: { isValid: boolean; error?: string }) {
    const verify = jest.fn().mockResolvedValue(verifyResult);
    const fakeMdoc = { deviceKeyId: undefined as string | undefined, verify };
    (Mdoc.fromBase64Url as jest.Mock).mockReturnValue(fakeMdoc);
    const stored = new (MdocRecord as unknown as new () => { tags: Record<string, unknown>; setTag: (k: string, v: unknown) => void })();
    const store = jest.fn().mockResolvedValue(stored);
    const update = jest.fn().mockResolvedValue(undefined);
    const agent = { mdoc: { store, update } } as unknown as WalletAgent;
    return { agent, fakeMdoc, verify, stored, store };
  }

  test('rejects and does NOT store when mdoc.verify() reports invalid', async () => {
    const { agent, store } = makeAgentAndMdoc({ isValid: false, error: 'signature mismatch' });
    const result: CredentialResult = {
      path: 'manual-mdoc', configId: 'org.iso.18013.5.1.mDL', credential: 'AAAA', keyId: 'k1', docType: 'org.iso.18013.5.1.mDL',
    };
    await expect(storeOid4VciCredential(agent, result, { issuerName: 'INTRANT' }, /* issuerBaseUrl */ 'https://issuer.example'))
      .rejects.toThrow();
    expect(store).not.toHaveBeenCalled();
  });

  test('stores when mdoc.verify() reports valid, having passed trustedCertificates from getAnchorsForIssuer', async () => {
    const { agent, verify, store } = makeAgentAndMdoc({ isValid: true });
    const result: CredentialResult = {
      path: 'manual-mdoc', configId: 'org.iso.18013.5.1.mDL', credential: 'AAAA', keyId: 'k1', docType: 'org.iso.18013.5.1.mDL',
    };
    await storeOid4VciCredential(agent, result, { issuerName: 'INTRANT' }, 'https://issuer.example');
    expect(store).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ trustedCertificates: expect.any(Array) }),
    );
  });
});
```

(La firma exacta de `storeOid4VciCredential` gana un parámetro nuevo — `issuerBaseUrl` — para poder llamar `getAnchorsForIssuer`; el implementador debe decidir si lo añade como parámetro posicional nuevo o lo incluye en el objeto `StorageMeta` ya existente, y actualizar TODOS los call-sites existentes de `storeOid4VciCredential` en consecuencia, no solo la rama `manual-mdoc`.)

- [ ] **Step 8: Confirmar que falla**

```bash
npx jest src/__tests__/storeCredentialMdoc.test.ts
```

Esperado: FAIL — la rama `manual-mdoc` hoy no llama `.verify()` en absoluto, y la firma de `storeOid4VciCredential` no acepta `issuerBaseUrl`.

- [ ] **Step 9: Implementar la verificación en `storeCredential.ts`**

```typescript
import { getAnchorsForIssuer } from '../mdocTrustAnchors';

export async function storeOid4VciCredential(
  agent: WalletAgent,
  result: CredentialResult,
  meta: StorageMeta,
  issuerBaseUrl?: string,
): Promise<void> {
  // ... ramas existentes (dc+sd-jwt, manual-jwt) sin cambios ...

  if (result.path === 'manual-mdoc') {
    const { credential, keyId, docType, configId, displayName } = result;
    const mdoc = Mdoc.fromBase64Url(credential, docType);
    mdoc.deviceKeyId = keyId;

    // Chequeo de INTEGRIDAD ESTRUCTURAL + CONFIANZA DEL EMISOR, en ese orden
    // lógico dentro de una sola llamada — mdoc.verify() hace ambas cosas:
    // verifyIssuerSignature confirma que la firma COSE_Sign1 cuadra
    // matemáticamente contra el certificate chain (esto es lo que prueba que
    // la corrección del envoltorio de Inji, si aplicó, no corrompió los bytes
    // firmados), Y ADEMÁS valida esa chain contra trustedCertificates — que
    // NO puede ser el x5chain embebido en la misma credencial (eso sería una
    // verificación vacía: cualquiera podría auto-firmar con su propio
    // certificado). trustedCertificates viene de getAnchorsForIssuer, el
    // MISMO mecanismo de confianza que el camino Credo-managed ya usa (ver
    // mdocTrustAnchors.ts) — este camino manual-mdoc simplemente no lo
    // invocaba antes, para NINGÚN emisor (walt.id incluido), no solo Inji.
    let trustedCertificates: string[] = [];
    if (issuerBaseUrl) {
      try {
        trustedCertificates = await getAnchorsForIssuer(issuerBaseUrl);
      } catch {
        // getAnchorsForIssuer ya maneja su propio fallback a anchors
        // cacheados; si además eso falla, trustedCertificates queda vacío y
        // verify() fallará abajo — fail closed, no fail open.
      }
    }
    const verification = await mdoc.verify(agent.context, { trustedCertificates });
    if (!verification.isValid) {
      throw new Error(
        `La credencial mdoc no pasó la verificación de firma/confianza: ${verification.error ?? 'motivo desconocido'}`,
      );
    }

    const stored = await agent.mdoc.store({ record: MdocRecord.fromMdoc(mdoc) });
    stored.setTag('issuerName', meta.issuerName);
    stored.setTag('credentialName', displayName ?? formatConfigId(configId));
    await agent.mdoc.update(stored);
    console.log('[oid4vci] stored manual-mdoc id:', stored.id, 'docType:', docType);
    return;
  }

  // ... resto de ramas existentes sin cambios ...
}
```

Actualizar el único call site real de `storeOid4VciCredential` (buscar con `grep -rn "storeOid4VciCredential(" src/` fuera de los archivos de test) para pasar el `issuerBaseUrl` correspondiente — probablemente el mismo `issuerUrl`/`credential_issuer` que `requestCredentials.ts` ya resuelve y usa para `setCurrentIssuerBaseUrl`.

- [ ] **Step 10: Confirmar que todos los tests pasan**

```bash
npx jest src/__tests__/storeCredentialMdoc.test.ts src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: PASS en todo, y confirmar que los tests preexistentes de la rama `credo`/`manual-w3c-ld`/`manual-jwt`/`dc+sd-jwt` en `storeCredentialMdoc.test.ts` siguen pasando sin cambios (la firma nueva de `storeOid4VciCredential` con `issuerBaseUrl` opcional no debe romper llamadas existentes que no lo pasen).

- [ ] **Step 11: Verificación empírica end-to-end contra Inji real (no solo mocks)**

Con Tasks 1-4 y este task completos, en un entorno con Inji Certify real (reusando el spike) y una build de desarrollo de `cdpi-wallet` (o un harness de prueba que ejecute el flujo real sin la app completa, si eso es más práctico): emitir un mDL real vía Inji, aceptarlo con este código actualizado, y confirmar en logs/inspección que (1) el envoltorio se detectó y corrigió, (2) `mdoc.verify()` devolvió `isValid: true` contra los anchors reales del deployment, (3) la credencial quedó almacenada y es presentable. Repetir emitiendo un mDL vía walt.id (sin envoltorio) y confirmar que también pasa — el chequeo de confianza nuevo no debe romper el camino walt.id existente.

- [ ] **Step 12: Commit**

```bash
git add src/agent/oid4vci/requestCredentials.ts src/agent/oid4vci/storeCredential.ts \
        src/__tests__/requestCredentialsMdocWrapper.test.ts src/__tests__/storeCredentialMdoc.test.ts \
        src/__tests__/fixtures/inji-mdoc-wrapped.json src/__tests__/fixtures/waltid-mdoc-unwrapped.json
git commit -m "fix(oid4vci): unwrap Inji's {docType, issuerSigned} mdoc envelope, verify trust chain

Inji Certify v0.14.0's MDocCredential.addProof wraps the signed
IssuerSigned map in an extra {docType, issuerSigned} container — the
manual-mdoc branch (already active for Inji via isLegacyEndpoint) now
detects and strips this without touching the signed bytes inside.

Also closes a pre-existing gap the design review for this feature
surfaced: the manual-mdoc path never called mdoc.verify() at all, for
ANY issuer — so a walt.id mdoc accepted through this path carried no
issuer-trust-chain verification either, only Credo-managed offers did.
Both DPGs now get mdoc.verify() with trustedCertificates sourced from
getAnchorsForIssuer (the same trust mechanism the Credo-managed path
already uses) before a credential is persisted — fail closed on any
verification error, no code path stores an unverified mdoc."
```

---

### Task 7: Verificación end-to-end real contra la VPS

**Files:** ninguno (verificación manual, sin cambios de código)

**Interfaces:** ninguna nueva — consume todo lo construido en Tasks 1-6, desplegado.

- [ ] **Step 1: Ejecutar la suite completa localmente antes de desplegar**

```bash
cd verifiably-go
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  sh -c "go build ./... && go vet ./... && go test ./..."
```

```bash
cd cdpi-wallet
npx jest
```

Esperado: build limpio, vet limpio, toda la suite Go en verde; toda la suite Jest en verde.

- [ ] **Step 2: Desplegar Inji Certify Pre-Auth real en la VPS junto a walt.id**

Levantar (o confirmar ya levantado) el servicio `inji-certify-preauth` en `/root/apps/demo-daas-3-0` — reusando la config `injistack/inji-certify-with-plugins:0.14.0` ya validada en el spike, con Postgres propio, siguiendo el patrón de despliegue ya establecido para los demás servicios Inji de este proyecto (`docker-compose.yml`).

- [ ] **Step 3: Provisionar el perfil mdoc real vía el builder de la UI**

Desde `/issuer/dpg` con el DPG Inji Pre-Auth seleccionado, crear el schema mdoc mDL a través del builder real (`ShowSchemaBuilder`), confirmando que `SaveCustomSchema` (Task 3) escribe correctamente en la base de datos de Inji Certify de producción.

- [ ] **Step 4: Emitir mDLs reales por cada emisor, 1 a 4 categorías, y comparar**

Repetir el patrón de verificación del plan anterior (`2026-08-24-mdl-driving-privileges-variable-count`), esta vez cubriendo AMBOS DPGs:
- walt.id: 4 credenciales (1-4 categorías) — sin cambios de comportamiento esperados, solo reconfirmación de que nada se rompió.
- Inji Pre-Auth: 4 credenciales (1-4 categorías), decodificando cada CBOR y confirmando exactamente N entradas en `driving_privileges`, sin duplicación ni truncamiento, portrait presente, firma COSE_Sign1 válida.

- [ ] **Step 5: Probar el formulario web real end-to-end, incluyendo rechazos**

Un humano (no un agente) debe:
1. Elegir Inji Pre-Auth en `/issuer/dpg`, seleccionar el schema mDL, llenar 1 categoría y emitir — confirmar en la wallet real que se recibe correctamente (envoltorio corregido, verificación de confianza pasa).
2. Repetir con 2, 3, y 4 categorías.
3. Intentar 0 categorías — confirmar el mensaje de rechazo del handler (sin llegar a construir la oferta contra Inji).
4. Intentar una 5ª categoría vía API directa (el HTML solo renderiza 4 filas, igual que con walt.id) — confirmar el rechazo de `injicertify.IssueToWallet` (Task 4) antes de que la request llegue a Inji.
5. Repetir el mismo flujo emitiendo vía walt.id, para confirmar que el chequeo de confianza nuevo en `cdpi-wallet` (Task 6) no rompió el camino existente.

- [ ] **Step 6: Confirmar la corrección de UI (Task 5) visible en producción**

Confirmar que el builder de schemas, bajo el DPG Inji, ya no muestra la copia "mock-only at v0.14" para `mso_mdoc`.

---

## Notas finales para quien ejecute este plan

- El orden de las tareas es deliberado: Task 1 (constante compartida) antes de Task 3 (que la consume); Task 2 (`stdToCredentialFormat`) antes de Task 3 (que rama sobre su valor) y antes de Task 4 (que también lo consulta); Task 3 (perfil persistido) antes de Task 4 (emisión que asume que el perfil existe) antes de Task 5 (UI que asume que ambos funcionan) antes de Task 6 (wallet, que necesita una credencial real de Inji para probar contra) antes de Task 7 (end-to-end). No reordenar.
- Tasks 1-5 son exclusivamente `verifiably-go`; Task 6 es exclusivamente `cdpi-wallet`; Task 7 cruza ambos repos y requiere acceso a la VPS real y a un dispositivo con la wallet — si quien ejecuta este plan no tiene ese acceso, las Tasks 1-6 dejan el código listo pero **no verificado en producción**, y debe decirse explícitamente así al reportar el resultado, mismo estándar que el plan anterior.
- Los dos valores marcados `TODO(implementer)` en Task 3 Step 3 (`keyManagerAppID`, `cryptoSuite` para firma EC en Inji Certify) DEBEN resolverse contra evidencia real capturada en el spike (`C:\tmp\spike\run\`) antes de que la tarea se considere completa — no son placeholders aceptables en el código final, son placeholders deliberados en ESTE PLAN marcando exactamente qué debe investigarse primero.
- La elección de librería CBOR para Task 6 (Step 0/4) debe documentarse explícitamente en el mensaje de commit de esa tarea — si `@animo-id/mdoc` ya expone un decoder reusable transitivamente, preferir eso sobre añadir una dependencia nueva.
- Cada `git commit` de este plan debe hacerse solo después de que la suite del paquete correspondiente esté en verde — no acumular cambios sin probar entre tareas.
