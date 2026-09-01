# Inji Certify (Pre-Auth) como segundo emisor de mdoc — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Revisado exhaustivamente dos veces (2026-08-25): la primera pasada del plan encontró 7 hallazgos Críticos contra el código real (docType mal resuelto, un commit intermedio que rompería producción, tests que no compilan, un mecanismo de confianza reimplementado peor que el existente, alcance filtrado a un modo que debía excluirse). Todos corregidos en esta versión con evidencia real — incluyendo releer `C:\tmp\spike\run\mdl_config.json`, el ÚNICO artefacto del spike que capturó los valores de firma/plantilla con los que Inji Certify realmente emitió un mdoc válido.

**Goal:** Incorporar Inji Certify (modo Pre-Auth únicamente) como un segundo emisor de mDL (ISO/IEC 18013-5, `mso_mdoc`) en `verifiably-go`, en modo redundancia/alternativa junto a walt.id `issuer-api2`, y corregir en `cdpi-wallet` el único bloqueante real de interoperabilidad encontrado.

**Architecture:** `internal/adapters/injicertify/` (ya en producción para formatos no-mdoc) gana soporte real para `mso_mdoc`, en modo `ModePreAuth` exclusivamente: (1) `SaveCustomSchema` aprende a persistir un schema mdoc con `doctype` (resuelto de `AdditionalTypes[0]`, igual que `waltid.mdocDocTypeFor`), `mso_mdoc_claims`, un `vc_template` Velocity real (Inji SÍ lo necesita para mdoc, confirmado por el spike — no es `NULL`), y la config de firma EC-ES256 real (`CERTIFY_VC_SIGN_EC_R1` / `EcdsaSecp256r1Signature2019`, valores capturados del spike, no inventados); (2) `IssueToWallet` aprende a leer `req.StructuredData["driving_privileges"]` además de `SubjectData`, con la misma defensa-en-profundidad de 0/>4 categorías que walt.id ya tiene — gateada explícitamente a `ModePreAuth` para no tocar el camino Auth-Code. Ningún código de selección de DPG cambia. En `cdpi-wallet`, la rama `manual-mdoc` existente de `requestCredentials.ts` (ya activa para Inji vía `isLegacyEndpoint`) gana: detección/corrección del envoltorio `{docType, issuerSigned}` que Inji antepone al CBOR firmado, y una verificación de confianza del emisor reusando el mecanismo YA EXISTENTE (`setCurrentIssuerBaseUrl`/`getTrustedCertificatesForVerification`, vía `mdoc.verify(agent.context)` sin pasar `trustedCertificates` explícitos) — sin tocar la firma pública de `storeOid4VciCredential` ni el único call site en `app/receive.tsx`. Esto se aplica a AMBOS DPGs (walt.id incluido), cerrando un hueco de seguridad preexistente que la revisión del spec encontró: el camino `manual-mdoc` nunca invocaba verificación de confianza para ningún emisor.

**Tech Stack:** Go 1.25 (`verifiably-go`), TypeScript/Jest + `@credo-ts/core` 0.6.3 + `@animo-id/mdoc` 0.5.2 (`cdpi-wallet` — confirmado que `@animo-id/mdoc` ya exporta `cborDecode`/`cborEncode`; no se añade ninguna dependencia CBOR nueva), PostgreSQL (Inji Certify's `certify.credential_config`), Docker (`golang:1.25-alpine` para build/test — no hay toolchain Go local).

**Spec:** `docs/superpowers/specs/2026-08-25-inji-mdoc-issuer-design.md` (revisado exhaustivamente, commit `0604439`)

## Global Constraints

- **Alcance: Inji Certify Pre-Auth únicamente.** El DPG Auth-Code (`inji_certify_authcode`) queda explícitamente fuera de alcance de todo este plan — ninguna tarea debe tocar `internal/handlers/schema.go`'s `injiOwnerSchemas`/`injiFormatToStd`, ni ningún archivo bajo el camino Auth-Code de `injicertify`. **Todo código nuevo que module comportamiento compartido entre modos (p. ej. dentro de `IssueToWallet`, que sirve a ambos `ModePreAuth` y `ModeAuthCode`) debe gatear explícitamente sobre `a.cfg.Mode == ModePreAuth` — no basta con gatear solo sobre `Std == "mso_mdoc"`, porque una llamada directa a la API (`POST /api/v1/credentials/issue`) podría en teoría enviar un schema mdoc contra un adapter en modo Auth-Code.**
- **No se toca la lógica de perfiles-por-conteo de walt.id** (`isoMdl_1cat`..`isoMdl_4cat`, `internal/adapters/waltid/`) — permanece exactamente como quedó tras el plan `2026-08-24-mdl-driving-privileges-variable-count`.
- **No se abstrae una interfaz Go común "mdoc issuer"** entre `waltid` e `injicertify` — cada adapter sigue implementando `backend.Adapter.IssueToWallet` de forma independiente.
- **No se reporta ni se depende de un fix upstream en `inji/inji-certify`** para el envoltorio `{docType, issuerSigned}` — se corrige exclusivamente en `cdpi-wallet`.
- **Límite operativo idéntico a walt.id**: 0 categorías de `driving_privileges` es error duro; más de 4 se rechaza — aplicado con la MISMA defensa en profundidad de dos capas que walt.id tiene (handler + adapter), porque `POST /api/v1/credentials/issue` puede invocar `IssueToWallet` evitando el handler.
- **La firma real del mdoc de Inji es ECDSA P-256/SHA-256 (ES256)** — confirmado en el spike, y los valores exactos de configuración de Inji Certify (`key_manager_app_id = "CERTIFY_VC_SIGN_EC_R1"`, `key_manager_ref_id = "EC_SECP256R1_SIGN"`, `signature_crypto_suite = "EcdsaSecp256r1Signature2019"`) están capturados textualmente en `C:\tmp\spike\run\mdl_config.json` — este plan los usa TAL CUAL, no como aproximación. NUNCA reusar los valores Ed25519 que `SaveCustomSchema` usa hoy para otros formatos.
- **El `vc_template` de un schema mdoc en Inji NO es NULL.** El spike confirmó que Inji Certify SÍ necesita una plantilla Velocity real para mdoc (`nameSpaces`/`docType`/`validityInfo` con marcadores `${...}`, incluyendo el mismo truco de "placeholder sin comillas" que `buildVCTemplate` ya usa para `statusIdx`/`nbf`/`exp` en otros formatos) — ver `C:\tmp\spike\run\mdl_config.json`'s campo `vcTemplate` (base64) para la forma exacta que funcionó.
- **`portrait` NO fue validado en el spike.** El perfil real que el spike usó para emitir mdocs válidos NO incluía `portrait` en absoluto. Este plan trata la emisión de `portrait` vía Inji como una verificación empírica obligatoria de Task 4, y si falla, Task 3 debe ajustarse ANTES de considerar el plan completo — no se asume que "funciona igual que driving_privileges".
- **Mensajes de error en español**, mismo tono que el resto del proyecto (ver `internal/handlers/issuance.go`, `internal/adapters/waltid/issuer2.go` para ejemplos de estilo).
- Cada tarea que modifique Go debe dejar su paquete con build/vet/tests en verde, verificado en Docker (`golang:1.25-alpine`, `MSYS_NO_PATHCONV=1` en Git Bash on Windows) — no hay toolchain Go local.
- Cada tarea que modifique TypeScript en `cdpi-wallet` debe dejar `npx jest <archivo afectado>` en verde, siguiendo el patrón de mock de `@credo-ts/core` ya establecido en `src/__tests__/storeCredentialMdoc.test.ts` (las clases mock se declaran DENTRO del factory de `jest.mock`, nunca a nivel de módulo).
- El chequeo de confianza en `cdpi-wallet` (Tarea 6) reusa el mecanismo YA EXISTENTE (`X509ModuleConfig.getTrustedCertificatesForVerification`, `mdocTrustAnchors.ts`) — no se reimplementa a mano pasando `trustedCertificates` explícitos, y no se cambia la firma pública de `storeOid4VciCredential` ni se toca `app/receive.tsx`.
- Cada commit se hace solo después de que la suite del paquete correspondiente esté en verde — no acumular cambios sin probar entre tareas. **Ningún commit intermedio debe dejar el estado de producción peor de lo que estaba antes de este plan** — si dos tareas están acopladas de forma que la primera sin la segunda produce una regresión, se fusionan en un solo commit (ver Task 2).

---

### Task 1: `internal/mdoc/doctypes.go` — constante de algoritmo de firma reusable

**Files:**
- Modify: `verifiably-go/internal/mdoc/doctypes.go`
- Test: `verifiably-go/internal/mdoc/doctypes_test.go` (**ya existe**, 176 líneas — añadir el nuevo test ahí, no crear un archivo nuevo; seguir el estilo de los 6 tests ya presentes en ese archivo)

**Interfaces:**
- Consumes: nada nuevo.
- Produces: `MdocSignatureAlgo` (constante string), para que Task 3 no hardcodee `"ES256"` suelto.

- [ ] **Step 1: Escribir el test que falla**

Añadir a `internal/mdoc/doctypes_test.go` (siguiendo el estilo de sus tests existentes — leerlos primero para igualar el patrón exacto de nombres/aserciones):

```go
func TestMdocSignatureAlgoIsES256(t *testing.T) {
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
  go test ./internal/mdoc/... -run TestMdocSignatureAlgoIsES256 -v
```

Esperado: `undefined: MdocSignatureAlgo` (no compila).

- [ ] **Step 3: Añadir la constante**

En `internal/mdoc/doctypes.go`, como un `const` de nivel de paquete independiente (el archivo no tiene un único "bloque de constantes" — `FormatDrivingPrivileges` y `FormatImage` son dos declaraciones `const` separadas por comentarios de varias líneas cada una; añadir esta como una tercera declaración en el mismo estilo, cerca de las otras dos):

```go
// MdocSignatureAlgo is the COSE signature algorithm every mdoc issued by
// this deployment uses: ES256 (ECDSA P-256/SHA-256). Confirmed empirically
// (header {1: -7}, IANA COSE algorithm -7 = ES256) against both walt.id
// issuer-api2 and Inji Certify v0.14.0 — the single source of truth so a
// new mdoc profile/schema config never hardcodes a different algorithm by
// accident (e.g. injicertify's Ed25519 default for its other formats).
const MdocSignatureAlgo = "ES256"
```

- [ ] **Step 4: Confirmar que pasa**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/mdoc/... -v
```

Esperado: PASS, toda la suite del paquete `internal/mdoc` sigue en verde (los 6 tests preexistentes de `doctypes_test.go` incluidos).

- [ ] **Step 5: Commit**

```bash
git add internal/mdoc/doctypes.go internal/mdoc/doctypes_test.go
git commit -m "feat(mdoc): declare MdocSignatureAlgo as the single source of truth (ES256)"
```

---

### Task 2: `internal/adapters/injicertify/db.go` — `SaveCustomSchema` soporta `mso_mdoc` de punta a punta

**Files:**
- Modify: `verifiably-go/internal/adapters/injicertify/db.go`
- Test: `verifiably-go/internal/adapters/injicertify/db_mdoc_test.go` (crear)

**Interfaces:**
- Consumes: `mdoc.MdocSignatureAlgo` (Task 1), `mdoc.MandatoryFields`, `mdoc.FormatDrivingPrivileges`/`mdoc.FormatImage` (`internal/mdoc/doctypes.go`, ya existen). **Importante**: `internal/adapters/injicertify` no importa `internal/mdoc` hoy (confirmado, cero resultados) — este es un import nuevo. No hay ciclo: `internal/mdoc` solo importa `vctypes` e `internal/mdl`, ninguno de los cuales importa `injicertify`.
- Produces: `stdToCredentialFormat("mso_mdoc")` devuelve `"mso_mdoc"`; `SaveCustomSchema` para `schema.Std == "mso_mdoc"` escribe una fila de `certify.credential_config` completa y coherente (doctype real, plantilla Velocity real, firma EC-ES256 real) — consumida después por `IssueToWallet` (Task 3).

**Nota sobre por qué esta tarea fusiona lo que el borrador anterior de este plan separaba en dos commits**: cambiar solo `stdToCredentialFormat` para devolver `"mso_mdoc"` sin ADEMÁS enseñarle a `buildVCTemplate`/`SaveCustomSchema` a manejar ese valor haría que un schema mdoc, si se guardara en ese estado intermedio, generara un `vc_template` JSON-LD (rama `default` de `buildVCTemplate`) con firma Ed25519 — una fila peor que no tener el caso en absoluto. Esta tarea entrega ambos cambios en un solo commit atómico para que nunca exista ese estado intermedio en el historial.

**Nota sobre `doctype`**: el docType real de un schema mdoc vive en `schema.AdditionalTypes[0]`, NUNCA en `schema.ID` (que para un schema custom es un ID generado tipo `"custom-<nano>"` — confirmado en `internal/handlers/schema.go:1175,1204-1206`). Replicar exactamente el patrón de resolución que `internal/adapters/waltid/issuer2.go`'s `mdocDocTypeFor` ya usa:

```go
if len(schema.AdditionalTypes) > 0 {
    if dt := strings.TrimSpace(schema.AdditionalTypes[0]); dt != "" {
        return dt
    }
}
if dt := schema.BaseType(); dt != "" {
    return dt
}
return schema.ID
```

**Nota sobre los valores de firma/plantilla**: usar EXACTAMENTE los valores capturados en `C:\tmp\spike\run\mdl_config.json` (el único artefacto del spike que registra la configuración con la que Inji Certify realmente emitió un mdoc válido) — no aproximarlos ni inventarlos:
- `key_manager_app_id`: `"CERTIFY_VC_SIGN_EC_R1"`
- `key_manager_ref_id`: `"EC_SECP256R1_SIGN"`
- `signature_crypto_suite`: `"EcdsaSecp256r1Signature2019"`
- `signature_algo`: `mdoc.MdocSignatureAlgo` (= `"ES256"`)

**Nota sobre `vc_template`**: NO es `NULL`. El spike usó una plantilla Velocity real con esta forma decodificada (confirmar releyendo el campo `vcTemplate` base64 de `mdl_config.json` antes de escribir el código, no confiar solo en esta transcripción):

```json
{
  "nameSpaces": {
    "org.iso.18013.5.1": [
      {"digestID": 0, "elementIdentifier": "family_name", "elementValue": "${family_name}"},
      {"digestID": 1, "elementIdentifier": "given_name", "elementValue": "${given_name}"},
      ...
      {"digestID": N, "elementIdentifier": "driving_privileges", "elementValue": ${driving_privileges}}
    ]
  },
  "docType": "${_doctype}",
  "validityInfo": {"validFrom": "${_validFrom}", "validUntil": "${_validUntil}"}
}
```

Notar que `driving_privileges`'s `elementValue` NO lleva comillas alrededor del marcador (`${driving_privileges}`, no `"${driving_privileges}"`) — es un array JSON, no un string, mismo truco de placeholder-sin-comillas que `buildVCTemplate` ya usa para `statusIdx`/`nbf`/`exp` (`statusIdxPlaceholder`, líneas ~313-321 del archivo existente). Reusar ese mismo mecanismo de placeholder-y-swap para `driving_privileges` en vez de inventar uno nuevo.

- [ ] **Step 1: Escribir el test que falla — `stdToCredentialFormat`**

```go
func TestStdToCredentialFormatMsoMdoc(t *testing.T) {
	got := stdToCredentialFormat("mso_mdoc")
	if got != "mso_mdoc" {
		t.Errorf("stdToCredentialFormat(%q) = %q, want %q", "mso_mdoc", got, "mso_mdoc")
	}
}
```

- [ ] **Step 2: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run TestStdToCredentialFormatMsoMdoc -v
```

Esperado: FAIL — `got = "ldp_vc"`.

- [ ] **Step 3: Escribir el test que falla — construcción de valores mdoc, usando un schema construido COMO EL BUILDER REAL LO HACE**

```go
func TestMdocCredentialConfigValues(t *testing.T) {
	// Construido igual que internal/handlers/schema.go's SaveSchema construye
	// un schema mdoc real: ID es el "custom-<nano>" generado, el docType ISO
	// vive en AdditionalTypes[0] — NUNCA en ID. Un test que ponga el docType
	// directamente en Schema.ID (como el borrador anterior de este plan
	// hacía) no habría detectado que mdocCredentialConfigValues necesita
	// leer AdditionalTypes.
	schema := vctypes.Schema{
		ID:              "custom-abc123",
		Std:             "mso_mdoc",
		Name:            "Mobile Driving Licence",
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
		FieldsSpec:      mdoc.MandatoryFields("org.iso.18013.5.1.mDL"),
	}

	doctype, vcTemplate, claims, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite := mdocCredentialConfigValues(schema)

	if doctype != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q, want %q (from AdditionalTypes[0], not schema.ID=%q)", doctype, "org.iso.18013.5.1.mDL", schema.ID)
	}
	if signatureAlgo != mdoc.MdocSignatureAlgo {
		t.Errorf("signatureAlgo = %q, want %q", signatureAlgo, mdoc.MdocSignatureAlgo)
	}
	if keyManagerAppID != "CERTIFY_VC_SIGN_EC_R1" {
		t.Errorf("keyManagerAppID = %q, want the real EC value captured from the spike, %q", keyManagerAppID, "CERTIFY_VC_SIGN_EC_R1")
	}
	if keyManagerRefID != "EC_SECP256R1_SIGN" {
		t.Errorf("keyManagerRefID = %q, want %q", keyManagerRefID, "EC_SECP256R1_SIGN")
	}
	if cryptoSuite != "EcdsaSecp256r1Signature2019" {
		t.Errorf("cryptoSuite = %q, want the real value captured from the spike, %q", cryptoSuite, "EcdsaSecp256r1Signature2019")
	}

	// vc_template must NOT be empty/NULL — the spike confirmed Inji needs a
	// real Velocity template for mdoc, unlike this plan's first (wrong) draft.
	if len(vcTemplate) == 0 {
		t.Fatal("vc_template is empty — Inji Certify needs a real template for mso_mdoc, confirmed by the spike")
	}
	decoded, err := base64.StdEncoding.DecodeString(vcTemplate)
	if err != nil {
		t.Fatalf("vc_template is not valid base64: %v", err)
	}
	if !strings.Contains(string(decoded), `"docType": "${_doctype}"`) {
		t.Errorf("vc_template missing docType marker, got: %s", decoded)
	}
	if !strings.Contains(string(decoded), `"driving_privileges", "elementValue": ${driving_privileges}`) {
		t.Errorf("vc_template's driving_privileges marker must be UNQUOTED (it's a JSON array, not a string), got: %s", decoded)
	}

	var claimsMap map[string]any
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		t.Fatalf("mso_mdoc_claims is not valid JSON: %v", err)
	}
	ns, ok := claimsMap["org.iso.18013.5.1"].(map[string]any)
	if !ok {
		t.Fatalf("mso_mdoc_claims missing namespace org.iso.18013.5.1, got: %v", claimsMap)
	}
	if _, ok := ns["driving_privileges"]; !ok {
		t.Error("mso_mdoc_claims missing driving_privileges")
	}
	if _, ok := ns["portrait"]; !ok {
		t.Error("mso_mdoc_claims missing portrait — ISO 18013-5 Table 3 mandatory element (NOTE: the spike's own working config did NOT include portrait — Task 4 Step 7 must verify this empirically; if it fails, this claim declaration alone is not sufficient and this task must be revisited)")
	}
}
```

- [ ] **Step 4: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go vet ./internal/adapters/injicertify/...
```

Esperado: `undefined: mdocCredentialConfigValues` (no compila).

- [ ] **Step 5: Implementar `stdToCredentialFormat`, `mdocCredentialConfigValues`, y conectar `SaveCustomSchema`**

En `db.go`, actualizar el `switch` existente:

```go
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

Añadir el import `"github.com/verifiably/verifiably-go/internal/mdoc"` y `"strings"` (si no está ya) al bloque de imports de `db.go`.

Añadir la función de construcción de valores (probar primero, como en el Step 3, antes de conectarla al INSERT):

```go
// mdocDocTypeForSchema resolves the ISO docType from a schema the same way
// waltid/issuer2.go's mdocDocTypeFor does: AdditionalTypes[0] first (what
// the schema builder writes for a custom mdoc schema — see
// handlers/schema.go's SaveSchema), falling back to BaseType(), falling
// back to the raw ID. schema.ID is a generated "custom-<nano>" string for
// every custom schema and is NEVER the docType directly.
func mdocDocTypeForSchema(schema vctypes.Schema) string {
	if len(schema.AdditionalTypes) > 0 {
		if dt := strings.TrimSpace(schema.AdditionalTypes[0]); dt != "" {
			return dt
		}
	}
	if dt := schema.BaseType(); dt != "" {
		return dt
	}
	return schema.ID
}

// mdocVCTemplate builds the base64-encoded Velocity template Inji Certify
// needs to render an mso_mdoc credential. Unlike buildVCTemplate's other
// branches, this is NOT optional/NULL — confirmed against a real Inji
// Certify v0.14.0 in the 2026-08-25 validation spike (see
// C:\tmp\spike\run\mdl_config.json's vcTemplate field, the only artifact
// from that spike that captured a template Inji actually accepted and
// issued a valid mdoc from).
//
// driving_privileges' marker is deliberately UNQUOTED (a JSON array, not a
// string) — same placeholder-and-swap trick buildVCTemplate already uses
// for statusIdx/nbf/exp (see statusIdxPlaceholder).
const drivingPrivilegesPlaceholder = "@@DRIVING_PRIVILEGES@@"

func mdocVCTemplate(doctype string, fields []vctypes.FieldSpec) string {
	items := make([]map[string]any, 0, len(fields))
	digestID := 0
	for _, f := range fields {
		if f.Format == mdoc.FormatDrivingPrivileges {
			items = append(items, map[string]any{
				"digestID":         digestID,
				"elementIdentifier": f.Name,
				"elementValue":      drivingPrivilegesPlaceholder,
			})
		} else {
			items = append(items, map[string]any{
				"digestID":         digestID,
				"elementIdentifier": f.Name,
				"elementValue":      "${" + f.Name + "}",
			})
		}
		digestID++
	}
	tmpl := map[string]any{
		"nameSpaces": map[string]any{
			mdocNamespaceForDocType(doctype): items,
		},
		"docType": "${_doctype}",
		"validityInfo": map[string]any{
			"validFrom":  "${_validFrom}",
			"validUntil": "${_validUntil}",
		},
	}
	b, _ := json.MarshalIndent(tmpl, "", "  ")
	out := strings.Replace(string(b), `"`+drivingPrivilegesPlaceholder+`"`, "${driving_privileges}", 1)
	return base64.StdEncoding.EncodeToString([]byte(out))
}

// mdocNamespaceForDocType derives the ISO namespace from a docType by
// stripping the last dot-segment — same heuristic as waltid's
// mdocNamespaceFor, valid for org.iso.18013.5.1.mDL (mDL is the only
// docType this task provisions; Photo ID is out of scope).
func mdocNamespaceForDocType(docType string) string {
	if i := strings.LastIndex(docType, "."); i > 0 {
		return docType[:i]
	}
	return docType
}

// mdocCredentialConfigValues builds every mso_mdoc-specific value
// SaveCustomSchema's mdoc branch needs. Extracted so it is testable without
// a live Postgres connection.
func mdocCredentialConfigValues(schema vctypes.Schema) (doctype, vcTemplate string, claims []byte, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite string) {
	doctype = mdocDocTypeForSchema(schema)
	vcTemplate = mdocVCTemplate(doctype, schema.FieldsSpec)

	nsClaims := map[string]any{}
	for _, f := range schema.FieldsSpec {
		nsClaims[f.Name] = map[string]any{
			"display": []map[string]any{{"name": fieldLabel(f.Name), "locale": "en"}},
		}
	}
	claimsMap := map[string]any{mdocNamespaceForDocType(doctype): nsClaims}
	claims, _ = json.Marshal(claimsMap)

	// Values captured verbatim from C:\tmp\spike\run\mdl_config.json — the
	// exact configuration Inji Certify v0.14.0 accepted and issued a real,
	// cryptographically valid mdoc from. Do not approximate these.
	return doctype, vcTemplate, claims, mdoc.MdocSignatureAlgo, "CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN", "EcdsaSecp256r1Signature2019"
}
```

Modificar `SaveCustomSchema` para ramificar sobre el resultado de `stdToCredentialFormat` ANTES de construir `vcTemplate`/`displayOrder` a la manera existente:

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

// saveMdocSchema is SaveCustomSchema's mso_mdoc branch — a separate INSERT
// because mdoc's columns (doctype, mso_mdoc_claims, EC signing config) are
// entirely disjoint from the shared INSERT's SD-JWT/ldp_vc-specific
// columns (sd_jwt_vct, context, credential_type, Ed25519 signing config),
// which stay NULL/irrelevant for mdoc.
func (a *Adapter) saveMdocSchema(ctx context.Context, conn *pgx.Conn, schema vctypes.Schema) error {
	doctype, vcTemplate, claims, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite := mdocCredentialConfigValues(schema)

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
	$1, $1, 'active', $2,
	$3, NULL, NULL, NULL, $4,
	$5, $6, $7,
	$8, $9, NULL,
	$10, $11, $12,
	ARRAY['cose_key'],
	ARRAY['ES256'],
	'{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}'::JSONB,
	NULL, NULL, $13,
	NULL, NOW(), NULL
)
ON CONFLICT (credential_config_key_id) DO UPDATE SET
	vc_template              = EXCLUDED.vc_template,
	doctype                  = EXCLUDED.doctype,
	credential_format        = EXCLUDED.credential_format,
	key_manager_app_id       = EXCLUDED.key_manager_app_id,
	key_manager_ref_id       = EXCLUDED.key_manager_ref_id,
	signature_algo           = EXCLUDED.signature_algo,
	signature_crypto_suite   = EXCLUDED.signature_crypto_suite,
	display                  = EXCLUDED.display,
	display_order            = EXCLUDED.display_order,
	mso_mdoc_claims          = EXCLUDED.mso_mdoc_claims,
	upd_dtimes               = NOW()
`,
		schema.ID,       // $1
		vcTemplate,      // $2
		doctype,         // $3
		"mso_mdoc",      // $4
		a.cfg.DB.DIDUrl, // $5
		keyManagerAppID, // $6
		keyManagerRefID, // $7
		signatureAlgo,   // $8
		cryptoSuite,     // $9
		displayRaw,      // $10 JSONB
		displayOrder,    // $11 TEXT[]
		scope,           // $12
		claims,          // $13 JSONB
	)
	if err != nil {
		return fmt.Errorf("injicertify db: upsert mdoc credential_config %q: %w", schema.ID, err)
	}
	return nil
}
```

**Nota sobre `key_manager_ref_id`**: el INSERT existente (camino no-mdoc) hardcodea `'ED25519_SIGN'` como literal — este plan lo parametriza a `$7` para mdoc en vez de repetir un literal distinto; confirmar que la columna acepta el valor `EC_SECP256R1_SIGN` sin truncar (`VARCHAR(128)` según `certify_init.sql:112` — cabe sin problema).

- [ ] **Step 6: Confirmar que los tests pasan**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -v
```

Esperado: PASS en `TestStdToCredentialFormatMsoMdoc` y `TestMdocCredentialConfigValues`, y confirmar que la suite completa del paquete sigue en verde — específicamente `db_format_test.go`'s `TestStdToCredentialFormat` (verificar que su caso `default` usa un valor que NO es `"mso_mdoc"`, para que no colisione) y `db_vcdm_test.go`/`db_protected_term_test.go` (deben seguir probando exactamente el mismo comportamiento para `vc+sd-jwt`/`ldp_vc`, sin ningún cambio).

- [ ] **Step 7: Verificación empírica contra Inji Certify real**

Usando el entorno del spike (`C:\tmp\spike\run\README.md`), insertar una fila real vía `saveMdocSchema` (o SQL equivalente construido a mano con estos valores) contra una instancia de Inji Certify v0.14.0 real, y confirmar:
1. Inji Certify arranca sin error con esta fila presente (`docker logs` limpio).
2. `GET /v1/certify/.well-known/openid-credential-issuer` incluye la nueva `credential_configuration_id` con `format: "mso_mdoc"`.
3. Emitir un mDL de prueba contra este perfil (reusando `C:\tmp\spike\run\flow.py`, adaptado al nuevo `credential_config_key_id`) produce un CBOR válido — reusar `verify_mdoc.py` para decodificar y confirmar `driving_privileges` con 2 y 3 categorías reales sin modificar la fila entre emisiones.

- [ ] **Step 8: Commit**

```bash
git add internal/adapters/injicertify/db.go internal/adapters/injicertify/db_mdoc_test.go
git commit -m "feat(injicertify): SaveCustomSchema issues real mso_mdoc credential_config rows

stdToCredentialFormat now recognizes mso_mdoc, and SaveCustomSchema grew
a dedicated mdoc branch, committed together (not as separate steps) so
no intermediate state exists where the format is recognized but produces
a broken row.

doctype is resolved from schema.AdditionalTypes[0] — never schema.ID,
which is a generated custom-<nano> string for every custom schema, same
mistake already fixed once for walt.id (see handlers/schema.go:1187-1206)
and now avoided here from the start, verified by a test that constructs
the schema the way the real builder does.

vc_template, signature_algo/key_manager_app_id/key_manager_ref_id/
signature_crypto_suite all use the EXACT values captured in
C:\tmp\spike\run\mdl_config.json — the one artifact from the 2026-08-25
spike that recorded a configuration Inji Certify v0.14.0 actually
accepted and issued a valid, cryptographically verified mdoc from. mdoc's
vc_template is real Velocity, not NULL as an earlier draft of this plan
assumed — Inji genuinely needs one, with driving_privileges rendered
unquoted (a JSON array marker, not a string) via the same
placeholder-and-swap trick buildVCTemplate already uses for
statusIdx/nbf/exp.

Verified empirically against a real Inji Certify v0.14.0 instance."
```

---

### Task 3: `internal/adapters/injicertify/issuer.go` — `IssueToWallet` lee `StructuredData` y aplica defensa en profundidad (Pre-Auth únicamente)

**Files:**
- Modify: `verifiably-go/internal/adapters/injicertify/issuer.go`
- Test: `verifiably-go/internal/adapters/injicertify/issuer_mdoc_test.go` (crear)

**Interfaces:**
- Consumes: `backend.IssueRequest.StructuredData`, `mdoc.DrivingPrivilegesMaxCategories`, `mdoc.EncodeDrivingPrivileges`, `mdoc.DrivingPrivilege` (`internal/mdoc/drivingprivileges.go`, ya existen); `stdToCredentialFormat` (Task 2).
- Produces: `injicertify.IssueToWallet`, cuando `a.cfg.Mode == ModePreAuth` Y `stdToCredentialFormat(req.Schema.Std) == "mso_mdoc"`, construye claims correctos para `mso_mdoc` incluyendo `driving_privileges` desde `StructuredData`, y rechaza 0/>4 categorías ANTES de llamar a `/v1/certify/pre-authorized-data`.

**Nota sobre alcance/gating**: el guard nuevo DEBE condicionar sobre `a.cfg.Mode == ModePreAuth` explícitamente, no solo sobre el `Std` del schema — `IssueToWallet` es compartida por `ModePreAuth` y `ModeAuthCode`, y el camino `ModeAuthCode` (líneas ~231-265 del archivo existente) construye una oferta local que nunca lee `claims`/`SubjectData`/`StructuredData` en absoluto. Sin el gate explícito de modo, una llamada hipotética con `Mode: ModeAuthCode` y un schema `mso_mdoc` (alcanzable solo vía `POST /api/v1/credentials/issue` con un schema construido a mano, ya que la UI de Auth-Code nunca produce `Std=="mso_mdoc"` — confirmado, `injiFormatToStd` no tiene ese caso) pasaría por el nuevo guard y sería rechazada con un error que no aplica a ese modo, en vez de simplemente ignorar por completo el mecanismo mdoc-específico como debería (Auth-Code no soporta mdoc en este plan, punto — no debe ni intentar rechazarlo con un mensaje "0 categorías", debe comportarse exactamente como hoy).

**Nota sobre construir el `*Adapter` en los tests**: usar el constructor real `New(cfg, vendor)` (`adapter.go:35-44`), NUNCA `&Adapter{cfg: ...}` a mano — el struct real tiene un campo `client *httpx.Client` no exportado que `New` inicializa; construir el struct a mano lo deja `nil` y cualquier código que llegue a `a.client.DoJSON(...)` paniquea con nil-deref en vez de fallar limpio. Confirmar el patrón exacto de test HTTP contra este paquete leyendo `internal_markers_test.go` o `validity_window_test.go` ANTES de escribir el test de este task — ambos ya construyen un `*Adapter` de prueba contra un `httptest.Server` con `New(...)`.

- [ ] **Step 1: Escribir el test que falla — caso positivo (1-4 categorías reales)**

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

		a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL, PublicBaseURL: srv.URL}, "Inji Certify · Pre-Auth")
		if err != nil {
			t.Fatalf("n=%d: New: %v", n, err)
		}

		privileges := make([]mdoc.DrivingPrivilege, n)
		for i := range privileges {
			privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
		}
		raw, err := mdoc.EncodeDrivingPrivileges(privileges)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}

		req := backend.IssueRequest{
			Schema:         vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
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

- [ ] **Step 2: Confirmar que falla**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run TestIssueToWalletMdocCarriesDrivingPrivilegesFromStructuredData -v
```

Esperado: FAIL — `claims[driving_privileges] is <nil>`.

- [ ] **Step 3: Escribir los tests negativos — 0 y >4 categorías, y confirmar que el gate de modo funciona**

```go
func TestIssueToWalletMdocRejectsZeroDrivingPrivileges(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		SubjectData: map[string]string{"family_name": "Perez"},
		// StructuredData sin driving_privileges en absoluto.
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with no driving_privileges returned no error, want a rejection — never call the network")
	}
}

func TestIssueToWalletMdocRejectsOverCapDrivingPrivileges(t *testing.T) {
	a, err := New(Config{Mode: ModePreAuth, BaseURL: "http://unused-if-guard-works", PublicBaseURL: "http://unused"}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		SubjectData: map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{
			// Construido directamente como JSON crudo, SIN pasar por
			// mdoc.EncodeDrivingPrivileges (que ya trunca a 4 por su
			// cuenta) — así se reproduce "más de 4 llegó al adapter", no
			// "el encoder ya lo truncó", para que el guard del adapter sea
			// lo que realmente se está probando.
			"driving_privileges": mustMarshalNPrivileges(mdoc.DrivingPrivilegesMaxCategories + 1),
		},
	}
	if _, err := a.IssueToWallet(context.Background(), req); err == nil {
		t.Error("IssueToWallet with 5 driving_privileges returned no error, want a rejection — never call the network")
	}
}

func mustMarshalNPrivileges(n int) json.RawMessage {
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = map[string]string{"vehicle_category_code": "B", "issue_date": "2021-06-01", "expiry_date": "2031-06-01"}
	}
	raw, _ := json.Marshal(out)
	return raw
}

// TestIssueToWalletMdocGuardDoesNotApplyToAuthCode confirms the mdoc guard
// is scoped to ModePreAuth only, per this task's explicit gating
// requirement — a schema with Std=="mso_mdoc" reaching an Auth-Code-mode
// adapter must fall through to the EXISTING auth_code offer construction
// unmodified (which never reads claims/driving_privileges at all), not be
// rejected by the new mdoc-specific error messages.
func TestIssueToWalletMdocGuardDoesNotApplyToAuthCode(t *testing.T) {
	a, err := New(Config{Mode: ModeAuthCode, BaseURL: "http://unused", PublicBaseURL: "http://unused", AuthorizationServer: "http://unused"}, "Inji Certify · Auth-Code")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := backend.IssueRequest{
		Schema: vctypes.Schema{ID: "custom-abc", Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}},
		// Sin driving_privileges — si el guard mdoc se ejecutara aquí,
		// esto fallaría con "driving_privileges es obligatorio...". No
		// debe fallar por esa razón: ModeAuthCode construye su oferta
		// local sin tocar claims en absoluto.
	}
	res, err := a.IssueToWallet(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueToWallet in ModeAuthCode should not apply the mdoc guard, got error: %v", err)
	}
	if res.Flow != "auth_code" {
		t.Errorf("Flow = %q, want %q", res.Flow, "auth_code")
	}
}
```

- [ ] **Step 4: Confirmar que los tres fallan/pasan según corresponda**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -run 'TestIssueToWalletMdoc' -v
```

Esperado: `TestIssueToWalletMdocRejectsZeroDrivingPrivileges` y `TestIssueToWalletMdocRejectsOverCapDrivingPrivileges` FALLAN (el guard no existe todavía, así que no rechazan nada — el modo Pre-Auth intentará golpear la red real y fallará de otra forma, o silenciosamente "pasará" si `BaseURL` no resuelve; en cualquier caso el mensaje de error esperado no aparecerá). `TestIssueToWalletMdocGuardDoesNotApplyToAuthCode` ya PASA hoy (nada cambió aún para Auth-Code) — este es el caso de regresión que debe seguir pasando después del Step 5, no uno que deba fallar ahora.

- [ ] **Step 5: Implementar el guard, gateado a `ModePreAuth`**

Modificar el inicio de `IssueToWallet`:

```go
func (a *Adapter) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	claims := map[string]any{}
	for k, v := range req.SubjectData {
		claims[k] = v
	}

	// mso_mdoc's driving_privileges is an array of objects — it cannot ride
	// in SubjectData (map[string]string). It lives in StructuredData, same
	// convention as waltid/issuer2.go's buildIssuer2Offer. Reading it here,
	// and rejecting 0/>4 categories BEFORE ever calling Inji, replicates
	// the same defense-in-depth waltid's buildIssuer2Offer already has: the
	// handler's own guard (validateDrivingPrivilegesCount) can be bypassed
	// by a direct POST /api/v1/credentials/issue call, so this
	// adapter-level check is the one that must never be skipped.
	//
	// Gated on a.cfg.Mode == ModePreAuth explicitly, not just on the
	// schema's Std: IssueToWallet is shared by BOTH Pre-Auth and Auth-Code,
	// and Auth-Code's offer construction (below) never reads claims at
	// all — an mdoc schema reaching an Auth-Code-mode adapter (only
	// possible via a hand-built API call; the UI never produces this
	// combination) must fall through to that unmodified path, not be
	// rejected by an mdoc-specific guard that has no meaning for a mode
	// this plan explicitly does not support for mdoc.
	if a.cfg.Mode == ModePreAuth && stdToCredentialFormat(req.Schema.Std) == "mso_mdoc" {
		n := 0
		if raw, ok := req.StructuredData["driving_privileges"]; ok && len(raw) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return backend.IssueToWalletResult{}, fmt.Errorf("inji: driving_privileges no es un array JSON válido: %w", err)
			}
			n = len(arr)
			var privileges []any
			if err := json.Unmarshal(raw, &privileges); err != nil {
				return backend.IssueToWalletResult{}, fmt.Errorf("inji: driving_privileges no es JSON válido: %w", err)
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

- [ ] **Step 6: Confirmar que todos los tests pasan, incluyendo el de no-regresión de Auth-Code**

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go:/workspace" -w /workspace golang:1.25-alpine \
  go test ./internal/adapters/injicertify/... -v
```

Esperado: PASS en los 4 tests nuevos (incluido `TestIssueToWalletMdocGuardDoesNotApplyToAuthCode`, que debe seguir pasando exactamente como antes), y confirmar que ningún test existente del paquete se rompió.

- [ ] **Step 7: Portrait — verificación empírica obligatoria, no opcional**

Repetir el Step 1 del test positivo, pero con `SubjectData["portrait"]` como una cadena base64 real (reusar cualquier imagen base64 pequeña de prueba) en vez de `driving_privileges`, contra el servidor real de Inji Certify usado en Task 2 Step 7 (no un `httptest.Server` simulado — este step necesita el servicio real para confirmar que Inji efectivamente convierte el base64 a byte string CBOR, algo que el spike NUNCA probó). Decodificar el CBOR resultante con `verify_mdoc.py` y confirmar:
1. El campo `portrait` está presente en el `nameSpaces` decodificado.
2. Su `elementValue` es un byte string CBOR (major type 2), NO un string de texto — si Inji lo deja como texto, el mdoc no es conforme a ISO 18013-5 y este step debe fallar explícitamente, documentando el hallazgo, en vez de continuar asumiendo que "funciona igual que driving_privileges".

Si el step falla: NO continuar a Task 4 sin antes volver a Task 2 y ajustar `mdocCredentialConfigValues`/`mdocVCTemplate` con la declaración adicional que Inji requiera para esa conversión (analizar cómo Inji Certify declara conversiones byte-string en su documentación/código, ya que el spike no cubrió este caso).

- [ ] **Step 8: Commit**

```bash
git add internal/adapters/injicertify/issuer.go internal/adapters/injicertify/issuer_mdoc_test.go
git commit -m "feat(injicertify): IssueToWallet reads StructuredData for mso_mdoc (Pre-Auth only)

driving_privileges lives exclusively in backend.IssueRequest.StructuredData
since the driving_privileges variable-count plan — but injicertify.IssueToWallet
only ever read SubjectData, so an mDL issued via Inji would silently omit
this ISO 18013-5 Table 3 mandatory element. Fixed, with the same
defense-in-depth 0/>4-category rejection waltid.buildIssuer2Offer already
has.

Explicitly gated on a.cfg.Mode == ModePreAuth: IssueToWallet is shared by
both Pre-Auth and Auth-Code, and Auth-Code's own offer construction never
reads claims at all. A test pins that an mdoc schema reaching an
Auth-Code-mode adapter falls through unmodified rather than being
rejected by a guard meant only for Pre-Auth.

Portrait handling verified empirically against a real Inji Certify
instance (Step 7) — the spike itself never validated this."
```

---

### Task 4: `verifiably-go` — corregir la copia "mock-only" en la UI del builder de schemas

**Files:**
- Modify: `verifiably-go/templates/pages/issuer_schema_builder.html`

**Interfaces:**
- Consumes: nada.
- Produces: nada de código — solo texto visible al operador.

**Nota**: hay DOS afirmaciones "mock-only" en este archivo, no una — confirmar ambas antes de editar, releyendo el archivo real (no confiar en la transcripción de este plan, que puede no reflejar exactamente la indentación/atributos reales del `<option>`).

- [ ] **Step 1: Localizar y confirmar el texto exacto de AMBAS afirmaciones**

Buscar en `templates/pages/issuer_schema_builder.html`:
1. El `<option value="mso_mdoc" ...>` cuyo contenido de texto visible menciona "mock-only at v0.14" (cerca de la línea 140 — confirmar la línea real, que puede incluir un atributo `{{if eq $cur "mso_mdoc"}}selected{{end}}` u otro condicional Go-template que NO debe tocarse, solo el texto del contenido).
2. Un párrafo/hint (`<p class="hint">` o similar, cerca de la línea 142) con el texto *"mso_mdoc is mock-only in Certify v0.14 — it'll configure but isn't a usefully-verifiable credential"* o su equivalente exacto en el archivo real.

- [ ] **Step 2: Corregir ambas, preservando cualquier lógica de template circundante**

Para el `<option>`: cambiar SOLO el texto visible dentro de la etiqueta, de `mso_mdoc — ISO 18013-5 mDL/mDoc (Inji Certify: mock-only at v0.14)` a `mso_mdoc — ISO 18013-5 mDL/mDoc`, sin tocar ningún atributo ni bloque `{{...}}` que la rodee.

Para el hint/párrafo: eliminar o reescribir la afirmación de que es mock-only, dado que Task 2/3 lo hacen real para el DPG Inji Pre-Auth. Redacción sugerida (ajustar al tono/estructura real del párrafo existente): *"mso_mdoc requiere un perfil pre-provisionado por el operador de la plataforma en el DPG elegido — confirma con tu operador si el DPG actual lo soporta antes de guardar."* (Genérico entre DPGs — no afirmar que TODOS los DPGs lo soportan, walt.id e Inji Pre-Auth sí, Inji Auth-Code no, sin nombrar cada uno explícitamente en este texto genérico del builder.)

- [ ] **Step 3: Verificar sintaxis del template**

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

(Ajustar el `FuncMap` con las funciones reales que el template usa si el comando falla por una función faltante.)

- [ ] **Step 4: Commit**

```bash
git add templates/pages/issuer_schema_builder.html
git commit -m "docs(inji): correct mso_mdoc copy — no longer mock-only under Inji Pre-Auth"
```

---

### Task 5: `cdpi-wallet` — corregir el envoltorio `{docType, issuerSigned}` y verificar confianza en el camino `manual-mdoc`, reusando el mecanismo existente

**Files:**
- Modify: `cdpi-wallet/src/agent/oid4vci/requestCredentials.ts`
- Modify: `cdpi-wallet/src/agent/oid4vci/storeCredential.ts`
- Create fixture: `cdpi-wallet/src/__tests__/fixtures/inji-mdoc-wrapped.json` (copiado de `C:\tmp\spike\run\mdl_4categories.json` o `credential_response.json`)
- Create fixture: `cdpi-wallet/src/__tests__/fixtures/waltid-mdoc-unwrapped.json` (cualquier CBOR mdoc válido ya emitido por walt.id en este proyecto)
- Test: `cdpi-wallet/src/__tests__/requestCredentialsMdocWrapper.test.ts` (crear)
- Test: `cdpi-wallet/src/__tests__/storeCredentialMdoc.test.ts` (existente — extender el mock de `@credo-ts/core` y añadir casos)

**Interfaces:**
- Consumes: `cborDecode`/`cborEncode` (ya exportados por `@animo-id/mdoc`, confirmado en `node_modules/@animo-id/mdoc/dist/index.d.ts:537-539,1117` — **no se añade ninguna dependencia CBOR nueva**), `Mdoc.fromBase64Url` (`@credo-ts/core`, ya usado en `storeCredential.ts`), `mdoc.verify(agentContext, options)` (método de instancia, confirmado en `Mdoc.mjs:111-140` — no muta el objeto `mdoc`, así que llamarlo antes de `MdocRecord.fromMdoc(mdoc)` es seguro), `setCurrentIssuerBaseUrl`/el resolver `getTrustedCertificatesForVerification` (`src/agent/mdocTrustAnchors.ts`, YA REGISTRADO en `setup.ts` como el `X509ModuleConfig.getTrustedCertificatesForVerification` del agente — no hace falta pasarle nada explícitamente a `verify()`).
- Produces: la rama `manual-mdoc` de `requestOid4VciCredentials` corrige el envoltorio antes de empujar el resultado; la rama `manual-mdoc` de `storeOid4VciCredential` llama `mdoc.verify(agent.context)` (SIN pasar `trustedCertificates` — dejando que el resolver ya registrado los resuelva) antes de persistir. **La firma pública de `storeOid4VciCredential` NO cambia**, y `app/receive.tsx` (el único call site real, confirmado por grep, línea 249) no se toca.

**Nota sobre por qué NO se añade un parámetro `issuerBaseUrl` a `storeOid4VciCredential`**: el único call site real está en `app/receive.tsx:249`, y su `offerInfo` state (`{issuer, credentials, txCodeRequired, txCodeDescription}`) no tiene una URL, solo un nombre para mostrar — añadir el parámetro habría exigido cambiar el shape del state, `resolveOID4VCI`, y el call site, tres ediciones en un archivo fuera de la lista de Files de esta tarea. El mecanismo YA EXISTENTE (`setCurrentIssuerBaseUrl`/`clearCurrentIssuerBaseUrl`, `mdocTrustAnchors.ts:118-125`) resuelve esto sin tocar ninguno de los tres: `requestOid4VciCredentials` ya tiene `issuerUrl` en scope (línea ~231 del archivo actual) y ya lo usa para la rama Credo-managed (línea ~407, `setCurrentIssuerBaseUrl(issuerUrl)`); esta tarea llama la misma función también antes/durante la rama `manual-mdoc`, y el resolver ya registrado en `setup.ts` hace el resto — `mdoc.verify(agent.context)` (sin `options.trustedCertificates`) internamente invoca ese resolver, exactamente igual que la rama Credo-managed ya hace, con la unión fetched+static y el fallback a stale-cache ya implementados ahí.

**Nota sobre `verify()` con array vacío no es "fail closed" automáticamente**: si `trustedCertificates` se pasara explícitamente como `[]` (NO lo hagas — ver arriba, no pases el parámetro en absoluto), `Mdoc.verify` lo trata como truthy y NO cae al fallback ni lanza — pasa `[]` a `verifyIssuerSignature`, que sí falla (rechazo correcto pero por el camino equivocado, con un mensaje críptico). Al no pasar `trustedCertificates` en absoluto (dejando `options` sin esa clave, o `options` como `{}`), `Mdoc.verify` cae correctamente a `x509ModuleConfig.getTrustedCertificatesForVerification`, que es el comportamiento deseado.

- [ ] **Step 1: Copiar las fixtures del spike y de walt.id al repo**

```bash
mkdir -p src/__tests__/fixtures
cp "/c/tmp/spike/run/mdl_4categories.json" src/__tests__/fixtures/inji-mdoc-wrapped.json
```

Confirmar (releyendo el JSON o con `verify_mdoc.py` si hace falta) que la forma es `{"credential": "<base64url>"}` cuyo CBOR decodificado es `{docType, issuerSigned}`. Para la segunda fixture, usar cualquier CBOR mdoc real ya emitido por walt.id en sesiones anteriores de este proyecto (forma `{nameSpaces, issuerAuth}` directa, sin envoltorio) — guardar como `src/__tests__/fixtures/waltid-mdoc-unwrapped.json` con la misma forma `{"credential": "<base64url>"}`.

- [ ] **Step 2: Escribir el test que falla — detección y extracción del envoltorio**

```typescript
import { detectAndUnwrapMdocEnvelope } from '../agent/oid4vci/requestCredentials';
import { cborDecode } from '@animo-id/mdoc';
import wrappedFixture from './fixtures/inji-mdoc-wrapped.json';
import unwrappedFixture from './fixtures/waltid-mdoc-unwrapped.json';

function base64UrlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

describe('detectAndUnwrapMdocEnvelope', () => {
  test('extracts issuerSigned from an Inji-style {docType, issuerSigned} wrapper', () => {
    const wrappedBase64Url = (wrappedFixture as { credential: string }).credential;
    const result = detectAndUnwrapMdocEnvelope(wrappedBase64Url);
    expect(result.wasWrapped).toBe(true);
    const decoded = cborDecode(base64UrlToBytes(result.base64Url)) as Record<string, unknown>;
    expect(decoded).toHaveProperty('nameSpaces');
    expect(decoded).toHaveProperty('issuerAuth');
    expect(decoded).not.toHaveProperty('docType');
    expect(decoded).not.toHaveProperty('issuerSigned');
  });

  test('passes a walt.id-style unwrapped CBOR through unmodified', () => {
    const unwrappedBase64Url = (unwrappedFixture as { credential: string }).credential;
    const result = detectAndUnwrapMdocEnvelope(unwrappedBase64Url);
    expect(result.wasWrapped).toBe(false);
    expect(result.base64Url).toBe(unwrappedBase64Url); // idéntico, sin re-serializar
  });
});
```

- [ ] **Step 3: Confirmar que falla**

```bash
cd cdpi-wallet
npx jest src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: `detectAndUnwrapMdocEnvelope is not a function`.

- [ ] **Step 4: Implementar `detectAndUnwrapMdocEnvelope` en `requestCredentials.ts`**

```typescript
import { cborDecode, cborEncode } from '@animo-id/mdoc';

/**
 * Detects and corrects Inji Certify's non-standard mdoc response shape.
 *
 * Inji Certify v0.14.0's MDocCredential.addProof wraps the already-signed
 * IssuerSigned map inside an extra {docType, issuerSigned} container — the
 * shape of a DeviceResponse Document, not a standalone credential. Credo/
 * @animo-id/mdoc expects the IssuerSigned map directly. Confirmed in the
 * 2026-08-25 validation spike: stripping this outer container makes the
 * same credential parse correctly.
 *
 * Only the OUTER container is discarded — the inner issuerSigned VALUE is
 * re-encoded as its own top-level CBOR item via @animo-id/mdoc's own
 * cborEncode (which is cbor-x under the hood — see its DataItem doc
 * comment about eager encoding). This does NOT guarantee byte-identical
 * output to what a hypothetical unwrapped response would have been (map
 * key ordering could differ), but the COSE_Sign1 signature inside
 * issuerAuth is an opaque byte string that travels through untouched —
 * the post-extraction integrity check in storeCredential.ts (via
 * mdoc.verify()) is what actually confirms nothing inside issuerSigned
 * was corrupted, not an assumption made here.
 *
 * Detection is on the actual decoded shape of the bytes received, never on
 * an assumption of which DPG produced them: a walt.id credential (no
 * wrapper) passes through completely unmodified, byte-for-byte.
 */
export function detectAndUnwrapMdocEnvelope(base64Url: string): { base64Url: string; wasWrapped: boolean } {
  const bytes = base64UrlToBytes(base64Url);
  let decoded: unknown;
  try {
    decoded = cborDecode(bytes);
  } catch {
    return { base64Url, wasWrapped: false }; // not decodable as the wrapper shape — pass through, let downstream parsing surface the real error
  }

  if (
    decoded &&
    typeof decoded === 'object' &&
    'issuerSigned' in decoded &&
    'docType' in decoded &&
    !('nameSpaces' in decoded)
  ) {
    const inner = (decoded as Record<string, unknown>).issuerSigned;
    const reEncoded = cborEncode(inner);
    return { base64Url: bytesToBase64Url(reEncoded), wasWrapped: true };
  }

  return { base64Url, wasWrapped: false };
}

function base64UrlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

(Si `TypedArrayEncoder`, ya importado en este archivo desde `@credo-ts/core`, expone métodos base64url equivalentes, preferirlos sobre estas dos funciones caseras — confirmar su API real antes de decidir.)

- [ ] **Step 5: Conectar `detectAndUnwrapMdocEnvelope` a la rama `manual-mdoc`, y registrar el issuer para el resolver de confianza**

Modificar el bloque `else if (format === 'mso_mdoc' && legacy)` existente:

```typescript
} else if (format === 'mso_mdoc' && legacy) {
  // ... código existente sin cambios hasta obtener rawCredential ...
  const rawCredential = (data.credential ?? (data.credentials as string[] | undefined)?.[0]) as string | undefined;
  if (!rawCredential) throw new Error('El emisor no retornó una credencial en la respuesta.');

  const { base64Url: credential, wasWrapped } = detectAndUnwrapMdocEnvelope(rawCredential);
  if (wasWrapped) {
    log('[oid4vci] mso_mdoc credential was wrapped in {docType, issuerSigned} — unwrapped');
  }
  log('[oid4vci] mso_mdoc credential bytes (base64url):', credential.length);
  results.push({ path: 'manual-mdoc', configId, displayName, credential, keyId, docType, issuerUrl });
}
```

Añadir `issuerUrl: string` a `ManualMdocResult` (el tipo, definido más arriba en el mismo archivo) — `issuerUrl` ya está en scope en toda la función (línea ~231), así que adjuntarlo al resultado es un cambio de una línea en el tipo y otra en el `results.push`, y es lo que permite a `storeCredential.ts` llamar `setCurrentIssuerBaseUrl` en el momento correcto SIN tocar `receive.tsx`.

- [ ] **Step 6: Confirmar que el test del envoltorio pasa**

```bash
npx jest src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: PASS ambos casos.

- [ ] **Step 7: Escribir el test que falla — verificación en `storeCredential.ts`, reusando el resolver existente**

Extender el mock de `@credo-ts/core` en `storeCredentialMdoc.test.ts` (el existente, línea 12-30) para que `Mdoc.fromBase64Url` sea espiable y `MdocRecord` tenga `fromMdoc`:

```typescript
jest.mock('@credo-ts/core', () => ({
  Mdoc: { fromBase64Url: jest.fn() },
  MdocRecord: class {
    tags: Record<string, unknown> = {};
    id = 'mdoc-record-id';
    setTag(key: string, value: unknown) { this.tags[key] = value; }
    static fromMdoc(_mdoc: unknown) { return new this(); }
  },
  SdJwtVcRecord: class {},
  W3cCredentialRecord: class {
    id = 'w3c-record-id';
    credentialInstances: unknown;
    constructor(opts: { credentialInstances: unknown }) { this.credentialInstances = opts.credentialInstances; }
  },
  W3cV2CredentialRecord: class {},
}));

jest.mock('../agent/mdocTrustAnchors', () => ({
  setCurrentIssuerBaseUrl: jest.fn(),
  clearCurrentIssuerBaseUrl: jest.fn(),
}));
```

(Este segundo `jest.mock` es nuevo — el archivo existente no lo tenía porque nunca llamaba nada de `mdocTrustAnchors.ts` antes de esta tarea.)

Añadir el describe nuevo:

```typescript
import { Mdoc, MdocRecord } from '@credo-ts/core';
import { setCurrentIssuerBaseUrl } from '../agent/mdocTrustAnchors';

describe('storeOid4VciCredential — manual-mdoc path: envelope + trust verification', () => {
  function makeAgentAndMdoc(verifyResult: { isValid: boolean; error?: string }) {
    const verify = jest.fn().mockResolvedValue(verifyResult);
    const fakeMdoc = { deviceKeyId: undefined as string | undefined, verify };
    (Mdoc.fromBase64Url as jest.Mock).mockReturnValue(fakeMdoc);
    const store = jest.fn().mockResolvedValue(new MdocRecord());
    const update = jest.fn().mockResolvedValue(undefined);
    const agent = { mdoc: { store, update }, context: {} } as unknown as WalletAgent;
    return { agent, verify, store };
  }

  test('rejects and does NOT store when mdoc.verify() reports invalid', async () => {
    const { agent, store } = makeAgentAndMdoc({ isValid: false, error: 'signature mismatch' });
    const result: CredentialResult = {
      path: 'manual-mdoc', configId: 'org.iso.18013.5.1.mDL', credential: 'AAAA', keyId: 'k1', docType: 'org.iso.18013.5.1.mDL', issuerUrl: 'https://issuer.example',
    };
    await expect(storeOid4VciCredential(agent, result, { issuerName: 'INTRANT' })).rejects.toThrow();
    expect(store).not.toHaveBeenCalled();
  });

  test('stores when mdoc.verify() reports valid, having registered the issuer via setCurrentIssuerBaseUrl and called verify with NO explicit trustedCertificates', async () => {
    const { agent, verify, store } = makeAgentAndMdoc({ isValid: true });
    const result: CredentialResult = {
      path: 'manual-mdoc', configId: 'org.iso.18013.5.1.mDL', credential: 'AAAA', keyId: 'k1', docType: 'org.iso.18013.5.1.mDL', issuerUrl: 'https://issuer.example',
    };
    await storeOid4VciCredential(agent, result, { issuerName: 'INTRANT' });
    expect(setCurrentIssuerBaseUrl).toHaveBeenCalledWith('https://issuer.example');
    expect(store).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledWith(agent.context, {}); // sin trustedCertificates explícito — deja que el resolver YA REGISTRADO en setup.ts los resuelva
  });
});
```

**Nota**: este test NO asserta `expect.objectContaining({ trustedCertificates: expect.any(Array) })` — deliberadamente, porque esa forma de llamar a `verify()` es exactamente lo que este plan evita (ver la nota de diseño arriba sobre por qué no pasar `trustedCertificates` explícito).

- [ ] **Step 8: Confirmar que falla**

```bash
npx jest src/__tests__/storeCredentialMdoc.test.ts
```

Esperado: FAIL — la rama `manual-mdoc` hoy no llama `.verify()` ni `setCurrentIssuerBaseUrl` en absoluto, y `CredentialResult`'s variante `manual-mdoc` no tiene el campo `issuerUrl` todavía (error de tipo TypeScript si se corre con chequeo de tipos, o simplemente el campo se ignora en runtime).

- [ ] **Step 9: Implementar la verificación en `storeCredential.ts`, sin cambiar la firma pública**

```typescript
import { setCurrentIssuerBaseUrl, clearCurrentIssuerBaseUrl } from '../mdocTrustAnchors';

// ... dentro de storeOid4VciCredential, reemplazar la rama manual-mdoc existente:

if (result.path === 'manual-mdoc') {
  const { credential, keyId, docType, configId, displayName, issuerUrl } = result;
  const mdoc = Mdoc.fromBase64Url(credential, docType);
  mdoc.deviceKeyId = keyId;

  // Verificación de INTEGRIDAD ESTRUCTURAL + CONFIANZA DEL EMISOR en una
  // sola llamada — mdoc.verify() hace ambas: verifyIssuerSignature confirma
  // que la firma COSE_Sign1 cuadra matemáticamente (lo que prueba que la
  // corrección del envoltorio de Inji, si aplicó, no corrompió los bytes
  // firmados), y valida esa chain contra trustedCertificates. Registrar el
  // issuer vía setCurrentIssuerBaseUrl ANTES de llamar verify() — es el
  // MISMO mecanismo que la rama Credo-managed ya usa (ver más abajo en este
  // archivo/en requestCredentials.ts), así que este camino manual-mdoc
  // simplemente lo estaba saltando antes, para NINGÚN emisor (walt.id
  // incluido), no solo Inji. No se pasa options.trustedCertificates
  // explícito: dejar que x509ModuleConfig.getTrustedCertificatesForVerification
  // (registrado en setup.ts) resuelva la unión fetched+static con su propio
  // fallback a cache — reimplementar eso aquí sería peor que reusarlo.
  setCurrentIssuerBaseUrl(issuerUrl);
  let verification: { isValid: boolean; error?: string };
  try {
    verification = await mdoc.verify(agent.context, {});
  } finally {
    clearCurrentIssuerBaseUrl();
  }
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
```

Actualizar el tipo `ManualMdocResult` en `requestCredentials.ts` (Step 5 ya lo hizo) y confirmar que `CredentialResult`'s uso en `storeCredential.ts` sigue siendo válido con el campo nuevo.

- [ ] **Step 10: Confirmar que todos los tests pasan**

```bash
npx jest src/__tests__/storeCredentialMdoc.test.ts src/__tests__/requestCredentialsMdocWrapper.test.ts
```

Esperado: PASS en todo, y confirmar que los tests preexistentes de la rama `credo`/`manual-w3c-ld` en `storeCredentialMdoc.test.ts` siguen pasando sin cambios — la firma pública de `storeOid4VciCredential` no cambió, así que no hay razón para que se rompan, pero confirmarlo explícitamente.

- [ ] **Step 11: Verificación empírica end-to-end contra Inji real**

Con Tasks 1-3 y esta tarea completas, en un entorno con Inji Certify real (reusando el spike): emitir un mDL real vía Inji, aceptarlo con este código actualizado, y confirmar en logs/inspección que (1) el envoltorio se detectó y corrigió, (2) `mdoc.verify()` devolvió `isValid: true` contra los anchors reales del deployment (vía el resolver existente, no un valor pasado a mano), (3) la credencial quedó almacenada y es presentable. Repetir emitiendo un mDL vía walt.id (sin envoltorio) y confirmar que también pasa — el chequeo de confianza nuevo no debe romper el camino walt.id existente.

- [ ] **Step 12: Commit**

```bash
git add src/agent/oid4vci/requestCredentials.ts src/agent/oid4vci/storeCredential.ts \
        src/__tests__/requestCredentialsMdocWrapper.test.ts src/__tests__/storeCredentialMdoc.test.ts \
        src/__tests__/fixtures/inji-mdoc-wrapped.json src/__tests__/fixtures/waltid-mdoc-unwrapped.json
git commit -m "fix(oid4vci): unwrap Inji's {docType, issuerSigned} mdoc envelope, verify trust via existing resolver

Inji Certify v0.14.0's MDocCredential.addProof wraps the signed
IssuerSigned map in an extra {docType, issuerSigned} container — the
manual-mdoc branch (already active for Inji via isLegacyEndpoint) now
detects and strips this, using @animo-id/mdoc's own already-exported
cborDecode/cborEncode (no new CBOR dependency).

Also closes a pre-existing gap: the manual-mdoc path never called
mdoc.verify() at all, for ANY issuer — a walt.id mdoc accepted through
this path carried no issuer-trust-chain verification either. Both DPGs
now get it, reusing the EXISTING setCurrentIssuerBaseUrl / X509ModuleConfig
resolver mechanism the Credo-managed path already relies on (fetched+static
anchor union, stale-cache fallback) rather than reimplementing a weaker
version of it — no explicit trustedCertificates are passed to verify(),
and storeOid4VciCredential's public signature is unchanged (the issuer URL
travels on ManualMdocResult itself, not as a new parameter), so the one
real call site in app/receive.tsx needs no changes."
```

---

### Task 6: Verificación end-to-end real contra la VPS

**Files:** ninguno (verificación manual, sin cambios de código)

**Interfaces:** ninguna nueva — consume todo lo construido en Tasks 1-5, desplegado.

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

Levantar (o confirmar ya levantado) el servicio `inji-certify-preauth` en `/root/apps/demo-daas-3-0` — reusando la imagen `injistack/inji-certify-with-plugins:0.14.0` ya validada en el spike, con Postgres propio, siguiendo el patrón de despliegue ya establecido para los demás servicios Inji de este proyecto.

- [ ] **Step 3: Provisionar el perfil mdoc real vía el builder de la UI**

Desde `/issuer/dpg` con el DPG Inji Pre-Auth seleccionado, crear el schema mdoc mDL a través del builder real (`ShowSchemaBuilder`), confirmando que `SaveCustomSchema` (Task 2) escribe correctamente en la base de datos de Inji Certify de producción — con el docType correcto (Task 2's corrección de `AdditionalTypes[0]`), no `"custom-<nano>"`.

- [ ] **Step 4: Emitir mDLs reales por cada emisor, 1 a 4 categorías, y comparar**

Repetir el patrón de verificación del plan anterior (`2026-08-24-mdl-driving-privileges-variable-count`), cubriendo AMBOS DPGs:
- walt.id: 4 credenciales (1-4 categorías) — sin cambios de comportamiento esperados, solo reconfirmación de que nada se rompió.
- Inji Pre-Auth: 4 credenciales (1-4 categorías), decodificando cada CBOR y confirmando exactamente N entradas en `driving_privileges`, sin duplicación ni truncamiento, portrait presente como byte string (no texto), firma COSE_Sign1 válida.

- [ ] **Step 5: Probar el formulario web real end-to-end, incluyendo rechazos**

Un humano (no un agente) debe:
1. Elegir Inji Pre-Auth en `/issuer/dpg`, seleccionar el schema mDL, llenar 1 categoría y emitir — confirmar en la wallet real que se recibe correctamente (envoltorio corregido, verificación de confianza pasa).
2. Repetir con 2, 3, y 4 categorías.
3. Intentar 0 categorías — confirmar el mensaje de rechazo del handler.
4. Intentar una 5ª categoría vía API directa — confirmar el rechazo de `injicertify.IssueToWallet` (Task 3) antes de que la request llegue a Inji.
5. Repetir el mismo flujo emitiendo vía walt.id, para confirmar que el chequeo de confianza nuevo en `cdpi-wallet` (Task 5) no rompió el camino existente.

- [ ] **Step 6: Confirmar la corrección de UI (Task 4) visible en producción**

Confirmar que el builder de schemas ya no muestra ninguna de las dos afirmaciones "mock-only at v0.14" para `mso_mdoc`.

---

## Notas finales para quien ejecute este plan

- El orden de las tareas es deliberado: Task 1 (constante compartida) antes de Task 2 (que la consume); Task 2 (perfil persistido, incluyendo `stdToCredentialFormat` — fusionadas en un solo commit, ver la nota en Task 2, para que nunca exista un estado intermedio donde el formato se reconoce pero produce una fila rota) antes de Task 3 (emisión que asume que el perfil existe) antes de Task 4 (UI) antes de Task 5 (wallet, que necesita una credencial real de Inji para probar contra) antes de Task 6 (end-to-end). No reordenar.
- Tasks 1-4 son exclusivamente `verifiably-go`; Task 5 es exclusivamente `cdpi-wallet`; Task 6 cruza ambos repos y requiere acceso a la VPS real y a un dispositivo con la wallet — si quien ejecuta este plan no tiene ese acceso, las Tasks 1-5 dejan el código listo pero **no verificado en producción**, y debe decirse explícitamente así al reportar el resultado.
- Los valores de firma/plantilla de Task 2 (`CERTIFY_VC_SIGN_EC_R1`, `EC_SECP256R1_SIGN`, `EcdsaSecp256r1Signature2019`, y la forma del `vc_template`) están tomados VERBATIM de `C:\tmp\spike\run\mdl_config.json` — releer ese archivo antes de escribir el código de Task 2, no confiar solo en la transcripción de este plan, que puede contener errores de transcripción del base64/JSON original.
- Portrait (Task 3 Step 7) es una verificación EMPÍRICA OBLIGATORIA contra un Inji Certify real, no opcional — el spike nunca lo probó, y si falla, Task 2 debe revisarse antes de continuar.
- El guard de `driving_privileges` en Task 3 está explícitamente gateado a `ModePreAuth` — cualquier implementador que lo generalice a ambos modos sin una razón nueva y documentada estaría violando el alcance de este plan.
- Cada `git commit` de este plan debe hacerse solo después de que la suite del paquete correspondiente esté en verde — no acumular cambios sin probar entre tareas.
