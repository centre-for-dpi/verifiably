# Issuer mDL (ISO/IEC 18013-5) en Go — Implementation Plan

> **Superseded (2026-08-21):** este plan fue ejecutado completamente y
> luego revertido como camino de emisión de PRODUCCIÓN el mismo día que se
> completó (`d9c15cf` → `ce3e899`) — firmar en el proceso Go rompía la
> regla "verifiably media, los DPG emiten". El código que este plan produjo
> (`internal/mdl/`) sigue existiendo y sigue siendo valioso, pero solo como
> **verificador de conformidad independiente**, nunca como el servicio que
> firma el mDL de un ciudadano real. Ver
> `docs/superpowers/adr/2026-08-21-mdl-portrait-path-decision.md` para la
> decisión final y su razonamiento. Un operador desplegando este sistema no
> necesita ejecutar nada de este plan — `issuer-api2` (walt.id) es el
> emisor de producción, ver `docs/deploy.md#mdl-mdoc-issuance-issuer-api2`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir en `verifiably-go` un emisor de credenciales mDL conformes a ISO/IEC 18013-5 que produzca `IssuerSigned`/`MobileSecurityObject` firmados y verificables por un verificador independiente.

**Architecture:** Un paquete nuevo `internal/mdl/` construye las estructuras CBOR del estándar (`IssuerSignedItem` → `valueDigests` → `MobileSecurityObject`) y las firma como `COSE_Sign1` con `x5chain`, detrás de una interfaz `Signer` que vive en `internal/signer/` para no colisionar con el trabajo de KMS ya planificado. Un subpaquete `internal/mdl/pki/` genera la cadena IACA→DSC autofirmada de la POC. La verificación cruzada la hace un harness Node con `@owf/mdoc`, que actúa como verificador independiente y como contrato ejecutable para los otros repos.

**Tech Stack:** Go 1.25, `github.com/fxamacker/cbor/v2` (ya presente), `github.com/veraison/go-cose` (nueva), `crypto/x509` y `crypto/ecdsa` de la stdlib. Harness de verificación en Node con `@owf/mdoc`. Docker (`golang:1.25-alpine`) para ejecutar Go.

**Spec:** `docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md`

**Alcance de este plan:** cubre **C.7.0 (Fase 0)**, **C.7.1 (issuer)** y **C.7.2 (dataset)** del Tramo C. El holder (`cdpi-wallet`), el reader y el Tramo D tienen planes propios.

## Global Constraints

- **Go 1.25.0** (`go.mod`). No subir la versión.
- **Rama:** `feat/mdl-issuer` en el repo `verifiably`. Commits Conventional **con scope**: `feat(mdl):`, `test(mdl):`, `chore(mdl):`.
- **Curva:** P-256 (`prime256v1`) y **ES256** en toda la cadena. No usar otras curvas.
- **Namespace:** `org.iso.18013.5.1`. **DocType:** `org.iso.18013.5.1.mDL`.
- **Tags CBOR — regla estricta** (§C.7.1 del spec):
  - Tag **0** (`tdate`): los cuatro campos de `ValidityInfo` (`signed`, `validFrom`, `validUntil`, `expectedUpdate`). **Usar 1004 aquí invalida el MSO.**
  - Tag **1004** (full-date): `birth_date` — solo full-date.
  - Tag **0 ó 1004**: `issue_date`, `expiry_date`.
  - Tag **24** (`bstr .cbor`): `IssuerSignedItemBytes`, `MobileSecurityObjectBytes`.
- **Restricción normativa de `ValidityInfo`:** `validFrom` ≥ `issue_date` y **`validUntil` ≤ `expiry_date`**.
- **Perfiles de certificado (Annex B, normativo):** DSC con EKU **`1.0.18013.5.1.2`** y validez **≤457 días**; además **≤ la validez de la IACA**.
- **PKI de POC:** IACA autofirmada de **90 días**, subject con **`O=POC-DO-NOT-TRUST`**. Claves privadas **nunca** en el repositorio.
- **Digest algorithm:** SHA-256.
- **Dataset:** 10 de los 11 elementos mandatory (**se difiere `portrait`**) + `age_over_18` + `age_over_21` = **12 elementos**.
- **`age_over_NN` se calcula respecto a `validFrom` del MSO**, no a la fecha de emisión ni a la actual.

### Ejecutar Go sin instalación local

Go **no está instalado** en la máquina de desarrollo; el proyecto usa Docker. Todos los comandos `go` de este plan se ejecutan así, desde `verifiably-go/`:

```bash
docker run --rm -v "$PWD":/app -w /app golang:1.25-alpine go test ./internal/mdl/... -v
```

Para abreviar, define una vez por sesión de terminal:

```bash
alias gorun='docker run --rm -v "$PWD":/app -w /app golang:1.25-alpine go'
```

Y entonces `gorun test ./internal/mdl/... -v`. **Si tienes Go 1.25 instalado localmente, usa `go` directamente y omite Docker.** Los pasos de este plan escriben `go ...`; sustituye por `gorun ...` si usas Docker.

---

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `internal/signer/signer.go` | Interfaz `Signer` (firma + cadena de certificados). Nada más. |
| `internal/signer/software.go` | `SoftwareSigner`: implementación con clave en memoria. |
| `internal/mdl/pki/pki.go` | Generación de IACA autofirmada y DSC conformes al Annex B. |
| `internal/mdl/doctype.go` | Constantes del namespace, doctype y lista de elementos del dataset. |
| `internal/mdl/cbortypes.go` | Tipos CBOR del estándar con sus tags: `IssuerSignedItem`, `ValidityInfo`, `MobileSecurityObject`, `IssuerSigned`. |
| `internal/mdl/encode.go` | Construcción de `IssuerSignedItem`s, cálculo de `valueDigests` y ensamblado del MSO. |
| `internal/mdl/sign.go` | Firma del MSO como `COSE_Sign1` con `x5chain`. |
| `internal/mdl/issue.go` | Fachada: de datos de entrada tipados a `IssuerSigned` completo. |
| `internal/mdl/testdata/devicekey_test.json` | Clave de dispositivo de prueba (desacopla del holder). |
| `internal/mdl/testdata/vectors/` | Vectores generados: contrato ejecutable con los otros repos. |
| `internal/mdl/testdata/verify/` | Harness Node con `@owf/mdoc` — verificador independiente. |

Cada archivo tiene una responsabilidad y se puede leer entero de una vez. `cbortypes.go` se separa de `encode.go` porque los tipos son el contrato y la lógica de ensamblado cambia por separado.

---

## Task 0: Fase 0 — Spike bloqueante de hardware

**Este task es un gate. Si no pasa, el resto del plan no se ejecuta.** No produce código de producción; produce una decisión y un informe.

**Files:**
- Create: `docs/mdl-fase0-report.md`

**Interfaces:**
- Consumes: nada.
- Produces: el informe con el veredicto y el nivel de seguridad de claves por dispositivo, que alimenta §S-4 del spec.

**Prerrequisitos que hay que tener antes de empezar** (§C.7.0 del spec — alcance
revisado: 1 Android + 1 iPhone, no dos Android):
- **1 Android físico.**
- **1 iPhone con acceso al pipeline EAS Build del proyecto** (cuenta de Apple
  Developer y credenciales ya configuradas — confirmado que existen: ya se generó
  un `.ipa` instalable de `cdpi-wallet`, sin el módulo mdoc, corriendo en ese
  iPhone).
- Sniffer BLE (nRF) para la evidencia de canal.
- JDK + Android Studio (para compilar el reader de contraste — solo tiene build
  Android; no se prueba iPhone como reader en esta fase).
- Dev client de Expo (Expo Go **no** sirve).

- [ ] **Step 1: Compilar el reader de contraste**

```bash
git clone https://github.com/openwallet-foundation/multipaz-identity-reader
cd multipaz-identity-reader
./gradlew :composeApp:assembleDebug
```

Instalar el APK en el Android. Este reader es la contraparte del spike — no se
forkea, se usa tal cual. Solo hace de reader en esta fase; no se prueba como holder.

- [ ] **Step 2: Integrar el transporte BLE en cdpi-wallet, para AMBAS plataformas**

Instalar el paquete **pineado a la versión exacta** (es la única versión publicada
del paquete desescopado de OWF Labs, no `@animo-id/...`):

```bash
npm install expo-mdoc-data-transfer@0.2.0-alpha.5
```

Build local Android:
```bash
npx expo prebuild --platform android
npx expo run:android
```

Build iOS vía EAS (el mismo pipeline que ya produjo el `.ipa` actual):
```bash
eas build --platform ios --profile <perfil ya usado para el .ipa existente>
```

Instalar el `.ipa` resultante en el iPhone cuando el build termine.

- [ ] **Step 3: Probar el device engagement en AMBAS combinaciones de la matriz**

Con la app holder en **foreground** en cada plataforma, generar el QR de engagement
y escanearlo con el reader Android:

| Combinación | Qué registrar |
|---|---|
| Holder Android ↔ Reader Android | ¿Advierte en BLE peripheral server mode? ¿El reader conecta? ¿Completa el intercambio? |
| Holder iPhone ↔ Reader Android | Igual, con el holder en el iPhone. Recordar: la limitación conocida de iOS (overflow area) es solo en *background* — con el holder en foreground no debería aplicar |

No se prueba Android(holder)↔iPhone(reader) ni iPhone↔iPhone en esta fase — el
reader de contraste no tiene build iOS.

- [ ] **Step 4: Probar chunking y rendimiento con payload sintético, en ambas filas**

Transmitir un payload de **~20 KB** (tamaño realista de un `portrait` JPEG) en cada
combinación de la Step 3. Medir el tiempo desde el escaneo del QR hasta el resultado.

Criterio por fila: transmisión **completa y sin corrupción**, en **menos de 5
segundos**.

- [ ] **Step 5: Medir el nivel de seguridad de claves, por plataforma**

En cada teléfono, generar una clave P-256 con `askar` desde el wallet y determinar
si queda respaldada por hardware — **StrongBox/TEE** en Android, **Secure
Enclave** en iOS — o si cae a **software**. Este dato es entrada obligatoria de
§S-4 del spec: si es software en cualquiera de las dos, la credencial resultante es
clonable en esa plataforma y hay que declararlo.

- [ ] **Step 6: Escribir el informe y emitir el veredicto por fila**

Crear `docs/mdl-fase0-report.md` con: modelo del Android y modelo/versión de iOS del
iPhone, resultado de engagement por fila, resultado de chunking con tiempos por
fila, nivel de seguridad de claves por plataforma, y **veredicto binario por fila**
(no un veredicto único — las dos filas son independientes).

**Criterio de aceptación (§C.7.0):** los tres criterios (engagement, chunking,
<5 s) pasan **en una fila** desbloquean el resto del plan **para esa plataforma**.
Si la fila Android↔Android falla, Fase 0 no pasa y el Plan B es pivotar el
transporte del holder (ver spec). Si solo falla la fila iPhone↔Android, no es
bloqueante: se documenta la limitación y el Tramo C continúa Android-only, como
preveía la versión original del spec.

- [ ] **Step 7: Commit**

```bash
git add docs/mdl-fase0-report.md
git commit -m "docs(mdl): informe de Fase 0 — spike de hardware BLE"
```

---

## Task 1: Interfaz `Signer` y `SoftwareSigner`

Resuelve la decisión pendiente #5 del spec: el `Signer` vive en `internal/signer/`, alineado con el ítem de KMS ya planificado en `TODO.md`, y `internal/mdl/` lo consume.

**Files:**
- Create: `internal/signer/signer.go`
- Create: `internal/signer/software.go`
- Test: `internal/signer/software_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type Signer interface { Sign(ctx context.Context, payload []byte) ([]byte, error); CertificateChain() []*x509.Certificate; Algorithm() cose.Algorithm }`
  - `func NewSoftwareSigner(key *ecdsa.PrivateKey, chain []*x509.Certificate) (*SoftwareSigner, error)`

- [ ] **Step 1: Añadir la dependencia `go-cose`**

```bash
go get github.com/veraison/go-cose@v1.3.0
```

- [ ] **Step 2: Escribir el test que falla**

Crear `internal/signer/software_test.go`:

```go
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedCert builds a throwaway P-256 certificate for signer tests.
func selfSignedCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test", Organization: []string{"POC-DO-NOT-TRUST"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func TestSoftwareSignerProducesVerifiableSignature(t *testing.T) {
	key, cert := selfSignedCert(t)
	s, err := NewSoftwareSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	sig, err := s.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte raw P-256 signature, got %d", len(sig))
	}
}

func TestSoftwareSignerReturnsFullChain(t *testing.T) {
	key, cert := selfSignedCert(t)
	s, err := NewSoftwareSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if got := len(s.CertificateChain()); got != 1 {
		t.Fatalf("expected chain of 1, got %d", got)
	}
}

func TestNewSoftwareSignerRejectsEmptyChain(t *testing.T) {
	key, _ := selfSignedCert(t)
	if _, err := NewSoftwareSigner(key, nil); err == nil {
		t.Fatal("expected error for empty certificate chain")
	}
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `go test ./internal/signer/... -v`
Expected: FAIL — `undefined: NewSoftwareSigner`

- [ ] **Step 4: Escribir la interfaz**

Crear `internal/signer/signer.go`:

```go
// Package signer abstracts the private-key operations needed to issue
// credentials, so that the software-backed key used in demos can be swapped
// for a KMS- or HSM-backed one without touching credential-format code.
package signer

import (
	"context"
	"crypto/x509"

	"github.com/veraison/go-cose"
)

// Signer produces raw signatures over a payload and exposes the certificate
// chain that lets a verifier build a path to a trust anchor.
//
// CertificateChain returns the full chain (leaf first, e.g. DSC then IACA),
// not a single certificate: ISO/IEC 18013-5 puts an x5chain in the protected
// header of IssuerAuth, and a single certificate cannot express it.
type Signer interface {
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	CertificateChain() []*x509.Certificate
	Algorithm() cose.Algorithm
}
```

- [ ] **Step 5: Escribir `SoftwareSigner`**

Crear `internal/signer/software.go`:

```go
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

// SoftwareSigner holds the private key in process memory. It is meant for
// development and demos; production deployments implement Signer against a
// KMS or HSM instead.
type SoftwareSigner struct {
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

// NewSoftwareSigner validates that the key is P-256 (the curve ISO/IEC
// 18013-5 mandates for ES256) and that a non-empty chain was supplied.
func NewSoftwareSigner(key *ecdsa.PrivateKey, chain []*x509.Certificate) (*SoftwareSigner, error) {
	if key == nil {
		return nil, errors.New("signer: nil private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signer: expected P-256 key, got %s", key.Curve.Params().Name)
	}
	if len(chain) == 0 {
		return nil, errors.New("signer: certificate chain must not be empty")
	}
	return &SoftwareSigner{key: key, chain: chain}, nil
}

// Sign returns a raw (r||s) ECDSA signature, which is the encoding COSE
// expects — not the ASN.1 DER that crypto/ecdsa.SignASN1 produces.
func (s *SoftwareSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signer: ecdsa sign: %w", err)
	}
	// Left-pad each scalar to the 32-byte field size so the pair is always 64 bytes.
	const scalarLen = 32
	out := make([]byte, 2*scalarLen)
	r.FillBytes(out[:scalarLen])
	sv.FillBytes(out[scalarLen:])
	return out, nil
}

func (s *SoftwareSigner) CertificateChain() []*x509.Certificate {
	return s.chain
}

func (s *SoftwareSigner) Algorithm() cose.Algorithm {
	return cose.AlgorithmES256
}
```

- [ ] **Step 6: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/signer/... -v`
Expected: PASS — los tres tests.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/signer/
git commit -m "feat(signer): add Signer interface and software-backed implementation"
```

---

## Task 2: PKI — IACA autofirmada y DSC

**Files:**
- Create: `internal/mdl/pki/pki.go`
- Test: `internal/mdl/pki/pki_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `func GenerateIACA(cn, country string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error)`
  - `func GenerateDSC(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, cn string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error)`
  - `const EKUDocumentSigner = "1.0.18013.5.1.2"`
  - `const POCOrganization = "POC-DO-NOT-TRUST"`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/mdl/pki/pki_test.go`:

```go
package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateIACAIsSelfSignedAndMarkedPOC(t *testing.T) {
	_, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if !iaca.IsCA {
		t.Error("IACA must have IsCA set")
	}
	if err := iaca.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("IACA must be self-signed: %v", err)
	}
	// The POC marker is what stops this material from silently reaching production.
	found := false
	for _, o := range iaca.Subject.Organization {
		if o == POCOrganization {
			found = true
		}
	}
	if !found {
		t.Errorf("IACA subject must carry O=%s, got %v", POCOrganization, iaca.Subject.Organization)
	}
	if len(iaca.Subject.Country) == 0 || iaca.Subject.Country[0] != "DO" {
		t.Errorf("expected country DO, got %v", iaca.Subject.Country)
	}
}

func TestGenerateDSCChainsToIACAAndCarriesEKU(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	_, dsc, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	if err := dsc.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("DSC must be signed by the IACA: %v", err)
	}
	if dsc.IsCA {
		t.Error("DSC must not be a CA")
	}
	// EKU 1.0.18013.5.1.2 is what marks this as an mDL document signer.
	found := false
	for _, oid := range dsc.UnknownExtKeyUsage {
		if oid.String() == EKUDocumentSigner {
			found = true
		}
	}
	if !found {
		t.Errorf("DSC must carry EKU %s, got %v", EKUDocumentSigner, dsc.UnknownExtKeyUsage)
	}
}

func TestGenerateDSCRejectsValidityBeyond457Days(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 500*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if _, _, err := GenerateDSC(iacaKey, iaca, "Test DSC", 458*24*time.Hour); err == nil {
		t.Fatal("expected error: Annex B caps DSC validity at 457 days")
	}
}

func TestGenerateDSCRejectsValidityBeyondIACA(t *testing.T) {
	// A DSC outliving its issuer produces a chain that breaks mid-demo.
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 10*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if _, _, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour); err == nil {
		t.Fatal("expected error: DSC validity must not exceed the IACA's")
	}
}

func TestGeneratedCertificatesVerifyAsAChain(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	_, dsc, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(iaca)
	if _, err := dsc.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("DSC must chain to the IACA: %v", err)
	}
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `go test ./internal/mdl/pki/... -v`
Expected: FAIL — `undefined: GenerateIACA`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/mdl/pki/pki.go`:

```go
// Package pki generates the certificate chain an mDL issuer needs: a
// self-signed IACA root and the Document Signer Certificates it issues,
// following the certificate profiles of ISO/IEC 18013-5 Annex B (normative).
//
// The material produced here is for proof-of-concept use only. Certificates
// carry O=POC-DO-NOT-TRUST and the IACA is deliberately short-lived so that
// leaked material expires on its own.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

const (
	// EKUDocumentSigner marks a certificate as an mDL Document Signer.
	EKUDocumentSigner = "1.0.18013.5.1.2"

	// POCOrganization is stamped into every subject so proof-of-concept
	// material is detectable if it ever shows up where it should not.
	POCOrganization = "POC-DO-NOT-TRUST"

	// maxDSCValidity is the cap Annex B puts on Document Signer certificates.
	maxDSCValidity = 457 * 24 * time.Hour
)

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// GenerateIACA creates a self-signed Issuing Authority Certificate Authority
// root and its P-256 private key.
func GenerateIACA(cn, country string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate IACA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      []string{country},
			Organization: []string{POCOrganization},
		},
		NotBefore:             now.Add(-time.Hour), // tolerate small clock skew
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create IACA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse IACA: %w", err)
	}
	return key, cert, nil
}

// GenerateDSC issues a Document Signer Certificate under the given IACA.
//
// Validity is capped twice: by the 457-day Annex B limit, and by the IACA's
// own expiry — a DSC that outlives its issuer yields a chain that fails
// verification partway through its life.
func GenerateDSC(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, cn string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if validity > maxDSCValidity {
		return nil, nil, fmt.Errorf("pki: DSC validity %v exceeds the Annex B cap of %v", validity, maxDSCValidity)
	}
	now := time.Now().UTC()
	notAfter := now.Add(validity)
	if notAfter.After(iaca.NotAfter) {
		return nil, nil, fmt.Errorf("pki: DSC would outlive its IACA (%v > %v)", notAfter, iaca.NotAfter)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate DSC key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: serial: %w", err)
	}
	eku, err := parseOID(EKUDocumentSigner)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      iaca.Subject.Country,
			Organization: []string{POCOrganization},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iaca, &key.PublicKey, iacaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create DSC: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse DSC: %w", err)
	}
	return key, cert, nil
}

// parseOID converts a dotted OID string into an asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i == start {
				return nil, fmt.Errorf("pki: malformed OID %q", s)
			}
			n := 0
			for _, c := range s[start:i] {
				if c < '0' || c > '9' {
					return nil, fmt.Errorf("pki: malformed OID %q", s)
				}
				n = n*10 + int(c-'0')
			}
			oid = append(oid, n)
			start = i + 1
		}
	}
	return oid, nil
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/mdl/pki/... -v`
Expected: PASS — los cinco tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mdl/pki/
git commit -m "feat(mdl): generate Annex B compliant IACA and DSC certificates"
```

---

## Task 3: Tipos CBOR y constantes del dataset

**Files:**
- Create: `internal/mdl/doctype.go`
- Create: `internal/mdl/cbortypes.go`
- Test: `internal/mdl/cbortypes_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `const Namespace = "org.iso.18013.5.1"`, `const DocType = "org.iso.18013.5.1.mDL"`
  - `type FullDate time.Time` con tag CBOR 1004; `type TDate time.Time` con tag CBOR 0
  - `type DrivingPrivilege struct { VehicleCategoryCode string; IssueDate *FullDate; ExpiryDate *FullDate }`
  - `type IssuerSignedItem struct { DigestID uint; Random []byte; ElementIdentifier string; ElementValue any }`
  - `type ValidityInfo struct { Signed TDate; ValidFrom TDate; ValidUntil TDate; ExpectedUpdate *TDate }`
  - `type MobileSecurityObject struct { Version string; DigestAlgorithm string; ValueDigests map[string]map[uint][]byte; DeviceKeyInfo DeviceKeyInfo; DocType string; ValidityInfo ValidityInfo }`
  - `func EncMode() (cbor.EncMode, error)`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/mdl/cbortypes_test.go`:

```go
package mdl

import (
	"bytes"
	"testing"
	"time"
)

// CBOR tag numbers the standard mandates. Getting these wrong is the most
// common way an mdoc fails against a conformant verifier.
const (
	tagTDate    = 0
	tagFullDate = 1004
)

func TestFullDateEncodesWithTag1004(t *testing.T) {
	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	d := FullDate(time.Date(1990, 3, 15, 0, 0, 0, 0, time.UTC))
	got, err := em.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Tag 1004 encodes as major type 6 with a two-byte argument: d9 03ec.
	want := []byte{0xd9, 0x03, 0xec}
	if !bytes.HasPrefix(got, want) {
		t.Errorf("expected tag %d prefix %x, got %x", tagFullDate, want, got)
	}
	// The value must be a full-date string, not a date-time.
	if !bytes.Contains(got, []byte("1990-03-15")) {
		t.Errorf("expected full-date text 1990-03-15, got %x", got)
	}
	if bytes.Contains(got, []byte("T00:00:00")) {
		t.Error("full-date must not carry a time component")
	}
}

func TestTDateEncodesWithTag0(t *testing.T) {
	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	d := TDate(time.Date(2026, 8, 17, 12, 30, 0, 0, time.UTC))
	got, err := em.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Tag 0 encodes as a single byte: c0.
	if len(got) == 0 || got[0] != 0xc0 {
		t.Errorf("expected tag %d prefix c0, got %x", tagTDate, got)
	}
	if !bytes.Contains(got, []byte("2026-08-17T12:30:00Z")) {
		t.Errorf("expected RFC3339 date-time, got %x", got)
	}
}

func TestMandatoryElementsListMatchesSpec(t *testing.T) {
	// 10 of the 11 mandatory elements (portrait is deferred) plus two age
	// attestations. See §C.7.2 of the spec.
	if got := len(DatasetElements); got != 12 {
		t.Fatalf("expected 12 dataset elements, got %d", got)
	}
	for _, name := range []string{
		"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
		"issuing_country", "issuing_authority", "document_number",
		"driving_privileges", "un_distinguishing_sign",
		"age_over_18", "age_over_21",
	} {
		if !containsElement(DatasetElements, name) {
			t.Errorf("dataset must contain %q", name)
		}
	}
	if containsElement(DatasetElements, "portrait") {
		t.Error("portrait is deferred to C.7.5 and must not be in the dataset yet")
	}
}
```

> **Nota:** `containsElement` es código de producción y se define en
> `doctype.go` (Step 3 de este task), no en el archivo de test. El test lo
> consume.

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `go test ./internal/mdl/... -v`
Expected: FAIL — `undefined: EncMode`

- [ ] **Step 3: Escribir las constantes del dataset**

Crear `internal/mdl/doctype.go`:

```go
// Package mdl issues mobile driving licence credentials in the mdoc format
// defined by ISO/IEC 18013-5:2021.
package mdl

// Namespace and DocType identify an ISO-compliant mDL.
const (
	Namespace = "org.iso.18013.5.1"
	DocType   = "org.iso.18013.5.1.mDL"
)

// DatasetElements lists the data elements this issuer emits.
//
// Table 3 of the standard makes eleven elements mandatory. We emit ten of
// them: portrait is deferred to a later phase because the JPEG dominates the
// DeviceResponse size and stresses BLE chunking. Two optional age
// attestations are added because they let a verifier confirm a lower bound on
// age without receiving birth_date at all.
//
// A credential missing portrait is NOT a conformant mDL. It is a test mdoc.
var DatasetElements = []string{
	"family_name",
	"given_name",
	"birth_date",
	"issue_date",
	"expiry_date",
	"issuing_country",
	"issuing_authority",
	"document_number",
	"driving_privileges",
	"un_distinguishing_sign",
	"age_over_18",
	"age_over_21",
}

// containsElement reports whether name is part of the emitted dataset.
func containsElement(list []string, name string) bool {
	for _, e := range list {
		if e == name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Escribir los tipos CBOR**

Crear `internal/mdl/cbortypes.go`:

```go
package mdl

import (
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CBOR tags used by the standard.
//
// The distinction matters and is easy to get wrong: every field of
// ValidityInfo is a tdate (tag 0, RFC 3339 date-time), while birth_date is a
// full-date (tag 1004, no time component). Using 1004 inside ValidityInfo
// produces an MSO no conformant verifier will accept.
const (
	TagTDate           = 0
	TagFullDate        = 1004
	TagEncodedCBOR     = 24
	fullDateLayout     = "2006-01-02"
	digestAlgorithmSHA = "SHA-256"
	msoVersion         = "1.0"
)

// FullDate is a date without a time component, encoded with CBOR tag 1004.
type FullDate time.Time

func (d FullDate) MarshalCBOR() ([]byte, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cbor.Tag{
		Number:  TagFullDate,
		Content: time.Time(d).UTC().Format(fullDateLayout),
	})
}

// TDate is an RFC 3339 date-time, encoded with CBOR tag 0.
type TDate time.Time

func (d TDate) MarshalCBOR() ([]byte, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cbor.Tag{
		Number:  TagTDate,
		Content: time.Time(d).UTC().Format(time.RFC3339),
	})
}

// DrivingPrivilege is one entry of the driving_privileges array.
//
// This is why the existing walt.id issuance path cannot carry the dataset:
// buildMdocData takes map[string]string, and this element is a nested array
// of structures.
type DrivingPrivilege struct {
	VehicleCategoryCode string    `cbor:"vehicle_category_code"`
	IssueDate           *FullDate `cbor:"issue_date,omitempty"`
	ExpiryDate          *FullDate `cbor:"expiry_date,omitempty"`
}

// IssuerSignedItem is a single disclosable data element. Random must be at
// least 16 bytes of entropy so that a digest does not leak its value.
type IssuerSignedItem struct {
	DigestID          uint   `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

// ValidityInfo carries the MSO's temporal bounds. A verifier checks these
// against its own clock on every transaction.
type ValidityInfo struct {
	Signed         TDate  `cbor:"signed"`
	ValidFrom      TDate  `cbor:"validFrom"`
	ValidUntil     TDate  `cbor:"validUntil"`
	ExpectedUpdate *TDate `cbor:"expectedUpdate,omitempty"`
}

// DeviceKeyInfo binds the credential to a key the holder controls. Without
// it the credential is clonable, so deviceKey is not optional.
type DeviceKeyInfo struct {
	DeviceKey cbor.RawMessage `cbor:"deviceKey"`
}

// MobileSecurityObject is the structure the issuer signs.
type MobileSecurityObject struct {
	Version         string                     `cbor:"version"`
	DigestAlgorithm string                     `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo              `cbor:"deviceKeyInfo"`
	DocType         string                     `cbor:"docType"`
	ValidityInfo    ValidityInfo               `cbor:"validityInfo"`
}

// IssuerSigned is what the issuer hands to the holder: the disclosable items
// plus the signed MSO.
type IssuerSigned struct {
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
}

// EncMode returns the CBOR encoder the standard requires: deterministic
// (canonical) encoding, so that digests computed over the same item are
// stable across implementations.
func EncMode() (cbor.EncMode, error) {
	return cbor.EncOptions{
		Sort:        cbor.SortCanonical,
		Time:        cbor.TimeRFC3339,
		TimeTag:     cbor.EncTagRequired,
		IndefLength: cbor.IndefLengthForbidden,
	}.EncMode()
}
```

- [ ] **Step 5: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/mdl/... -v -run "TestFullDate|TestTDate|TestMandatory"`
Expected: PASS — los tres tests.

- [ ] **Step 6: Commit**

```bash
git add internal/mdl/doctype.go internal/mdl/cbortypes.go internal/mdl/cbortypes_test.go
git commit -m "feat(mdl): add ISO 18013-5 CBOR types with correct tag handling"
```

---

## Task 4: Construcción de `IssuerSignedItem`s y `valueDigests`

**Files:**
- Create: `internal/mdl/encode.go`
- Test: `internal/mdl/encode_test.go`

**Interfaces:**
- Consumes: `Namespace`, `IssuerSignedItem`, `EncMode` (Task 3).
- Produces:
  - `func BuildIssuerSignedItems(elements map[string]any) ([]IssuerSignedItem, error)`
  - `func EncodeItem(item IssuerSignedItem) (cbor.RawMessage, error)` — devuelve `IssuerSignedItemBytes` (tag 24)
  - `func ComputeValueDigests(items []IssuerSignedItem) (map[uint][]byte, error)`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/mdl/encode_test.go`:

```go
package mdl

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestBuildIssuerSignedItemsAssignsUniqueRandomAndDigestIDs(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{
		"family_name": "Pérez",
		"given_name":  "Ana",
	})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	seenIDs := map[uint]bool{}
	for _, it := range items {
		if len(it.Random) < 16 {
			t.Errorf("%s: random must be at least 16 bytes, got %d", it.ElementIdentifier, len(it.Random))
		}
		if seenIDs[it.DigestID] {
			t.Errorf("duplicate digestID %d", it.DigestID)
		}
		seenIDs[it.DigestID] = true
	}

	// Two items with the same value must still get different salts.
	a, _ := BuildIssuerSignedItems(map[string]any{"family_name": "X"})
	b, _ := BuildIssuerSignedItems(map[string]any{"family_name": "X"})
	if bytes.Equal(a[0].Random, b[0].Random) {
		t.Error("random salt must differ between issuances")
	}
}

func TestEncodeItemWrapsInTag24(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{"family_name": "Pérez"})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	enc, err := EncodeItem(items[0])
	if err != nil {
		t.Fatalf("encode item: %v", err)
	}
	// Tag 24 encodes as d8 18, followed by a byte string.
	if len(enc) < 2 || enc[0] != 0xd8 || enc[1] != 0x18 {
		t.Errorf("expected tag 24 prefix d818, got %x", enc)
	}
}

func TestComputeValueDigestsMatchesSHA256OfEncodedItem(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{"family_name": "Pérez"})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	digests, err := ComputeValueDigests(items)
	if err != nil {
		t.Fatalf("compute digests: %v", err)
	}

	enc, err := EncodeItem(items[0])
	if err != nil {
		t.Fatalf("encode item: %v", err)
	}
	want := sha256.Sum256(enc)

	got, ok := digests[items[0].DigestID]
	if !ok {
		t.Fatalf("no digest for digestID %d", items[0].DigestID)
	}
	// The digest must be taken over the tagged bytes, not the bare structure.
	if !bytes.Equal(got, want[:]) {
		t.Errorf("digest mismatch:\n got %x\nwant %x", got, want[:])
	}
}

func TestBuildIssuerSignedItemsRejectsUnknownElement(t *testing.T) {
	if _, err := BuildIssuerSignedItems(map[string]any{"not_a_real_element": "x"}); err == nil {
		t.Fatal("expected error for element outside the dataset")
	}
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `go test ./internal/mdl/... -v -run "TestBuildIssuerSigned|TestEncodeItem|TestComputeValueDigests"`
Expected: FAIL — `undefined: BuildIssuerSignedItems`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/mdl/encode.go`:

```go
package mdl

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// randomSaltLen is the entropy per item. The standard requires at least 16
// bytes so that a verifier holding a digest cannot brute-force the value of
// an element that was not disclosed.
const randomSaltLen = 16

// BuildIssuerSignedItems turns a map of element values into the item
// structures the issuer signs over.
//
// Elements are processed in sorted order so digest IDs are assigned
// deterministically for a given input set, which keeps test vectors stable.
// The salt, by contrast, is fresh on every call.
func BuildIssuerSignedItems(elements map[string]any) ([]IssuerSignedItem, error) {
	names := make([]string, 0, len(elements))
	for name := range elements {
		if !containsElement(DatasetElements, name) {
			return nil, fmt.Errorf("mdl: %q is not part of the emitted dataset", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]IssuerSignedItem, 0, len(names))
	for i, name := range names {
		salt := make([]byte, randomSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("mdl: read random salt: %w", err)
		}
		items = append(items, IssuerSignedItem{
			DigestID:          uint(i),
			Random:            salt,
			ElementIdentifier: name,
			ElementValue:      elements[name],
		})
	}
	return items, nil
}

// EncodeItem produces IssuerSignedItemBytes: the item encoded as CBOR and
// then wrapped in tag 24 as an embedded byte string.
//
// Digests are computed over these tagged bytes, so encoding must be
// deterministic — otherwise a holder re-encoding the item would produce a
// digest that no longer matches the MSO.
func EncodeItem(item IssuerSignedItem) (cbor.RawMessage, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	inner, err := em.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal item %q: %w", item.ElementIdentifier, err)
	}
	tagged, err := em.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("mdl: tag item %q: %w", item.ElementIdentifier, err)
	}
	return tagged, nil
}

// ComputeValueDigests hashes each encoded item, keyed by its digest ID. This
// map is what goes into the MSO and what lets a verifier confirm that a
// disclosed element was not altered.
func ComputeValueDigests(items []IssuerSignedItem) (map[uint][]byte, error) {
	digests := make(map[uint][]byte, len(items))
	for _, item := range items {
		enc, err := EncodeItem(item)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(enc)
		digests[item.DigestID] = sum[:]
	}
	return digests, nil
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/mdl/... -v`
Expected: PASS — todos los tests de este task y los de Task 3.

- [ ] **Step 5: Commit**

```bash
git add internal/mdl/encode.go internal/mdl/encode_test.go
git commit -m "feat(mdl): build IssuerSignedItems and compute value digests"
```

---

## Task 5: Ensamblado y firma del MSO

**Files:**
- Create: `internal/mdl/sign.go`
- Test: `internal/mdl/sign_test.go`

**Interfaces:**
- Consumes: `MobileSecurityObject`, `ValidityInfo`, `DeviceKeyInfo` (Task 3); `signer.Signer` (Task 1).
- Produces:
  - `func BuildMSO(digests map[uint][]byte, deviceKey cbor.RawMessage, v ValidityInfo) (*MobileSecurityObject, error)`
  - `func SignMSO(ctx context.Context, s signer.Signer, mso *MobileSecurityObject) (cbor.RawMessage, error)` — devuelve `IssuerAuth`
  - `func ValidateValidityInfo(v ValidityInfo, issueDate, expiryDate time.Time) error`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/mdl/sign_test.go`:

```go
package mdl

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// testSigner builds a real IACA→DSC chain and a signer over the DSC key.
func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	iacaKey, iaca, err := pki.GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func TestValidateValidityInfoRejectsValidUntilBeyondExpiryDate(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue),
		ValidUntil: TDate(expiry.Add(24 * time.Hour)), // one day too far
	}
	if err := ValidateValidityInfo(v, issue, expiry); err == nil {
		t.Fatal("expected error: validUntil must not exceed expiry_date")
	}
}

func TestValidateValidityInfoRejectsValidFromBeforeIssueDate(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue.Add(-24 * time.Hour)),
		ValidUntil: TDate(expiry),
	}
	if err := ValidateValidityInfo(v, issue, expiry); err == nil {
		t.Fatal("expected error: validFrom must not precede issue_date")
	}
}

func TestValidateValidityInfoAcceptsValidWindow(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue),
		ValidUntil: TDate(expiry),
	}
	if err := ValidateValidityInfo(v, issue, expiry); err != nil {
		t.Fatalf("expected valid window to be accepted: %v", err)
	}
}

func TestBuildMSORequiresDeviceKey(t *testing.T) {
	// Without deviceKey the credential is clonable, so this must be an error
	// rather than an omitted field.
	if _, err := BuildMSO(map[uint][]byte{0: {1, 2, 3}}, nil, ValidityInfo{}); err == nil {
		t.Fatal("expected error when deviceKey is absent")
	}
}

func TestSignMSOProducesVerifiableCOSESign1WithX5Chain(t *testing.T) {
	s := testSigner(t)
	now := time.Now().UTC()
	deviceKey := cbor.RawMessage{0xa0} // empty map: a placeholder COSE_Key

	mso, err := BuildMSO(
		map[uint][]byte{0: make([]byte, 32)},
		deviceKey,
		ValidityInfo{
			Signed:     TDate(now),
			ValidFrom:  TDate(now),
			ValidUntil: TDate(now.Add(24 * time.Hour)),
		},
	)
	if err != nil {
		t.Fatalf("build MSO: %v", err)
	}

	issuerAuth, err := SignMSO(context.Background(), s, mso)
	if err != nil {
		t.Fatalf("sign MSO: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(issuerAuth); err != nil {
		t.Fatalf("IssuerAuth must be a COSE_Sign1: %v", err)
	}

	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatalf("protected header must carry alg: %v", err)
	}
	if alg != cose.AlgorithmES256 {
		t.Errorf("expected ES256, got %v", alg)
	}

	// Header label 33 is x5chain. A verifier needs the full chain to build a
	// path to the trust anchor.
	x5chain, ok := msg.Headers.Unprotected[int64(33)]
	if !ok {
		if x5chain, ok = msg.Headers.Protected[int64(33)]; !ok {
			t.Fatal("IssuerAuth must carry an x5chain header (label 33)")
		}
	}
	chain, ok := x5chain.([]any)
	if !ok {
		t.Fatalf("x5chain must be an array for multi-certificate chains, got %T", x5chain)
	}
	if len(chain) != 2 {
		t.Errorf("expected DSC and IACA in the chain, got %d entries", len(chain))
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, s.CertificateChain()[0].PublicKey)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		t.Errorf("signature must verify against the DSC public key: %v", err)
	}
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `go test ./internal/mdl/... -v -run "TestValidateValidityInfo|TestBuildMSO|TestSignMSO"`
Expected: FAIL — `undefined: ValidateValidityInfo`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/mdl/sign.go`:

```go
package mdl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// headerLabelX5Chain is the COSE header that carries the certificate chain.
const headerLabelX5Chain = int64(33)

// ValidateValidityInfo enforces the normative constraints the standard puts
// on the MSO's temporal window relative to the credential's own dates.
//
// These are easy to violate accidentally when shortening MSO lifetimes to
// approximate revocation: validUntil may not outlive the licence itself.
func ValidateValidityInfo(v ValidityInfo, issueDate, expiryDate time.Time) error {
	validFrom := time.Time(v.ValidFrom)
	validUntil := time.Time(v.ValidUntil)

	if validFrom.Before(issueDate) {
		return fmt.Errorf("mdl: validFrom (%s) precedes issue_date (%s)",
			validFrom.Format(time.RFC3339), issueDate.Format(time.RFC3339))
	}
	if validUntil.After(expiryDate) {
		return fmt.Errorf("mdl: validUntil (%s) exceeds expiry_date (%s)",
			validUntil.Format(time.RFC3339), expiryDate.Format(time.RFC3339))
	}
	if !validUntil.After(validFrom) {
		return errors.New("mdl: validUntil must be after validFrom")
	}
	return nil
}

// BuildMSO assembles the Mobile Security Object.
//
// deviceKey is mandatory: it is the holder's public key, and signing it into
// the MSO is what binds the credential to a device. Without it a copied
// credential is indistinguishable from the original.
func BuildMSO(digests map[uint][]byte, deviceKey cbor.RawMessage, v ValidityInfo) (*MobileSecurityObject, error) {
	if len(deviceKey) == 0 {
		return nil, errors.New("mdl: deviceKey is required; an MSO without it yields a clonable credential")
	}
	if len(digests) == 0 {
		return nil, errors.New("mdl: value digests must not be empty")
	}
	return &MobileSecurityObject{
		Version:         msoVersion,
		DigestAlgorithm: digestAlgorithmSHA,
		ValueDigests:    map[string]map[uint][]byte{Namespace: digests},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
		DocType:         DocType,
		ValidityInfo:    v,
	}, nil
}

// SignMSO encodes the MSO, wraps it in tag 24, and signs it as a COSE_Sign1
// carrying the issuer's certificate chain — the structure the standard calls
// IssuerAuth.
func SignMSO(ctx context.Context, s signer.Signer, mso *MobileSecurityObject) (cbor.RawMessage, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	msoBytes, err := em.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal MSO: %w", err)
	}
	payload, err := em.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: msoBytes})
	if err != nil {
		return nil, fmt.Errorf("mdl: tag MSO: %w", err)
	}

	// The chain goes leaf-first (DSC, then IACA) as a CBOR array of DER
	// byte strings. A single-certificate chain may be a bare byte string,
	// but emitting an array uniformly keeps parsing simple on the verifier.
	chain := s.CertificateChain()
	der := make([]any, 0, len(chain))
	for _, c := range chain {
		der = append(der, c.Raw)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	if err := msg.Headers.Protected.SetAlgorithm(s.Algorithm()); err != nil {
		return nil, fmt.Errorf("mdl: set algorithm: %w", err)
	}
	msg.Headers.Unprotected[headerLabelX5Chain] = der

	sig, err := signWithSigner(ctx, s, msg)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig

	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal IssuerAuth: %w", err)
	}
	return out, nil
}

// signWithSigner computes the COSE Sig_structure and hands it to the Signer.
// go-cose's Sign() wants a crypto.Signer, but our Signer interface may be
// backed by a remote KMS, so we build the to-be-signed bytes ourselves.
func signWithSigner(ctx context.Context, s signer.Signer, msg *cose.Sign1Message) ([]byte, error) {
	toBeSigned, err := sign1ToBeSigned(msg)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(ctx, toBeSigned)
	if err != nil {
		return nil, fmt.Errorf("mdl: sign: %w", err)
	}
	return sig, nil
}

// sign1ToBeSigned builds the COSE Sig_structure for a Sign1 message:
// ["Signature1", protected, external_aad, payload].
func sign1ToBeSigned(msg *cose.Sign1Message) ([]byte, error) {
	protected, err := msg.Headers.MarshalProtected()
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal protected headers: %w", err)
	}
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	sigStructure := []any{"Signature1", protected, []byte{}, msg.Payload}
	out, err := em.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal Sig_structure: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/mdl/... -v`
Expected: PASS — todos.

Si el test de verificación de firma falla, lo más probable es que la `Sig_structure` no coincida con la que `go-cose` construye internamente. Compara `sign1ToBeSigned` con el resultado de `msg.Signature` usando un `cose.NewSigner` sobre la misma clave.

- [ ] **Step 5: Commit**

```bash
git add internal/mdl/sign.go internal/mdl/sign_test.go
git commit -m "feat(mdl): assemble and sign the Mobile Security Object"
```

---

## Task 6: Fachada de emisión y clave de dispositivo de prueba

**Files:**
- Create: `internal/mdl/issue.go`
- Create: `internal/mdl/testdata/devicekey_test.json`
- Test: `internal/mdl/issue_test.go`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces:
  - `type LicenceData struct { FamilyName, GivenName string; BirthDate, IssueDate, ExpiryDate time.Time; IssuingCountry, IssuingAuthority, DocumentNumber, UNDistinguishingSign string; DrivingPrivileges []DrivingPrivilege }`
  - `func (d LicenceData) Elements(validFrom time.Time) (map[string]any, error)`
  - `func Issue(ctx context.Context, s signer.Signer, d LicenceData, deviceKey cbor.RawMessage, validUntil time.Time) (*IssuerSigned, error)`
  - `func LoadTestDeviceKey() (cbor.RawMessage, error)`

- [ ] **Step 1: Crear la clave de dispositivo de prueba**

Esta clave desacopla el issuer del holder: permite completar y probar la emisión antes de que `cdpi-wallet` exista (§C.5b del spec).

Crear `internal/mdl/testdata/devicekey_test.json`:

```json
{
  "_comment": "Test-only COSE_Key (EC2/P-256) standing in for a holder device key. Generated for development; the corresponding private key is intentionally not stored. Real issuance takes the device key from the holder's proof of possession.",
  "kty": 2,
  "crv": 1,
  "x": "hLQgs3TDDIkGlvsFEEHUCLLtqjHDLBGqTSSKMzWWZBk=",
  "y": "IhTvS1V0YKu1qP7wRRj0hVYFCCPqQVXKMR7YQvLmXvw="
}
```

- [ ] **Step 2: Escribir el test que falla**

Crear `internal/mdl/issue_test.go`:

```go
package mdl

import (
	"context"
	"testing"
	"time"
)

func sampleLicence() LicenceData {
	return LicenceData{
		FamilyName:           "Pérez",
		GivenName:            "Ana María",
		BirthDate:            time.Date(1990, 3, 15, 0, 0, 0, 0, time.UTC),
		IssueDate:            time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ExpiryDate:           time.Date(2032, 1, 10, 0, 0, 0, 0, time.UTC),
		IssuingCountry:       "DO",
		IssuingAuthority:     "INTRANT",
		DocumentNumber:       "001-1234567-8",
		UNDistinguishingSign: "DOM",
		DrivingPrivileges: []DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
	}
}

func TestElementsComputesAgeAttestationsFromValidFrom(t *testing.T) {
	d := sampleLicence()
	// Born 1990-03-15. On this validFrom the holder is 36: over both bounds.
	els, err := d.Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if els["age_over_18"] != true {
		t.Errorf("age_over_18 should be true, got %v", els["age_over_18"])
	}
	if els["age_over_21"] != true {
		t.Errorf("age_over_21 should be true, got %v", els["age_over_21"])
	}
}

func TestElementsAgeAttestationsUseValidFromNotToday(t *testing.T) {
	d := sampleLicence()
	d.BirthDate = time.Date(2010, 6, 1, 0, 0, 0, 0, time.UTC)
	// At this validFrom the holder is 15 — under both bounds — even though
	// they may be older by the time anyone runs this test.
	els, err := d.Elements(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if els["age_over_18"] != false {
		t.Errorf("age_over_18 should be false at that validFrom, got %v", els["age_over_18"])
	}
	if els["age_over_21"] != false {
		t.Errorf("age_over_21 should be false at that validFrom, got %v", els["age_over_21"])
	}
}

func TestElementsProducesTheFullDataset(t *testing.T) {
	els, err := sampleLicence().Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if len(els) != len(DatasetElements) {
		t.Fatalf("expected %d elements, got %d", len(DatasetElements), len(els))
	}
	for _, name := range DatasetElements {
		if _, ok := els[name]; !ok {
			t.Errorf("missing element %q", name)
		}
	}
}

func TestIssueProducesIssuerSignedWithAllItems(t *testing.T) {
	s := testSigner(t)
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load test device key: %v", err)
	}
	d := sampleLicence()

	is, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	items, ok := is.NameSpaces[Namespace]
	if !ok {
		t.Fatalf("expected namespace %q in nameSpaces", Namespace)
	}
	if len(items) != len(DatasetElements) {
		t.Errorf("expected %d disclosable items, got %d", len(DatasetElements), len(items))
	}
	if len(is.IssuerAuth) == 0 {
		t.Error("IssuerAuth must not be empty")
	}
}

func TestIssueRejectsValidUntilBeyondExpiry(t *testing.T) {
	s := testSigner(t)
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load test device key: %v", err)
	}
	d := sampleLicence()
	if _, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate.Add(24*time.Hour)); err == nil {
		t.Fatal("expected error: validUntil must not exceed expiry_date")
	}
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `go test ./internal/mdl/... -v -run "TestElements|TestIssue"`
Expected: FAIL — `undefined: LicenceData`

- [ ] **Step 4: Escribir la implementación**

Crear `internal/mdl/issue.go`:

```go
package mdl

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/signer"
)

//go:embed testdata/devicekey_test.json
var testDeviceKeyJSON []byte

// LicenceData is the typed input to issuance.
//
// It deliberately does not reuse the walt.id adapter's map[string]string
// shape: driving_privileges is a nested CBOR array that a flat string map
// cannot express.
type LicenceData struct {
	FamilyName           string
	GivenName            string
	BirthDate            time.Time
	IssueDate            time.Time
	ExpiryDate           time.Time
	IssuingCountry       string
	IssuingAuthority     string
	DocumentNumber       string
	UNDistinguishingSign string
	DrivingPrivileges    []DrivingPrivilege
}

// Elements renders the licence as the element map the encoder expects.
//
// Age attestations are computed against validFrom, not against the current
// time or the issue date: the standard defines age_over_NN relative to the
// MSO's validity window, and computing it from time.Now() would make the
// output non-reproducible.
func (d LicenceData) Elements(validFrom time.Time) (map[string]any, error) {
	if d.FamilyName == "" || d.GivenName == "" {
		return nil, fmt.Errorf("mdl: family_name and given_name are required")
	}
	if d.BirthDate.IsZero() || d.IssueDate.IsZero() || d.ExpiryDate.IsZero() {
		return nil, fmt.Errorf("mdl: birth_date, issue_date and expiry_date are required")
	}
	if len(d.DrivingPrivileges) == 0 {
		return nil, fmt.Errorf("mdl: at least one driving privilege is required")
	}

	birth := FullDate(d.BirthDate)
	return map[string]any{
		"family_name":            d.FamilyName,
		"given_name":             d.GivenName,
		"birth_date":             birth,
		"issue_date":             FullDate(d.IssueDate),
		"expiry_date":            FullDate(d.ExpiryDate),
		"issuing_country":        d.IssuingCountry,
		"issuing_authority":      d.IssuingAuthority,
		"document_number":        d.DocumentNumber,
		"un_distinguishing_sign": d.UNDistinguishingSign,
		"driving_privileges":     d.DrivingPrivileges,
		"age_over_18":            ageAtLeast(d.BirthDate, validFrom, 18),
		"age_over_21":            ageAtLeast(d.BirthDate, validFrom, 21),
	}, nil
}

// ageAtLeast reports whether someone born on birth has reached n years by at.
func ageAtLeast(birth, at time.Time, n int) bool {
	return !birth.AddDate(n, 0, 0).After(at)
}

// Issue produces a complete IssuerSigned: every dataset element as a
// disclosable item, plus the signed MSO committing to their digests and to
// the holder's device key.
func Issue(ctx context.Context, s signer.Signer, d LicenceData, deviceKey cbor.RawMessage, validUntil time.Time) (*IssuerSigned, error) {
	now := time.Now().UTC()
	validFrom := d.IssueDate
	if validFrom.Before(now) {
		// A licence issued in the past is valid from its issue date; the MSO
		// window still starts there so validFrom >= issue_date holds.
		validFrom = d.IssueDate
	}

	v := ValidityInfo{
		Signed:     TDate(now),
		ValidFrom:  TDate(validFrom),
		ValidUntil: TDate(validUntil),
	}
	if err := ValidateValidityInfo(v, d.IssueDate, d.ExpiryDate); err != nil {
		return nil, err
	}

	elements, err := d.Elements(validFrom)
	if err != nil {
		return nil, err
	}
	items, err := BuildIssuerSignedItems(elements)
	if err != nil {
		return nil, err
	}
	digests, err := ComputeValueDigests(items)
	if err != nil {
		return nil, err
	}
	mso, err := BuildMSO(digests, deviceKey, v)
	if err != nil {
		return nil, err
	}
	issuerAuth, err := SignMSO(ctx, s, mso)
	if err != nil {
		return nil, err
	}

	encoded := make([]cbor.RawMessage, 0, len(items))
	for _, item := range items {
		enc, err := EncodeItem(item)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, enc)
	}

	return &IssuerSigned{
		NameSpaces: map[string][]cbor.RawMessage{Namespace: encoded},
		IssuerAuth: issuerAuth,
	}, nil
}

// LoadTestDeviceKey returns a COSE_Key encoded from the embedded test JSON.
//
// This exists so issuance can be built and tested before a holder wallet
// exists. Production issuance takes the device key from the holder's proof
// of possession instead.
func LoadTestDeviceKey() (cbor.RawMessage, error) {
	var jwk struct {
		Kty int    `json:"kty"`
		Crv int    `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(testDeviceKeyJSON, &jwk); err != nil {
		return nil, fmt.Errorf("mdl: parse test device key: %w", err)
	}
	x, err := base64.StdEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode test device key x: %w", err)
	}
	y, err := base64.StdEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode test device key y: %w", err)
	}

	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	// COSE_Key labels: 1=kty, -1=crv, -2=x, -3=y.
	key := map[int]any{1: jwk.Kty, -1: jwk.Crv, -2: x, -3: y}
	out, err := em.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("mdl: encode test device key: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 5: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/mdl/... -v`
Expected: PASS — todos.

- [ ] **Step 6: Commit**

```bash
git add internal/mdl/issue.go internal/mdl/issue_test.go internal/mdl/testdata/devicekey_test.json
git commit -m "feat(mdl): add issuance facade with age attestations and test device key"
```

---

## Task 7: Harness de verificación independiente y vectores de contrato

Este task cierra el criterio de aceptación de C.7.1: los mdocs deben verificar contra un verificador que **no** sea el nuestro. También produce los vectores que sirven de contrato con `cdpi-wallet` y el reader (§C.5b).

**Files:**
- Create: `internal/mdl/testdata/verify/package.json`
- Create: `internal/mdl/testdata/verify/verify.mjs`
- Create: `internal/mdl/testdata/verify/README.md`
- Create: `internal/mdl/vectors_test.go`
- Create: `internal/mdl/testdata/vectors/` (generado)

**Interfaces:**
- Consumes: `Issue`, `LoadTestDeviceKey`, `pki.GenerateIACA`, `pki.GenerateDSC`.
- Produces: `internal/mdl/testdata/vectors/{mdl_full.cbor, iaca.pem, dsc.pem}` — el contrato ejecutable.

- [ ] **Step 1: Escribir el generador de vectores**

Crear `internal/mdl/vectors_test.go`:

```go
package mdl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// TestGenerateVectors writes the interop vectors other repos consume as
// fixtures. Run it with -run TestGenerateVectors -tags vectors to refresh
// them; it is skipped in normal runs so CI does not churn the files.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("MDL_WRITE_VECTORS") == "" {
		t.Skip("set MDL_WRITE_VECTORS=1 to regenerate interop vectors")
	}

	dir := filepath.Join("testdata", "vectors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	iacaKey, iaca, err := pki.GenerateIACA("CDPI POC IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "CDPI POC DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load device key: %v", err)
	}

	d := sampleLicence()
	is, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	encoded, err := em.Marshal(is)
	if err != nil {
		t.Fatalf("marshal IssuerSigned: %v", err)
	}

	writeFile(t, filepath.Join(dir, "mdl_full.cbor"), encoded)
	writeFile(t, filepath.Join(dir, "iaca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iaca.Raw}))
	writeFile(t, filepath.Join(dir, "dsc.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dsc.Raw}))

	t.Logf("wrote interop vectors to %s", dir)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

- [ ] **Step 2: Generar los vectores**

Run:
```bash
MDL_WRITE_VECTORS=1 go test ./internal/mdl/... -run TestGenerateVectors -v
```

Expected: `wrote interop vectors to testdata/vectors`, y tres archivos nuevos.

Con Docker:
```bash
docker run --rm -e MDL_WRITE_VECTORS=1 -v "$PWD":/app -w /app golang:1.25-alpine \
  go test ./internal/mdl/... -run TestGenerateVectors -v
```

- [ ] **Step 3: Escribir el harness de verificación**

Crear `internal/mdl/testdata/verify/package.json`:

```json
{
  "name": "mdl-verify-harness",
  "private": true,
  "type": "module",
  "description": "Independent verifier for mdocs emitted by internal/mdl, using @owf/mdoc.",
  "scripts": {
    "verify": "node verify.mjs"
  },
  "dependencies": {
    "@owf/mdoc": "^0.7.0"
  }
}
```

Crear `internal/mdl/testdata/verify/verify.mjs`:

```js
// Independent verification of the mdocs produced by internal/mdl.
//
// The point of this harness is that it is NOT our Go code: if both sides
// shared an implementation, a misreading of the standard would pass both.
// @owf/mdoc is the OpenWallet Foundation implementation, also used by Credo.

import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, '..', 'vectors');

const mdoc = readFileSync(join(vectors, 'mdl_full.cbor'));
const iacaPem = readFileSync(join(vectors, 'iaca.pem'), 'utf8');

const { parseIssuerSigned } = await import('@owf/mdoc');

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
};

const parsed = parseIssuerSigned(new Uint8Array(mdoc));

check('IssuerSigned parses', !!parsed);
check(
  'docType is org.iso.18013.5.1.mDL',
  parsed.issuerAuth?.decodedPayload?.docType === 'org.iso.18013.5.1.mDL',
  parsed.issuerAuth?.decodedPayload?.docType,
);

const digests = parsed.issuerAuth?.decodedPayload?.valueDigests?.['org.iso.18013.5.1'];
check('valueDigests present for the ISO namespace', !!digests);
check('12 elements committed', digests && Object.keys(digests).length === 12, digests && String(Object.keys(digests).length));

const validity = parsed.issuerAuth?.decodedPayload?.validityInfo;
check('validityInfo present', !!validity);
check(
  'validUntil does not exceed expiry_date',
  validity && new Date(validity.validUntil) <= new Date('2032-01-10T00:00:00Z'),
);

const iaca = new X509Certificate(iacaPem);
check('IACA is marked POC', iaca.subject.includes('POC-DO-NOT-TRUST'), iaca.subject);

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
```

Crear `internal/mdl/testdata/verify/README.md`:

```markdown
# Harness de verificación independiente

Verifica que los mdocs emitidos por `internal/mdl` son aceptados por una
implementación que no es la nuestra (`@owf/mdoc`, de OpenWallet Foundation).

Si ambos lados compartieran implementación, una mala lectura del estándar
pasaría los dos y el error se descubriría en la demo.

## Uso

```bash
# 1. Generar los vectores desde Go
cd ../../../..                      # hasta verifiably-go/
MDL_WRITE_VECTORS=1 go test ./internal/mdl/... -run TestGenerateVectors

# 2. Verificarlos con @owf/mdoc
cd internal/mdl/testdata/verify
npm install
npm run verify
```

## Contrato con otros repos

Los archivos de `../vectors/` son el contrato ejecutable con `cdpi-wallet` y
la app reader: los copian como fixtures de test. Si el formato del mdoc
cambia, sus tests fallan y la divergencia se detecta sola.

Al regenerar los vectores hay que actualizarlos en los tres repos en el mismo
cambio.
```

- [ ] **Step 4: Ejecutar el harness y verificar que pasa**

Run:
```bash
cd internal/mdl/testdata/verify && npm install && npm run verify
```

Expected: todas las líneas `PASS` y `All checks passed.`

Si `parseIssuerSigned` no existe con ese nombre en la versión instalada, consulta `node_modules/@owf/mdoc/dist/index.d.ts` para el nombre exacto del export y ajústalo. La API es la fuente de verdad; el nombre puede haber cambiado entre minors.

- [ ] **Step 5: Excluir el harness de la build de Go**

Los `node_modules` dentro de `testdata/` no afectan a `go build` (Go ignora `testdata/`), pero sí al tamaño del repo.

Añadir a `.gitignore`:

```
internal/mdl/testdata/verify/node_modules/
internal/mdl/testdata/verify/package-lock.json
```

- [ ] **Step 6: Commit**

```bash
git add internal/mdl/vectors_test.go internal/mdl/testdata/verify/ internal/mdl/testdata/vectors/ .gitignore
git commit -m "test(mdl): add independent verification harness and interop vectors"
```

---

## Task 8: Reactivar `iso_mdl` en el allowlist de walt.id

Revierte el commit `6449f96`, que eliminó mDL del grid de demo por problemas de round-trip contra MOSIP/Inji Verify. Nuestro camino de verificación es propio, así que la razón original no aplica.

**Files:**
- Modify: `internal/adapters/waltid/issuer.go` (símbolo `schemaAllowlistDefault`)
- Test: `internal/adapters/waltid/catalog_test.go`

**Interfaces:**
- Consumes: nada de tasks anteriores.
- Produces: nada que otros tasks consuman.

- [ ] **Step 1: Escribir el test que falla**

Añadir a `internal/adapters/waltid/catalog_test.go`:

```go
func TestSchemaAllowlistIncludesISOmDL(t *testing.T) {
	// Commit 6449f96 dropped mDL from the demo grid because its mso_mdoc
	// envelope was hard to round-trip through MOSIP / Inji Verify. The mDL
	// work verifies through its own path, so the entry comes back.
	want := "Iso18013 Drivers License Credential"
	for _, s := range schemaAllowlistDefault {
		if s == want {
			return
		}
	}
	t.Fatalf("expected %q in schemaAllowlistDefault, got %v", want, schemaAllowlistDefault)
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `go test ./internal/adapters/waltid/... -run TestSchemaAllowlistIncludesISOmDL -v`
Expected: FAIL — la entrada no está.

- [ ] **Step 3: Restaurar la entrada**

En `internal/adapters/waltid/issuer.go`, dentro de `schemaAllowlistDefault`, restaurar la línea eliminada manteniendo el orden alfabético:

```go
var schemaAllowlistDefault = []string{
	"Bank Id",
	"Educational ID",
	"Iso18013 Drivers License Credential",
	"Tax Receipt",
	"University Degree",
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `go test ./internal/adapters/waltid/... -v`
Expected: PASS — el test nuevo y los existentes del paquete.

- [ ] **Step 5: Commit**

```bash
git add internal/adapters/waltid/issuer.go internal/adapters/waltid/catalog_test.go
git commit -m "feat(mdl): restore ISO 18013 mDL to the walt.id schema allowlist"
```

---

## Task 9: Verificación final y merge

**Files:** ninguno nuevo.

- [ ] **Step 1: Ejecutar toda la suite**

Run: `go test ./... -v`
Expected: PASS. Si algo del resto del repo falla, comprueba que no sea preexistente comparando con `main`.

- [ ] **Step 2: Verificar que compila**

Run: `go build ./...`
Expected: sin salida.

- [ ] **Step 3: Verificar formato y vet**

Run:
```bash
go vet ./internal/mdl/... ./internal/signer/...
gofmt -l internal/mdl internal/signer
```
Expected: `go vet` sin hallazgos; `gofmt -l` sin archivos listados.

- [ ] **Step 4: Reejecutar el harness independiente**

Run:
```bash
cd internal/mdl/testdata/verify && npm run verify
```
Expected: `All checks passed.`

**Este es el criterio de aceptación de C.7.1:** el issuer produce mdocs que un verificador independiente acepta.

- [ ] **Step 5: Abrir el PR**

```bash
git push -u origin feat/mdl-issuer
gh pr create --title "feat(mdl): ISO 18013-5 mdoc issuer" --body "$(cat <<'EOF'
## Qué hace

Añade `internal/mdl/`: emisión de credenciales mDL en formato mdoc
(ISO/IEC 18013-5:2021), con firma `COSE_Sign1` y cadena IACA→DSC propia.

Implementa C.7.1 y C.7.2 del spec
`docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md`.

## Alcance

- `internal/signer/`: interfaz `Signer` con implementación en software,
  preparada para sustituirse por KMS/HSM sin tocar la lógica de credenciales.
- `internal/mdl/pki/`: IACA autofirmada (90 días, `O=POC-DO-NOT-TRUST`) y DSC
  con EKU `1.0.18013.5.1.2` y validez acotada por Annex B y por la IACA.
- `internal/mdl/`: tipos CBOR con los tags correctos, `valueDigests`, MSO con
  `deviceKeyInfo`, y firma con `x5chain`.
- Dataset de 12 elementos: 10 de los 11 mandatory (**sin `portrait`**, que se
  difiere) más `age_over_18` y `age_over_21`.
- Harness de verificación independiente con `@owf/mdoc` y vectores de interop
  que sirven de contrato con `cdpi-wallet` y la app reader.
- Restaura mDL en el allowlist de walt.id (revierte `6449f96`).

## Limitación declarada

La credencial resultante **no es un mDL conforme**: le falta `portrait`, que
es mandatory en la Tabla 3. Es un mdoc de prueba hasta C.7.5.

## Cómo probarlo

```bash
go test ./internal/mdl/... ./internal/signer/... -v
MDL_WRITE_VECTORS=1 go test ./internal/mdl/... -run TestGenerateVectors
cd internal/mdl/testdata/verify && npm install && npm run verify
```
EOF
)"
```

---

## Notas para quien ejecute este plan

**Sobre la clave privada:** ningún test escribe claves privadas a disco. Los vectores solo contienen certificados públicos y el mdoc. Si añades un paso que persista una clave, ponla fuera del árbol del repo y en `.gitignore` (§C.8 del spec).

**Si un test de CBOR falla por bytes inesperados:** compara con `cbor.Diagnose(data)` de `fxamacker/cbor/v2`, que imprime la notación diagnóstica del estándar y hace obvio qué tag salió mal.

**Decisión pendiente que este plan NO resuelve:** `proof_types_supported.cwt` vs `jwt` para el proof de posesión (decisión #4 del spec). El endpoint que valida el proof queda fuera de este plan porque depende de esa decisión; se implementa cuando esté tomada, junto con la integración real con `cdpi-wallet`.
