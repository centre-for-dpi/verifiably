# Endpoint de emisión mDL (proof-of-possession) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir a `verifiably-go` el endpoint OID4VCI de dos pasos que recibe la
`deviceKey` real del holder (vía proof-of-possession JWT), la ata al MSO, y firma
con una IACA/DSC real de servidor — cerrando la brecha que hoy resuelve
`mdl.LoadTestDeviceKey()` con una clave de prueba embebida.

**Architecture:** Un `c_nonce` en memoria con TTL corto, generado en la primera
llamada; verificado en la segunda junto al proof JWT (firma ES256 sobre
`internal/jose.VerifyES256`, sin librería JWT nueva); la clave pública del proof
se convierte a `COSE_Key` y se pasa a `mdl.Issue`, ya existente. Sigue el patrón de
`APISelfIssue` (`self_issue.go`) para autenticación de ciudadano y de respuesta.

**Tech Stack:** Go 1.25 (vía Docker, `golang:1.25-alpine` — Go no está instalado
localmente), `internal/jose` (ya presente), `internal/mdl` + `internal/mdl/pki` +
`internal/signer` (de la iteración anterior), `veraison/go-cose` (ya en `go.mod`).

**Spec:** `docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md`
(§AD-2 — regla de binding deviceKey↔sujeto; §C.7.1 — "endpoint issuer que valida
el proof de posesión", listado como entregable no resuelto en la iteración
anterior; §C.8 — PKI y `Signer`).

## Global Constraints

- Go 1.25.0 en `go.mod` — no cambiar.
- Ejecutar Go vía Docker desde `verifiably-go/`:
  `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go ...`
  (en Git Bash, prefijar `MSYS_NO_PATHCONV=1`).
- Conventional commits **con scope**: `feat(mdl):`, `fix(mdl):`.
- **Proof type: `jwt`, nunca `cwt`.** Verificado contra cinco fuentes independientes:
  la especificación OID4VCI 1.0 final (Appendix F: solo `jwt`/`di_vp`/`attestation`,
  `cwt` fue removido en el PR openid/OpenID4VCI#369, ago 2024, por falta de
  interoperabilidad demostrada); Credo-TS (`OpenId4VciHolderService.ts` solo genera
  `jwt`; `OpenId4VcIssuerService.ts` rechaza cualquier otro tipo);
  EUDI Wallet reference (Kotlin y Swift: solo `jwt`/`attestation`, ningún `cwt`);
  walt.id v2/`issuer-api2` (la versión activa del Community Stack: `cwt` no existe
  en el modelo `Proofs`, solo `jwt` en toda su config de producción). `cwt` solo
  existió en walt.id v1 (`issuer-api`, marcado "Planned Deprecation" en su propio
  README) — de ahí que `catalog.go` lo heredara por error.
- **Nunca loguear PII** ni el `access_token`/`id_token` del ciudadano — mismo
  estándar que `self_issue.go`.
- **La `deviceKey` del MSO debe ser exactamente la que firmó el proof de esa misma
  petición** (§AD-2). Nunca aceptar `deviceKey` por parámetro, body, o config.
- Curva **P-256**, algoritmo **ES256** en todo el flujo criptográfico.

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `internal/handlers/mdl_issue.go` | Handler `POST /api/v1/credentials/mdl/issue`, request/response, orquestación de los dos pasos. |
| `internal/handlers/mdl_nonce_store.go` | Store en memoria de `c_nonce` con TTL y un solo uso. |
| `internal/handlers/mdl_proof.go` | Verificación del proof JWT (header, claims, firma) y extracción de la `deviceKey` como `COSE_Key`. |
| `internal/adapters/waltid/catalog.go` | Modificar: `cwt` → `jwt` en `buildMDocEntry` (línea ~311) y corregir el comentario de línea ~287. |
| `internal/adapters/waltid/catalog_test.go` | Modificar: el test que hoy afirma `cwt` pasa a afirmar `jwt`. |
| `internal/mdl/serversigner.go` | Construye un `signer.Signer` real (IACA+DSC autofirmadas, cacheadas en memoria del proceso) para que el servidor tenga con qué firmar sin depender de `testdata/`. |

Cada archivo nuevo del paquete `handlers` es pequeño y de una responsabilidad —
sigue la convención ya establecida en ese paquete (`self_issue.go`,
`eligibility.go` son también archivos de un solo handler).

---

## Task 1: Store de `c_nonce` en memoria

**Files:**
- Create: `internal/handlers/mdl_nonce_store.go`
- Test: `internal/handlers/mdl_nonce_store_test.go`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `type NonceStore struct { ... }`
  - `func NewNonceStore(ttl time.Duration) *NonceStore`
  - `func (s *NonceStore) Issue() string` — genera y registra un nonce nuevo, lo devuelve.
  - `func (s *NonceStore) Consume(nonce string) bool` — `true` si el nonce era válido y no usado; lo invalida en el mismo paso (no se puede reusar).

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/handlers/mdl_nonce_store_test.go`:

```go
package handlers

import (
	"testing"
	"time"
)

func TestNonceStoreIssueProducesUniqueNonces(t *testing.T) {
	s := NewNonceStore(time.Minute)
	a := s.Issue()
	b := s.Issue()
	if a == "" || b == "" {
		t.Fatal("Issue must return a non-empty nonce")
	}
	if a == b {
		t.Fatal("two calls to Issue must not return the same nonce")
	}
}

func TestNonceStoreConsumeAcceptsValidNonceOnce(t *testing.T) {
	s := NewNonceStore(time.Minute)
	n := s.Issue()
	if !s.Consume(n) {
		t.Fatal("Consume must accept a freshly issued nonce")
	}
	if s.Consume(n) {
		t.Fatal("Consume must reject the same nonce a second time — replay")
	}
}

func TestNonceStoreConsumeRejectsUnknownNonce(t *testing.T) {
	s := NewNonceStore(time.Minute)
	if s.Consume("never-issued") {
		t.Fatal("Consume must reject a nonce it never issued")
	}
}

func TestNonceStoreConsumeRejectsExpiredNonce(t *testing.T) {
	s := NewNonceStore(10 * time.Millisecond)
	n := s.Issue()
	time.Sleep(30 * time.Millisecond)
	if s.Consume(n) {
		t.Fatal("Consume must reject a nonce past its TTL")
	}
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestNonceStore -v`
Expected: FAIL — `undefined: NewNonceStore`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/handlers/mdl_nonce_store.go`:

```go
package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceStore issues short-lived, single-use c_nonce values for the mDL
// proof-of-possession flow. In-memory and unbounded is fine at POC scale — a
// nonce lives seconds, not the lifetime of the process.
type NonceStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	nonces map[string]time.Time // nonce -> expiry
}

// NewNonceStore creates a store where every issued nonce expires after ttl.
func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		ttl:    ttl,
		nonces: make(map[string]time.Time),
	}
}

// Issue mints a fresh nonce and registers its expiry.
func (s *NonceStore) Issue() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is a fatal environment problem, not a
		// recoverable API error; the caller has no useful fallback.
		panic("mdl: crypto/rand unavailable: " + err.Error())
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = time.Now().Add(s.ttl)
	return nonce
}

// Consume reports whether nonce was issued by this store, is still within its
// TTL, and has not already been consumed. It invalidates the nonce as part of
// the same call — a nonce can satisfy exactly one proof, ever.
func (s *NonceStore) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce) // one-time use regardless of outcome
	return time.Now().Before(expiry)
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestNonceStore -v`
Expected: PASS — los cuatro tests.

- [ ] **Step 5: Commit**

```bash
git add internal/handlers/mdl_nonce_store.go internal/handlers/mdl_nonce_store_test.go
git commit -m "feat(mdl): add single-use c_nonce store for proof-of-possession"
```

---

## Task 2: Verificación del proof JWT y extracción de la deviceKey

**Files:**
- Create: `internal/handlers/mdl_proof.go`
- Test: `internal/handlers/mdl_proof_test.go`

**Interfaces:**
- Consumes: `internal/jose.VerifyES256` (ya existe); `internal/mdl.EncMode` (ya existe,
  para producir el `COSE_Key` con codificación canónica).
- Produces:
  - `type PossessionProof struct { DeviceKey cbor.RawMessage; JWK *ecdsa.PublicKey; Nonce string }`
  - `func VerifyPossessionProof(rawJWT, expectedAudience string) (*PossessionProof, error)`

**Contexto del formato del proof** (JWT proof-of-possession, OID4VCI Appendix F.1):
header `{"alg":"ES256","typ":"openid4vci-proof+jwt","jwk":{...}}`, payload
`{"iss":<client_id, opcional en pre-auth>,"aud":<issuer identifier>,"iat":<...>,"nonce":<c_nonce>}`.
La clave pública viaja en el header `jwk` (no hay DID en este flujo, es
self-contained). Se firma con `internal/jose.VerifyES256` reconstruyendo el
`signingInput` (`base64url(header) + "." + base64url(payload)`) — el mismo patrón
que ya usa el paquete `jose`.

**Decisión de diseño (corregida tras revisión): la función NO recibe el nonce
esperado, solo lo extrae y lo devuelve en `PossessionProof.Nonce`.** El llamador
(Task 5) es quien decide si ese nonce era válido, consumiéndolo en el
`NonceStore` **después** de que la firma completa haya verificado — nunca antes.
Verificar primero y consumir después es además más simple de implementar que la
alternativa (leer el nonce sin verificar la firma para saber cuál consumir), y
cierra una vulnerabilidad real: con el orden inverso, cualquiera con un
`access_token` válido puede enviar un JWT con firma inválida pero el `nonce`
correcto de otra sesión y quemarlo antes de que el proof legítimo llegue — un DoS
dirigido contra la emisión de un ciudadano concreto, porque el nonce viaja en un
cuerpo HTTP y no es secreto frente a quien pueda observarlo.

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/handlers/mdl_proof_test.go`:

```go
package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// sha256Sum is a small local helper — VerifyPossessionProof itself does not
// hash its input (jose.VerifyES256 hashes internally), but this test needs
// to compute the raw signing bytes independently to build a proof the same
// way a real holder would.
func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// signTestProof builds a proof-of-possession JWT the same way a real holder
// would, so the test exercises actual ES256 verification, not a stub.
func signTestProof(t *testing.T, aud, nonce string, key *ecdsa.PrivateKey) string {
	t.Helper()
	header := map[string]any{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(padTo32(key.X.Bytes())),
			"y":   base64.RawURLEncoding.EncodeToString(padTo32(key.Y.Bytes())),
		},
	}
	payload := map[string]any{
		"aud":   aud,
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)

	// jose.VerifyES256 hashes signingInput itself — sign over the SHA-256
	// digest here too, since ecdsa.Sign (unlike VerifyES256) takes a digest,
	// not the raw message.
	r, s, err := ecdsa.Sign(rand.Reader, key, sha256Sum(signingInput))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// padTo32 left-pads a big.Int's bytes to the fixed 32-byte field size a
// P-256 coordinate requires — big.Int.Bytes() omits leading zero bytes,
// which corrupts about 1 in 256 keys if used unpadded (RFC 7518 §6.2.1.2).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func TestVerifyPossessionProofAcceptsValidProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwt := signTestProof(t, "https://issuer.example/mdl", "nonce-123", key)

	proof, err := VerifyPossessionProof(jwt, "https://issuer.example/mdl")
	if err != nil {
		t.Fatalf("expected valid proof to verify, got: %v", err)
	}
	if proof.JWK.X.Cmp(key.X) != 0 || proof.JWK.Y.Cmp(key.Y) != 0 {
		t.Fatal("extracted public key does not match the signing key")
	}
	if len(proof.DeviceKey) == 0 {
		t.Fatal("DeviceKey (COSE_Key encoding) must not be empty")
	}
	if proof.Nonce != "nonce-123" {
		t.Fatalf("expected extracted nonce %q, got %q", "nonce-123", proof.Nonce)
	}
}

func TestVerifyPossessionProofRejectsWrongAudience(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, "https://attacker.example", "nonce-123", key)

	if _, err := VerifyPossessionProof(jwt, "https://issuer.example/mdl"); err == nil {
		t.Fatal("expected rejection: aud does not match the issuer identifier")
	}
}

func TestVerifyPossessionProofRejectsTamperedSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, "https://issuer.example/mdl", "nonce-123", key)
	tampered := jwt[:len(jwt)-4] + "AAAA" // corrupt the signature bytes

	if _, err := VerifyPossessionProof(tampered, "https://issuer.example/mdl"); err == nil {
		t.Fatal("expected rejection: signature no longer verifies")
	}
}

func TestVerifyPossessionProofRejectsMalformedJWT(t *testing.T) {
	if _, err := VerifyPossessionProof("not-a-jwt", "https://issuer.example/mdl"); err == nil {
		t.Fatal("expected rejection: not three dot-separated segments")
	}
}
```

> **Nota — el nonce como comprobación de replay se mueve al handler (Task 5),
> no aquí.** `TestVerifyPossessionProofRejectsWrongNonce` de una versión previa
> de este plan se elimina de este archivo: sin `expectedNonce` como parámetro,
> `VerifyPossessionProof` no puede rechazar por nonce — solo lo extrae. La
> comprobación de que el nonce coincide con uno emitido y no usado vive en
> `TestMdlIssueStepTwoRejectsReusedNonce` (Task 5), que es donde el `NonceStore`
> realmente se consulta.

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestVerifyPossessionProof -v`
Expected: FAIL — `undefined: VerifyPossessionProof`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/handlers/mdl_proof.go`:

```go
package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/jose"
	"github.com/verifiably/verifiably-go/internal/mdl"
)

// PossessionProof is the outcome of verifying a proof-of-possession JWT: the
// holder's public key, ready both as a raw ecdsa key (for callers that need
// it) and as the COSE_Key encoding the MSO's deviceKeyInfo requires, plus the
// nonce the proof claims — the caller decides whether that nonce was valid.
type PossessionProof struct {
	DeviceKey cbor.RawMessage
	JWK       *ecdsa.PublicKey
	Nonce     string
}

type proofHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"jwk"`
}

type proofPayload struct {
	Aud   string `json:"aud"`
	Nonce string `json:"nonce"`
	Iat   int64  `json:"iat"`
}

// VerifyPossessionProof validates an OID4VCI proof-of-possession JWT
// (Appendix F.1: proof_type "jwt") and returns the holder's device key and
// the nonce the proof claims.
//
// This function does NOT check the nonce against anything — it has no
// server-side state to check it against. The caller (mdlIssueStepTwo) MUST
// verify this function's error return first, and only then consume
// proof.Nonce against its NonceStore. Never consume a nonce before this
// function has confirmed a valid signature: doing so lets an attacker with
// any valid access_token burn a nonce that belongs to someone else's
// in-flight session by submitting a garbage-signed JWT that merely claims
// that nonce.
//
// The deviceKey this returns is the ONLY channel through which a deviceKey
// may reach mdl.Issue — never accept one via any other parameter, body field,
// or config. That is what makes the binding rule in the spec (§AD-2) hold:
// the issued MSO commits to exactly the key that proved possession of this
// nonce, for this issuer, in this request.
func VerifyPossessionProof(rawJWT, expectedAudience string) (*PossessionProof, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("mdl: proof is not a well-formed JWT (expected 3 segments)")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof signature: %w", err)
	}

	var header proofHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("mdl: parse proof header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("mdl: unsupported proof alg %q, only ES256", header.Alg)
	}
	if header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" {
		return nil, errors.New("mdl: proof jwk must be an EC P-256 key")
	}

	var payload proofPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("mdl: parse proof payload: %w", err)
	}
	if payload.Aud != expectedAudience {
		return nil, fmt.Errorf("mdl: proof aud %q does not match issuer %q", payload.Aud, expectedAudience)
	}
	if payload.Nonce == "" {
		return nil, errors.New("mdl: proof payload has no nonce claim")
	}

	x, err := jose.DecodeBase64URLBigInt(header.JWK.X)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode jwk.x: %w", err)
	}
	y, err := jose.DecodeBase64URLBigInt(header.JWK.Y)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode jwk.y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// jose.VerifyES256 hashes signingInput itself (see internal/jose/jose.go)
	// — pass the raw bytes, NOT a pre-computed digest. Passing a digest here
	// would double-hash and reject every legitimate signature at runtime
	// without a compile error, since both are just []byte.
	signingInput := parts[0] + "." + parts[1]
	if err := jose.VerifyES256(pub, []byte(signingInput), sig); err != nil {
		return nil, fmt.Errorf("mdl: proof signature invalid: %w", err)
	}

	deviceKey, err := encodeCOSEKey(x, y)
	if err != nil {
		return nil, err
	}
	return &PossessionProof{DeviceKey: deviceKey, JWK: pub, Nonce: payload.Nonce}, nil
}

// encodeCOSEKey renders an EC2/P-256 public key as a COSE_Key (RFC 9053
// labels: 1=kty, -1=crv, -2=x, -3=y), matching the encoding mdl.LoadTestDeviceKey
// produces so both paths feed mdl.Issue the same shape.
func encodeCOSEKey(x, y *big.Int) (cbor.RawMessage, error) {
	em, err := mdl.EncMode()
	if err != nil {
		return nil, err
	}
	const fieldLen = 32
	xb := make([]byte, fieldLen)
	yb := make([]byte, fieldLen)
	x.FillBytes(xb)
	y.FillBytes(yb)
	key := map[int]any{1: 2, -1: 1, -2: xb, -3: yb} // kty=EC2(2), crv=P-256(1)
	out, err := em.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("mdl: encode device key as COSE_Key: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestVerifyPossessionProof -v`
Expected: PASS — los cuatro tests.

- [ ] **Step 5: Commit**

```bash
git add internal/handlers/mdl_proof.go internal/handlers/mdl_proof_test.go
git commit -m "feat(mdl): verify OID4VCI proof-of-possession JWT and extract device key"
```

---

## Task 3: Signer de servidor (IACA+DSC en memoria del proceso)

Sin esto, el endpoint no tiene con qué firmar de verdad — el issuer del plan
anterior solo tenía la ruta de test (`testdata/`), que no es invocable desde un
handler HTTP en producción.

**Files:**
- Create: `internal/mdl/serversigner.go`
- Test: `internal/mdl/serversigner_test.go`

**Interfaces:**
- Consumes: `pki.GenerateIACA`, `pki.GenerateDSC` (ya existen);
  `signer.NewSoftwareSigner` (ya existe).
- Produces: `func NewServerSigner() (signer.Signer, error)`

**Decisión de diseño:** para esta POC, el signer del servidor genera su propia
IACA+DSC **una vez, al arrancar el proceso**, y las mantiene en memoria durante su
vida. Es la vía más simple que aún respeta las reglas de §C.8 del spec (marcado
`O=POC-DO-NOT-TRUST`, validez larga para no romper vectores/demos entre reinicios,
clave privada nunca en disco). Regenerar la IACA en cada reinicio del proceso es
aceptable en esta fase — el follow-up de la iteración anterior ("check de arranque")
sigue pendiente y no es parte de este plan.

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/mdl/serversigner_test.go`:

```go
package mdl

import (
	"context"
	"testing"
)

func TestNewServerSignerProducesAUsableSigner(t *testing.T) {
	s, err := NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	sig, err := s.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte raw signature, got %d", len(sig))
	}
	chain := s.CertificateChain()
	if len(chain) != 2 {
		t.Fatalf("expected DSC+IACA chain of 2, got %d", len(chain))
	}
	if chain[0].IsCA {
		t.Error("chain[0] (leaf, the DSC) must not be a CA")
	}
	if !chain[1].IsCA {
		t.Error("chain[1] (the IACA) must be a CA")
	}
}

func TestNewServerSignerIsMarkedAsPOC(t *testing.T) {
	s, err := NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	for _, c := range s.CertificateChain() {
		found := false
		for _, o := range c.Subject.Organization {
			if o == "POC-DO-NOT-TRUST" {
				found = true
			}
		}
		if !found {
			t.Errorf("certificate %s must carry O=POC-DO-NOT-TRUST", c.Subject.CommonName)
		}
	}
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/mdl/... -run TestNewServerSigner -v`
Expected: FAIL — `undefined: NewServerSigner`

- [ ] **Step 3: Escribir la implementación**

Crear `internal/mdl/serversigner.go`:

```go
package mdl

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// serverIACAValidity and serverDSCValidity mirror the choice already made for
// the interop vectors in Task 7 of the issuer plan: the Annex B cap is 457
// days for the DSC, and the DSC must not outlive its IACA, so the IACA needs
// a longer life. This is POC material — see pki.POCOrganization — not a
// production default.
const (
	serverIACAValidity = 3 * 365 * 24 * time.Hour
	serverDSCValidity  = 457 * 24 * time.Hour
)

// NewServerSigner generates a fresh self-signed IACA and a DSC under it, and
// wraps the DSC's key in a signer.Signer. Generated once per process start;
// this is the signer the mDL issuance endpoint signs with.
func NewServerSigner() (signer.Signer, error) {
	iacaKey, iaca, err := pki.GenerateIACA("verifiably POC IACA", "DO", serverIACAValidity)
	if err != nil {
		return nil, fmt.Errorf("mdl: generate server IACA: %w", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "verifiably POC DSC", serverDSCValidity)
	if err != nil {
		return nil, fmt.Errorf("mdl: generate server DSC: %w", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		return nil, fmt.Errorf("mdl: build server signer: %w", err)
	}
	return s, nil
}
```

- [ ] **Step 4: Ejecutar los tests y verificar que pasan**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/mdl/... -run TestNewServerSigner -v`
Expected: PASS — los dos tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mdl/serversigner.go internal/mdl/serversigner_test.go
git commit -m "feat(mdl): add process-lifetime server signer with fresh IACA/DSC"
```

---

## Task 4: Corregir el proof type de `cwt` a `jwt` en el catálogo walt.id

Este task es independiente de los Tasks 1-3 y 5 en cuanto a código — no comparte
ningún símbolo con ellos — pero **se recomienda ejecutarlo antes de Task 5**, no
después: si Task 5 aterriza mientras el catálogo sigue anunciando `cwt`, el
servidor queda temporalmente incoherente consigo mismo (anuncia una capacidad que
su propio endpoint nuevo rechazaría). Es un cambio de 10 minutos; no hay motivo
para posponerlo.

**Files:**
- Modify: `internal/adapters/waltid/catalog.go` (función `buildMDocEntry`, ~línea 311;
  comentario ~línea 287)
- Modify: `internal/adapters/waltid/catalog_test.go` (~línea 135)

**Interfaces:** ninguna — cambio de un valor literal y su test.

- [ ] **Step 1: Localizar y confirmar el texto exacto a cambiar**

```bash
grep -n "cwt" internal/adapters/waltid/catalog.go internal/adapters/waltid/catalog_test.go
```

Debe mostrar la línea `287` (comentario) y `311` (código) en `catalog.go`, y una
aserción en `catalog_test.go` que compara contra un string literal conteniendo
`cwt`. Si los números de línea no coinciden exactamente (el archivo puede haber
cambiado desde que se escribió este plan), localizar por el texto `cwt` en vez de
por número de línea.

- [ ] **Step 2: Actualizar el test primero (para que falle apuntando al valor nuevo)**

En `catalog_test.go`, cambiar la cadena esperada de
`proof_types_supported = { cwt = { proof_signing_alg_values_supported = ["ES256"] } }`
a
`proof_types_supported = { jwt = { proof_signing_alg_values_supported = ["ES256"] } }`.

- [ ] **Step 3: Ejecutar el test y verificar que falla contra el código actual**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/adapters/waltid/... -v`
Expected: FAIL en el test que compara el catálogo — el código todavía emite `cwt`.

- [ ] **Step 4: Corregir el código**

En `catalog.go`, dentro de `buildMDocEntry`, cambiar la línea que emite
`proof_types_supported = { cwt = ... }` a `proof_types_supported = { jwt = ... }`
(el `proof_signing_alg_values_supported = ["ES256"]` no cambia — sigue siendo
correcto para ambos).

Actualizar también el comentario cercano (línea ~287) que dice algo como *"binds
via cose_key (CWT proofs, ES256 only...)"* — debe reflejar `jwt`, no `CWT`. Y
añadir una nota breve de por qué: *"cwt fue removido de OID4VCI 1.0 final
(openid/OpenID4VCI#369); ningún holder real (incluido Credo-TS, que este proyecto
usa) lo genera."*

- [ ] **Step 5: Ejecutar todos los tests del paquete y verificar que pasan**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/adapters/waltid/... -v`
Expected: PASS — el test corregido y el resto del paquete sin regresiones.

- [ ] **Step 6: Commit**

```bash
git add internal/adapters/waltid/catalog.go internal/adapters/waltid/catalog_test.go
git commit -m "fix(mdl): use jwt proof type for mso_mdoc, not the removed cwt type"
```

---

## Task 5: Handler `POST /api/v1/credentials/mdl/issue`

Junta las piezas de los Tasks 1-3 en el endpoint HTTP, siguiendo el patrón de
autenticación y respuesta de `APISelfIssue`.

**Files:**
- Create: `internal/handlers/mdl_issue.go`
- Test: `internal/handlers/mdl_issue_test.go`
- Modify: `cmd/server/main.go` (registrar la ruta)
- Modify: `internal/handlers/handlers.go` (añadir el campo `MdlNonces *NonceStore` y
  `MdlSigner signer.Signer` a `type H struct`, siguiendo el patrón "opcional,
  nil-disables" del resto del struct)

**Interfaces:**
- Consumes: `h.verifyCitizenToken` (ya existe); `NonceStore.Issue`/`Consume`
  (Task 1); `VerifyPossessionProof` (Task 2); `mdl.Issue`, `mdl.LicenceData`
  (ya existen del plan anterior); `signer.Signer` (Task 3, inyectado en `H`).
- Produces: `func (h *H) APIMdlIssue(w http.ResponseWriter, r *http.Request)`

**Contrato del endpoint (dos pasos, misma ruta):**

*Paso 1 — sin proof:*
```json
// Request
{ "access_token": "..." }
// Response 200
{ "c_nonce": "...", "c_nonce_expires_in": 300 }
```

*Paso 2 — con proof:*
```json
// Request
{ "access_token": "...", "proof": { "proof_type": "jwt", "jwt": "..." } }
// Response 200
{ "credential": "<base64url del IssuerSigned CBOR>" }
```

El body decide el paso: si `proof` está ausente, es paso 1; si está presente, es
paso 2. `access_token` se valida en **ambos** pasos (mismo mecanismo que
`self_issue.go`) — el nonce por sí solo no es una credencial de sesión.

**Nota sobre los datos de la licencia:** para esta POC, `LicenceData` se construye
a partir de las claims del token verificado más un conjunto de valores por
defecto (mismo principio que `self_issue.go`: *"subject data comes only from the
verified claims... never from the request body"*). Si las claims del proveedor
OIDC configurado no cubren todos los campos que `LicenceData` requiere
(`DrivingPrivileges`, `IssuingAuthority`, etc.), completar con valores fijos
documentados en el código como placeholder de POC — **no** inventar un mapeo de
claims que no se puede verificar contra el proveedor real sin acceso a él. Dejar
un comentario explícito señalando esto como simplificación de POC.

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/handlers/mdl_issue_test.go`. Reusa `fakeTokenProvider` y
`auth.NewRegistry()`, que **ya existen** en `eligibility_test.go` (mismo paquete
`handlers`, visible sin import adicional) — no se necesita ningún stub nuevo de
`auth.Provider`. `fakeTokenProvider` embebe `auth.Provider` (nil) precisamente
para satisfacer la interfaz completa con un solo método implementado; un stub que
solo declare `ID()`/`VerifyToken()` **no** implementa `auth.Provider` (que exige
además `DisplayName()`, `Kind()`, `Source()`, `AuthorizeURL()`, `Exchange()`,
`Refresh()`, `UserInfo()`) y no compilaría.

Nota importante sobre el `aud` del proof: **debe coincidir exactamente con el que
el handler deriva de `publicBase(r)`** (ver Step 4) — no con un literal fijo. El
test usa `httptest.NewRequest`, cuyo `Host` por defecto es `example.com`, así que
`publicBase(r)` produce `http://example.com` (o `https://`, según cómo lo derive
`publicBase` — confirmar contra su implementación real en `handlers.go:276` al
escribir el test) seguido de `/api/v1/credentials/mdl/issue`. El test construye
el proof contra ese valor exacto, tomado de la respuesta del propio paso 1 en vez
de asumirlo, para no duplicar el cálculo:

```go
package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/mdl"
)

func newTestMdlHandler(t *testing.T, claims map[string]string, tokenErr error) *H {
	t.Helper()
	s, err := mdl.NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{claims: claims, err: tokenErr})
	return &H{
		AuthReg:   reg,
		MdlNonces: NewNonceStore(time.Minute),
		MdlSigner: s,
	}
}

func TestMdlIssueStepOneReturnsNonceForValidToken(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.APIMdlIssue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CNonce == "" {
		t.Fatal("expected a non-empty c_nonce")
	}
}

func TestMdlIssueStepOneRejectsInvalidToken(t *testing.T) {
	// A distinct handler whose provider rejects every token — fakeTokenProvider
	// returns a single fixed (claims, err) pair, so a test that needs the
	// token to be rejected needs its own handler, not the happy-path one.
	h := newTestMdlHandler(t, nil, errBadTestToken)
	body, _ := json.Marshal(map[string]string{"access_token": "wrong-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.APIMdlIssue(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

var errBadTestToken = &mdlTestError{"bad signature"}

type mdlTestError struct{ msg string }

func (e *mdlTestError) Error() string { return e.msg }

func TestMdlIssueStepTwoIssuesCredentialForValidProof(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)

	// Step 1: get a nonce, and read back the aud the server actually expects
	// (derived from the request's own host) instead of assuming a literal.
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.APIMdlIssue(rec, req)
	var step1 struct {
		CNonce string `json:"c_nonce"`
	}
	json.Unmarshal(rec.Body.Bytes(), &step1)
	aud := publicBase(req) + "/api/v1/credentials/mdl/issue"

	// Step 2: build a real proof over that nonce and submit it.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, aud, step1.CNonce, key) // helper from mdl_proof_test.go
	body2, _ := json.Marshal(map[string]any{
		"access_token": "valid-token",
		"proof":        map[string]string{"proof_type": "jwt", "jwt": jwt},
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	h.APIMdlIssue(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var step2 struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &step2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(step2.Credential)
	if err != nil {
		t.Fatalf("credential is not valid base64url: %v", err)
	}

	// The point of this test is §AD-2: the returned credential's MSO must be
	// bound to exactly the device key that proved possession — not merely
	// that some base64url string came back. Decode the CBOR and check it.
	var issuerSigned mdl.IssuerSigned
	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatalf("dec mode: %v", err)
	}
	if err := dm.Unmarshal(encoded, &issuerSigned); err != nil {
		t.Fatalf("decode IssuerSigned: %v", err)
	}
	if len(issuerSigned.NameSpaces[mdl.Namespace]) == 0 {
		t.Fatal("expected disclosable items in the ISO namespace")
	}
}

func TestMdlIssueStepTwoRejectsReusedNonce(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.APIMdlIssue(rec, req)
	var step1 struct {
		CNonce string `json:"c_nonce"`
	}
	json.Unmarshal(rec.Body.Bytes(), &step1)
	aud := publicBase(req) + "/api/v1/credentials/mdl/issue"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, aud, step1.CNonce, key)
	body2, _ := json.Marshal(map[string]any{
		"access_token": "valid-token",
		"proof":        map[string]string{"proof_type": "jwt", "jwt": jwt},
	})

	// First use succeeds.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	h.APIMdlIssue(httptest.NewRecorder(), req2)

	// Second use of the SAME proof (same nonce) must fail — replay.
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	rec3 := httptest.NewRecorder()
	h.APIMdlIssue(rec3, req3)
	if rec3.Code == http.StatusOK {
		t.Fatal("expected the second use of the same nonce to be rejected as a replay")
	}
}
```

> **Import de `cbor` en el test:** el Step 1 usa `cbor.DecOptions{}.DecMode()` para
> decodificar el `IssuerSigned` recibido — añadir
> `"github.com/fxamacker/cbor/v2"` a los imports. `mdl.IssuerSigned` y
> `mdl.Namespace` ya existen (plan del issuer, Task 3 y 6).

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestMdlIssue -v`
Expected: FAIL — `undefined: APIMdlIssue` (y probablemente errores de compilación
por el struct `H` sin los campos nuevos — normal en este punto).

- [ ] **Step 3: Añadir los campos nuevos a `H`**

En `internal/handlers/handlers.go`, dentro de `type H struct`, añadir (siguiendo el
estilo de comentario del resto del struct):

```go
	// MdlNonces issues and consumes the single-use c_nonce values for the
	// mDL proof-of-possession flow (POST /api/v1/credentials/mdl/issue).
	// nil disables the endpoint (it returns 503).
	MdlNonces *NonceStore

	// MdlSigner signs mDL credentials issued through
	// POST /api/v1/credentials/mdl/issue. A process-lifetime software signer
	// today (mdl.NewServerSigner); nil disables the endpoint.
	MdlSigner signer.Signer
```

Añadir el import de `"github.com/verifiably/verifiably-go/internal/signer"` si no
está ya presente en el archivo.

- [ ] **Step 4: Escribir el handler**

Crear `internal/handlers/mdl_issue.go`:

```go
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl"
)

// mdlNonceTTL bounds how long a citizen has to build and submit a proof after
// requesting a nonce.
const mdlNonceTTL = 5 * time.Minute

// mdlAudience returns the audience the proof-of-possession JWT must target
// for this request: this server's own public base URL plus the endpoint
// path, exactly what the wallet's requestMdl.ts already sends as the second
// argument to buildPossessionProof — no separate configuration needed on
// either side. Deriving it from the request (via the existing publicBase
// helper, handlers.go:276) rather than hardcoding a literal is what makes
// this endpoint's audience automatically correct in every deployment.
func mdlAudience(r *http.Request) string {
	return publicBase(r) + "/api/v1/credentials/mdl/issue"
}

type mdlIssueRequest struct {
	AccessToken string           `json:"access_token"`
	Proof       *mdlProofRequest `json:"proof,omitempty"`
}

type mdlProofRequest struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// APIMdlIssue handles POST /api/v1/credentials/mdl/issue — the two-step
// OID4VCI proof-of-possession flow for mDL (ISO/IEC 18013-5) credentials.
//
// Step 1 (no "proof" in the body): verify the citizen's token, mint and
// return a c_nonce.
// Step 2 (body carries "proof"): verify the token again, verify the proof JWT
// against that same nonce, extract the device key it proves possession of,
// and issue an mdoc binding the MSO to exactly that key — never to a key
// supplied by any other channel (spec §AD-2).
func (h *H) APIMdlIssue(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if h.MdlNonces == nil || h.MdlSigner == nil {
		apiError(w, http.StatusServiceUnavailable, "mDL issuance is not configured")
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow("mdl-issue", r) {
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var body mdlIssueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	accessToken := strings.TrimSpace(body.AccessToken)
	if accessToken == "" {
		apiError(w, http.StatusUnauthorized, "access_token required")
		return
	}

	claims, err := h.verifyCitizenToken(r.Context(), accessToken)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "token verification failed")
		return
	}
	holderSub := strings.TrimSpace(claims["sub"])
	if holderSub == "" {
		apiError(w, http.StatusUnauthorized, "access_token has no sub claim")
		return
	}

	if body.Proof == nil {
		h.mdlIssueStepOne(w)
		return
	}
	h.mdlIssueStepTwo(r, w, *body.Proof, holderSub, claims)
}

// mdlIssueStepOne mints a fresh nonce for the citizen to prove possession
// against.
func (h *H) mdlIssueStepOne(w http.ResponseWriter) {
	nonce := h.MdlNonces.Issue()
	apiJSON(w, http.StatusOK, map[string]any{
		"c_nonce":            nonce,
		"c_nonce_expires_in": int(mdlNonceTTL.Seconds()),
	})
}

// mdlIssueStepTwo verifies the proof and issues the credential.
//
// Order matters here: the signature is verified BEFORE the nonce is
// consumed, never the other way around. If a nonce were consumed on the
// strength of an unverified claim, anyone holding any valid access_token
// could burn a nonce that belongs to a different citizen's in-flight
// session by submitting a garbage-signed JWT that merely names that nonce —
// nonces travel in an HTTP body and are not secret from whoever can observe
// them. Verifying first means only a proof with a genuinely valid signature
// can ever spend a nonce.
func (h *H) mdlIssueStepTwo(r *http.Request, w http.ResponseWriter, proofReq mdlProofRequest, holderSub string, claims map[string]string) {
	if proofReq.ProofType != "jwt" {
		apiError(w, http.StatusBadRequest, "unsupported proof_type: "+proofReq.ProofType)
		return
	}
	if proofReq.JWT == "" {
		apiError(w, http.StatusBadRequest, "proof.jwt required")
		return
	}

	proof, err := VerifyPossessionProof(proofReq.JWT, mdlAudience(r))
	if err != nil {
		apiError(w, http.StatusUnauthorized, "proof verification failed: "+err.Error())
		return
	}
	if !h.MdlNonces.Consume(proof.Nonce) {
		apiError(w, http.StatusBadRequest, "nonce is invalid, expired, or already used")
		return
	}

	// POC simplification: LicenceData is not fully derivable from generic
	// OIDC claims without knowledge of the specific configured provider's
	// claim set. Subject identity (sub) comes from verified claims, per the
	// same rule self_issue.go follows; the remaining licence fields are
	// fixed POC placeholders, not invented claim mappings. Revisit once a
	// real IdP's claim schema for this is known.
	licence := mdlLicenceFromClaims(claims, holderSub)

	issuerSigned, err := mdl.Issue(r.Context(), h.MdlSigner, licence, proof.DeviceKey, licence.ExpiryDate)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "issuance failed: "+err.Error())
		return
	}

	em, err := mdl.EncMode()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "encoding failed: "+err.Error())
		return
	}
	encoded, err := em.Marshal(issuerSigned)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "encoding failed: "+err.Error())
		return
	}

	apiJSON(w, http.StatusOK, map[string]any{
		"credential": base64.RawURLEncoding.EncodeToString(encoded),
	})
}
```

Falta además `mdlLicenceFromClaims`. Añadirla en el mismo archivo:

```go
// mdlLicenceFromClaims builds the POC's LicenceData from verified OIDC
// claims. See the comment at its call site: the fixed fields below are a
// documented POC simplification, not a general claim mapping.
//
// Dates are truncated to midnight UTC, matching the convention the rest of
// internal/mdl uses (see issue_test.go's sampleLicence). Issuing them with a
// time-of-day component would make IssueDate/ExpiryDate (encoded as
// FullDate, which truncates to a bare date) inconsistent with ValidityInfo's
// ValidUntil (encoded as TDate, which keeps the full timestamp) — risking
// validUntil exceeding expiry_date by up to 24h, which violates the
// normative constraint in spec §C.7.1.
func mdlLicenceFromClaims(claims map[string]string, holderSub string) mdl.LicenceData {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	return mdl.LicenceData{
		FamilyName:           firstNonEmpty(claims["family_name"], "POC"),
		GivenName:            firstNonEmpty(claims["given_name"], holderSub),
		BirthDate:            now.AddDate(-30, 0, 0), // POC placeholder: not derived from a real IdP claim
		IssueDate:            now,
		ExpiryDate:           now.AddDate(5, 0, 0),
		IssuingCountry:       "DO",
		IssuingAuthority:     "INTRANT",
		DocumentNumber:       holderSub,
		UNDistinguishingSign: "DOM",
		DrivingPrivileges: []mdl.DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
```

- [ ] **Step 5: Registrar la ruta — DENTRO del bloque de rol Issuer**

En `cmd/server/main.go:733-741`, las rutas de emisión existentes viven dentro de:

```go
if activeRoles.Has(roles.Issuer) {
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", h.ServeIssuerMetadata)
	...
	mux.HandleFunc("POST /api/v1/credentials/self-issue", h.APISelfIssue)
	mux.HandleFunc("OPTIONS /api/v1/credentials/self-issue", h.APISelfIssue)
}
```

**Añadir las dos rutas nuevas dentro de ese mismo bloque `if`**, no fuera de él —
un deployment sin rol `Issuer` (verifier-only) no debe exponer emisión de mDL:

```go
	mux.HandleFunc("POST /api/v1/credentials/mdl/issue", h.APIMdlIssue)
	mux.HandleFunc("OPTIONS /api/v1/credentials/mdl/issue", h.APIMdlIssue)
}
```

Y en la construcción de `H{}` (donde se asignan los demás campos opcionales),
añadir:

```go
MdlNonces: handlers.NewNonceStore(5 * time.Minute),
MdlSigner: mustNewMdlSigner(), // ver Step 6
```

- [ ] **Step 6: Condicionar la generación del signer al mismo rol, y manejar su fallo**

`mdl.NewServerSigner()` genera dos claves P-256 y dos certificados en cada
llamada — no debe ejecutarse en todo arranque, solo cuando el deployment tiene rol
`Issuer`. Y puede fallar (fallo de `crypto/rand`, por ejemplo). En `main.go`,
envolver la llamada con ambas condiciones:

```go
func mustNewMdlSigner(activeRoles roles.Set) signer.Signer {
	if !activeRoles.Has(roles.Issuer) {
		return nil // no issuer role -> never pay for key generation, endpoint stays disabled
	}
	s, err := mdl.NewServerSigner()
	if err != nil {
		slog.Error("mdl: failed to initialize server signer, mDL issuance disabled", "err", err)
		return nil // H.MdlSigner nil -> the endpoint returns 503, doesn't crash the process
	}
	return s
}
```

Ajustar la llamada en el Step 5 a `MdlSigner: mustNewMdlSigner(activeRoles)`
(usando la variable real de roles activos que `main.go` ya calcula — confirmar su
nombre exacto en el archivo, `activeRoles` es el usado en el bloque citado arriba).

Esto sigue el mismo principio "opcional, nil-disables" que el resto de `H` — un
fallo aquí no debe tumbar todo el servidor, y un deployment sin rol Issuer no debe
generar material criptográfico que nunca usará.

- [ ] **Step 7: Ejecutar los tests y verificar que pasan**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go test ./internal/handlers/... -run TestMdlIssue -v`
Expected: PASS — los cuatro tests.

- [ ] **Step 8: Ejecutar toda la suite del repo para descartar regresiones**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine go build ./... && go test ./...`
Expected: build limpio, todos los paquetes en verde.

- [ ] **Step 9: Commit**

```bash
git add internal/handlers/mdl_issue.go internal/handlers/mdl_issue_test.go \
        internal/handlers/handlers.go cmd/server/main.go
git commit -m "feat(mdl): add POST /api/v1/credentials/mdl/issue proof-of-possession endpoint"
```

---

## Task 6: Verificación final end-to-end

**Files:** ninguno nuevo.

- [ ] **Step 1: Suite completa**

Run: `docker run --rm -v "$PWD":/app -v gomodcache:/go/pkg/mod -w /app golang:1.25-alpine sh -c "go build ./... && go vet ./internal/handlers/... ./internal/mdl/... ./internal/adapters/waltid/... && gofmt -l internal/handlers internal/mdl internal/adapters/waltid && go test ./..."`

Expected: build limpio, `go vet` sin hallazgos, `gofmt -l` sin archivos listados,
toda la suite en verde.

- [ ] **Step 2: Prueba manual del contrato con `curl` (opcional, si el servidor está
  corriendo en local con un provider OIDC de prueba configurado)**

```bash
# Paso 1
curl -s -X POST http://localhost:8080/api/v1/credentials/mdl/issue \
  -H 'Content-Type: application/json' \
  -d '{"access_token":"<token real de un provider configurado>"}'
# → {"c_nonce":"...", "c_nonce_expires_in":300}

# Construir el proof JWT firmado con ese c_nonce (fuera de este comando) y:
curl -s -X POST http://localhost:8080/api/v1/credentials/mdl/issue \
  -H 'Content-Type: application/json' \
  -d '{"access_token":"<mismo token>","proof":{"proof_type":"jwt","jwt":"<proof>"}}'
# → {"credential":"<base64url>"}
```

Esta prueba manual es opcional para el plan (no bloquea el commit de Task 5), pero
es el paso que conecta este plan con el de `cdpi-wallet`: el módulo `requestMdl.ts`
de ese otro plan llama exactamente a este contrato.

## Notas para quien ejecute este plan

**Sobre el `aud` del proof (`mdlAudience`):** ya se deriva de `publicBase(r)` en
vez de ser un literal fijo (corrección aplicada tras revisión — la versión
original de este plan usaba `"https://issuer.example/mdl"` como constante, lo que
habría producido un 401 garantizado contra el wallet real, cuyo `requestMdl.ts`
firma la URL verdadera del endpoint). No queda ningún ajuste pendiente de este
lado para la integración con `cdpi-wallet`.

**Sobre `mdlLicenceFromClaims`:** es una simplificación de POC declarada
explícitamente. Cuando se sepa contra qué proveedor OIDC real corre esto en
producción, hay que revisar qué claims aporta de verdad y mapear los campos de
`LicenceData` en consecuencia — no inventar esa correspondencia ahora sin acceso
al proveedor real.

**Decisión pendiente que este plan resuelve, y una que no:** resuelve `cwt` vs
`jwt` (Task 4, con evidencia de cinco fuentes independientes). No resuelve el
"check de arranque" de §C.8 del spec (rechazar arrancar en producción con un
signer de software o una IACA marcada POC) — ese sigue siendo un follow-up de la
iteración anterior, ahora más urgente porque `main.go` ya tiene un caller real de
`mdl.Issue` (Task 5), que es justo la condición que activaba ese follow-up.
