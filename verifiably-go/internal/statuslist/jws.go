package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/verifiably/verifiably-go/internal/jose"
)

// SigningKey is the parsed P-256 private key used to sign every status
// list this package emits. We pull the raw JWK out of walt.id's issuer-key
// envelope at adapter init time and convert it to a *ecdsa.PrivateKey
// once, so the per-request sign path stays cheap (no JSON parse / no
// big-int decode on every status list fetch).
type SigningKey struct {
	priv *ecdsa.PrivateKey
	// kid is what we put in the JWS header. Walt.id's onboarded JWKs don't
	// always carry one; if the inner JWK has no `kid`, we leave it empty
	// (verifiers fall back to `iss` + the JWK at iss/.well-known/jwks).
	kid string
	// iss is what we put in JWT payloads (`iss` claim) and as the issuer
	// part of status list URLs the verifier will dereference. Typically
	// the walt.id-onboarded DID.
	iss string
}

// ParseWaltidIssuerKey accepts walt.id's `issuerKey` envelope (the
// json.RawMessage we cached on the adapter at onboard time) and pulls out
// the inner JWK for local signing. Walt.id's envelope shape:
//
//	{ "type": "jwk", "jwk": {"kty":"EC","crv":"P-256","x":...,"y":...,"d":...} }
//
// Older / alternative builds put the JWK fields at the envelope level,
// so we accept both shapes.
func ParseWaltidIssuerKey(raw []byte, iss string) (*SigningKey, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("statuslist: issuer key empty")
	}
	var env struct {
		Type string          `json:"type"`
		JWK  json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("statuslist: parse issuer key envelope: %w", err)
	}
	jwkBytes := env.JWK
	if len(jwkBytes) == 0 {
		// Some walt.id versions put JWK fields at the envelope level.
		jwkBytes = raw
	}
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
		Kid string `json:"kid,omitempty"`
	}
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("statuslist: parse JWK: %w", err)
	}
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("statuslist: kty=%q not supported (need EC)", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("statuslist: crv=%q not supported (need P-256)", jwk.Crv)
	}
	if jwk.D == "" {
		return nil, fmt.Errorf("statuslist: JWK missing private component d (need a private key)")
	}
	x, err := jose.DecodeBase64URLBigInt(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("statuslist: decode x: %w", err)
	}
	y, err := jose.DecodeBase64URLBigInt(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("statuslist: decode y: %w", err)
	}
	d, err := jose.DecodeBase64URLBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("statuslist: decode d: %w", err)
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}
	return &SigningKey{priv: priv, kid: jwk.Kid, iss: iss}, nil
}

// Issuer returns the iss claim string (walt.id-onboarded DID).
func (k *SigningKey) Issuer() string { return k.iss }

// signES256 produces a compact-serialization JWS over the given header +
// payload using SHA-256 + ECDSA over P-256. We hand-roll instead of
// depending on go-jose because every status list fetch goes through this
// path; keeping it stdlib-only avoids pulling a CGO transitive on the hot
// path of an HTTP handler.
func (k *SigningKey) signES256(headerJSON, payloadJSON []byte) (string, error) {
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, h[:])
	if err != nil {
		return "", fmt.Errorf("statuslist: ecdsa sign: %w", err)
	}
	// JWS ES256 wants R || S as fixed-width 32-byte big-endian halves
	// (RFC 7518 §3.4). big.Int.Bytes strips leading zeros, so left-pad
	// to 32 each before concatenating; otherwise verifiers reject with
	// "invalid signature length".
	const halfLen = 32
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, halfLen*2)
	copy(sig[halfLen-len(rb):halfLen], rb)
	copy(sig[halfLen*2-len(sb):], sb)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// SignJWT serializes claims as a JSON object and produces an ES256 JWS
// over it. The `typ` argument lets callers distinguish a generic JWT
// (typ="JWT") from a Token Status List (typ="statuslist+jwt") or a
// Bitstring Status List VC enveloped as JWT (typ="vc+jwt"). The header
// always carries alg=ES256 + the configured kid (when present).
func (k *SigningKey) SignJWT(typ string, claims any) (string, error) {
	header := map[string]string{"alg": "ES256", "typ": typ}
	if k.kid != "" {
		header["kid"] = k.kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("statuslist: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("statuslist: marshal payload: %w", err)
	}
	return k.signES256(headerJSON, payloadJSON)
}

// VerifyES256 decodes a compact JWS and verifies the signature against the
// public half of the SigningKey. Mainly for round-trip tests; production
// verifiers fetch the issuer's JWK independently, so this isn't on any hot
// path.
func (k *SigningKey) VerifyES256(token string) ([]byte, error) {
	parts := splitDots(token)
	if len(parts) != 3 {
		return nil, fmt.Errorf("statuslist: jws must have 3 segments (got %d)", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("statuslist: decode header: %w", err)
	}
	var header struct{ Alg string }
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("statuslist: parse header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("statuslist: alg=%q not supported", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("statuslist: decode signature: %w", err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("statuslist: signature must be 64 bytes (got %d)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(&k.priv.PublicKey, h[:], r, s) {
		return nil, fmt.Errorf("statuslist: signature verification failed")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

func splitDots(s string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
