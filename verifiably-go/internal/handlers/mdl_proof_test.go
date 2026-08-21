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
