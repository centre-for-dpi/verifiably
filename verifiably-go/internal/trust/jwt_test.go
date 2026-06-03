package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// ── HS256 ─────────────────────────────────────────────────────────────────────

func TestBuildJWT_RoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	issuers := []TrustedIssuer{{DID: "did:web:a.gov", DisplayName: "A"}}

	token, err := BuildJWT(issuers, "did:web:hub.gov", secret, time.Hour)
	if err != nil {
		t.Fatalf("BuildJWT: %v", err)
	}
	if len(strings.Split(token, ".")) != 3 {
		t.Fatal("JWT must have 3 parts separated by dots")
	}

	claims, err := VerifyJWT(token, secret)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims["iss"] != "did:web:hub.gov" {
		t.Errorf("iss claim: got %v", claims["iss"])
	}
}

func TestBuildJWT_WrongSecret(t *testing.T) {
	token, _ := BuildJWT(nil, "iss", []byte("secret-a"), time.Hour)
	_, err := VerifyJWT(token, []byte("secret-b"))
	if err == nil {
		t.Fatal("wrong secret should fail VerifyJWT")
	}
}

func TestBuildJWT_DefaultTTL(t *testing.T) {
	// ttl=0 should default to 24h (not error)
	_, err := BuildJWT(nil, "iss", []byte("s"), 0)
	if err != nil {
		t.Fatalf("zero TTL should use default: %v", err)
	}
}

func TestVerifyJWT_Expired(t *testing.T) {
	// Negative TTL produces an exp Unix timestamp in the past.
	token, _ := BuildJWT(nil, "iss", []byte("s"), -time.Hour)
	_, err := VerifyJWT(token, []byte("s"))
	if err == nil {
		t.Fatal("expired JWT should fail VerifyJWT")
	}
}

func TestVerifyJWT_Malformed(t *testing.T) {
	_, err := VerifyJWT("not.a.valid.jwt.token.at.all", []byte("s"))
	if err == nil {
		t.Fatal("malformed JWT should fail")
	}
}

// ── ES256 ─────────────────────────────────────────────────────────────────────

func TestBuildJWTES256_Structure(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuers := []TrustedIssuer{{DID: "did:web:issuer.gov"}}

	token, err := BuildJWTES256(issuers, "did:web:hub.gov", key, time.Hour)
	if err != nil {
		t.Fatalf("BuildJWTES256: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ES256 JWT must have 3 parts, got %d", len(parts))
	}

	// Header should decode to alg=ES256
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if !strings.Contains(string(hdrJSON), `"ES256"`) {
		t.Errorf("header should contain ES256, got: %s", hdrJSON)
	}

	// Signature must be 64 bytes (R || S, each 32 bytes for P-256)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("ES256 signature must be 64 bytes, got %d", len(sig))
	}
}

func TestBuildJWTES256_DefaultTTL(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := BuildJWTES256(nil, "iss", key, 0)
	if err != nil {
		t.Fatalf("zero TTL should use default: %v", err)
	}
}

// ── PublicKeyToJWK ────────────────────────────────────────────────────────────

func TestPublicKeyToJWK_Fields(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := PublicKeyToJWK(&key.PublicKey)

	for _, field := range []string{"kty", "crv", "x", "y", "alg", "use"} {
		if _, ok := jwk[field]; !ok {
			t.Errorf("JWK missing field %q", field)
		}
	}
	if jwk["kty"] != "EC" {
		t.Errorf("kty: got %v, want EC", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("crv: got %v, want P-256", jwk["crv"])
	}
	if jwk["alg"] != "ES256" {
		t.Errorf("alg: got %v, want ES256", jwk["alg"])
	}
}

func TestPublicKeyToJWK_CoordinatePadding(t *testing.T) {
	// x and y coordinates must always decode to exactly 32 bytes (P-256)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := PublicKeyToJWK(&key.PublicKey)

	for _, coord := range []string{"x", "y"} {
		s, ok := jwk[coord].(string)
		if !ok {
			t.Fatalf("%s is not a string", coord)
		}
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decode %s: %v", coord, err)
		}
		if len(b) != 32 {
			t.Errorf("%s must be 32 bytes, got %d", coord, len(b))
		}
	}
}

// ── ErrUntrusted sentinel ─────────────────────────────────────────────────────

func TestErrUntrusted_IsWrappable(t *testing.T) {
	// A plain unrelated error must not match.
	plain := errors.New("outer: " + ErrUntrusted.Error())
	if errors.Is(plain, ErrUntrusted) {
		t.Error("plain string error should not match ErrUntrusted via errors.Is")
	}
	// errors.Join wraps; errors.Is must unwrap it.
	joined := errors.Join(ErrUntrusted, errors.New("extra"))
	if !errors.Is(joined, ErrUntrusted) {
		t.Error("joined ErrUntrusted should match via errors.Is")
	}
}
