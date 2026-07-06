package statuslistcache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func didjwkB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func didjwkPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// P2: a did:jwk-signed status list (walt.id's) must have its signature actually
// verified, not silently skipped.
func TestVerifyJWT_DIDJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{"kty": "EC", "crv": "P-256",
		"x": didjwkB64(didjwkPad32(priv.X.Bytes())), "y": didjwkB64(didjwkPad32(priv.Y.Bytes()))}
	jwkJSON, _ := json.Marshal(jwk)
	did := "did:jwk:" + didjwkB64(jwkJSON)

	sign := func(payload string) string {
		in := didjwkB64([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + didjwkB64([]byte(payload))
		h := sha256.Sum256([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
		return in + "." + didjwkB64(append(didjwkPad32(r.Bytes()), didjwkPad32(s.Bytes())...))
	}

	f := &Fetcher{} // no resolver needed for did:jwk
	good := sign(`{"iss":"` + did + `"}`)
	if err := f.verifyJWT(context.Background(), good, did); err != nil {
		t.Fatalf("valid did:jwk JWT must verify: %v", err)
	}

	// A tampered signature must be rejected (not silently skipped).
	bad := good[:len(good)-4] + "AAAA"
	if err := f.verifyJWT(context.Background(), bad, did); err == nil {
		t.Fatal("tampered did:jwk JWT must fail signature verification")
	}
}

func TestDecodeDIDJWK(t *testing.T) {
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": "aa", "y": "bb"}
	j, _ := json.Marshal(jwk)
	got, err := decodeDIDJWK("did:jwk:" + base64.RawURLEncoding.EncodeToString(j) + "#0")
	if err != nil || got["crv"] != "P-256" {
		t.Fatalf("decode did:jwk (with #frag): err=%v got=%v", err, got)
	}
	if _, err := decodeDIDJWK("did:jwk:not base64 !!!"); err == nil {
		t.Fatal("invalid base64 must error")
	}
	if _, err := decodeDIDJWK("did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte("not json"))); err == nil {
		t.Fatal("invalid JWK JSON must error")
	}
}
