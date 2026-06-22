package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// idpServer stands in for an OIDC provider: it serves discovery +
// jwks.json built from the given keys. keyByKid maps kid → public JWK.
func idpServer(t *testing.T, jwks map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	return httptest.NewServer(mux)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	signingInput := b64u(hdr) + "." + b64u(pl)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return signingInput + "." + b64u(sig)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	signingInput := b64u(hdr) + "." + b64u(pl)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64u(sig)
}

func rsaJWKS(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "alg": "RS256",
		"n": b64u(pub.N.Bytes()),
		"e": b64u(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

func ecJWKS(kid string, pub *ecdsa.PublicKey) map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{"keys": []map[string]any{{
		"kty": "EC", "kid": kid, "crv": "P-256",
		"x": b64u(x), "y": b64u(y),
	}}}
}

func newProvider(t *testing.T, issuer string) *Provider {
	t.Helper()
	p, err := New(Config{ID: "test-idp", IssuerURL: issuer, ClientID: "client"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestVerifyToken_RS256_Valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, key, "k1", map[string]any{
		"iss": srv.URL, "sub": "user-1", "given_name": "Ana",
		"aud": "client",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := p.VerifyToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["sub"] != "user-1" || claims["given_name"] != "Ana" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifyToken_ES256_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := idpServer(t, ecJWKS("ec1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signES256(t, key, "ec1", map[string]any{
		"iss": srv.URL, "sub": "user-2",
		"aud": "client",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := p.VerifyToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["sub"] != "user-2" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifyToken_TamperedSignatureRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, key, "k1", map[string]any{
		"iss": srv.URL, "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	// Flip a byte in the middle of the decoded signature and re-encode, so the
	// change survives base64url (flipping a trailing char can land on padding
	// bits and decode identically).
	parts := splitJWT(tok)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[len(sig)/2] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + b64u(sig)
	if _, err := p.VerifyToken(context.Background(), tampered); err == nil {
		t.Fatal("expected error on tampered signature, got nil")
	}
}

func splitJWT(tok string) [3]string {
	var out [3]string
	i := 0
	start := 0
	for j := 0; j < len(tok) && i < 3; j++ {
		if tok[j] == '.' {
			out[i] = tok[start:j]
			i++
			start = j + 1
		}
	}
	if i == 2 {
		out[2] = tok[start:]
	}
	return out
}

func TestVerifyToken_ExpiredRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, key, "k1", map[string]any{
		"iss": srv.URL, "sub": "user-1", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := p.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error on expired token, got nil")
	}
}

func TestVerifyToken_WrongIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, key, "k1", map[string]any{
		"iss": "https://evil.example.com", "sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := p.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error on wrong issuer, got nil")
	}
}

func TestVerifyToken_AudienceEnforcedWhenPresent(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL) // ClientID "client"

	base := map[string]any{"iss": srv.URL, "sub": "u", "exp": time.Now().Add(time.Hour).Unix()}

	// aud naming a different relying party, no azp → rejected (audience confusion attack).
	wrong := signRS256(t, key, "k1", merge(base, map[string]any{"aud": "other-client"}))
	if _, err := p.VerifyToken(context.Background(), wrong); err == nil {
		t.Error("expected reject when aud excludes our client id")
	}

	// aud (string) naming our client → accepted.
	right := signRS256(t, key, "k1", merge(base, map[string]any{"aud": "client"}))
	if _, err := p.VerifyToken(context.Background(), right); err != nil {
		t.Errorf("aud=client should be accepted: %v", err)
	}

	// aud (array) including our client alongside other audiences (e.g. Keycloak
	// access_token after adding an Audience mapper: ["account","client"]) → accepted.
	arr := signRS256(t, key, "k1", merge(base, map[string]any{"aud": []string{"account", "client"}}))
	if _, err := p.VerifyToken(context.Background(), arr); err != nil {
		t.Errorf("aud array including client should be accepted: %v", err)
	}

	// No aud, no azp, ClientID configured → rejected (fail closed).
	none := signRS256(t, key, "k1", base)
	if _, err := p.VerifyToken(context.Background(), none); err == nil {
		t.Error("expected reject when aud absent and no azp fallback (fail closed)")
	}

	// No aud but azp == ClientID (Keycloak access_token without Audience mapper) → accepted.
	azpOnly := signRS256(t, key, "k1", merge(base, map[string]any{"azp": "client"}))
	if _, err := p.VerifyToken(context.Background(), azpOnly); err != nil {
		t.Errorf("azp=client without aud should be accepted as fallback: %v", err)
	}
}

func TestVerifyToken_NotYetValidRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := idpServer(t, rsaJWKS("k1", &key.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, key, "k1", map[string]any{
		"iss": srv.URL, "sub": "u",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(10 * time.Minute).Unix(), // well beyond the 60s leeway
	})
	if _, err := p.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected reject for not-yet-valid token (nbf in future)")
	}
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestVerifyToken_WrongKeyRejected(t *testing.T) {
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// JWKS publishes a DIFFERENT key than the one that signed the token.
	srv := idpServer(t, rsaJWKS("k1", &otherKey.PublicKey))
	defer srv.Close()
	p := newProvider(t, srv.URL)

	tok := signRS256(t, signKey, "k1", map[string]any{
		"iss": srv.URL, "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := p.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error when signing key isn't in JWKS, got nil")
	}
}
