// SPDX-License-Identifier: Apache-2.0

package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T, alg Algorithm) any {
	t.Helper()
	k, err := GenerateKey(alg)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", alg, err)
	}
	return k
}

func TestAlgorithmFor(t *testing.T) {
	cases := []struct {
		name string
		key  any
		want Algorithm
		err  bool
	}{
		{"es256", mustKey(t, ES256), ES256, false},
		{"eddsa", mustKey(t, EdDSA), EdDSA, false},
		{"rsa", &rsa.PrivateKey{}, "", true},
		{"nil", nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AlgorithmFor(tc.key)
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("got %q err %v, want %q err %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestGenerateKeyUnknownAlg(t *testing.T) {
	if _, err := GenerateKey(RS256); err == nil {
		t.Fatal("expected error for RS256")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range SigningAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			key := mustKey(t, alg)
			tok, err := Sign(key, "k1", "JWT", map[string]any{"sub": "alice"})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if strings.Count(tok, ".") != 2 {
				t.Fatalf("not compact: %q", tok)
			}
			hdr, err := PeekHeader(tok)
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Alg != string(alg) || hdr.Kid != "k1" || hdr.Typ != "JWT" {
				t.Fatalf("header = %+v", hdr)
			}
			pub, err := PublicJWK(key, "k1")
			if err != nil {
				t.Fatal(err)
			}
			payload, vh, err := Verify(tok, pub.Key, []Algorithm{alg})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if vh.Kid != "k1" || !strings.Contains(string(payload), `"alice"`) {
				t.Fatalf("payload %s header %+v", payload, vh)
			}
			claims, err := PeekPayload(tok)
			if err != nil || claims["sub"] != "alice" {
				t.Fatalf("PeekPayload = %v, %v", claims, err)
			}
		})
	}
}

func TestSignNoKid(t *testing.T) {
	tok, err := Sign(mustKey(t, ES256), "", "statuslist+jwt", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := PeekHeader(tok)
	if hdr.Kid != "" || hdr.Typ != "statuslist+jwt" {
		t.Fatalf("header = %+v", hdr)
	}
}

func TestSignErrors(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := []struct {
		name   string
		key    any
		claims any
	}{
		{"unsupported key", &rsa.PrivateKey{}, map[string]any{}},
		{"bad claims", mustKey(t, ES256), map[string]any{"c": make(chan int)}},
		{"nil ecdsa key", (*ecdsa.PrivateKey)(nil), map[string]any{}},
		{"wrong curve", p384, map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.key, "", "JWT", tc.claims); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPeekErrors(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	cases := []struct{ name, tok string }{
		{"segments", "a.b"},
		{"header b64", "!!!.b.c"},
		{"header json", b64([]byte("x")) + ".b.c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PeekHeader(tc.tok); err == nil {
				t.Fatal("expected header error")
			}
		})
	}
	pcases := []struct{ name, tok string }{
		{"segments", "a"},
		{"payload b64", "a.!!!.c"},
		{"payload json", "a." + b64([]byte("x")) + ".c"},
	}
	for _, tc := range pcases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PeekPayload(tc.tok); err == nil {
				t.Fatal("expected payload error")
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	key := mustKey(t, ES256).(*ecdsa.PrivateKey)
	other := mustKey(t, ES256).(*ecdsa.PrivateKey)
	tok, _ := Sign(key, "k1", "JWT", map[string]any{"a": 1})

	if _, _, err := Verify(tok, &other.PublicKey, []Algorithm{ES256}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, _, err := Verify(tok, &key.PublicKey, []Algorithm{EdDSA}); err == nil {
		t.Fatal("alg not allowed must fail")
	}
	if _, _, err := Verify("bad", &key.PublicKey, []Algorithm{ES256}); err == nil {
		t.Fatal("malformed must fail")
	}
	parts := strings.Split(tok, ".")
	if _, _, err := Verify(parts[0]+"."+parts[1]+".!!", &key.PublicKey, []Algorithm{ES256}); err == nil {
		t.Fatal("bad signature encoding must fail")
	}
}

func TestVerifyWithJWKS(t *testing.T) {
	k1 := mustKey(t, ES256)
	k2 := mustKey(t, EdDSA)
	j1, _ := PublicJWK(k1, "k1")
	j2, _ := PublicJWK(k2, "k2")
	set := JWKS{Keys: []JWK{j1, j2}}
	algs := []Algorithm{ES256, EdDSA}

	withKid, _ := Sign(k2, "k2", "JWT", map[string]any{"x": 1})
	if _, hdr, err := VerifyWithJWKS(withKid, set, algs); err != nil || hdr.Kid != "k2" {
		t.Fatalf("kid match: %v %+v", err, hdr)
	}
	noKid, _ := Sign(k1, "", "JWT", map[string]any{"x": 1})
	if _, _, err := VerifyWithJWKS(noKid, set, algs); err != nil {
		t.Fatalf("no kid tries all keys: %v", err)
	}
	unknownKid, _ := Sign(k1, "zz", "JWT", map[string]any{"x": 1})
	if _, _, err := VerifyWithJWKS(unknownKid, set, algs); !errors.Is(err, ErrNoKey) {
		t.Fatalf("unknown kid: %v", err)
	}
	k3 := mustKey(t, ES256)
	foreign, _ := Sign(k3, "", "JWT", map[string]any{"x": 1})
	if _, _, err := VerifyWithJWKS(foreign, set, algs); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("foreign key: %v", err)
	}
	if _, _, err := VerifyWithJWKS("bad", set, algs); err == nil {
		t.Fatal("malformed must fail")
	}
}

func TestJWKParse(t *testing.T) {
	key := mustKey(t, ES256)
	pub, _ := PublicJWK(key, "kid-1")
	raw, _ := json.Marshal(pub)
	k, err := ParseJWK(raw)
	if err != nil || k.KeyID != "kid-1" {
		t.Fatalf("ParseJWK: %v %+v", err, k)
	}
	if _, err := ParseJWK([]byte("nope")); err == nil {
		t.Fatal("bad json must fail")
	}
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`)); err == nil {
		t.Fatal("invalid point must fail")
	}
	if _, err := ParseJWK([]byte(`{"kty":"RSA","n":"AQAB","e":"AA"}`)); err == nil {
		t.Fatal("zero exponent must fail")
	}

	setRaw := []byte(`{"keys":[` + string(raw) + `,{"kty":"oct"}]}`)
	set, err := ParseJWKS(setRaw)
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("ParseJWKS: %v %d", err, len(set.Keys))
	}
	if _, err := ParseJWKS([]byte("[")); err == nil {
		t.Fatal("bad json must fail")
	}
	if _, err := ParseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("empty set must fail")
	}
}

func TestPublicJWK(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed := mustKey(t, EdDSA).(ed25519.PrivateKey)
	cases := []struct {
		name string
		key  any
		alg  string
	}{
		{"ecdsa private", mustKey(t, ES256), "ES256"},
		{"ecdsa public", &mustKey(t, ES256).(*ecdsa.PrivateKey).PublicKey, "ES256"},
		{"ed private", ed, "EdDSA"},
		{"ed public", ed.Public(), "EdDSA"},
		{"rsa private", rsaKey, "RS256"},
		{"rsa public", &rsaKey.PublicKey, "RS256"},
		{"p384 no alg", &p384.PublicKey, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := PublicJWK(tc.key, "id")
			if err != nil {
				t.Fatal(err)
			}
			if !jwk.IsPublic() || jwk.Algorithm != tc.alg || jwk.Use != "sig" {
				t.Fatalf("jwk = %+v", jwk)
			}
		})
	}
	if _, err := PublicJWK("nope", ""); err == nil {
		t.Fatal("unsupported type must fail")
	}
}

func TestThumbprintAndMaps(t *testing.T) {
	jwk, _ := PublicJWK(mustKey(t, ES256), "")
	tp, err := Thumbprint(jwk)
	if err != nil || len(tp) != 43 {
		t.Fatalf("Thumbprint = %q, %v", tp, err)
	}
	if _, err := Thumbprint(JWK{Key: "nope"}); err == nil {
		t.Fatal("bad key must fail")
	}
	m, err := JWKToMap(jwk)
	if err != nil || m["kty"] != "EC" {
		t.Fatalf("JWKToMap = %v, %v", m, err)
	}
	if _, err := JWKToMap(JWK{Key: "nope"}); err == nil {
		t.Fatal("bad key must fail")
	}
	back, err := JWKFromMap(m)
	if err != nil {
		t.Fatal(err)
	}
	tp2, _ := Thumbprint(back)
	if tp2 != tp {
		t.Fatal("thumbprint changed across map round trip")
	}
	if _, err := JWKFromMap(map[string]any{"kty": make(chan int)}); err == nil {
		t.Fatal("unmarshalable map must fail")
	}
}

func FuzzParseJWK(f *testing.F) {
	jwk, _ := PublicJWK(mustKeyF(f), "k")
	raw, _ := json.Marshal(jwk)
	f.Add(raw)
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if k, err := ParseJWK(data); err == nil {
			_, _ = Thumbprint(k)
		}
		_, _ = ParseJWKS(data)
	})
}

func FuzzParseToken(f *testing.F) {
	key := mustKeyF(f)
	tok, _ := Sign(key, "k", "JWT", map[string]any{"a": "b"})
	f.Add(tok)
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = PeekHeader(tok)
		_, _ = PeekPayload(tok)
		pub, _ := PublicJWK(key, "k")
		_, _, _ = Verify(tok, pub.Key, SigningAlgorithms)
		_, _, _ = VerifyWithJWKS(tok, JWKS{Keys: []JWK{pub}}, SigningAlgorithms)
	})
}

func mustKeyF(f *testing.F) any {
	k, err := GenerateKey(ES256)
	if err != nil {
		f.Fatal(err)
	}
	return k
}
