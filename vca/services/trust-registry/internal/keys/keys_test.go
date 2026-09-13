// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestGenerateAndNew(t *testing.T) {
	es, err := Generate(jose.ES256, t0)
	if err != nil || es.Alg != jose.ES256 || es.ID == "" || es.CreatedAt != t0 || es.IsEd25519() {
		t.Fatalf("es256 %+v %v", es, err)
	}
	ed, err := Generate(jose.EdDSA, t0)
	if err != nil || ed.Alg != jose.EdDSA || !ed.IsEd25519() {
		t.Fatalf("eddsa %+v %v", ed, err)
	}
	if _, err := Generate(jose.RS256, t0); err == nil {
		t.Fatal("rs256 must fail")
	}
	named, err := New(es.Private, "k1", t0)
	if err != nil || named.ID != "k1" {
		t.Fatal("named kid")
	}
	pub := named.Public()
	if pub.KeyID != "k1" || !pub.IsPublic() {
		t.Fatal("public jwk")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := New(rsaKey, "", t0); err == nil {
		t.Fatal("rsa must fail")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := New(p384, "", t0); err == nil {
		t.Fatal("p384 must fail")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	a, _ := Generate(jose.ES256, t0)
	b, _ := Generate(jose.EdDSA, t0)
	data, err := EncodePEM([]Key{a, b})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePEM(data, t0)
	if err != nil || len(keys) != 2 || keys[0].ID != a.ID || keys[1].ID != b.ID {
		t.Fatalf("parse %v %d", err, len(keys))
	}
	if _, err := ParsePEM([]byte("no pem"), t0); err == nil {
		t.Fatal("empty")
	}
	if _, err := ParsePEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), t0); err == nil {
		t.Fatal("wrong block type")
	}
	if _, err := ParsePEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), t0); err == nil {
		t.Fatal("bad der")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	if _, err := ParsePEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), t0); err == nil {
		t.Fatal("rsa pem must fail")
	}
	if _, err := EncodePEM([]Key{{Private: "not a key"}}); err == nil {
		t.Fatal("encode bad key")
	}
}

func TestRing(t *testing.T) {
	if _, err := NewRing(); err == nil {
		t.Fatal("empty ring")
	}
	a, _ := Generate(jose.ES256, t0)
	if _, err := NewRing(a, a); err == nil {
		t.Fatal("duplicate kid")
	}
	old, _ := Generate(jose.EdDSA, t0.Add(-48*time.Hour))
	r, err := NewRing(a, old)
	if err != nil {
		t.Fatal(err)
	}
	if r.Active().ID != a.ID || len(r.Keys()) != 2 {
		t.Fatal("initial ring")
	}
	token, err := r.Sign("trust-list+jwt", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := jose.PeekHeader(token)
	if hdr.Kid != a.ID || hdr.Typ != "trust-list+jwt" {
		t.Fatalf("header %+v", hdr)
	}
	if _, _, err := jose.VerifyWithJWKS(token, r.JWKS(), jose.SigningAlgorithms); err != nil {
		t.Fatal(err)
	}
	set, err := jose.ParseJWKS(r.JWKSJSON())
	if err != nil || len(set.Keys) != 2 || !strings.Contains(string(r.JWKSJSON()), a.ID) {
		t.Fatal("jwks json")
	}
	if err := r.Rotate(a); err == nil {
		t.Fatal("rotate to active")
	}
	if err := r.Rotate(old); err == nil {
		t.Fatal("rotate to retired")
	}
	b, _ := Generate(jose.ES256, t0.Add(time.Hour))
	if err := r.Rotate(b); err != nil {
		t.Fatal(err)
	}
	if r.Active().ID != b.ID || r.Keys()[1].ID != a.ID || len(r.Keys()) != 3 {
		t.Fatal("after rotate")
	}
	if _, _, err := jose.VerifyWithJWKS(token, r.JWKS(), jose.SigningAlgorithms); err != nil {
		t.Fatal("old token still checks after rotation")
	}
	if n := r.Prune(t0.Add(-time.Hour)); n != 1 || len(r.Keys()) != 2 {
		t.Fatalf("prune %d", n)
	}
}
