// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func pemOf(t *testing.T, keys ...any) []byte {
	t.Helper()
	var out []byte
	for _, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	}
	return out
}

func TestNewAndGenerate(t *testing.T) {
	for _, alg := range []jose.Algorithm{jose.ES256, jose.EdDSA} {
		k, err := Generate(alg, t0)
		if err != nil {
			t.Fatal(err)
		}
		if k.Alg != alg || k.ID == "" || !k.CreatedAt.Equal(t0) {
			t.Fatalf("key = %+v", k)
		}
		if !strings.HasPrefix(k.DIDJWK(), "did:jwk:") {
			t.Fatalf("did = %s", k.DIDJWK())
		}
		doc, err := did.JWKDocument(k.DIDJWK())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := doc.Key(k.DIDJWK() + "#0"); !ok {
			t.Fatal("did:jwk document has no key #0")
		}
		if k.Public("x").KeyID != "x" {
			t.Fatal("kid not set")
		}
	}
	if _, err := Generate("HS256", t0); err == nil {
		t.Fatal("expected error for HS256")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	if _, err := New(rsaKey, t0); err == nil {
		t.Fatal("expected error for RSA")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, err := New(p384, t0); err == nil || !strings.Contains(err.Error(), "curve") {
		t.Fatalf("expected curve error, got %v", err)
	}
}

func TestParsePEM(t *testing.T) {
	a, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	b, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	keys, err := ParsePEM(pemOf(t, a, b), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Alg != jose.ES256 || keys[1].Alg != jose.EdDSA {
		t.Fatalf("keys = %+v", keys)
	}
	bad := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"wrong block", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})},
		{"bad der", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		{"rsa", func() []byte {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("rsa.GenerateKey: %v", err)
			}
			return pemOf(t, k)
		}()},
	}
	for _, tc := range bad {
		if _, err := ParsePEM(tc.data, t0); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestSlug(t *testing.T) {
	if Slug("") != DefaultSlug {
		t.Fatal("empty slug")
	}
	if Slug("did:web:a") == Slug("did:web:b") || len(Slug("did:web:a")) != 16 {
		t.Fatal("slug collision or length")
	}
}

func TestOpenGeneratesAndReloads(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	is, err := Open(ctx, kv, Options{Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	if !is.Generated {
		t.Fatal("expected a generated key")
	}
	def := is.Default()
	if def.Slug != DefaultSlug || def.Active().Alg != jose.ES256 {
		t.Fatalf("default = %+v", def)
	}
	if !strings.HasPrefix(def.DID(), "did:jwk:") || def.Kid(def.Active()) != def.DID()+"#0" {
		t.Fatalf("did = %s kid = %s", def.DID(), def.Kid(def.Active()))
	}
	again, err := Open(ctx, kv, Options{Now: func() time.Time { return t0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if again.Generated || again.Default().Active().ID != def.Active().ID {
		t.Fatal("reload did not keep the key")
	}
	if !again.Default().Active().CreatedAt.Equal(t0) {
		t.Fatal("reload lost the creation time")
	}
	if _, ok := again.BySlug(DefaultSlug); !ok {
		t.Fatal("BySlug")
	}
	if _, ok := again.BySlug("nope"); ok {
		t.Fatal("BySlug nope")
	}
}

func TestOpenConfiguredAndImport(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	a, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	b, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatalf("jose.GenerateKey: %v", err)
	}
	opts := Options{Configured: []string{"did:web:one", "did:web:two"}, ImportPEM: pemOf(t, a, b), Alg: jose.EdDSA}
	is, err := Open(ctx, kv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if is.Generated {
		t.Fatal("import must not count as generated")
	}
	one := is.Default()
	if one.DID() != "did:web:one" || len(one.Keys) != 2 || one.Active().Alg != jose.EdDSA {
		t.Fatalf("one = %+v", one)
	}
	if one.Kid(one.Active()) != one.Active().ID {
		t.Fatal("configured issuer must use the thumbprint kid")
	}
	if !one.Matches("did:web:one") || one.Matches("did:web:two") {
		t.Fatal("Matches")
	}
	two, err := is.Resolve("did:web:two")
	if err != nil || two.DID() != "did:web:two" || len(two.Keys) != 1 || two.Active().Alg != jose.EdDSA {
		t.Fatalf("two = %+v %v", two, err)
	}
	if _, err := is.Resolve("did:web:three"); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("err = %v", err)
	}
	if got := is.All(); len(got) != 2 || got[0].Slug != one.Slug || got[1].Slug != two.Slug {
		t.Fatal("All order")
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(is.JWKSJSON(), &set); err != nil || len(set.Keys) != 3 {
		t.Fatalf("jwks = %s %v", is.JWKSJSON(), err)
	}
	// A second Open with another configured DID for the same slug fails.
	if _, err := Open(ctx, kv, Options{Configured: []string{"did:web:one", "did:web:one"}}); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if _, err := Open(ctx, kv, Options{ImportPEM: []byte("junk")}); err == nil {
		t.Fatal("expected import error")
	}
	if err := kv.Put(ctx, Prefix+DefaultSlug, []byte("{")); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, kv, Options{}); err == nil {
		t.Fatal("expected parse error")
	}
	if err := kv.Put(ctx, Prefix+DefaultSlug, []byte(`{"keys":[]}`)); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, kv, Options{}); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("err = %v", err)
	}
	if err := kv.Put(ctx, Prefix+DefaultSlug, []byte(`{"keys":[{"pkcs8":"AQ==","created_at":"2026-01-01T00:00:00Z"}]}`)); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, kv, Options{}); err == nil {
		t.Fatal("expected PKCS #8 error")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	doc, err := json.Marshal(document{Keys: []keyDocument{{PKCS8: der, CreatedAt: t0}}})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := kv.Put(ctx, Prefix+DefaultSlug, doc); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, kv, Options{}); err == nil {
		t.Fatal("expected key type error")
	}
	if err := kv.Delete(ctx, Prefix+DefaultSlug); err != nil {
		t.Fatalf("kv.Delete: %v", err)
	}
	if _, err := Open(ctx, kv, Options{}); err != nil {
		t.Fatal(err)
	}
	// The ring on disk belongs to a different issuer.
	if _, err := Open(ctx, kv, Options{Configured: []string{"did:web:x"}}); err != nil {
		t.Fatal(err)
	}
	if err := kv.Put(ctx, Prefix+Slug("did:web:x"), []byte(`{"configured_did":"did:web:y","keys":[]}`)); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, kv, Options{Configured: []string{"did:web:x"}}); err == nil {
		t.Fatal("expected ring mismatch")
	}
	if _, err := Open(ctx, failing{store.Memory()}, Options{}); err == nil {
		t.Fatal("expected store error")
	}
	if _, err := Open(ctx, kv, Options{Alg: "HS256", Configured: []string{"did:web:new"}}); err == nil {
		t.Fatal("expected alg error")
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	is, err := Open(ctx, kv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	oldDID := is.Default().DID()
	next, retired, err := is.Rotate(ctx, "", jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if retired.DIDJWK() != oldDID || next.Active().Alg != jose.EdDSA || len(next.Keys) != 2 {
		t.Fatalf("next = %+v retired = %+v", next, retired)
	}
	if !next.Matches(oldDID) || !next.Matches(next.DID()) || next.DID() == oldDID {
		t.Fatal("a did:jwk issuer must match old and new DIDs")
	}
	if len(next.JWKS().Keys) != 2 {
		t.Fatal("JWKS must keep the retired key")
	}
	// Keeping the algorithm.
	next2, _, err := is.Rotate(ctx, "", "")
	if err != nil || next2.Active().Alg != jose.EdDSA {
		t.Fatalf("rotate keep alg: %+v %v", next2, err)
	}
	reload, err := Open(ctx, kv, Options{})
	if err != nil || len(reload.Default().Keys) != 3 {
		t.Fatalf("reload: %v", err)
	}
	if _, _, err := is.Rotate(ctx, "did:web:none", ""); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := is.Rotate(ctx, "", "HS256"); err == nil {
		t.Fatal("expected alg error")
	}
	broken := &Issuers{kv: failing{kv}, now: time.Now, order: is.order, issuers: is.issuers}
	if _, _, err := broken.Rotate(ctx, "", ""); err == nil {
		t.Fatal("expected save error")
	}
}

// failing is a store whose writes fail.
type failing struct{ store.KeyValue }

func (failing) Put(context.Context, string, []byte) error { return errors.New("disk full") }
