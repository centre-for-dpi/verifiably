// SPDX-License-Identifier: Apache-2.0

package did

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Regression: legacy TestDIDWebToURL_* cases plus the port and error cases.
func TestWebURL(t *testing.T) {
	cases := []struct {
		did, want string
		err       bool
	}{
		{"did:web:example.com", "https://example.com/.well-known/did.json", false},
		{"did:web:example.com:path:to", "https://example.com/path/to/did.json", false},
		{"did:web:example.com:users", "https://example.com/users/did.json", false},
		{"did:web:example.com%3A8443:a", "https://example.com:8443/a/did.json", false},
		{"did:web:example.com#key-1", "https://example.com/.well-known/did.json", false},
		{"did:key:abc", "", true},
		{"did:web:", "", true},
		{"did:web:%zz", "", true},
		{"did:web:example.com::x", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.did, func(t *testing.T) {
			got, err := WebURL(tc.did)
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("WebURL = %q, %v", got, err)
			}
		})
	}
}

func TestMethod(t *testing.T) {
	if m, err := Method("did:web:x"); err != nil || m != "web" {
		t.Fatalf("Method = %q, %v", m, err)
	}
	for _, bad := range []string{"", "did:", "did:web", "did::x", "http://x", "did:web:"} {
		if _, err := Method(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

const sampleDoc = `{
  "id": "did:web:example.com",
  "verificationMethod": [{
    "id": "did:web:example.com#key-1",
    "type": "JsonWebKey2020",
    "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
  }],
  "assertionMethod": ["did:web:example.com#key-1"]
}`

type memCache struct{ m map[string]Document }

func (c *memCache) Get(d string) (Document, bool) { doc, ok := c.m[d]; return doc, ok }
func (c *memCache) Put(d string, doc Document)    { c.m[d] = doc }

func fetcher(body string, err error, calls *int) Fetcher {
	return func(_ context.Context, _ string) ([]byte, error) {
		*calls++
		return []byte(body), err
	}
}

// Regression: legacy TestResolve_* cases with an injected fetcher.
func TestResolveWeb(t *testing.T) {
	ctx := context.Background()
	calls := 0
	r := NewResolver(fetcher(sampleDoc, nil, &calls), nil)
	doc, docErr := r.Resolve(ctx, "did:web:example.com")
	if docErr != nil {
		t.Fatalf("Resolve: %v", docErr)
	}
	if doc.ID != "did:web:example.com" || len(doc.VerificationMethod) != 1 || doc.VerificationMethod[0].PublicKeyJWK["kty"] != "EC" {
		t.Fatalf("doc = %+v", doc)
	}
	_, errAssign := r.Resolve(ctx, "did:web:example.com")
	if errAssign != nil {
		t.Fatalf("r.Resolve: %v", errAssign)
	}
	if calls != 2 {
		t.Fatalf("no cache: expected 2 fetches, got %d", calls)
	}

	calls = 0
	cached := NewResolver(fetcher(sampleDoc, nil, &calls), &memCache{m: map[string]Document{}})
	_, errAssign2 := cached.Resolve(ctx, "did:web:a.example.com")
	if errAssign2 != nil {
		t.Fatalf("cached.Resolve: %v", errAssign2)
	}
	_, errAssign3 := cached.Resolve(ctx, "did:web:a.example.com")
	if errAssign3 != nil {
		t.Fatalf("cached.Resolve: %v", errAssign3)
	}
	_, errAssign4 := cached.Resolve(ctx, "did:web:b.example.com")
	if errAssign4 != nil {
		t.Fatalf("cached.Resolve: %v", errAssign4)
	}
	if calls != 2 {
		t.Fatalf("cache: expected 2 fetches, got %d", calls)
	}

	failing := []struct {
		name string
		r    Resolver
		did  string
	}{
		{"network error", NewResolver(fetcher("", errors.New("refused"), &calls), nil), "did:web:example.com"},
		{"invalid json", NewResolver(fetcher("not json", nil, &calls), nil), "did:web:example.com"},
		{"no id", NewResolver(fetcher(`{}`, nil, &calls), nil), "did:web:example.com"},
		{"no fetcher", NewResolver(nil, nil), "did:web:example.com"},
		{"bad did:web", NewResolver(fetcher(sampleDoc, nil, &calls), nil), "did:web:example.com::x"},
		{"unsupported method", r, "did:ion:abc"},
		{"not a did", r, "example.com"},
	}
	for _, tc := range failing {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.r.Resolve(ctx, tc.did); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := r.Resolve(ctx, "did:ion:abc"); !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("want ErrUnsupportedMethod, got %v", err)
	}
	empty, err := NewResolver(fetcher(`{"id":"did:web:empty.com"}`, nil, &calls), nil).Resolve(ctx, "did:web:empty.com")
	if err != nil || len(empty.VerificationMethod) != 0 {
		t.Fatalf("empty doc = %+v, %v", empty, err)
	}
}

func TestDocumentKey(t *testing.T) {
	doc, err := ParseDocument([]byte(sampleDoc))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	for _, id := range []string{"", "did:web:example.com#key-1", "#key-1", "key-1"} {
		if vm, ok := doc.Key(id); !ok || vm.ID != "did:web:example.com#key-1" {
			t.Fatalf("Key(%q) = %+v, %v", id, vm, ok)
		}
	}
	if _, ok := doc.Key("#nope"); ok {
		t.Fatal("unknown fragment must not match")
	}
	if _, ok := (Document{}).Key(""); ok {
		t.Fatal("empty document has no key")
	}
	rel := Document{ID: "did:web:x", VerificationMethod: []VerificationMethod{{ID: "#k"}}}
	if _, ok := rel.Key("k"); !ok {
		t.Fatal("relative id must match")
	}
}

func TestPublicKey(t *testing.T) {
	edPub, _, edPubErr := ed25519.GenerateKey(rand.Reader)
	if edPubErr != nil {
		t.Fatalf("ed25519.GenerateKey: %v", edPubErr)
	}
	jwk, jwkErr := jose.PublicJWK(edPub, "")
	if jwkErr != nil {
		t.Fatalf("jose.PublicJWK: %v", jwkErr)
	}
	m, mErr := jose.JWKToMap(jwk)
	if mErr != nil {
		t.Fatalf("jose.JWKToMap: %v", mErr)
	}
	if k, err := PublicKey(VerificationMethod{PublicKeyJWK: m}); err != nil || !bytes.Equal(anyval.As[ed25519.PublicKey](k), edPub) {
		t.Fatalf("jwk: %v", err)
	}
	if _, err := PublicKey(VerificationMethod{PublicKeyJWK: map[string]any{"kty": "EC"}}); err == nil {
		t.Fatal("bad jwk must fail")
	}
	didKey, err := FromPublicKey(edPub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	mb := strings.TrimPrefix(didKey, "did:key:")
	if k, err := PublicKey(VerificationMethod{PublicKeyMultibase: mb}); err != nil || !bytes.Equal(anyval.As[ed25519.PublicKey](k), edPub) {
		t.Fatalf("multibase: %v", err)
	}
	if _, err := PublicKey(VerificationMethod{ID: "x"}); err == nil {
		t.Fatal("no key must fail")
	}
}

// Regression: legacy ldproof_test pinned did:key:z6Mk for Ed25519.
func TestDIDKeyRoundTrip(t *testing.T) {
	edPub, _, edPubErr := ed25519.GenerateKey(rand.Reader)
	if edPubErr != nil {
		t.Fatalf("ed25519.GenerateKey: %v", edPubErr)
	}
	ec, ecErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ecErr != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", ecErr)
	}
	edDID, err := FromPublicKey(edPub)
	if err != nil || !strings.HasPrefix(edDID, "did:key:z6Mk") {
		t.Fatalf("ed25519 did:key = %q, %v", edDID, err)
	}
	ecDID, err := FromPublicKey(&ec.PublicKey)
	if err != nil || !strings.HasPrefix(ecDID, "did:key:zDn") {
		t.Fatalf("p256 did:key = %q, %v", ecDID, err)
	}
	for _, d := range []string{edDID, ecDID, ecDID + "#frag"} {
		doc, docErr := KeyDocument(d)
		if docErr != nil {
			t.Fatalf("KeyDocument(%s): %v", d, docErr)
		}
		if doc.ID != strings.SplitN(d, "#", 2)[0] || len(doc.VerificationMethod) != 1 || doc.AssertionMethod[0] != doc.VerificationMethod[0].ID {
			t.Fatalf("doc = %+v", doc)
		}
		vm, _ := doc.Key("")
		if _, keyErr := PublicKey(vm); keyErr != nil {
			t.Fatal(keyErr)
		}
	}
	vm, _ := must(KeyDocument(ecDID)).Key("")
	k, err := PublicKey(vm)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !anyval.As[*ecdsa.PublicKey](k).Equal(&ec.PublicKey) {
		t.Fatal("P-256 key did not round trip")
	}
	// Resolver dispatch.
	if _, gotErr := NewResolver(nil, nil).Resolve(context.Background(), edDID); gotErr != nil {
		t.Fatal(gotErr)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, err := FromPublicKey(&p384.PublicKey); err == nil {
		t.Fatal("P-384 must fail")
	}
	if _, err := FromPublicKey("nope"); err == nil {
		t.Fatal("string must fail")
	}
	badPoint := "did:key:z" + base58Encode(append([]byte{0x80, 0x24, 0x02}, bytes.Repeat([]byte{0xff}, 32)...))
	bad := []string{"did:web:x", "did:key:abc", "did:key:z0", "did:key:z" + base58Encode([]byte{1, 2, 3}), badPoint}
	for _, d := range bad {
		if _, err := KeyDocument(d); err == nil {
			t.Fatalf("%q must fail", d)
		}
	}
}

func must(doc Document, err error) Document {
	if err != nil {
		panic(err)
	}
	return doc
}

// Regression: legacy TestNewSelfSignedKeyDIDJWKRoundTrip.
func TestDIDJWKRoundTrip(t *testing.T) {
	ec, ecErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ecErr != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", ecErr)
	}
	jwk, jwkErr := jose.PublicJWK(&ec.PublicKey, "")
	if jwkErr != nil {
		t.Fatalf("jose.PublicJWK: %v", jwkErr)
	}
	m, mErr := jose.JWKToMap(jwk)
	if mErr != nil {
		t.Fatalf("jose.JWKToMap: %v", mErr)
	}
	d, err := FromJWK(m)
	if err != nil || !strings.HasPrefix(d, "did:jwk:") {
		t.Fatalf("FromJWK = %q, %v", d, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(d, "did:jwk:"))
	if err != nil || strings.Contains(string(raw), `"d"`) {
		t.Fatalf("payload = %s, %v", raw, err)
	}
	doc, err := JWKDocument(d + "#0")
	if err != nil || doc.ID != d || doc.VerificationMethod[0].ID != d+"#0" {
		t.Fatalf("JWKDocument = %+v, %v", doc, err)
	}
	k, err := PublicKey(doc.VerificationMethod[0])
	if err != nil || !anyval.As[*ecdsa.PublicKey](k).Equal(&ec.PublicKey) {
		t.Fatalf("key mismatch: %v", err)
	}
	// Padded base64url is accepted.
	padded := "did:jwk:" + base64.URLEncoding.EncodeToString(raw)
	if _, gotErr := JWKDocument(padded); gotErr != nil {
		t.Fatalf("padded: %v", gotErr)
	}
	if _, gotErr := NewResolver(nil, nil).Resolve(context.Background(), d); gotErr != nil {
		t.Fatal(gotErr)
	}

	priv := map[string]any{"kty": "EC", "crv": "P-256", "x": m["x"], "y": m["y"], "d": "AA"}
	if _, gotErr := FromJWK(priv); gotErr == nil {
		t.Fatal("private jwk must fail")
	}
	if _, gotErr := FromJWK(map[string]any{"kty": "EC"}); gotErr == nil {
		t.Fatal("invalid jwk must fail")
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	privRaw := `{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(edPub) + `","d":"` + base64.RawURLEncoding.EncodeToString(edPriv.Seed()) + `"}`
	bad := []string{
		"did:web:x",
		"did:jwk:!!!",
		"did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte("{")),
		"did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte(privRaw)),
	}
	for _, d := range bad {
		if _, err := JWKDocument(d); err == nil {
			t.Fatalf("%q must fail", d)
		}
	}
}

// Regression: legacy TestBase58RoundTrip.
func TestBase58(t *testing.T) {
	cases := [][]byte{
		{}, {0}, {0, 0, 1, 2, 3}, {255, 254, 253}, []byte("hello world"), make([]byte, 32),
	}
	for i, in := range cases {
		enc := base58Encode(in)
		dec, err := base58Decode(enc)
		if err != nil {
			t.Fatalf("case %d decode %q: %v", i, enc, err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("case %d round trip: got %v want %v (enc %q)", i, dec, in, enc)
		}
	}
	if got := base58Encode([]byte("hello world")); got != "StV1DL6CwTryKyV" {
		t.Fatalf("known vector: %q", got)
	}
	if _, err := base58Decode("0OIl"); err == nil {
		t.Fatal("non-base58 characters must fail")
	}
}

func FuzzParseDocument(f *testing.F) {
	f.Add([]byte(sampleDoc))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := ParseDocument(data)
		if err != nil {
			return
		}
		for _, vm := range doc.VerificationMethod {
			if _, err := PublicKey(vm); err != nil && err.Error() == "" {
				t.Fatalf("PublicKey must describe the failure")
			}
		}
	})
}

func FuzzParseDID(f *testing.F) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("ed25519.GenerateKey: %v", err)
	}
	d, err := FromPublicKey(edPub)
	if err != nil {
		f.Fatalf("FromPublicKey: %v", err)
	}
	f.Add(d)
	f.Add("did:jwk:eyJrdHkiOiJPS1AifQ")
	f.Add("did:web:example.com%3A8443:a:b")
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := KeyDocument(s); err != nil && err.Error() == "" {
			t.Fatalf("KeyDocument must describe the failure")
		}
		if _, err := JWKDocument(s); err != nil && err.Error() == "" {
			t.Fatalf("JWKDocument must describe the failure")
		}
		if _, err := WebURL(s); err != nil && err.Error() == "" {
			t.Fatalf("WebURL must describe the failure")
		}
		if b, err := base58Decode(strings.TrimPrefix(s, "z")); err == nil && len(s) > 1 {
			if base58Encode(b) != strings.TrimPrefix(s, "z") {
				t.Fatalf("base58 round trip mismatch for %q", s)
			}
		}
	})
}
