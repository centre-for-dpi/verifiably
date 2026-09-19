// SPDX-License-Identifier: Apache-2.0

package ports

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)

func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mustWrite(t, w, []byte("hello"))
	}))
	defer srv.Close()
	fetch := HTTPFetcher(srv.Client(), 16)
	body, err := fetch(context.Background(), srv.URL+"/ok")
	if err != nil || string(body) != "hello" {
		t.Fatalf("want the body, got %q %v", body, err)
	}
	if _, err := fetch(context.Background(), srv.URL+"/missing"); err == nil {
		t.Fatal("want an error for status 404")
	}
	if _, err := fetch(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("want an error for a non http URL")
	}
	if _, err := fetch(context.Background(), "http://127.0.0.1:1/x"); err == nil {
		t.Fatal("want an error for a closed port")
	}
	small := HTTPFetcher(nil, 2)
	if _, err := small(context.Background(), srv.URL+"/ok"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want a size error, got %v", err)
	}
	if _, err := fetch(context.Background(), "http://[::1]:x/"); err == nil {
		t.Fatal("want an error for a broken URL")
	}
}

func TestCacheWrap(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	c := NewCache(time.Minute, 2, clock)
	calls := 0
	fetch := c.Wrap(func(context.Context, string) ([]byte, error) {
		calls++
		return []byte("doc"), nil
	})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := fetch(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("want one fetch, got %d", calls)
	}
	now = now.Add(2 * time.Minute)
	if _, err := fetch(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("want a second fetch after the ttl, got %d", calls)
	}
	for _, url := range []string{"b", "c", "d"} {
		if _, err := fetch(ctx, url); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) != 2 {
		t.Fatalf("want two entries, got %d", len(c.entries))
	}
	bad := NewCache(time.Minute, 1, nil).Wrap(func(context.Context, string) ([]byte, error) {
		return nil, errors.New("offline")
	})
	if _, err := bad(ctx, "a"); err == nil {
		t.Fatal("want the fetch error")
	}
}

func TestDIDCache(t *testing.T) {
	now := time.Now()
	c := NewDIDCache(time.Minute, func() time.Time { return now })
	if _, ok := c.Get("did:web:a"); ok {
		t.Fatal("want an empty cache")
	}
	c.Put("did:web:a", did.Document{ID: "did:web:a"})
	if _, ok := c.Get("did:web:a"); !ok {
		t.Fatal("want the cached document")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("did:web:a"); ok {
		t.Fatal("want the entry to expire")
	}
	if NewDIDCache(time.Minute, nil) == nil {
		t.Fatal("want a cache with the wall clock")
	}
}

func TestKeysFromDID(t *testing.T) {
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := did.FromJWK(m)
	if err != nil {
		t.Fatal(err)
	}
	resolver := did.NewResolver(nil, nil)
	set, err := Keys(resolver, nil)(context.Background(), id, "")
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("want one key, got %d %v", len(set.Keys), err)
	}
	if _, err := Keys(resolver, nil)(context.Background(), "did:unknown:x", ""); err == nil {
		t.Fatal("want an error for an unknown method")
	}
	if _, err := Keys(resolver, nil)(context.Background(), "urn:issuer", ""); err == nil {
		t.Fatal("want an error for an issuer that is not a DID or a URL")
	}
}

func TestKeysFromJWKS(t *testing.T) {
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != JWKSPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, verr := json.Marshal(jose.JWKS{Keys: []jose.JWK{pub}})
		if verr != nil {
			t.Fatalf("unexpected error: %v", verr)
		}
		mustWrite(t, w, raw)
	}))
	defer srv.Close()
	fetch := HTTPFetcher(srv.Client(), 1<<20)
	set, err := Keys(did.NewResolver(nil, nil), fetch)(context.Background(), srv.URL+"/", "")
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("want one key, got %d %v", len(set.Keys), err)
	}
	broken := Keys(did.NewResolver(nil, nil), func(context.Context, string) ([]byte, error) {
		return nil, errors.New("offline")
	})
	if _, err := broken(context.Background(), "https://issuer.example", ""); err == nil {
		t.Fatal("want the fetch error")
	}
}

func TestKeysOfDocument(t *testing.T) {
	if _, err := keysOf(did.Document{ID: "did:web:a"}); err == nil {
		t.Fatal("want an error for a document without keys")
	}
	doc := did.Document{ID: "did:web:a", VerificationMethod: []did.VerificationMethod{{ID: "#1", Type: "JsonWebKey"}}}
	if _, err := keysOf(doc); err == nil {
		t.Fatal("want an error when no method holds a key")
	}
}

// fakeTrust answers TrustLookup with a fixed response.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	resp *trustv1.TrustLookupResponse
	err  error
}

func (f fakeTrust) TrustLookup(context.Context, *connect.Request[trustv1.TrustLookupRequest]) (
	*connect.Response[trustv1.TrustLookupResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.resp), nil
}

func TestTrustLookup(t *testing.T) {
	ctx := context.Background()
	trusted := Trust(fakeTrust{resp: &trustv1.TrustLookupResponse{
		Outcome:    trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
		Entry:      &trustv1.TrustEntry{DisplayName: "Ministry"},
		Provenance: &trustv1.TrustLookupResponse_Provenance{ListUrl: "https://trust.example/list"},
	}})
	got, err := trusted(ctx, "did:web:a", "Passport")
	if err != nil || !got.Trusted || got.DisplayName != "Ministry" {
		t.Fatalf("want a trusted issuer, got %+v %v", got, err)
	}

	unknown := Trust(fakeTrust{resp: &trustv1.TrustLookupResponse{
		Outcome: trustv1.TrustLookupResponse_OUTCOME_UNKNOWN,
	}})
	got, err = unknown(ctx, "did:web:a", "")
	if err != nil || got.Trusted || got.Reason == "" {
		t.Fatalf("want an untrusted issuer with a reason, got %+v %v", got, err)
	}

	unavailable := Trust(fakeTrust{resp: &trustv1.TrustLookupResponse{
		Outcome: trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE,
	}})
	if _, err := unavailable(ctx, "did:web:a", ""); err == nil {
		t.Fatal("want an error when the lists are not available")
	}

	broken := Trust(fakeTrust{err: errors.New("offline")})
	if _, err := broken(ctx, "did:web:a", ""); err == nil {
		t.Fatal("want the client error")
	}

	if _, err := Trust(nil)(ctx, "did:web:a", ""); err == nil {
		t.Fatal("want an error without a client")
	}
}

func TestPolicyFetcherType(t *testing.T) {
	var f = HTTPFetcher(nil, 1)
	if f == nil {
		t.Fatal("want a fetcher")
	}
}
