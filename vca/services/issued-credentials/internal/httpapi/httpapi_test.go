// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/httpapi"
)

// fakeHeads returns a fixed head or a fixed error.
type fakeHeads struct {
	head *issuedv1.ChainHead
	err  error
}

func (f fakeHeads) SignedHead() (*issuedv1.ChainHead, error) { return f.head, f.err }

// fakeKeys returns a fixed key set.
type fakeKeys struct{ set jose.JWKS }

func (f fakeKeys) JWKS() jose.JWKS { return f.set }

func get(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func keySet(t *testing.T) jose.JWKS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	jwk, err := jose.PublicJWK(key.Public(), "k1")
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}
	return jose.JWKS{Keys: []jose.JWK{jwk}}
}

func TestChainHead(t *testing.T) {
	mux := http.NewServeMux()
	head := &issuedv1.ChainHead{RecordId: "a", RecordHash: "hash", Length: 2, Jws: "aa.bb.cc", KeyId: "k1"}
	httpapi.Register(mux, fakeHeads{head: head}, nil)
	rec := get(t, mux, httpapi.ChainHeadPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Body.String() != "aa.bb.cc" {
		t.Errorf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != httpapi.MediaTypeJOSE {
		t.Errorf("content type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("ETag") != `"hash"` {
		t.Errorf("etag = %q", rec.Header().Get("ETag"))
	}
	// The JWKS endpoint is off without a key source.
	if got := get(t, mux, httpapi.JWKSPath); got.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", got.Code)
	}
}

func TestChainHeadErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"empty log", connect.NewError(connect.CodeNotFound, errors.New("the log is empty")), http.StatusNotFound},
		{"no key", connect.NewError(connect.CodeFailedPrecondition, errors.New("no key")), http.StatusServiceUnavailable},
		{"other", errors.New("broken"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		mux := http.NewServeMux()
		httpapi.Register(mux, fakeHeads{err: c.err}, nil)
		if got := get(t, mux, httpapi.ChainHeadPath); got.Code != c.want {
			t.Errorf("%s: code = %d, want %d", c.name, got.Code, c.want)
		}
	}
}

func TestJWKS(t *testing.T) {
	mux := http.NewServeMux()
	set := keySet(t)
	httpapi.Register(mux, fakeHeads{head: &issuedv1.ChainHead{}}, fakeKeys{set: set})
	rec := get(t, mux, httpapi.JWKSPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Errorf("content type = %q", rec.Header().Get("Content-Type"))
	}
	if _, err := jose.ParseJWKS(rec.Body.Bytes()); err != nil {
		t.Errorf("the body must be a key set: %v", err)
	}
}

func TestJWKSReportsAnEncodeFailure(t *testing.T) {
	mux := http.NewServeMux()
	broken := jose.JWKS{Keys: []jose.JWK{{Key: make(chan int)}}}
	httpapi.Register(mux, fakeHeads{head: &issuedv1.ChainHead{}}, fakeKeys{set: broken})
	if got := get(t, mux, httpapi.JWKSPath); got.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", got.Code)
	}
}
