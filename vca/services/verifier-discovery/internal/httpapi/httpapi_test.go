// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/httpapi"
)

// reader answers a fixed catalogue.
type reader struct {
	issuers []catalog.Issuer
	err     error
}

func (r reader) Catalogue(context.Context) ([]catalog.Issuer, error) { return r.issuers, r.err }

// sample is one issuer with two types.
var sample = []catalog.Issuer{{
	CredentialIssuer: "https://a.example", DID: "did:web:a", DisplayName: "Alpha",
	Trust: catalog.TrustTrusted, CrawledAt: time.Unix(1700000000, 0).UTC(),
	Types: []catalog.CredentialType{
		{Type: "PID", Format: "dc+sd-jwt", ConfigurationID: "pid", Fields: []catalog.Field{{Path: "given_name"}}},
		{Type: "Degree", Format: "ldp_vc"},
	},
}}

// server returns a test server over the API.
func server(t *testing.T, r reader, maxAge time.Duration) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	httpapi.New(httpapi.Options{Reader: r, MaxAge: maxAge}).Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// get performs one request and returns the response.
// answer holds the part of an HTTP response that the tests read.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func get(t *testing.T, url string, header http.Header) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

func TestCatalogue(t *testing.T) {
	s := server(t, reader{issuers: sample}, 5*time.Minute)
	resp := get(t, s.URL+"/catalog", nil)
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d", resp.status)
	}
	if resp.header.Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("cache control = %q", resp.header.Get("Cache-Control"))
	}
	if resp.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("a wallet reads the catalogue from another origin")
	}
	var body struct {
		Issuers []catalog.Issuer `json:"issuers"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Issuers) != 1 || len(body.Issuers[0].Types) != 2 {
		t.Errorf("body = %+v", body)
	}
	etag := resp.header.Get("ETag")
	if etag == "" {
		t.Fatal("the answer carries an entity tag")
	}
	again := get(t, s.URL+"/catalog", http.Header{"If-None-Match": []string{etag}})
	if again.status != http.StatusNotModified {
		t.Errorf("a matching entity tag wants 304, got %d", again.status)
	}
}

func TestIssuersAndTypes(t *testing.T) {
	s := server(t, reader{issuers: sample}, 0)
	resp := get(t, s.URL+"/catalog/issuers", nil)
	var issuers struct {
		Issuers []struct {
			CredentialIssuer string `json:"credential_issuer"`
			TypeCount        int    `json:"type_count"`
		} `json:"issuers"`
	}
	if err := json.Unmarshal(resp.body, &issuers); err != nil {
		t.Fatal(err)
	}
	if len(issuers.Issuers) != 1 || issuers.Issuers[0].TypeCount != 2 {
		t.Errorf("issuers = %+v", issuers)
	}
	if resp.header.Get("Cache-Control") != "" {
		t.Error("a zero max age writes no cache header")
	}
	all := get(t, s.URL+"/catalog/types", nil)
	var types struct {
		Types []struct {
			Type   string `json:"type"`
			Format string `json:"format"`
		} `json:"types"`
	}
	if err := json.Unmarshal(all.body, &types); err != nil {
		t.Fatal(err)
	}
	if len(types.Types) != 2 {
		t.Errorf("types = %+v", types)
	}
	filtered := get(t, s.URL+"/catalog/types?format=ldp_vc&type=Degree", nil)
	types.Types = nil
	if err := json.Unmarshal(filtered.body, &types); err != nil {
		t.Fatal(err)
	}
	if len(types.Types) != 1 || types.Types[0].Type != "Degree" {
		t.Errorf("filtered = %+v", types)
	}
	none := get(t, s.URL+"/catalog/types?format=mso_mdoc", nil)
	types.Types = nil
	if err := json.Unmarshal(none.body, &types); err != nil {
		t.Fatal(err)
	}
	if len(types.Types) != 0 {
		t.Errorf("a filter that matches nothing gives an empty list, got %+v", types)
	}
}

func TestCatalogueErrors(t *testing.T) {
	s := server(t, reader{err: errors.New("the store is down")}, 0)
	for _, path := range []string{"/catalog", "/catalog/issuers", "/catalog/types"} {
		resp := get(t, s.URL+path, nil)
		if resp.status != http.StatusInternalServerError {
			t.Errorf("%s status = %d", path, resp.status)
		}
	}
}
