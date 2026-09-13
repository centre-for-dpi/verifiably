// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

const doc = `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

// fake is a Source with a fixed set of versions.
type fake struct{ list []record.Record }

func (f fake) Published() []record.Record {
	var out []record.Record
	for _, r := range f.list {
		if r.State == record.StatePublished {
			out = append(out, r)
		}
	}
	return out
}

func (f fake) Get(id string, version int) (record.Record, bool) {
	for _, r := range f.list {
		if r.ID == id && r.Version == version {
			return r, true
		}
	}
	return record.Record{}, false
}

func source() fake {
	return fake{list: []record.Record{
		{
			ID: "degree", Version: 1, Type: "UniversityDegree", JSONSchema: doc, State: record.StateDraft,
			Formats: []string{record.FormatDcSdJwt},
		},
		{
			ID: "degree", Version: 2, Type: "UniversityDegree", JSONSchema: doc, State: record.StatePublished,
			Formats: []string{record.FormatDcSdJwt}, PublishedAt: now,
			Display: []record.Display{{Name: "Degree", Locale: "en"}},
		},
	}}
}

func handler() *Handler {
	opts := metadata.Options{BaseURL: "https://registry.example", Now: now}
	return New(source(), func() metadata.Options { return opts }, time.Minute)
}

// get runs one request through a mux with the handler registered.
func get(t *testing.T, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	handler().Register(mux)
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestSchemas(t *testing.T) {
	rec := get(t, http.MethodGet, metadata.SchemasPath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("cache control %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("ETag") == "" || rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatal("etag or vary missing")
	}
	body := decode(t, rec)
	list, ok := body["schemas"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("schemas %v", body["schemas"])
	}
	first := list[0].(map[string]any)
	if first["id"] != "degree" || first["version"] != float64(2) {
		t.Fatalf("entry %v", first)
	}
}

func TestIssuerMetadata(t *testing.T) {
	rec := get(t, http.MethodGet, metadata.IssuerMetadataPath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := decode(t, rec)
	configs, ok := body["credential_configurations_supported"].(map[string]any)
	if !ok || len(configs) != 1 {
		t.Fatalf("configurations %v", body)
	}
	if body["credential_issuer"] != "https://registry.example" {
		t.Fatalf("issuer %v", body["credential_issuer"])
	}
}

func TestVctAndAlias(t *testing.T) {
	for _, path := range []string{
		metadata.VctPrefix + "UniversityDegree",
		metadata.VctAliasPrefix + "UniversityDegree",
	} {
		rec := get(t, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.ietf.sd-jwt-vc-type-metadata+json" {
			t.Fatalf("%s content type %q", path, ct)
		}
		body := decode(t, rec)
		if body["vct"] != "https://registry.example/.well-known/vct/UniversityDegree" {
			t.Fatalf("%s vct %v", path, body["vct"])
		}
	}
}

func TestVctNotFound(t *testing.T) {
	rec := get(t, http.MethodGet, metadata.VctPrefix+"Unknown", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestSchemaDocument(t *testing.T) {
	rec := get(t, http.MethodGet, "/schemas/degree/2", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/schema+json" {
		t.Fatalf("content type %q", ct)
	}
	body := decode(t, rec)
	if body["$id"] != "https://registry.example/schemas/degree/2" {
		t.Fatalf("$id %v", body["$id"])
	}
}

func TestSchemaDocumentRejects(t *testing.T) {
	cases := []string{"/schemas/degree/x", "/schemas/degree/0", "/schemas/degree/1", "/schemas/other/2"}
	for _, path := range cases {
		if rec := get(t, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("%s status %d", path, rec.Code)
		}
	}
}

func TestNotModified(t *testing.T) {
	first := get(t, http.MethodGet, metadata.SchemasPath, nil)
	etag := first.Header().Get("ETag")
	for _, value := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		rec := get(t, http.MethodGet, metadata.SchemasPath, http.Header{"If-None-Match": []string{value}})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("%q status %d", value, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("%q has a body", value)
		}
	}
	rec := get(t, http.MethodGet, metadata.SchemasPath, http.Header{"If-None-Match": []string{`"stale"`}})
	if rec.Code != http.StatusOK {
		t.Fatalf("stale status %d", rec.Code)
	}
}

func TestHeadSendsNoBody(t *testing.T) {
	mux := http.NewServeMux()
	handler().Register(mux)
	req := httptest.NewRequest(http.MethodHead, metadata.SchemasPath, nil)
	rec := httptest.NewRecorder()
	// The mux pattern is "GET /api/schemas", which also answers HEAD.
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("no content length")
	}
}

func TestWriteEncodeFailure(t *testing.T) {
	h := New(source(), func() metadata.Options { return metadata.Options{} }, time.Minute)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.write(rec, req, make(chan int), "application/json")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
}
