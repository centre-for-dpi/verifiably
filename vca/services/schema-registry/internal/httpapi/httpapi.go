// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the public read endpoints as plain HTTP GET
// handlers (ADR-003 decision 7, ADR-013 decisions 4 and 5). Every
// response carries an ETag and a Cache-Control header. A request with a
// matching If-None-Match header gets 304 Not Modified.
//
// Paths:
//
//	GET /api/schemas                            the published schemas
//	GET /.well-known/openid-credential-issuer   the OID4VCI issuer metadata
//	GET /.well-known/vct/{vct}                  the SD-JWT VC type metadata
//	GET /vct/{vct}                              alias of the type metadata
//	GET /schemas/{id}/{version}                 one JSON Schema document
package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

// Source gives the handler the published versions and the options.
type Source interface {
	// Published returns every published version.
	Published() []record.Record
	// Get returns one version of one schema.
	Get(id string, version int) (record.Record, bool)
}

// Handler serves the public documents.
type Handler struct {
	src    Source
	opts   func() metadata.Options
	maxAge time.Duration
}

// New builds a handler. opts returns the current metadata options.
// maxAge sets the Cache-Control max-age.
func New(src Source, opts func() metadata.Options, maxAge time.Duration) *Handler {
	return &Handler{src: src, opts: opts, maxAge: maxAge}
}

// Register adds the endpoints to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+metadata.SchemasPath, h.schemas)
	mux.HandleFunc("GET "+metadata.IssuerMetadataPath, h.issuerMetadata)
	mux.HandleFunc("GET "+metadata.VctPrefix+"{vct...}", h.vct)
	mux.HandleFunc("GET "+metadata.VctAliasPrefix+"{vct...}", h.vct)
	mux.HandleFunc("GET "+metadata.SchemaPrefix+"{id}/{version}", h.schema)
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, metadata.PublicList(h.src.Published(), h.opts()), "application/json")
}

func (h *Handler) issuerMetadata(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, metadata.IssuerMetadata(h.src.Published(), h.opts()), "application/json")
}

func (h *Handler) vct(w http.ResponseWriter, r *http.Request) {
	opts := h.opts()
	vct := r.PathValue("vct")
	rec, ok := metadata.FindVct(h.src.Published(), vct, opts)
	if !ok {
		http.Error(w, "no published schema has this vct", http.StatusNotFound)
		return
	}
	h.write(w, r, metadata.TypeMetadata(rec, opts), "application/vnd.ietf.sd-jwt-vc-type-metadata+json")
}

func (h *Handler) schema(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version <= 0 {
		http.Error(w, "the version must be a positive number", http.StatusNotFound)
		return
	}
	rec, ok := h.src.Get(r.PathValue("id"), version)
	if !ok || rec.State == record.StateDraft {
		http.Error(w, "no such schema version", http.StatusNotFound)
		return
	}
	h.write(w, r, metadata.SchemaDocument(rec, h.opts()), "application/schema+json")
}

// write encodes doc, sets the cache headers, and answers 304 when the
// ETag matches.
func (h *Handler) write(w http.ResponseWriter, r *http.Request, doc any, contentType string) {
	body, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.maxAge.Seconds())))
	w.Header().Set("Vary", "Accept-Encoding")
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// matches reports whether the If-None-Match header names etag.
func matches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "W/"))
		if part == etag || part == "*" {
			return true
		}
	}
	return false
}
