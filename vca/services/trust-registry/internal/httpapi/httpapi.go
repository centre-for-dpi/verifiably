// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the published trust lists and the JWKS as plain
// HTTP GET endpoints (ADR-003 decision 7). Every response carries an
// ETag and a Cache-Control header. A request with a matching
// If-None-Match header gets 304 Not Modified.
//
// Paths:
//
//	GET /trust-list/etsi.json          the ETSI TS 119 602 JSON list
//	GET /trust-list/etsi.jws           the same list as a compact JWS
//	GET /.well-known/jwks.json         the signing keys (RFC 7517)
//	GET /.well-known/dedi.index.json   the DeDi manifest
//	GET /dedi/dedi.<name>.json         one DeDi directory file
//
// The paths of the proto comment are aliases:
//
//	GET /trust/etsi/list.json          alias of /trust-list/etsi.jws
//	GET /trust/dedi/<file>             alias of /dedi/<file>
package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// JWKSPath is the path of the key set.
const JWKSPath = "/.well-known/jwks.json"

// Source gives the handler the current files and keys.
type Source interface {
	// Snapshot returns the published files. Nil means nothing is published.
	Snapshot() *publish.Snapshot
	// JWKSJSON returns the JWKS document.
	JWKSJSON() []byte
}

// Handler serves the published files.
type Handler struct {
	src    Source
	maxAge time.Duration
}

// New builds a handler. maxAge sets the Cache-Control max-age.
func New(src Source, maxAge time.Duration) *Handler {
	return &Handler{src: src, maxAge: maxAge}
}

// Register adds the handler to mux under every served prefix.
func (h *Handler) Register(mux *http.ServeMux) {
	for _, prefix := range []string{"/trust-list/", "/.well-known/", "/dedi/", "/trust/"} {
		mux.Handle(prefix, h)
	}
}

// resolve maps an alias path to the published path.
func resolve(path string) string {
	if path == "/trust/etsi/list.json" {
		return "/trust-list/etsi.jws"
	}
	if rest, ok := strings.CutPrefix(path, "/trust/dedi/"); ok {
		return "/dedi/" + rest
	}
	return path
}

// ServeHTTP answers GET and HEAD requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := resolve(r.URL.Path)
	var f publish.File
	if path == JWKSPath {
		f = publish.File{ContentType: "application/json", Body: h.src.JWKSJSON()}
	} else {
		var ok bool
		f, ok = h.src.Snapshot().File(path)
		if !ok {
			http.NotFound(w, r)
			return
		}
	}
	etag := f.ETag()
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.maxAge.Seconds())))
	w.Header().Set("Content-Type", f.ContentType)
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(f.Body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(f.Body)
}

// matches reports whether the If-None-Match header names etag.
func matches(header, etag string) bool {
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || tag == etag || strings.TrimPrefix(tag, "W/") == etag {
			return true
		}
	}
	return false
}
