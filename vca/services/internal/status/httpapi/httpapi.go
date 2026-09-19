// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the public status list over plain HTTP
// (ADR-003 decision 7, ADR-018 decision 5). A verifier reads the list
// without a Connect client.
//
// Paths:
//
//	GET /status/<list_id>       the signed list
//	GET /.well-known/jwks.json  the signing keys (RFC 7517)
//
// Every response carries a strong ETag and a Cache-Control max-age. A
// request with a matching If-None-Match header gets 304 Not Modified.
// The handler never signs on the request path unless the stored
// signature expired, so verifier load does not reach the signer.
//
// The token service serves two media types from one bit array (ADR-019
// decision 2). The handler picks one with the Accept header. A request
// without an Accept header gets the default media type of the service.
package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
)

// JWKSPath is the path of the key set.
const JWKSPath = "/.well-known/jwks.json"

// ListPrefix is the path prefix of a list.
const ListPrefix = lists.PathPrefix

// Source gives the handler the signed lists and the keys.
type Source interface {
	// Signed returns the record and the current signature of the list.
	Signed(ctx context.Context, id string) (lists.Record, lists.Signed, error)
	// MediaTypes returns the media types of this service, default first.
	MediaTypes() []string
	// JWKS returns the JWKS document.
	JWKS() []byte
}

// Handler serves the public endpoints.
type Handler struct {
	src    Source
	maxAge time.Duration
}

// DefaultMaxAge is the Cache-Control max-age when the caller gives none.
const DefaultMaxAge = 5 * time.Minute

// New builds a handler over src. maxAge sets Cache-Control max-age.
// Zero means DefaultMaxAge.
func New(src Source, maxAge time.Duration) *Handler {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	return &Handler{src: src, maxAge: maxAge}
}

// Register adds the endpoints to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+ListPrefix+"{listID}", h.serveList)
	mux.HandleFunc("GET "+JWKSPath, h.serveJWKS)
}

func (h *Handler) serveJWKS(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, "application/jwk-set+json", h.src.JWKS(), "")
}

func (h *Handler) serveList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("listID")
	_, signed, err := h.src.Signed(r.Context(), id)
	if err != nil {
		http.Error(w, "list not found", http.StatusNotFound)
		return
	}
	want, err := Negotiate(r.Header.Get("Accept"), h.src.MediaTypes())
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}
	art, ok := signed.Artifact(want)
	if !ok {
		http.Error(w, "no representation of this list matches the Accept header", http.StatusNotAcceptable)
		return
	}
	h.write(w, r, art.MediaType, art.Body, art.ETag)
}

// write sends body with cache headers, or 304 when the ETag matches.
func (h *Handler) write(w http.ResponseWriter, r *http.Request, mediaType string, body []byte, etag string) {
	if etag == "" {
		etag = lists.ETagOf(body)
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(h.maxAge.Seconds())))
	w.Header().Set("Content-Type", mediaType)
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		anyval.DiscardWrite(w.Write(body))
	}
}

// matches reports whether the If-None-Match header covers etag.
func matches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}
	return false
}

// Negotiate picks one media type from the Accept header. An empty
// header selects the first offer. The error names the offers when
// nothing matches.
func Negotiate(accept string, offers []string) (string, error) {
	if len(offers) == 0 {
		return "", fmt.Errorf("httpapi: this service serves no media type")
	}
	accept = strings.TrimSpace(accept)
	if accept == "" {
		return offers[0], nil
	}
	type candidate struct {
		offer string
		q     float64
		order int
	}
	var best []candidate
	for i, part := range strings.Split(accept, ",") {
		name, q, ok := parseAccept(part)
		if !ok || q == 0 {
			continue
		}
		for _, offer := range offers {
			if matchType(name, offer) {
				best = append(best, candidate{offer: offer, q: q, order: i})
			}
		}
	}
	if len(best) == 0 {
		return "", fmt.Errorf("httpapi: this service serves %s only", strings.Join(offers, ", "))
	}
	sort.SliceStable(best, func(a, b int) bool {
		if best[a].q != best[b].q {
			return best[a].q > best[b].q
		}
		return best[a].order < best[b].order
	})
	return best[0].offer, nil
}

// parseAccept splits one Accept element into the media type and its q
// value. The third value is false when the element is empty.
func parseAccept(part string) (string, float64, bool) {
	fields := strings.Split(part, ";")
	name := strings.ToLower(strings.TrimSpace(fields[0]))
	if name == "" {
		return "", 0, false
	}
	q := 1.0
	for _, p := range fields[1:] {
		k, v, found := strings.Cut(p, "=")
		if !found || strings.ToLower(strings.TrimSpace(k)) != "q" {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || parsed < 0 || parsed > 1 {
			continue
		}
		q = parsed
	}
	return name, q, true
}

// matchType reports whether the Accept name covers the offer. It
// accepts "*/*" and "type/*".
func matchType(name, offer string) bool {
	offer = strings.ToLower(offer)
	if name == "*/*" || name == offer {
		return true
	}
	prefix, star := strings.CutSuffix(name, "/*")
	if !star {
		return false
	}
	return strings.HasPrefix(offer, prefix+"/")
}
