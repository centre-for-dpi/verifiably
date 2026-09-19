// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the read only catalogue of the discovery
// service (ADR-022 decision 5). A wallet reads the same catalogue the
// verifier pages show.
//
// Paths:
//
//	GET /catalog                 every crawled issuer with its types
//	GET /catalog/issuers         the issuers without their types
//	GET /catalog/types           every credential type of every issuer
//
// The endpoints are plain net/http handlers, because a wallet is not a
// Connect client (ADR-003 decision 7).
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
)

// Reader returns the crawled catalogue.
type Reader interface {
	Catalogue(ctx context.Context) ([]catalog.Issuer, error)
}

// Options configure the endpoints.
type Options struct {
	// Reader returns the catalogue.
	Reader Reader
	// MaxAge is the Cache-Control max-age of a response.
	MaxAge time.Duration
}

// API serves the catalogue.
type API struct {
	opts Options
}

// New builds the API.
func New(opts Options) *API { return &API{opts: opts} }

// Register adds the endpoints to mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /catalog", a.catalogue)
	mux.HandleFunc("GET /catalog/issuers", a.issuers)
	mux.HandleFunc("GET /catalog/types", a.types)
}

// issuerView is one issuer without its types.
type issuerView struct {
	CredentialIssuer string    `json:"credential_issuer"`
	DID              string    `json:"did,omitempty"`
	DisplayName      string    `json:"display_name,omitempty"`
	Trust            string    `json:"trust,omitempty"`
	TypeCount        int       `json:"type_count"`
	CrawledAt        time.Time `json:"crawled_at"`
}

// typeView is one credential type with its issuer.
type typeView struct {
	CredentialIssuer string            `json:"credential_issuer"`
	Type             string            `json:"type"`
	ConfigurationID  string            `json:"configuration_id,omitempty"`
	Format           string            `json:"format,omitempty"`
	Display          []catalog.Display `json:"display,omitempty"`
	Fields           []catalog.Field   `json:"fields,omitempty"`
}

// catalogue answers GET /catalog.
func (a *API) catalogue(w http.ResponseWriter, r *http.Request) {
	issuers, err := a.opts.Reader.Catalogue(r.Context())
	if err != nil {
		http.Error(w, "the catalogue is not available", http.StatusInternalServerError)
		return
	}
	a.write(w, r, map[string]any{"issuers": issuers})
}

// issuers answers GET /catalog/issuers.
func (a *API) issuers(w http.ResponseWriter, r *http.Request) {
	issuers, err := a.opts.Reader.Catalogue(r.Context())
	if err != nil {
		http.Error(w, "the catalogue is not available", http.StatusInternalServerError)
		return
	}
	out := make([]issuerView, 0, len(issuers))
	for _, i := range issuers {
		out = append(out, issuerView{
			CredentialIssuer: i.CredentialIssuer, DID: i.DID, DisplayName: i.DisplayName,
			Trust: i.Trust, TypeCount: len(i.Types), CrawledAt: i.CrawledAt,
		})
	}
	a.write(w, r, map[string]any{"issuers": out})
}

// types answers GET /catalog/types. The format and type query values
// filter the list.
func (a *API) types(w http.ResponseWriter, r *http.Request) {
	issuers, err := a.opts.Reader.Catalogue(r.Context())
	if err != nil {
		http.Error(w, "the catalogue is not available", http.StatusInternalServerError)
		return
	}
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	wanted := strings.TrimSpace(r.URL.Query().Get("type"))
	out := make([]typeView, 0)
	for _, i := range issuers {
		for _, t := range i.Types {
			if format != "" && t.Format != format {
				continue
			}
			if wanted != "" && t.Type != wanted {
				continue
			}
			out = append(out, typeView{
				CredentialIssuer: i.CredentialIssuer, Type: t.Type, ConfigurationID: t.ConfigurationID,
				Format: t.Format, Display: t.Display, Fields: t.Fields,
			})
		}
	}
	a.write(w, r, map[string]any{"types": out})
}

// write answers with JSON, an entity tag, and a cache header.
func (a *API) write(w http.ResponseWriter, r *http.Request, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "the catalogue is not available", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if a.opts.MaxAge > 0 {
		w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(a.opts.MaxAge.Seconds())))
	}
	if strings.Contains(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	if _, err := w.Write(data); err != nil {
		return
	}
}
