// Package factory is the one place that imports every concrete adapter
// package and turns a backends.json entry into a backend.Adapter. Living
// under internal/adapters/ is deliberate — the CI agnosticism rule exempts
// this path because it must know vendor types by name.
package factory

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/adapters/credebl"
	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
	"github.com/verifiably/verifiably-go/internal/adapters/injiverify"
	"github.com/verifiably/verifiably-go/internal/adapters/injiweb"
	"github.com/verifiably/verifiably-go/internal/adapters/registry"
	"github.com/verifiably/verifiably-go/internal/adapters/waltid"
)

// Build constructs the adapter matching entry.Type. Unknown types return
// (nil, nil) so the caller can skip them with a log line.
func Build(entry registry.BackendEntry) (backend.Adapter, error) {
	switch entry.Type {
	case "credebl":
		cfg, err := credebl.UnmarshalConfig(entry.Config)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return credebl.New(cfg, entry.Vendor)
	case "walt_community":
		cfg, err := waltid.UnmarshalConfig(entry.Config)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return waltid.New(cfg, entry.Vendor)
	case "inji_certify_authcode", "inji_certify_preauth":
		cfg, err := injicertify.UnmarshalConfig(entry.Config)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return injicertify.New(cfg, entry.Vendor)
	case "inji_verify":
		cfg, err := injiverify.UnmarshalConfig(entry.Config)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return injiverify.New(cfg, entry.Vendor)
	case "inji_web":
		cfg, err := injiweb.UnmarshalConfig(entry.Config)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return injiweb.New(cfg, entry.Vendor)
	}
	return nil, nil
}

// OffersHandler returns an http.Handler for the /offers/{vendor}/{id} route.
// The path form lets one handler dispatch across every configured issuer
// adapter that hosts pre-constructed offers (currently injicertify). Main.go
// attaches this under the root ServeMux so the path collision stays in one
// place.
func OffersHandler(r *registry.Registry) http.Handler {
	// Index the injicertify adapters by the vendor key they were registered under
	// so we can look up the correct one when the wallet dereferences the URI.
	index := map[string]*injicertify.Adapter{}
	for _, ad := range r.AllAdapters() {
		if a, ok := ad.(*injicertify.Adapter); ok {
			index[a.Slug()] = a
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(parts) != 3 || parts[0] != "offers" {
			http.NotFound(w, req)
			return
		}
		vendor, id := parts[1], parts[2]
		ad, ok := index[vendor]
		if !ok {
			http.NotFound(w, req)
			return
		}
		raw, ok := ad.OfferJSON(id)
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
}
