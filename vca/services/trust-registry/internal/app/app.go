// SPDX-License-Identifier: Apache-2.0

// Package app wires the trust registry from its configuration: store,
// key ring, publishers, lookup cache, DID resolver, Connect handler, and
// the plain HTTP endpoints.
package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/dedi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/store"
)

// MaxDocumentSize caps a fetched DID document.
const MaxDocumentSize = 1 << 20

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Ring    *keys.Ring
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ReadFile reads the signing key file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Fetch fetches DID documents. Nil means an HTTP client with a timeout.
	Fetch did.Fetcher
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.Fetch == nil {
		deps.Fetch = HTTPFetcher(&http.Client{Timeout: 10 * time.Second})
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	ring, err := loadRing(cfg, deps)
	if err != nil {
		return nil, err
	}
	backend := store.Memory()
	if cfg.StoreFile != "" {
		backend = store.File(cfg.StoreFile)
	}
	st, err := store.Open(backend)
	if err != nil {
		return nil, err
	}
	var publishers []publish.Publisher
	for _, m := range cfg.Methods {
		switch m {
		case publish.MethodEtsi:
			publishers = append(publishers, etsi.Publisher{})
		case publish.MethodDedi:
			publishers = append(publishers, dedi.Publisher{})
		}
	}
	cache := lookup.New(publishers, ring.JWKS, lookup.Options{Policy: cfg.LookupPolicy, MaxAge: cfg.LookupMaxAge, Now: deps.Now})
	var resolver *did.Resolver
	if cfg.ResolveDIDs {
		r := did.NewResolver(deps.Fetch, nil)
		resolver = &r
	}
	svc, err := service.New(service.Options{
		Store: st, Ring: ring, Publishers: publishers, Cache: cache, Resolver: resolver,
		BaseURL: cfg.BaseURL, Issuer: cfg.Issuer, ListTTL: cfg.ListTTL, PageSizeMax: cfg.PageSizeMax, Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(trustv1connect.NewTrustServiceHandler(svc))
	httpapi.New(svc, cfg.HTTPMaxAge).Register(mux)
	deps.Log.Info("trust registry ready", "methods", cfg.Methods, "kid", ring.Active().ID, "alg", ring.Active().Alg, "base_url", cfg.BaseURL)
	return &App{Mux: mux, Service: svc, Ring: ring}, nil
}

// loadRing reads the PEM file or generates one key for development.
func loadRing(cfg config.Config, deps Deps) (*keys.Ring, error) {
	now := deps.Now()
	if cfg.SigningKeyFile == "" {
		k, err := keys.Generate(jose.Algorithm(cfg.SigningAlg), now)
		if err != nil {
			return nil, err
		}
		deps.Log.Warn("no signing key file, generated a key for this process only", "alg", cfg.SigningAlg, "setting", config.Prefix+"SIGNING_KEY_FILE")
		return keys.NewRing(k)
	}
	data, err := deps.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("app: read signing key file: %w", err)
	}
	ks, err := keys.ParsePEM(data, now)
	if err != nil {
		return nil, err
	}
	return keys.NewRing(ks...)
}

// HTTPFetcher returns a DID document fetcher over client.
// It accepts https URLs only and caps the body at MaxDocumentSize.
func HTTPFetcher(client *http.Client) did.Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		if len(url) < 8 || url[:8] != "https://" {
			return nil, fmt.Errorf("app: refuse to fetch %s, https only", url)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/did+json, application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("app: %s returned %d", url, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, MaxDocumentSize))
	}
}
