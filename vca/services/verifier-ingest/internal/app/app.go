// SPDX-License-Identifier: Apache-2.0

// Package app wires the ingestion service from its configuration: the
// transaction store, the request object key, the discovery client, the
// Connect handler, the wallet endpoints, and the camera page.
package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// DefaultPruneInterval is the time between two prune runs of the store.
const DefaultPruneInterval = 10 * time.Minute

// App is the wired service.
type App struct {
	// Mux serves every path of the service.
	Mux *http.ServeMux
	// Service is the Connect handler.
	Service *service.Service
	// Store keeps the transactions.
	Store *txn.Store
	// Config is the configuration the wiring used.
	Config config.Config
	// PruneInterval is the time between two prune runs. Build sets it
	// to DefaultPruneInterval. Tests shorten it.
	PruneInterval time.Duration
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Discovery reads a presentation template. Nil builds a Connect
	// client from the configured URL.
	Discovery discoveryv1connect.DiscoveryServiceClient
	// Client performs the request object fetches.
	Client *http.Client
	// ReadFile reads the signing key file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	backend := sharedstore.Memory()
	if cfg.StateDir != "" {
		var err error
		if backend, err = sharedstore.File(cfg.StateDir); err != nil {
			return nil, err
		}
	}
	key, kid, err := loadKey(cfg, deps)
	if err != nil {
		return nil, err
	}
	discovery := deps.Discovery
	if discovery == nil && cfg.DiscoveryURL != "" {
		discovery = discoveryv1connect.NewDiscoveryServiceClient(&http.Client{Timeout: cfg.DiscoveryTimeout}, cfg.DiscoveryURL)
	}
	store, storeErr := txn.NewStore(backend)
	svc, serviceErr := service.New(service.Options{
		Store:     store,
		Discovery: discovery,
		Fetcher: oid4vp.Fetcher{
			Allow:    oid4vp.Allowlist{Hosts: cfg.RequestURIHosts, AllowPlainHTTP: cfg.AllowPlainHTTP},
			Client:   deps.Client,
			Timeout:  cfg.RequestURITimeout,
			MaxBytes: cfg.MaxRequestURIBytes,
		},
		SigningKey:    key,
		KeyID:         kid,
		BaseURL:       cfg.BaseURL,
		ClientID:      cfg.ClientID,
		RequestTTL:    cfg.RequestTTL,
		MaxInputBytes: cfg.MaxInputBytes,
		XML:           xmlConfig(cfg),
		RedirectURI:   cfg.RedirectURI,
		Now:           deps.Now,
	})
	wallet, walletErr := httpapi.New(svc)
	page, pageErr := scanner.New(scanner.Options{Client: svc, Prefix: cfg.ScannerPrefix})
	assets, assetsErr := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err := errors.Join(storeErr, serviceErr, walletErr, pageErr, assetsErr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(ingestv1connect.NewIngestServiceHandler(svc))
	wallet.Register(mux)
	page.Register(mux)
	mux.Handle("GET "+ui.Prefix, assets)
	deps.Log.Info("verifier ingest ready",
		"base_url", cfg.BaseURL, "client_id", cfg.ClientID, "discovery_url", cfg.DiscoveryURL,
		"scanner", page.Prefix(), "request_uri_hosts", cfg.RequestURIHosts, "kid", kid)
	return &App{Mux: mux, Service: svc, Store: store, Config: cfg, PruneInterval: DefaultPruneInterval}, nil
}

// xmlConfig returns the default XML configuration of the deployment.
func xmlConfig(cfg config.Config) ingest.XMLConfig {
	out := ingest.XMLConfig{Path: cfg.XMLPath, Encoding: ingest.XMLText}
	if cfg.XMLEncoding == "base64" {
		out.Encoding = ingest.XMLBase64
	}
	return out
}

// loadKey reads the request object key, or generates one for this
// process.
func loadKey(cfg config.Config, deps Deps) (crypto.Signer, string, error) {
	if cfg.SigningKeyFile == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("app: generate a request object key: %w", err)
		}
		deps.Log.Warn("no signing key file, generated a key for this process only",
			"setting", config.Prefix+"SIGNING_KEY_FILE")
		return key, keyID(key), nil
	}
	data, err := deps.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("app: read the signing key file: %w", err)
	}
	key, err := parsePEM(data)
	if err != nil {
		return nil, "", err
	}
	return key, keyID(key), nil
}

// parsePEM reads the first PKCS 8 private key of a PEM file. The key
// must be able to sign.
func parsePEM(data []byte) (crypto.Signer, error) {
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("app: read the signing key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("app: the signing key of type %T cannot sign", key)
		}
		return signer, nil
	}
	return nil, errors.New("app: the signing key file holds no PKCS 8 private key")
}

// keyID returns the JWK thumbprint of the public key, or an empty id.
func keyID(key crypto.Signer) string {
	jwk, err := jose.PublicJWK(key.Public(), "")
	if err != nil {
		return ""
	}
	// A JWK the kit built always has a thumbprint.
	thumbprint, ignored := jose.Thumbprint(jwk)
	_ = ignored
	return thumbprint
}

// Prune removes old transactions on every tick until ctx ends.
func (a *App) Prune(ctx context.Context, log *slog.Logger) {
	if a.Config.TransactionTTL <= 0 || a.PruneInterval <= 0 {
		return
	}
	ticker := time.NewTicker(a.PruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			removed, err := a.Store.Prune(ctx, now.Add(-a.Config.TransactionTTL))
			if err != nil {
				log.Warn("prune failed", "error", err.Error())
				continue
			}
			if removed > 0 {
				log.Info("pruned transactions", "removed", removed)
			}
		}
	}
}
