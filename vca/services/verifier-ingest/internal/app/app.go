// SPDX-License-Identifier: Apache-2.0

// Package app wires the ingestion service from its configuration: the
// transaction store, the request object key, the discovery client, the
// Connect handler, the wallet endpoints, and the camera page behind the
// session guard.
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
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui"
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
	// SessionKeys replaces the key set of verifier-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Prober replaces the probe of the peers.
	Prober *topology.Prober
	// Stack replaces the verifier client of the adapter. Tests set it.
	Stack func(adapterURL string) scanner.StackVerifier
	// Requests replaces the client that sends a request through the
	// verifier of an adapter. Tests set it.
	Requests func(adapterURL string) service.StackVerifier
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
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: cfg.Peers, Auth: cfg.Auth, PublicURL: cfg.BaseURL,
		SignOut: "/" + strings.Trim(cfg.ScannerPrefix, "/") + "/signout", Prober: deps.Prober,
		Client: &http.Client{Timeout: cfg.DiscoveryTimeout}, Now: deps.Now,
	})
	internal := &http.Client{Timeout: cfg.EvaluateTimeout}
	var policy service.Evaluator
	if cfg.PolicyURL != "" {
		policy = policyv1connect.NewPolicyServiceClient(internal, cfg.PolicyURL)
	}
	var results resultsv1connect.ResultsServiceClient
	if cfg.ResultsURL != "" {
		results = resultsv1connect.NewResultsServiceClient(internal, cfg.ResultsURL)
	}
	requests := deps.Requests
	if requests == nil {
		stackClient := &http.Client{Timeout: cfg.StackTimeout}
		requests = func(adapterURL string) service.StackVerifier {
			return backendv1connect.NewVerifierBackendServiceClient(stackClient, adapterURL)
		}
	}
	stacks := StacksOf(shell)
	store, storeErr := txn.NewStore(backend)
	svc, serviceErr := service.New(service.Options{
		Policy: policy, Results: resultsStore(results), Stacks: stacks, StackClient: requests,
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
	assets, kit, _, assetsErr := uikit.LoadFile(cfg.ThemeFile)
	// A pasted link goes through the shared guard (ADR-002 decision 7).
	links := fetchguard.New(fetchguard.Options{
		Guard: fetchguard.Guard{
			AllowedHosts: cfg.LinkHosts, AllowPrivateNetwork: cfg.LinkAllowPrivateNetwork, AllowPlainHTTP: cfg.AllowPlainHTTP,
		},
		Client: deps.Client, Timeout: cfg.RequestURITimeout, MaxBytes: cfg.MaxInputBytes,
		Accept: "application/dc+sd-jwt, application/vc+sd-jwt, application/jwt, application/json, application/pdf, image/*, */*;q=0.5",
	})
	page, pageErr := scanner.New(scanner.Options{
		Client: svc, Prefix: cfg.ScannerPrefix, Kit: kit, Shell: shell, SignOut: signOut,
		Links: links, Stack: deps.Stack, StackTimeout: cfg.StackTimeout,
		Discovery: discovery, Results: resultsReader(results), Stacks: stacks,
	})
	guard, guardErr := staffsession.Build(cfg.Auth, staffsession.VerifierRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, ReadFile: deps.ReadFile, Now: deps.Now, Log: deps.Log, MaxFormBytes: scanner.MaxUploadBytes,
	})
	if err := errors.Join(storeErr, serviceErr, walletErr, assetsErr, pageErr, guardErr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(ingestv1connect.NewIngestServiceHandler(svc))
	wallet.Register(mux)
	// The camera page sits behind the guard. The OID4VP endpoints of the
	// wallet above stay open (ADR-036 decision 2).
	staff := http.NewServeMux()
	page.Register(staff)
	mux.Handle(page.Prefix()+"/", guard.Wrap(staff))
	mux.Handle("GET "+ui.Prefix, assets)
	deps.Log.Info("verifier ingest ready",
		"base_url", cfg.BaseURL, "client_id", cfg.ClientID, "discovery_url", cfg.DiscoveryURL,
		"scanner", page.Prefix(), "request_uri_hosts", cfg.RequestURIHosts, "kid", kid)
	return &App{Mux: mux, Service: svc, Store: store, Config: cfg, PruneInterval: DefaultPruneInterval}, nil
}

// StacksOf returns the live verifier stacks of the probe that have an
// adapter: the stacks a request can go through (spec VE4).
func StacksOf(shell *staffshell.Shell) func(ctx context.Context) []service.Stack {
	return func(ctx context.Context) []service.Stack {
		if shell == nil {
			return nil
		}
		f := shell.Frame(ctx)
		var out []service.Stack
		for _, st := range f.Live(commonv1.Role_ROLE_VERIFIER) {
			if adapter := st.Peer.Adapter(); adapter != "" {
				out = append(out, service.Stack{
					Pair: st.Peer.Pair, Name: f.Snapshot().StackName(st.Peer.Dpg), Adapter: adapter,
					Protocols: st.Capabilities.GetProtocols(), Features: st.Capabilities.GetFeatures(),
				})
			}
		}
		return out
	}
}

// resultsStore returns the store side of a results client, or nil.
func resultsStore(c resultsv1connect.ResultsServiceClient) service.ResultStore {
	if c == nil {
		return nil
	}
	return c
}

// resultsReader returns the read side of a results client, or nil.
func resultsReader(c resultsv1connect.ResultsServiceClient) scanner.Results {
	if c == nil {
		return nil
	}
	return c
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
	data, err := sharedconfig.ReadKey(deps.ReadFile, cfg.SigningKeyFile)
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
