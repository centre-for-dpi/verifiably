// SPDX-License-Identifier: Apache-2.0

// Package app wires the issued credentials service from its
// configuration: the hash chain store, the head signer, the status
// service client, the Connect handler, and the chain head endpoints.
package app

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Store   *store.Store
	Signer  *head.Signer
	// PruneInterval is the time between two prune runs. Zero turns the
	// scheduled job off.
	PruneInterval time.Duration
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ReadFile reads the salt file and the head key file. Nil means
	// os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// HTTPClient calls the status service. Nil means http.DefaultClient.
	HTTPClient connect.HTTPClient
	// Status replaces the status service client. Tests set it. When it
	// is nil the wiring builds a Connect client from the configuration.
	Status statusv1connect.StatusServiceClient
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
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	backend := sharedstore.MemoryDoc()
	if cfg.StoreFile != "" {
		backend = sharedstore.FileDoc(cfg.StoreFile)
	}
	st, err := store.Open(backend)
	if err != nil {
		return nil, err
	}
	salt, err := salt(cfg, deps)
	if err != nil {
		return nil, err
	}
	signer, err := signer(cfg, deps)
	if err != nil {
		return nil, err
	}
	status := deps.Status
	if status == nil && cfg.StatusURL != "" {
		status = statusv1connect.NewStatusServiceClient(httpClient(cfg, deps), cfg.StatusURL)
	}
	svc, err := service.New(service.Options{
		Store:       st,
		Status:      status,
		Head:        signer,
		Retention:   cfg.Retention,
		Salt:        salt,
		PageSizeMax: cfg.PageSizeMax,
		Now:         deps.Now,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(issuedv1connect.NewIssuedServiceHandler(svc))
	httpapi.Register(mux, svc, signer)
	if status == nil {
		deps.Log.Warn("no status service, revoke and reinstate report a failed precondition",
			"setting", config.Prefix+"STATUS_URL")
	}
	if salt == "" {
		deps.Log.Warn("no subject salt, the subject reference is not hard to guess",
			"setting", config.Prefix+"SALT_FILE")
	}
	deps.Log.Info("issued credentials ready",
		"store_file", cfg.StoreFile, "key_id", signer.KeyID(), "schemas", cfg.Retention.Schemas())
	return &App{Mux: mux, Service: svc, Store: st, Signer: signer, PruneInterval: cfg.PruneInterval}, nil
}

// httpClient returns the client that calls the status service.
func httpClient(cfg config.Config, deps Deps) connect.HTTPClient {
	if deps.HTTPClient != nil {
		return deps.HTTPClient
	}
	return &http.Client{Timeout: cfg.StatusTimeout}
}

// salt returns the subject salt. The file wins over the variable, so a
// deployment can mount a secret.
func salt(cfg config.Config, deps Deps) (string, error) {
	if cfg.SaltFile == "" {
		return cfg.Salt, nil
	}
	raw, err := deps.ReadFile(cfg.SaltFile)
	if err != nil {
		return "", fmt.Errorf("app: read %s: %w", config.Prefix+"SALT_FILE", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// signer returns the head signer. It generates a key when the
// configuration names no file. A generated key changes on every restart,
// so an auditor must read the key set again.
func signer(cfg config.Config, deps Deps) (*head.Signer, error) {
	var key crypto.PrivateKey
	var err error
	if cfg.HeadKeyFile == "" {
		if key, err = head.GenerateKey(); err != nil {
			return nil, err
		}
	} else {
		raw, rerr := deps.ReadFile(cfg.HeadKeyFile)
		if rerr != nil {
			return nil, fmt.Errorf("app: read %s: %w", config.Prefix+"HEAD_KEY_FILE", rerr)
		}
		if key, err = head.ParsePEM(raw); err != nil {
			return nil, err
		}
	}
	return head.NewSigner(head.Options{Key: key, Issuer: cfg.HeadIssuer, Period: cfg.HeadPeriod})
}

// Prune runs the retention job until ctx ends (ADR-017 decision 5). A
// zero interval returns at once.
func (a *App) Prune(ctx context.Context, log *slog.Logger) {
	if a.PruneInterval <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(a.PruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := a.Service.PruneDue()
			if err != nil {
				log.Error("prune failed", "error", err)
				continue
			}
			if n > 0 {
				log.Info("pruned records whose retention ended", "count", n)
			}
		}
	}
}
