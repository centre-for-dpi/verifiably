// SPDX-License-Identifier: Apache-2.0

// Package app wires the issuance service from its configuration.
package app

import (
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/datasource"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// App is the wired service.
type App struct {
	// Mux serves the Connect routes and the document endpoint.
	Mux *http.ServeMux
	// Service holds the RPC implementation.
	Service *service.Service
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTPClient calls the other services. Nil builds one.
	HTTPClient connect.HTTPClient
	// Store replaces the state store.
	Store store.KeyValue
	// Capability replaces the capability client of the DPG adapter.
	Capability clients.Capability
	// Issuer replaces the issuer client of the DPG adapter.
	Issuer clients.Issuer
	// Schemas replaces the schema client.
	Schemas clients.Schemas
	// Status replaces the status client.
	Status clients.Status
	// Recorder replaces the issued credentials client.
	Recorder clients.Recorder
	// Rows replaces the data source client.
	Rows clients.Rows
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	backend := deps.Store
	if backend == nil {
		var err error
		if backend, err = openStore(cfg); err != nil {
			return nil, err
		}
	}
	httpClient := deps.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	capability := deps.Capability
	if capability == nil {
		capability = backendv1connect.NewCapabilityServiceClient(httpClient, cfg.AdapterURL)
	}
	issuer := deps.Issuer
	if issuer == nil {
		issuer = backendv1connect.NewIssuerBackendServiceClient(httpClient, cfg.AdapterURL)
	}
	schemas := deps.Schemas
	if schemas == nil && cfg.SchemaURL != "" {
		schemas = schemav1connect.NewSchemaServiceClient(httpClient, cfg.SchemaURL)
	}
	status := deps.Status
	if status == nil && cfg.StatusURL != "" {
		status = statusv1connect.NewStatusServiceClient(httpClient, cfg.StatusURL)
	}
	rows := deps.Rows
	if rows == nil && cfg.DataSourceURL != "" {
		rows = datasource.New(datasourcev1connect.NewDataSourceServiceClient(
			httpClient, cfg.DataSourceURL), "")
	}
	recorder := deps.Recorder
	if recorder == nil {
		if cfg.IssuedURL != "" {
			recorder = clients.NewConnectRecorder(cfg.IssuedURL, &http.Client{Timeout: cfg.Timeout})
		} else {
			recorder = clients.LogRecorder(deps.Log)
		}
	}
	svc, err := service.New(service.Options{
		Capabilities:   clients.NewCapabilityCache(capability, cfg.Timeout*10, deps.Now),
		Issuer:         issuer,
		Schemas:        schemas,
		Status:         status,
		Recorder:       recorder,
		Rows:           rows,
		Delivery:       senders(cfg, deps),
		Store:          offers.New(backend, deps.Now),
		AdapterName:    cfg.AdapterName,
		PublicURL:      cfg.PublicURL,
		DocumentTitle:  cfg.DocumentTitle,
		DocumentIssuer: cfg.DocumentIssuer,
		DocumentFooter: cfg.DocumentFooter,
		OfferTTL:       cfg.OfferTTL,
		BatchWorkers:   cfg.BatchWorkers,
		PageSizeMax:    cfg.PageSizeMax,
		Now:            deps.Now,
		Log:            deps.Log,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(issuancev1connect.NewIssuanceServiceHandler(svc))
	mux.HandleFunc("GET "+service.DocumentPath+"{ref}", documentHandler(svc))
	if schemas == nil {
		deps.Log.Warn("no schema registry, so the claims of a request are not checked",
			"setting", config.Prefix+"SCHEMA_URL")
	}
	if status == nil {
		deps.Log.Warn("no status service, so every credential is not revocable",
			"setting", config.Prefix+"STATUS_URL")
	}
	deps.Log.Info("issuance ready", "adapter", cfg.AdapterURL, "sender", cfg.DeliverySender)
	return &App{Mux: mux, Service: svc}, nil
}

// documentHandler serves one rendered document to a citizen.
func documentHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		document, ok := svc.Document(r.Context(), r.PathValue("ref"))
		if !ok {
			http.Error(w, "the document does not exist or it expired", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="credential.pdf"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(document)
	}
}

// senders returns the delivery registry of the deployment
// (ADR-016 decision 5).
//
// The email channel and the SMS channel need a gateway. Their default
// sender is the stub, which reports that the deployment has none. An
// operator turns on the log sender or the file sender to try a flow
// without a gateway.
func senders(cfg config.Config, deps Deps) *delivery.Registry {
	pick := func(name string, stub delivery.Sender) delivery.Sender {
		switch name {
		case "log":
			return delivery.Log(deps.Log)
		case "file":
			return delivery.File(cfg.DeliveryDir, deps.Now)
		default:
			return stub
		}
	}
	base := pick(cfg.DeliverySender, delivery.Log(deps.Log))
	return delivery.NewRegistry(map[delivery.Channel]delivery.Sender{
		delivery.ChannelOID4VCI: base,
		delivery.ChannelPDF:     base,
		delivery.ChannelLink:    base,
		delivery.ChannelEmail:   pick(cfg.EmailSender, delivery.Email()),
		delivery.ChannelSMS:     pick(cfg.SMSSender, delivery.SMS()),
	})
}

// openStore returns the state store of the service.
func openStore(cfg config.Config) (store.KeyValue, error) {
	if cfg.StoreFile == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StoreFile)
}
