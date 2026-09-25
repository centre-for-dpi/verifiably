// SPDX-License-Identifier: Apache-2.0

// Package app wires the issuance service from its configuration.
package app

import (
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui"
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
	// PageSchemas replaces the schema list of the pages.
	PageSchemas pages.Schemas
	// PageIssued replaces the issued credentials list of the pages.
	PageIssued pages.Issued
	// PageIdentity replaces the identity client of the pages.
	PageIdentity pages.Identity
	// Trust replaces the trust registry client of the identity page.
	Trust func(url string) pages.Trust
	// SessionKeys replaces the key set of issuer-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Prober replaces the probe of the peers.
	Prober *topology.Prober
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
	recorder := deps.Recorder
	if recorder == nil {
		if cfg.IssuedURL != "" {
			recorder = clients.NewConnectRecorder(cfg.IssuedURL, &http.Client{Timeout: cfg.Timeout})
		} else {
			recorder = clients.LogRecorder(deps.Log)
		}
	}
	events, err := auditlog.Open(cfg.AuditDir, deps.Now)
	if err != nil {
		return nil, err
	}
	svc, err := service.New(service.Options{
		Capabilities:   clients.NewCapabilityCache(capability, cfg.Timeout*10, deps.Now),
		Issuer:         issuer,
		Schemas:        schemas,
		Status:         status,
		Recorder:       recorder,
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
		Audit:          events,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(issuancev1connect.NewIssuanceServiceHandler(svc))
	auditPath, auditHandler := auditlog.NewHandler(auditlog.Handler{
		Log: events, Service: service.Name, Authorize: oidcflow.AuditAuthorizer(cfg.AdminToken, cfg.AdminJWKSURL, nil),
	})
	mux.Handle(auditPath, oidcflow.RejectQueryTokens(auditHandler))
	mux.HandleFunc("GET "+service.DocumentPath+"{ref}", documentHandler(svc))
	if err := mountPages(mux, wiring{cfg: cfg, deps: deps, client: httpClient, capability: capability, events: events, issuance: svc}); err != nil {
		return nil, err
	}
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
		if _, err := w.Write(document); err != nil {
			return
		}
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

// wiring is what the pages share with the RPC service.
type wiring struct {
	cfg        config.Config
	deps       Deps
	client     connect.HTTPClient
	capability clients.Capability
	events     *auditlog.Log
	// issuance is the RPC service. The pages call it in process, so the
	// proxy never publishes it (ADR-047).
	issuance pages.Issuance
}

// mountPages adds the issuer home and its pages behind the staff guard,
// the shared assets, the DID document of a did:web issuer, and the
// redirect of the root (ADR-044 decision 1, ADR-046).
func mountPages(mux *http.ServeMux, wr wiring) error {
	cfg, deps, httpClient := wr.cfg, wr.deps, wr.client
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return err
	}
	guard, err := staffsession.Build(cfg.Auth, staffsession.IssuerRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, Now: deps.Now, Log: deps.Log,
	})
	if err != nil {
		return err
	}
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_ISSUER, Peers: cfg.Peers, Auth: cfg.Auth, PublicURL: cfg.PublicURL,
		SignOut: pages.SignOutPath, Prober: deps.Prober, Client: httpClient, Now: deps.Now,
	})
	opts := pages.Options{
		Kit: kit, Shell: shell, Capability: wr.capability, Schemas: deps.PageSchemas, Issued: deps.PageIssued,
		Identity: deps.PageIdentity, Trust: deps.Trust, Audit: wr.events, PublicURL: cfg.PublicURL, DocsURL: cfg.DocsURL, SignOut: signOut,
		Issuance: wr.issuance,
	}
	if opts.Identity == nil {
		opts.Identity = backendv1connect.NewIssuerBackendServiceClient(httpClient, cfg.AdapterURL)
	}
	if opts.Trust == nil {
		opts.Trust = func(url string) pages.Trust { return trustv1connect.NewTrustServiceClient(httpClient, url) }
	}
	if opts.Schemas == nil && cfg.SchemaURL != "" {
		opts.Schemas = schemav1connect.NewSchemaServiceClient(httpClient, cfg.SchemaURL)
	}
	if opts.Issued == nil && cfg.IssuedURL != "" {
		opts.Issued = issuedv1connect.NewIssuedServiceClient(httpClient, cfg.IssuedURL)
	}
	p, err := pages.New(opts)
	if err != nil {
		return err
	}
	staff := http.NewServeMux()
	p.Register(staff)
	guarded := guard.Wrap(staff)
	for _, prefix := range pages.Prefixes() {
		mux.Handle(prefix, guarded)
	}
	mux.Handle("GET "+ui.Prefix, assets)
	mux.Handle("GET "+pages.DIDDocumentPath, p.DIDDocument())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, pages.HomePath, http.StatusSeeOther)
	})
	return nil
}
