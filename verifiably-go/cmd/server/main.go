// verifiably-go — Go + HTMX port of the Verifiable Credentials prototype.
//
// Architecture: this app is deliberately thin. Every handler is small, every
// template is focused, and every piece of fake data lives in internal/mock.
// Swap the backend by implementing the backend.Adapter interface and replacing
// the `mock.NewAdapter()` call below with your own.
//
// See README.md + docs/architecture.md for structure and docs/integration.md
// for endpoint-mapping details.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verifiably/verifiably-go/internal/adapters/factory"
	"github.com/verifiably/verifiably-go/internal/adapters/registry"
	"github.com/verifiably/verifiably-go/internal/handlers"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/jobs"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/internal/storage/pg"
	redisstore "github.com/verifiably/verifiably-go/internal/storage/redis"
	"github.com/verifiably/verifiably-go/internal/tracing"
	"github.com/verifiably/verifiably-go/vctypes"
)

// wireIssuanceAndStatusLists initializes the audit log + the two status-list
// stores. When pool is non-nil the PostgreSQL backends are used; otherwise the
// file-backed stores persist to VERIFIABLY_STATE_DIR.
// Designed to be lossy: errors disable the feature surface without blocking
// startup (the DPG picker, schema browser, and holder/wallet flows still work).
func wireIssuanceAndStatusLists(ctx context.Context, h *handlers.H, pool *pgxpool.Pool) error {
	publicURL := strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/")
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	if pool != nil {
		return wireIssuancePG(ctx, h, pool, publicURL)
	}
	return wireIssuanceFile(h, publicURL)
}

// wireIssuancePG wires PostgreSQL-backed stores.
func wireIssuancePG(_ context.Context, h *handlers.H, pool *pgxpool.Pool, publicURL string) error {

	h.IssuanceLog = pg.NewIssuanceLog(pool)

	bs, err := pg.NewStatusListStore(pool, "bitstring", "v1", publicURL+"/status-list/bitstring/v1")
	if err != nil {
		return fmt.Errorf("pg: bitstring store: %w", err)
	}
	h.BitstringStore = bs

	tk, err := pg.NewStatusListStore(pool, "token", "v1", publicURL+"/status-list/token/v1")
	if err != nil {
		return fmt.Errorf("pg: token store: %w", err)
	}
	h.TokenStore = tk
	return nil
}

// wireIssuanceFile wires the original file-backed stores.
func wireIssuanceFile(h *handlers.H, publicURL string) error {
	stateDir := os.Getenv("VERIFIABLY_STATE_DIR")
	if stateDir == "" {
		stateDir = "state"
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	logger, err := issuance.NewLog(filepath.Join(stateDir, "issued-credentials.json"))
	if err != nil {
		return fmt.Errorf("open issuance log: %w", err)
	}
	h.IssuanceLog = logger

	bs, err := statuslist.NewStore("bitstring", "v1",
		filepath.Join(stateDir, "status-list-bitstring-v1.json"),
		publicURL+"/status-list/bitstring/v1")
	if err != nil {
		return fmt.Errorf("open bitstring store: %w", err)
	}
	h.BitstringStore = bs

	tk, err := statuslist.NewStore("token", "v1",
		filepath.Join(stateDir, "status-list-token-v1.json"),
		publicURL+"/status-list/token/v1")
	if err != nil {
		return fmt.Errorf("open token store: %w", err)
	}
	h.TokenStore = tk
	return nil
}

// maskDSN replaces the password in a DSN with *** for log output.
func maskDSN(dsn string) string {
	// postgres://user:pass@host/db → postgres://user:***@host/db
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if j := strings.Index(rest, "@"); j >= 0 {
			creds := rest[:j]
			if k := strings.Index(creds, ":"); k >= 0 {
				return dsn[:i+3] + creds[:k+1] + "***" + rest[j:]
			}
		}
	}
	return dsn
}

func main() {
	// Structured JSON logs to stdout when running in a container (auto-detected
	// via VERIFIABLY_LOG_JSON=1). Default keeps the dev-friendly text format
	// for `go run`. Pipe to slog and route the legacy `log` package through
	// it so existing log.Printf calls also emit JSON.
	if os.Getenv("VERIFIABLY_LOG_JSON") == "1" {
		h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(h))
		log.SetFlags(0)
		log.SetOutput(slogWriter{})
	}

	addr := os.Getenv("VERIFIABLY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	debug := os.Getenv("VERIFIABLY_DEBUG_MOCK_MARKERS") == "1"

	// Build translator before templates so MakeTranslateFunc can capture it
	// in a closure registered in the FuncMap at parse time (no global state).
	translator := buildTranslator()

	tmpl, err := loadTemplates("templates", translator)
	if err != nil {
		log.Fatalf("template load: %v", err)
	}

	// --- The adapter swap seam ---
	// Set VERIFIABLY_ADAPTER=registry to use live DPG backends declared in
	// config/backends.json; default "mock" keeps the in-memory demo adapter.
	adapter := selectAdapter()

	shutCtx, shutCancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer shutCancel()

	// Open the PostgreSQL pool once (if configured) so sessions + issuance log
	// + status lists all share the same connection pool and migration run.
	var pgPool *pgxpool.Pool
	if dsn := os.Getenv("VERIFIABLY_DATABASE_URL"); dsn != "" {
		p, err := pg.Open(shutCtx, dsn)
		if err != nil {
			log.Printf("pg: failed to open (%v) — falling back to file-backed stores", err)
		} else {
			log.Printf("storage: PostgreSQL backend active (%s)", maskDSN(dsn))
			pgPool = p
		}
	}

	// Session store: PostgreSQL when pool is available, otherwise the file-backed
	// encrypted store (flushed every 5 s with a final flush on shutdown).
	sessionStore := buildSessionStore(shutCtx, pgPool)
	sessionStore.StartFlusher(shutCtx)

	authReg := buildAuthRegistry()
	wireAuthHelpers()
	authStore := buildAuthUserStore()
	adminMode := authAdminMode()
	h := &handlers.H{
		Adapter:       adapter,
		Sessions:      sessionStore,
		Templates:     tmpl,
		AuthReg:       authReg,
		Translator:    translator,
		Debug:         debug,
		AuthStore:     authStore,
		AuthAdminMode: adminMode,
		APIKeys:       handlers.ParseAPIKeys(os.Getenv("VERIFIABLY_API_KEYS")),
		RateLimiter:   handlers.NewRateLimiter(),
	}
	// Issuance audit log + revocation status lists. Optional: when the
	// state directory isn't writable we log and continue with the features
	// disabled (the list page returns 404, the issuance flow doesn't
	// allocate). VERIFIABLY_STATE_DIR defaults to ./state on bare metal
	// and /app/state in the docker image (Dockerfile mounts a volume there
	// so revocations survive container rebuilds).
	if err := wireIssuanceAndStatusLists(shutCtx, h, pgPool); err != nil {
		log.Printf("status-list: feature disabled — %v", err)
	}

	// Async bulk issuance job queue. Worker count is configurable via
	// VERIFIABLY_BULK_WORKERS (default 4). When PostgreSQL is available
	// the queue persists job state in bulk_jobs so in-flight jobs survive
	// a graceful restart (running jobs restart from pending on next boot).
	bulkWorkers := 4
	if wStr := os.Getenv("VERIFIABLY_BULK_WORKERS"); wStr != "" {
		if n, err := strconv.Atoi(wStr); err == nil && n > 0 {
			bulkWorkers = n
		}
	}
	h.BulkJobQueue = jobs.NewQueue(shutCtx, pgPool, bulkWorkers)
	log.Printf("bulk queue: %d workers (pg=%v)", bulkWorkers, pgPool != nil)

	// Distributed tracing. The global tracer is set before any handler runs
	// so tracing.Start() / tracing.Global() are safe to call from handlers.
	//
	// Export modes (stackable):
	//   VERIFIABLY_OTEL_ENDPOINT set → OTLP/HTTP JSON → Grafana Tempo / Jaeger
	//   Always → SlogExporter (one structured log line per span; Loki picks up
	//             trace_id for log-to-trace correlation without extra infra).
	//
	// Sample rate: VERIFIABLY_OTEL_SAMPLE_RATE (float 0.0-1.0, default 1.0).
	// Service name: VERIFIABLY_OTEL_SERVICE_NAME (default "verifiably-go").
	tracer := buildTracer(shutCtx)

	// /docs browser reads markdown from VERIFIABLY_DOCS_ROOT (set by the
	// Dockerfile to /app/docs-src — a snapshot of the repo's .md files).
	// Falls back to "." for bare-metal `go run` from the repo root.
	docsRoot := os.Getenv("VERIFIABLY_DOCS_ROOT")
	if docsRoot == "" {
		docsRoot = "."
	}
	if err := handlers.SetDocsRoot(docsRoot); err != nil {
		log.Printf("docs: SetDocsRoot(%q) failed: %v (TOC may be empty)", docsRoot, err)
	}

	mux := http.NewServeMux()

	// Liveness + readiness for K8s probes. /healthz: always 200 once the
	// process is up. /readyz: checks VERIFIABLY_READYZ_URL reachability (2 s
	// timeout) when the env var is set; 503 if the primary adapter is down.
	// /metrics: Prometheus text format; protected by API key when keys are configured.
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if len(h.APIKeys) > 0 {
			if _, ok := h.APIKeys.Authenticate(r); !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="verifiably"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		metrics.Handler().ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if targetURL := os.Getenv("VERIFIABLY_READYZ_URL"); targetURL != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
			if err != nil {
				http.Error(w, "readyz: bad VERIFIABLY_READYZ_URL", http.StatusServiceUnavailable)
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err != nil {
				http.Error(w, "adapter unreachable: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Static files
	staticFS := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", staticFS))

	// Offer-hosting route for adapters that stage credential_offer JSON
	// locally. Dispatches on /offers/{slug}/{id}; adapters store offers and
	// serve them by id through factory.OffersHandler.
	if reg, ok := adapter.(*registry.Registry); ok {
		mux.Handle("/offers/", factory.OffersHandler(reg))
	}

	// Landing + auth
	mux.HandleFunc("GET /{$}", h.Landing)
	mux.HandleFunc("POST /role", h.PickRole)
	mux.HandleFunc("GET /auth", h.Auth)
	mux.HandleFunc("POST /auth", h.CompleteAuth)
	mux.HandleFunc("POST /auth/start", h.StartAuth)
	mux.HandleFunc("POST /auth/custom", h.AddCustomProvider)
	mux.HandleFunc("GET /auth/callback", h.AuthCallback)
	mux.HandleFunc("POST /auth/logout", h.Logout)
	mux.HandleFunc("GET /admin/login", h.ShowAdminLogin)
	mux.HandleFunc("POST /admin/login", h.AdminLogin)
	mux.HandleFunc("POST /admin/logout", h.AdminLogout)
	mux.HandleFunc("GET /admin/auth-providers", h.ShowAuthProvidersAdmin)
	mux.HandleFunc("POST /admin/auth-providers/{id}/delete", h.DeleteAuthProvider)
	mux.HandleFunc("GET /lang", h.SetLang)
	mux.HandleFunc("POST /lang", h.SetLang)
	mux.HandleFunc("GET /qr", h.QRImage)
	mux.HandleFunc("GET /docs", h.DocsIndex)
	mux.HandleFunc("GET /docs/view", h.DocsView)

	// Inji Web integration: certify-nginx routes POST /v1/certify/issuance/credential
	// back to us at host.docker.internal:8080/inji-proxy/issuance/credential. We
	// forward straight to inji-certify:8090, patching the request body for wallets
	// that omit credential_definition.@context.
	mux.HandleFunc("POST /inji-proxy/issuance/credential", h.InjiProxyCredential)
	// did:web resolution split PER INJI CERTIFY INSTANCE. Each instance has
	// its own DID (did:web:certify-nginx for primary, did:web:certify-preauth-nginx
	// for pre-auth) and its own handler that fetches ONLY that instance's
	// upstream did.json — no merge, no ordering, no ambient kid-collision
	// risk. Each handler also synthesises verificationMethod aliases for
	// every kid the corresponding injidid.Observer has seen the instance
	// sign with, so Inji Verify's strict kid matcher can resolve the key.
	mux.HandleFunc("GET /inji-proxy/.well-known/did.json", h.InjiProxyPrimaryDidJSON)
	mux.HandleFunc("GET /inji-proxy-preauth/.well-known/did.json", h.InjiProxyPreauthDidJSON)
	// Bitstring status-list credentials are signed with a DIFFERENT kid than
	// the main VC (both derive from the same key, different code paths).
	// Proxy this endpoint too so rememberSigningKids() records the status-list
	// kid and our did.json advertises it before Inji Verify tries to resolve.
	mux.HandleFunc("GET /inji-proxy/credentials/status-list/{id}", h.InjiProxyStatusList)

	// Issuer
	mux.HandleFunc("GET /issuer/dpg", h.ShowIssuerDpgs)
	mux.HandleFunc("POST /issuer/dpg", h.PickIssuerDpg)
	mux.HandleFunc("POST /issuer/dpg/toggle", h.ToggleIssuerDpg)
	mux.HandleFunc("GET /issuer/schema", h.ShowSchemaBrowser)
	mux.HandleFunc("GET /issuer/schema/search", h.SchemaSearch)
	mux.HandleFunc("POST /issuer/schema/filter", h.SetSchemaFilter)
	mux.HandleFunc("POST /issuer/schema/expand", h.ToggleSchemaExpand)
	mux.HandleFunc("POST /issuer/schema/select", h.SelectSchema)
	mux.HandleFunc("POST /issuer/schema/delete", h.DeleteSchema)
	mux.HandleFunc("GET /issuer/schema/build", h.ShowSchemaBuilder)
	mux.HandleFunc("POST /issuer/schema/build/preview", h.SchemaPreview)
	mux.HandleFunc("POST /issuer/schema/build/add-field", h.AddSchemaField)
	mux.HandleFunc("POST /issuer/schema/build/remove-field", h.RemoveSchemaField)
	mux.HandleFunc("POST /issuer/schema/build/save", h.SaveSchema)
	mux.HandleFunc("GET /issuer/mode", h.ShowIssuanceMode)
	mux.HandleFunc("POST /issuer/mode", h.SetIssuanceMode)
	// Public status-list endpoints — verifiers GET these to check
	// revocation. Must be unauthenticated and survive any session cookie
	// gymnastics, hence registered before any auth middleware below.
	mux.HandleFunc("GET /status-list/bitstring/{id}", h.PublishBitstringStatusList)
	mux.HandleFunc("GET /status-list/token/{id}", h.PublishTokenStatusList)

	// Issued-credentials list page + Revoke action.
	mux.HandleFunc("GET /issuer/credentials", h.ShowIssuedCredentials)
	mux.HandleFunc("GET /issuer/credentials/search", h.IssuedCredentialsSearch)
	mux.HandleFunc("POST /issuer/credentials/{id}/revoke", h.RevokeIssuedCredential)

	mux.HandleFunc("GET /issuer/issue", h.ShowIssue)
	mux.HandleFunc("POST /issuer/issue", h.SubmitIssue)
	mux.HandleFunc("POST /issuer/issue/source", h.SetSingleSource)
	mux.HandleFunc("POST /issuer/issue/csv", h.SimulateCSV)
	mux.HandleFunc("POST /issuer/issue/bulk/source", h.BulkSource)
	mux.HandleFunc("POST /issuer/issue/bulk/api", h.BulkFromAPI)
	mux.HandleFunc("POST /issuer/issue/bulk/db", h.BulkFromDB)
	mux.HandleFunc("GET /issuer/issue/pdf/{id}", h.DownloadPDF)
	mux.HandleFunc("POST /issuer/issue/preview-pdf", h.PreviewPDF)

	// Holder / Wallet
	mux.HandleFunc("GET /holder/dpg", h.ShowHolderDpgs)
	mux.HandleFunc("POST /holder/dpg", h.PickHolderDpg)
	mux.HandleFunc("POST /holder/dpg/toggle", h.ToggleHolderDpg)
	mux.HandleFunc("GET /holder/wallet", h.ShowWallet)
	mux.HandleFunc("POST /holder/wallet/scan", h.ScanOffer)
	mux.HandleFunc("POST /holder/wallet/paste", h.PasteOffer)
	mux.HandleFunc("POST /holder/wallet/example", h.PrefillExample)
	mux.HandleFunc("POST /holder/wallet/accept", h.AcceptCred)
	mux.HandleFunc("POST /holder/wallet/reject", h.RejectCred)
	mux.HandleFunc("GET /holder/present", h.ShowPresent)
	mux.HandleFunc("POST /holder/present/confirm", h.ConfirmPresent)
	mux.HandleFunc("POST /holder/present/submit", h.SubmitPresent)
	mux.HandleFunc("POST /holder/present/decline", h.DeclinePresent)
	mux.HandleFunc("POST /holder/wallet/delete", h.DeleteCredential)

	// Verifier
	mux.HandleFunc("GET /verifier/dpg", h.ShowVerifierDpgs)
	mux.HandleFunc("POST /verifier/dpg", h.PickVerifierDpg)
	mux.HandleFunc("POST /verifier/dpg/toggle", h.ToggleVerifierDpg)
	mux.HandleFunc("GET /verifier/verify", h.ShowVerify)
	mux.HandleFunc("POST /verifier/verify/request", h.GenerateRequest)
	mux.HandleFunc("POST /verifier/verify/response", h.SimulateResponse)
	mux.HandleFunc("POST /verifier/verify/direct", h.VerifyDirect)
	mux.HandleFunc("POST /verifier/verify/build", h.BuildVerifierTemplate)

	// REST API — /api/v1/*
	// Auth: Authorization: Bearer <key> (VERIFIABLY_API_KEYS env var).
	mux.HandleFunc("POST /api/v1/credentials/issue/bulk/async", h.APIIssueBulkAsync)
	mux.HandleFunc("GET /api/v1/bulk/{jobID}/events", h.APIBulkJobEvents)
	mux.HandleFunc("GET /api/v1/bulk/{jobID}", h.APIBulkJobStatus)
	mux.HandleFunc("POST /api/v1/credentials/issue/bulk", h.APIIssueBulk)
	mux.HandleFunc("POST /api/v1/credentials/issue", h.APIIssue)
	mux.HandleFunc("GET /api/v1/credentials", h.APIListCredentials)
	mux.HandleFunc("GET /api/v1/credentials/{id}", h.APIGetCredential)
	mux.HandleFunc("POST /api/v1/credentials/{id}/revoke", h.APIRevoke)
	mux.HandleFunc("POST /api/v1/credentials/{id}/reinstate", h.APIReinstate)
	mux.HandleFunc("POST /api/v1/verify/request", h.APIVerifyRequest)
	mux.HandleFunc("GET /api/v1/verify/result/{state}", h.APIVerifyResult)

	// API docs — redirect to static files already served by the staticFS handler.
	mux.HandleFunc("GET /api/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/scalar.html", http.StatusFound)
	})
	mux.HandleFunc("GET /api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/openapi.yaml", http.StatusFound)
	})

	// Wrap the mux with tracing (outermost) then request-ID. Order matters:
	// tracing middleware creates the root span for every request; the request-ID
	// middleware runs inside it so the request-id attribute appears on the span.
	srv := &http.Server{Addr: addr, Handler: tracing.Middleware(tracer)(withRequestID(mux))}

	go func() {
		log.Printf("verifiably-go listening on %s (debug markers: %v)", addr, debug)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-shutCtx.Done()
	log.Printf("verifiably-go shutting down …")
	// Allow up to 10 s for in-flight requests to drain, then hard-close.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("verifiably-go forced shutdown: %v", err)
	}
	// Flush any buffered spans to the OTLP collector before exiting.
	if err := tracer.Shutdown(drainCtx); err != nil {
		log.Printf("tracing: shutdown: %v", err)
	}
}

// buildTracer initialises the process-wide tracer from environment variables
// and installs it via tracing.SetGlobal. Logs the active configuration.
func buildTracer(_ context.Context) *tracing.Tracer {
	svcName := os.Getenv("VERIFIABLY_OTEL_SERVICE_NAME")
	if svcName == "" {
		svcName = "verifiably-go"
	}

	sampleRate := 1.0
	if s := os.Getenv("VERIFIABLY_OTEL_SAMPLE_RATE"); s != "" {
		if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f <= 1 {
			sampleRate = f
		}
	}

	// Always include the slog exporter for Loki log-to-trace correlation.
	var exp tracing.SpanExporter = tracing.SlogExporter{}

	if endpoint := os.Getenv("VERIFIABLY_OTEL_ENDPOINT"); endpoint != "" {
		otlp := tracing.NewOTLPExporter(endpoint)
		exp = tracing.CombinedExporter{exp, otlp}
		log.Printf("tracing: OTLP → %s (service=%s sample=%.2f)", endpoint, svcName, sampleRate)
	} else {
		log.Printf("tracing: slog-only (set VERIFIABLY_OTEL_ENDPOINT for OTLP; service=%s sample=%.2f)", svcName, sampleRate)
	}

	t := tracing.NewTracer(svcName, sampleRate, exp)
	tracing.SetGlobal(t)
	return t
}

// buildSessionStore returns a persistent store backed by encrypted files in
// VERIFIABLY_STATE_DIR/sessions/. The encryption key is taken from
// VERIFIABLY_SESSION_SECRET; when that env var is absent the key is loaded
// from (or generated into) VERIFIABLY_STATE_DIR/session.key so the secret
// survives container restarts without operator intervention. Session blobs are
// encrypted (AES-256-GCM) in all backends — file, PG, and Redis — using the
// same derived key, so a credential leak of any backing store does not expose
// live OAuth tokens.
//
// Backend priority order:
//  1. VERIFIABLY_REDIS_URL set → Redis (true multi-replica; pair with Caddy cookie lb)
//  2. pool (VERIFIABLY_DATABASE_URL) non-nil → PostgreSQL (restart-safe, single-replica)
//  3. VERIFIABLY_SESSION_SECRET set → encrypted file store (single-replica)
//  4. otherwise → in-memory only (dev/test)
func buildSessionStore(_ context.Context, pool *pgxpool.Pool) handlers.SessionStore {
	// Derive the AES key from the session secret early — all backends need it.
	stateDir := os.Getenv("VERIFIABLY_STATE_DIR")
	if stateDir == "" {
		stateDir = "state"
	}
	secret := os.Getenv("VERIFIABLY_SESSION_SECRET")
	if secret == "" {
		keyPath := filepath.Join(stateDir, "session.key")
		if data, err := os.ReadFile(keyPath); err == nil {
			secret = strings.TrimSpace(string(data))
		} else {
			_ = os.MkdirAll(stateDir, 0o700)
			b := make([]byte, 32)
			if _, err := rand.Read(b); err == nil {
				secret = hex.EncodeToString(b)
				_ = os.WriteFile(keyPath, []byte(secret+"\n"), 0o600)
				log.Printf("session store: generated new session key at %s", keyPath)
			}
		}
	}
	var aesKey []byte
	if secret != "" {
		k := sha256.Sum256([]byte(secret))
		aesKey = k[:]
	} else {
		log.Printf("session store: WARNING — no session secret; sessions will be stored unencrypted")
	}

	if redisURL := os.Getenv("VERIFIABLY_REDIS_URL"); redisURL != "" {
		client, err := redisstore.Dial(redisURL)
		if err != nil {
			log.Printf("session store: redis unavailable (%v), trying postgres/file", err)
		} else {
			log.Printf("session store: using Redis backend (encrypted=%v)", aesKey != nil)
			return redisstore.NewSessionStore(client, aesKey)
		}
	}

	if pool != nil {
		log.Printf("session store: using PostgreSQL backend (encrypted=%v)", aesKey != nil)
		return pg.NewSessionStore(pool, aesKey)
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Printf("session store: state dir not writable (%v), using in-memory store", err)
		return handlers.NewStore()
	}
	if secret == "" {
		log.Printf("session store: cannot obtain session secret, using in-memory store")
		return handlers.NewStore()
	}
	return handlers.NewPersistentStore(filepath.Join(stateDir, "sessions"), secret)
}

// slogWriter routes legacy `log` package output through slog so JSON mode
// captures every existing log.Printf call without rewriting them.
type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	slog.Info(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// ctxKeyRequestID is the context key for the per-request ID.
type ctxKeyRequestID struct{}

// withRequestID generates a unique X-Request-ID for every inbound request,
// echoes it in the response header, and stores it in the context so handlers
// can include it in log attributes. If the client already sends X-Request-ID
// we propagate it unchanged (enables tracing across service boundaries).
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID{}, id)))
	})
}

// loadTemplates walks templates/ and parses every *.html file into a single tree
// with template names matching their {{define}} directives.
func loadTemplates(root string, tr handlers.Translator) (*template.Template, error) {
	var tmpl *template.Template
	fns := funcMap(tr)
	// render lets the layout dispatch to a content sub-template by name
	// (html/template's built-in {{template}} action requires a constant name).
	fns["render"] = func(name string, data any) (template.HTML, error) {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}
	tmpl = template.New("").Funcs(fns)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".html") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tmpl.Parse(string(b))
		return err
	})
	return tmpl, err
}

// funcMap exposes small helpers to templates. Kept minimal — if this grows
// past a dozen entries, move to its own file.
func funcMap(tr handlers.Translator) template.FuncMap {
	return template.FuncMap{
		"titleIf": func(cond bool, s string) string {
			if cond {
				return s
			}
			return ""
		},
		"hasPrefix":         strings.HasPrefix,
		"replaceUnderscore": func(s string) string { return strings.ReplaceAll(s, "_", " ") },
		"trimPrefix":        strings.TrimPrefix,

		// list builds an []any from the args so templates can range over
		// inline literal sequences. Usage: {{range list "a" "b" "c"}}.
		"list": func(args ...any) []any { return args },

		// jsonRows marshals arbitrary data to a JSON literal the bulk-result
		// fragment embeds into its <script> block so client-side handlers
		// (copy-all, download-CSV) can operate on the per-row data without
		// a round trip. html/template escapes the result safely for <script>
		// context.
		"jsonRows": func(v any) template.JS {
			b, err := json.Marshal(v)
			if err != nil {
				return template.JS("[]")
			}
			return template.JS(b)
		},

		// dict builds a map[string]any from alternating key/value args so templates
		// can pass multiple named params into sub-templates.
		// Usage: {{template "partial" (dict "K1" v1 "K2" v2)}}
		// t is the translation helper. Takes (text, lang); lang comes from $.Lang.
		// MakeTranslateFunc captures tr at startup — no per-request global state.
		"t": handlers.MakeTranslateFunc(tr),

		// hasCapability returns true if the given DPG declares a capability
		// with the given Kind+Key. Templates use it to hide flow-specific UI
		// surfaces when the backing DPG doesn't support them, e.g. hiding the
		// "paste credential" card on a verifier that has no direct-verify
		// endpoint.
		"hasCapability": func(dpg vctypes.DPG, kind, key string) bool {
			for _, c := range dpg.Capabilities {
				if c.Kind == kind && c.Key == key {
					return true
				}
			}
			return false
		},

		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, fmt.Errorf("dict requires even number of args, got %d", len(pairs))
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict key at position %d is not a string", i)
				}
				m[key] = pairs[i+1]
			}
			return m, nil
		},

		// deref dereferences a pointer-to-struct so templates can feed the
		// value into sub-template calls. Returns the zero value if nil.
		"deref": func(p *vctypes.OID4VPTemplate) vctypes.OID4VPTemplate {
			if p == nil {
				return vctypes.OID4VPTemplate{}
			}
			return *p
		},

		// indexSchemas looks up a schema by ID (or variant id) in a slice.
		// After the grouped-by-name refactor, the primary Schema.ID only
		// matches the default variant; non-default variant ids live on the
		// Variants slice, so match against either and return the schema
		// with ID+Std swapped to the picked variant.
		"indexSchemas": func(schemas []vctypes.Schema, id string) vctypes.Schema {
			for _, s := range schemas {
				if s.HasVariantID(id) {
					return s.ApplyVariant(id)
				}
			}
			return vctypes.Schema{}
		},

		// fieldSet returns a lookup map from a []string so templates can
		// use {{index $.Selected .Name}} without iterating the slice per field.
		"fieldSet": func(xs []string) map[string]bool {
			out := make(map[string]bool, len(xs))
			for _, x := range xs {
				out[x] = true
			}
			return out
		},

		// schemaStdList returns the distinct Std values across a []Schema
		// slice in stable sorted order. Used to render the filter chips
		// above the verifier's schema picker without hardcoding format
		// names in the template.
		"schemaStdList": func(schemas []vctypes.Schema) []string {
			seen := map[string]struct{}{}
			for _, s := range schemas {
				if s.Std != "" {
					seen[s.Std] = struct{}{}
				}
			}
			out := make([]string, 0, len(seen))
			for k := range seen {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		},

		// lowerStr lowercases a string so a data-attribute can hold a
		// pre-normalised search corpus — the client-side filter does a
		// case-insensitive substring match without per-option work.
		"lowerStr": strings.ToLower,

		// uniqueTitles returns the distinct Title values across a credential
		// list, sorted alphabetically.
		"uniqueTitles": func(creds []vctypes.Credential) []string {
			seen := map[string]bool{}
			out := []string{}
			for _, c := range creds {
				if c.Title != "" && !seen[c.Title] {
					seen[c.Title] = true
					out = append(out, c.Title)
				}
			}
			sort.Strings(out)
			return out
		},

		// uniqueFormats returns the distinct wire-format values (e.g.
		// "jwt_vc_json", "vc+sd-jwt", "ldp_vc") across a credential list,
		// sorted. Used by the wallet's format-filter dropdown — more
		// actionable than filtering by type because the verifier's
		// limit_disclosure match is format-specific.
		"uniqueFormats": func(creds []vctypes.Credential) []string {
			seen := map[string]bool{}
			out := []string{}
			for _, c := range creds {
				if c.Format != "" && !seen[c.Format] {
					seen[c.Format] = true
					out = append(out, c.Format)
				}
			}
			sort.Strings(out)
			return out
		},
	}
}
