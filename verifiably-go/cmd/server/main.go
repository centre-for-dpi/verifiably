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
	"strings"
	"syscall"
	"time"

	"github.com/verifiably/verifiably-go/internal/adapters/factory"
	"github.com/verifiably/verifiably-go/internal/adapters/registry"
	"github.com/verifiably/verifiably-go/internal/handlers"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// wireIssuanceAndStatusLists initializes the on-disk audit log + the two
// status-list stores and binds them to the handler. Designed to be lossy:
// any error here disables the feature surface but doesn't block startup,
// because the rest of the demo (DPG picker, schema browser, holder/wallet
// flows) still works fine without revocation.
func wireIssuanceAndStatusLists(h *handlers.H) error {
	stateDir := os.Getenv("VERIFIABLY_STATE_DIR")
	if stateDir == "" {
		stateDir = "state"
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	logPath := filepath.Join(stateDir, "issued-credentials.json")
	logger, err := issuance.NewLog(logPath)
	if err != nil {
		return fmt.Errorf("open issuance log: %w", err)
	}
	h.IssuanceLog = logger

	// Public URL the verifier dereferences. VERIFIABLY_PUBLIC_URL is set
	// by deploy.sh to the browser-facing origin
	// ("http://172.24.0.1:8080" / "https://vc.bootcamp.cdpi.dev"); we
	// append the route shape exposed in mux.HandleFunc above.
	publicURL := strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/")
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
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

	tmpl, err := loadTemplates("templates")
	if err != nil {
		log.Fatalf("template load: %v", err)
	}

	// --- The adapter swap seam ---
	// Set VERIFIABLY_ADAPTER=registry to use live DPG backends declared in
	// config/backends.json; default "mock" keeps the in-memory demo adapter.
	adapter := selectAdapter()

	// Session store: persistent when VERIFIABLY_SESSION_SECRET is set.
	// The store flushes to VERIFIABLY_STATE_DIR/sessions/ every 5 s and
	// performs a final flush on SIGTERM/SIGINT. Without the secret the store
	// is in-memory only (original behaviour — fine for dev and bare-metal run).
	shutCtx, shutCancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer shutCancel()
	sessionStore := buildSessionStore()
	sessionStore.StartFlusher(shutCtx)

	authReg := buildAuthRegistry()
	wireAuthHelpers()
	translator := buildTranslator()
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
	}
	// Issuance audit log + revocation status lists. Optional: when the
	// state directory isn't writable we log and continue with the features
	// disabled (the list page returns 404, the issuance flow doesn't
	// allocate). VERIFIABLY_STATE_DIR defaults to ./state on bare metal
	// and /app/state in the docker image (Dockerfile mounts a volume there
	// so revocations survive container rebuilds).
	if err := wireIssuanceAndStatusLists(h); err != nil {
		log.Printf("status-list: feature disabled — %v", err)
	}

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
	// process is up. /readyz: same today; if a future startup step is
	// async, gate it on a sync.Once-set ready flag instead.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
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

	srv := &http.Server{Addr: addr, Handler: mux}

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
}

// buildSessionStore returns a persistent store backed by encrypted files in
// VERIFIABLY_STATE_DIR/sessions/. The encryption key is taken from
// VERIFIABLY_SESSION_SECRET; when that env var is absent the key is loaded
// from (or generated into) VERIFIABLY_STATE_DIR/session.key so the secret
// survives container restarts without operator intervention, as long as the
// state dir is on a persistent volume. Falls back to in-memory if the state
// dir is not writable.
func buildSessionStore() *handlers.Store {
	stateDir := os.Getenv("VERIFIABLY_STATE_DIR")
	if stateDir == "" {
		stateDir = "state"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Printf("session store: state dir not writable (%v), using in-memory store", err)
		return handlers.NewStore()
	}

	secret := os.Getenv("VERIFIABLY_SESSION_SECRET")
	if secret == "" {
		keyPath := filepath.Join(stateDir, "session.key")
		if data, err := os.ReadFile(keyPath); err == nil {
			secret = strings.TrimSpace(string(data))
		} else {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err == nil {
				secret = hex.EncodeToString(b)
				_ = os.WriteFile(keyPath, []byte(secret+"\n"), 0o600)
				log.Printf("session store: generated new session key at %s", keyPath)
			}
		}
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

// loadTemplates walks templates/ and parses every *.html file into a single tree
// with template names matching their {{define}} directives.
func loadTemplates(root string) (*template.Template, error) {
	var tmpl *template.Template
	fns := funcMap()
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
func funcMap() template.FuncMap {
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
		// t is the translation helper bound at parse time. Takes (text, lang)
		// — the current lang is passed in via `$.Lang` in templates.
		// handlers.TranslateFunc looks up the request-scoped translator +
		// context via package state set in handlers.(*H).render before
		// template execution.
		"t": handlers.TranslateFunc,

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
