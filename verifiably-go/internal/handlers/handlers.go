package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/didresolver"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/jobs"
	"github.com/verifiably/verifiably-go/internal/schemacache"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/internal/statuslistcache"
	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/internal/verification"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Translator is the shim the handlers use to translate UI strings. Injected by
// main so the handlers package doesn't depend on internal/adapters/*.
type Translator interface {
	Translate(ctx context.Context, text, target string) string
}

// MemberVerifierRegistrar wires a new federation member's verifier adapter
// into the Hub's live Registry + SchemaCache without a restart.
// Implemented in cmd/server/main.go; the handlers package stays import-free
// of the concrete adapter/factory packages.
type MemberVerifierRegistrar interface {
	// RegisterMemberVerifier builds a "verifiably"-type adapter for the
	// given member and registers it under did as the vendor key. Idempotent.
	RegisterMemberVerifier(did, serviceEndpoint, apiKey string)
}

// H is the handler struct; holds deps injected from main.
type H struct {
	Adapter    backend.Adapter
	Sessions   SessionStore
	Templates  *template.Template
	AuthReg    *auth.Registry
	Translator Translator
	Debug      bool // DEBUG_SHOW_MOCK_MARKERS equivalent

	// AuthStore persists OIDC providers added via /auth/custom across
	// deploy runs. Wired in every admin mode (including "off") because
	// persistence is independent of the admin surface — locking down
	// the admin page should never silently disable user adds.
	AuthStore *auth.UserStore
	// AuthAdminMode gates the admin auth-providers UI:
	//   "rw"  — list + add + edit + delete (default)
	//   "ro"  — list only; mutating POSTs return 403
	//   "off" — page route 404s, nav link hidden
	// Anything else is treated as "rw". Honored by ShowAuthProvidersAdmin
	// + AddAuthProvider + DeleteAuthProvider.
	AuthAdminMode string

	// IssuanceLog is the audit log of every credential the operator has
	// issued through the /issuer/issue flow. Powers /issuer/credentials
	// (list page) and Revoke. Optional — when nil the list page returns 404
	// and the issuance flow simply doesn't record (back-compat with tests
	// + the mock adapter integration).
	IssuanceLog issuance.Backend

	// BitstringStore is the W3C Bitstring Status List 2023 the verifiably-go
	// instance hosts for VCDM 2.0 credentials it issues. Optional; nil
	// disables W3C revocation end-to-end.
	BitstringStore statuslist.Backend

	// TokenStore is the IETF Token Status List the instance hosts for
	// SD-JWT VCs it issues. Optional; nil disables SD-JWT revocation.
	TokenStore statuslist.Backend

	// Subjects upserts dynamic claims into the Inji auth-code data-provider
	// table (certify.vc_subject), keyed by the eSignet subject id. Powers
	// POST /api/v1/subjects. Optional - nil when INJI_CERTIFY_DATABASE_URL is
	// unset (the endpoint then returns 503).
	Subjects SubjectProvisioner

	// APIKeys gates /api/v1/* endpoints. Populated from VERIFIABLY_API_KEYS
	// ("name1:key1,name2:key2"). When nil or empty, all API routes return 503.
	APIKeys APIKeyMap

	// RateLimiter throttles POST /api/v1/credentials/issue and .../bulk.
	// Built from VERIFIABLY_RATE_KEY_RPM (default 60/min) and
	// VERIFIABLY_RATE_IP_RPM (default 20/min). nil disables rate limiting.
	RateLimiter *RateLimiter

	// BulkJobQueue is the async worker pool for bulk credential issuance.
	// When non-nil, POST /api/v1/credentials/issue/bulk/async submits a job
	// and returns 202 immediately; the client polls .../bulk/{id} or streams
	// .../bulk/{id}/events for progress. nil falls back to the synchronous
	// /api/v1/credentials/issue/bulk endpoint.
	BulkJobQueue *jobs.Queue

	// TrustRegistry is the national trust registry used to validate issuer
	// DIDs during credential verification. When non-nil, every terminal
	// OID4VP result and every VerifyDirect call checks the Issuer DID
	// against the registry and populates VerificationResult.TrustStatus.
	// nil disables trust-registry checks (all results show TrustStatus="").
	// TrustJWTSecret is the HMAC key used to sign the /trust-registry JWT (HS256 dev path).
	TrustRegistry  trust.Registry
	TrustJWTSecret []byte
	TrustJWTIssuer string
	// TrustSigningKey is the ECDSA P-256 private key for ES256 JWT signing.
	// When non-nil, GET /trust-registry uses ES256 and GET /.well-known/jwks.json
	// exposes the matching public key. When nil, falls back to HS256 (dev only).
	// Set from VERIFIABLY_TRUST_SIGNING_KEY (PEM); an ephemeral key is generated
	// when the env var is absent so the endpoint always works.
	TrustSigningKey *ecdsa.PrivateKey
	// DIDResolver resolves did:web DIDs to their DID Documents.
	// Used by status list verification (Fase 10) and federation validation (Fase 5).
	// Wired at startup with a WebResolver (10-minute document cache).
	DIDResolver didresolver.Resolver

	// StatusListCache holds cached copies of trusted issuers' status list JWTs.
	// Wired in Hub mode by cmd/server/main.go; nil disables the availability check
	// on the public /verify portal (StatusListSource will be "" for all results).
	StatusListCache statuslistcache.Cache

	// SchemaCache aggregates schemas from all federation members (Hub mode).
	// When non-nil, ShowPublicVerify uses the federated schema list and
	// PublicVerifyRequest routes by SourceDeployment to the correct adapter.
	// Wired at startup in hub mode by cmd/server/main.go.
	SchemaCache *schemacache.Aggregator

	// VerificationLog records completed verification events for ecosystem
	// analytics (Fase 6). PostgreSQL-backed in Hub mode; nil disables logging
	// so file-only deployments work without a DB. Events are written in a
	// fire-and-forget goroutine — errors are logged but never block the response.
	VerificationLog verification.Log

	// TrustHealthMonitor probes registered issuers' /healthz endpoints every
	// 5 minutes and emits trusted_issuer_endpoint_up / trusted_issuer_days_until_expiry
	// Prometheus gauges (Fase 9). In-memory status is used to render the health
	// semaphore in the admin federation page. nil disables health monitoring.
	TrustHealthMonitor *trust.Monitor

	// IssuerAPIKeyStore manages per-issuer API keys for the ecosystem
	// analytics API (Fase 7). PostgreSQL-backed; nil when no DB is available
	// (disables GET /api/ecosystem/issuers/{did}/stats and the key management
	// UI in admin federation). Keys are stored as SHA-256 hashes; plaintext
	// is shown once at generation time and never stored.
	IssuerAPIKeyStore trust.APIKeyStore

	// PrometheusURL is the base URL of the Prometheus server used to back
	// the /admin/metrics UI with persistent historical data.
	// Example: "http://prometheus:9090". Set via VERIFIABLY_PROMETHEUS_URL.
	// When empty the admin metrics page falls back to in-process counters.
	PrometheusURL string

	// GrafanaURL is the Grafana base URL shown as a link on /admin/metrics.
	// Example: "http://localhost:3100". Set via VERIFIABLY_GRAFANA_URL.
	GrafanaURL string

	// RegistryAdminURL is the browser-facing URL of the Registry Admin console
	// (the data-source / registrar tier that populates the Sunbird RC registry
	// backing Inji credentials). Set via VERIFIABLY_REGISTRY_ADMIN_URL by
	// deploy.sh (per-host: https://registry-admin.<domain> in subdomain mode).
	// When empty, the navbar "Registry" link is hidden.
	RegistryAdminURL string

	// IsHub is true when the server is running in hub mode (VERIFIABLY_ROLES=hub).
	// Controls which admin sections are shown in the nav and landing page.
	IsHub bool

	// ShowIssuer / ShowHolder / ShowVerifier reflect which roles are active
	// (parsed from VERIFIABLY_ROLES). Used to conditionally render role cards
	// on the landing page. All three default to true when VERIFIABLY_ROLES is unset.
	ShowIssuer   bool
	ShowHolder   bool
	ShowVerifier bool

	// MemberVerifierRegistrar wires a federation member's verifier adapter at
	// runtime when the admin registers a new member. Set by main.go in hub mode;
	// nil disables dynamic adapter registration (member takes effect on restart).
	MemberVerifierRegistrar MemberVerifierRegistrar

	// signingKeyMu guards lazy fetching of the walt.id issuer JWK.
	// After a successful fetch signingKey is non-nil and the hot path
	// takes only an RLock. Errors are NOT cached — each failed attempt
	// retries on the next /status-list/* request so the feature self-heals
	// when walt.id comes up after a slow compose-up.
	signingKeyMu sync.RWMutex
	signingKey   *statuslist.SigningKey
}

// isHTMX returns true if the request came from HTMX.
// externalScheme returns "http" or "https" honoring X-Forwarded-Proto when
// the request came through a reverse proxy (Caddy, nginx). Falls back to
// inspecting r.TLS for direct connections.
func externalScheme(r *http.Request) string {
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		// Take the first value if the header is comma-separated (chained proxies).
		if i := strings.IndexByte(xfp, ','); i >= 0 {
			xfp = xfp[:i]
		}
		return strings.TrimSpace(xfp)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// externalHost returns the hostname the client used, preferring X-Forwarded-Host
// from a reverse proxy over r.Host (which is the internal upstream's view).
func externalHost(r *http.Request) string {
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		if i := strings.IndexByte(xfh, ','); i >= 0 {
			xfh = xfh[:i]
		}
		return strings.TrimSpace(xfh)
	}
	return r.Host
}

// publicBase returns the browser-facing origin used to build absolute URLs
// such as OIDC redirect URIs. VERIFIABLY_PUBLIC_URL is the authoritative
// source (set by deploy.sh to the actual public domain); this avoids trusting
// X-Forwarded-Host from potentially untrusted clients. Falls back to
// externalScheme + externalHost when the env var is unset (dev/bare-metal).
func publicBase(r *http.Request) string {
	if pub := strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/"); pub != "" {
		return pub
	}
	return externalScheme(r) + "://" + externalHost(r)
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// render executes a template. For full page loads it wraps content_<page>
// inside the "layout" template. For HTMX boost targets it renders just the
// content block so it can replace the <main> element directly.
//
// When Lang != "en", the rendered HTML is walked and every user-visible text
// node + translatable attribute (title/placeholder/alt/aria-label) is
// translated. This is a safety net: explicit {{t "..."}} wrappers in the
// templates still win via the cache, and text nodes that were missed by the
// template author still get translated at render time.
func (h *H) render(w http.ResponseWriter, r *http.Request, page string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.ContentTemplate = "content_" + page
	if data.Title == "" {
		data.Title = titleFor(page)
	}
	if data.Crumb == "" {
		data.Crumb = crumbFor(page)
	}
	if data.Lang == "" {
		data.Lang = h.langFor(r)
	}
	name := "layout"
	if isHTMX(r) && r.Header.Get("HX-Target") == "main" {
		name = data.ContentTemplate
	}

	if data.Lang == "" || data.Lang == "en" || h.Translator == nil {
		if err := h.Templates.ExecuteTemplate(w, name, data); err != nil {
			log.Printf("template error (page=%s, name=%s): %v", page, name, err)
			http.Error(w, "internal server error", 500)
		}
		return
	}
	// Non-English: capture, walk, translate, then write.
	var buf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("template error (page=%s, name=%s): %v", page, name, err)
		http.Error(w, "internal server error", 500)
		return
	}
	translated := translateHTML(r.Context(), buf.Bytes(), data.Lang, h.Translator)
	_, _ = w.Write(translated)
}

// MakeTranslateFunc returns the `t` template helper bound to tr. Call once at
// startup and register the result in the funcMap. Because tr is fixed after
// startup (it is h.Translator, which is never replaced), the closure has no
// mutable state — all package-level globals and the installTranslatorForRequest
// pattern are gone, eliminating the race under concurrent requests.
//
// The context passed to tr.Translate is context.Background() because the `t`
// function signature is fixed by html/template (it receives only the text and
// lang arguments); request cancellation is handled at the translateHTML layer.
func MakeTranslateFunc(tr Translator) func(string, string) string {
	return func(text, lang string) string {
		if tr == nil || lang == "" || lang == "en" {
			return text
		}
		return tr.Translate(context.Background(), text, lang)
	}
}

// renderFragment renders a named sub-template directly (for HTMX partial swaps).
// Applies the same post-render translation pass as render() when a non-English
// language is active, keyed off the verifiably_lang cookie on the request.
func (h *H) renderFragment(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	lang := h.langFor(r)
	if lang == "" || lang == "en" || h.Translator == nil {
		if err := h.Templates.ExecuteTemplate(w, name, data); err != nil {
			log.Printf("fragment error (%s): %v", name, err)
			http.Error(w, "internal server error", 500)
		}
		return
	}
	var buf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("fragment error (%s): %v", name, err)
		http.Error(w, "internal server error", 500)
		return
	}
	_, _ = w.Write(translateHTML(r.Context(), buf.Bytes(), lang, h.Translator))
}

// renderFragments renders multiple named sub-templates to the response in order.
// Use when a handler needs to return a primary fragment + one or more hx-swap-oob
// fragments concatenated together.
func (h *H) renderFragments(w http.ResponseWriter, r *http.Request, data any, names ...string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	lang := h.langFor(r)
	translating := lang != "" && lang != "en" && h.Translator != nil
	for _, name := range names {
		if !translating {
			if err := h.Templates.ExecuteTemplate(w, name, data); err != nil {
				log.Printf("fragment error (%s): %v", name, err)
				http.Error(w, "internal server error", 500)
				return
			}
			continue
		}
		var buf bytes.Buffer
		if err := h.Templates.ExecuteTemplate(&buf, name, data); err != nil {
			log.Printf("fragment error (%s): %v", name, err)
			http.Error(w, "internal server error", 500)
			return
		}
		_, _ = w.Write(translateHTML(r.Context(), buf.Bytes(), lang, h.Translator))
	}
}

// PageData is the common view model passed to page templates.
type PageData struct {
	Title           string
	Crumb           string
	ContentTemplate string
	Debug           bool
	Session         *Session
	Body            any    // page-specific sub-data
	FlashToast      string // one-shot toast message via HX-Trigger header alternative
	Lang            string // current UI language code from the verifiably_lang cookie
	// AuthAdminAvailable is true when H.AuthAdminMode != "off" so the
	// topbar can hide the "Admin" link on deployments that disabled it
	// entirely. Independent of any session state — the link goes to
	// /admin/login when the visitor isn't already an admin, and to
	// /admin when they are.
	AuthAdminAvailable bool
	// IsHub is true when running in hub mode. Templates use this to render
	// hub-specific navigation links (Federation, Trust, Providers, Metrics).
	IsHub bool

	// RegistryAdminURL is the public URL of the Registry Admin console, surfaced
	// as the navbar "Registry" link when non-empty (see H.RegistryAdminURL).
	RegistryAdminURL string

	// ShowIssuer / ShowHolder / ShowVerifier mirror the active VERIFIABLY_ROLES
	// so templates can hide role cards that are not enabled on this deployment.
	ShowIssuer   bool
	ShowHolder   bool
	ShowVerifier bool
}

// langFromRequest returns the current UI language code (default "en") from
// the verifiably_lang cookie.
func langFromRequest(r *http.Request) string {
	if c, err := r.Cookie("verifiably_lang"); err == nil {
		return c.Value
	}
	return "en"
}

// SetLang is GET/POST /lang — switches the user's UI language.
func (h *H) SetLang(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("lang")
	if code == "" {
		code = r.URL.Query().Get("lang")
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "verifiably_lang",
		Value:    code,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   365 * 24 * 3600,
	})
	// Redirect back to the referrer's path-only component so the new language
	// takes effect on an immediate re-render. We parse and discard the origin
	// to prevent an open redirect: only the path (+ query + fragment) is used.
	dest := "/"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Path != "" {
			dest = u.RequestURI() // path?query#fragment, no scheme/host
		}
	}
	h.redirect(w, r, dest)
}

func (h *H) pageData(sess *Session, body any) PageData {
	return PageData{
		Debug:              h.Debug,
		Session:            sess,
		Body:               body,
		AuthAdminAvailable: h.AuthAdminMode != "off",
		IsHub:              h.IsHub,
		RegistryAdminURL:   h.RegistryAdminURL,
		ShowIssuer:         h.ShowIssuer,
		ShowHolder:         h.ShowHolder,
		ShowVerifier:       h.ShowVerifier,
	}
}

// langFor returns the current lang code from the request and stores it on the
// session so handlers can feed it into Translator.Translate when needed.
func (h *H) langFor(r *http.Request) string {
	return langFromRequest(r)
}

func titleFor(page string) string {
	return map[string]string{
		"landing":               "",
		"auth":                  "Sign in",
		"issuer_dpg":            "Issuer · DPG",
		"issuer_schema":         "Issuer · Schema",
		"issuer_schema_builder": "Issuer · Build schema",
		"issuer_mode":           "Issuer · Mode",
		"issuer_issue":          "Issuer · Issue",
		"issuer_credentials":    "Issuer · My credentials",
		"issuer_issued_log":     "Issuer · Issued credentials",
		"holder_dpg":            "Holder · Wallet",
		"holder_wallet":         "Wallet",
		"holder_present":        "Present credential",
		"verifier_dpg":          "Verifier · Engine",
		"verifier_verify":       "Verify",
		"redirect_notice":       "Redirect",
		"docs_index":            "Docs",
		"docs_view":             "Docs",
		"admin_login":           "Admin · Sign in",
		"admin_auth_providers":  "Admin · OIDC providers",
		"admin_trust":           "Admin · Trust registry",
		"admin_metrics":         "Admin · Metrics",
		"admin_federation":      "Admin · Federation",
		"public_verify":         "Verificar",
	}[page]
}

func crumbFor(page string) string {
	return map[string]string{
		"landing":               "",
		"auth":                  "role → auth",
		"issuer_dpg":            "issuer → dpg",
		"issuer_schema":         "issuer → schema",
		"issuer_schema_builder": "issuer → schema → build",
		"issuer_mode":           "issuer → mode",
		"issuer_issue":          "issuer → issue",
		"issuer_credentials":    "issuer → my credentials",
		"issuer_issued_log":     "issuer → issued credentials",
		"holder_dpg":            "holder → wallet",
		"holder_wallet":         "holder → wallet",
		"holder_present":        "holder → present",
		"verifier_dpg":          "verifier → engine",
		"verifier_verify":       "verifier → verify",
		"redirect_notice":       "redirect",
		"docs_index":            "docs",
		"docs_view":             "docs",
		"admin_login":           "admin → sign in",
		"admin_auth_providers":  "admin → auth providers",
		"admin_trust":           "admin → trust registry",
		"admin_metrics":         "admin → metrics",
	}[page]
}

// --- Routes ---

func (h *H) Landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	// Union of all configured DPGs across issuer/holder/verifier — powers the
	// landing page's version disclosure without naming any specific vendor.
	dpgs := h.allDPGs(r)
	h.render(w, r, "landing", h.pageData(sess, map[string]any{
		"DPGs": dpgs,
	}))
}

// allDPGs returns the deduped set of DPG entries across every role, used on
// vendor-agnostic pages like the landing disclosure.
func (h *H) allDPGs(r *http.Request) []vendorDesc {
	ctx := r.Context()
	seen := map[string]struct{}{}
	var out []vendorDesc
	add := func(m map[string]vctypes.DPG) {
		for _, d := range m {
			if _, dup := seen[d.Vendor+d.Version]; dup {
				continue
			}
			seen[d.Vendor+d.Version] = struct{}{}
			out = append(out, vendorDesc{Vendor: d.Vendor, Version: d.Version})
		}
	}
	if i, err := h.Adapter.ListIssuerDpgs(ctx); err == nil {
		add(i)
	}
	if hh, err := h.Adapter.ListHolderDpgs(ctx); err == nil {
		add(hh)
	}
	if v, err := h.Adapter.ListVerifierDpgs(ctx); err == nil {
		add(v)
	}
	return out
}

type vendorDesc struct {
	Vendor, Version string
}

// PickRole is POST /role — sets role and redirects to /auth.
func (h *H) PickRole(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	role := r.FormValue("role")
	if role != "issuer" && role != "holder" && role != "verifier" {
		http.Error(w, "invalid role", 400)
		return
	}
	sess.Role = role
	h.redirect(w, r, "/auth")
}

// Auth renders the auth page. The provider list is whatever the auth registry
// holds — handlers never name providers directly.
func (h *H) Auth(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.Role == "" {
		h.redirect(w, r, "/")
		return
	}
	// Clear any prior auth state so revisiting /auth behaves like a fresh
	// login — the user always sees the provider picker as a choice, never
	// as a confirmation of an already-authenticated session.
	sess.AuthOK = false
	var providers []auth.Descriptor
	if h.AuthReg != nil {
		providers = h.AuthReg.Descriptors()
	}
	// FirstRun is the registry-empty bootstrap mode. The /auth/custom
	// form persists in both states; FirstRun just promotes the form
	// from a collapsed <details> to the page's primary action so a
	// fresh install (deploy.sh --no-default-idps) doesn't land on an
	// empty-tile page that gives the operator nothing to click.
	firstRun := len(providers) == 0 && h.AuthStore != nil
	// "+ Add OIDC provider" expansion visibility is driven by the admin
	// mode flag: ro hides it, off and rw show it. FirstRun bypasses ro
	// so an admin can't accidentally lock everyone out of bootstrapping
	// a fresh install.
	allowAdd := h.addFormVisible() || firstRun
	h.render(w, r, "auth", h.pageData(sess, map[string]any{
		"Providers":        providers,
		"FirstRun":         firstRun,
		"AllowAddProvider": allowAdd,
	}))
}

// addFormVisible returns whether the "+ Add OIDC provider" expansion on
// /auth should render for regular users. Visible only in `rw`. `ro`
// hides it because the admin curates the list; `off` hides it because
// there's no provider-management surface in the UI at all (providers
// must be set via env / system file / deploy.sh).
//
// Persistence still works in every mode — a fresh-install operator
// reaching the FirstRun branch (registry empty) bypasses this flag and
// gets the form regardless, so flipping `off` can't permanently lock
// everyone out of bootstrapping.
func (h *H) addFormVisible() bool {
	return h.adminModeOrDefault() == "rw"
}

// AddCustomProvider handles POST /auth/custom — the persistent "Add OIDC
// provider" form on the auth page. Validates discovery via oidcBuildProvider,
// writes to the user store so the entry survives `./deploy.sh run all`,
// and registers the result in-memory so the new tile appears on the next
// /auth render.
//
// Auth model: any session that has picked a role can register a provider.
// First-run installs (registry empty) reach the same form via /auth's
// FirstRun branch; the path is identical, just the page copy differs.
//
// Honest about scope: works only with servers that speak OIDC discovery
// (must serve /.well-known/openid-configuration). The form prose calls
// this out. SAML, plain OAuth2, LDAP need separate provider types.
//
// Re-submitting with the same display name updates the existing entry
// in place (Registry.Register + UserStore.Add both upsert by id), so the
// operator can iterate on a misconfigured provider without restart-thrash.
func (h *H) AddCustomProvider(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	// First-run window OR any session with a role chosen — let through.
	// Anonymous visitors with no role get punted to /role first.
	registryEmpty := h.AuthReg == nil || len(h.AuthReg.All()) == 0
	if sess.Role == "" && !registryEmpty {
		h.redirect(w, r, "/")
		return
	}
	// Server-side enforcement of the mode-driven add-form gate. The
	// /auth template hides the form when AuthAdminMode=ro, but a hand-
	// crafted curl could still POST here — re-check and refuse. First-
	// run (registry empty) bypasses the gate for the same reason the
	// template does: lockout-prevention.
	if !registryEmpty && !h.addFormVisible() {
		h.errorToast(w, r, "Adding new identity providers is disabled by the administrator.")
		return
	}
	if h.persistProviderFromForm(w, r) {
		h.redirect(w, r, "/auth")
	}
}

// persistProviderFromForm parses the shared add-form fields, validates
// via oidcBuildProvider, persists to the user store, and registers
// in-memory. Returns true on success (caller redirects), false on
// failure (toast already emitted by this function).
//
// Lives here in handlers.go (not admin_*.go) because the public /auth/custom
// path uses it too; the admin and bootstrap surfaces went away in favour
// of a single persistent endpoint.
func (h *H) persistProviderFromForm(w http.ResponseWriter, r *http.Request) bool {
	if h.AuthReg == nil {
		h.errorToast(w, r, "Auth registry unavailable.")
		return false
	}
	if h.AuthStore == nil {
		// AuthStore is wired in every admin mode (including "off") so
		// reaching here means a misconfigured deployment / test scaffold,
		// not a deliberate lockdown. Surface as a server error rather
		// than the user-facing "disabled by admin" copy.
		h.errorToast(w, r, "Provider persistence is unconfigured on this deployment.")
		return false
	}
	_ = r.ParseForm()
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	issuer := strings.TrimSpace(r.FormValue("issuer_url"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	scopesRaw := strings.TrimSpace(r.FormValue("scopes"))
	insecure := r.FormValue("insecure_skip_verify") == "on"

	if displayName == "" || issuer == "" || clientID == "" {
		h.errorToast(w, r, "Display name, issuer URL, and client ID are required.")
		return false
	}
	scopes := defaultOIDCScopes
	if scopesRaw != "" {
		scopes = nil
		for _, s := range strings.Split(scopesRaw, ",") {
			if t := strings.TrimSpace(s); t != "" {
				scopes = append(scopes, t)
			}
		}
	}
	id := slugify(displayName)
	if id == "" {
		id = "custom"
	}
	p, err := oidcBuildProvider(r.Context(), CustomProviderInput{
		ID:                 id,
		DisplayName:        displayName,
		IssuerURL:          issuer,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		Scopes:             scopes,
		InsecureSkipVerify: insecure,
		Source:             auth.SourceUser,
	})
	if err != nil {
		h.errorToast(w, r, "Could not register OIDC provider: "+err.Error())
		return false
	}
	if _, err := h.AuthStore.Add(auth.ProviderConfig{
		ID:                 id,
		Type:               "oidc",
		DisplayName:        displayName,
		Kind:               "OIDC",
		IssuerURL:          issuer,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		Scopes:             scopes,
		InsecureSkipVerify: insecure,
	}); err != nil {
		h.errorToast(w, r, "Could not persist provider: "+err.Error())
		return false
	}
	h.AuthReg.Register(p)
	return true
}

// defaultOIDCScopes are what every OIDC provider implicitly accepts.
// Used when the operator leaves the Scopes field blank on /auth/custom.
var defaultOIDCScopes = []string{"openid", "profile", "email"}

// slugify lower-cases a display name and replaces non-alphanumerics with
// hyphens so it's safe for use as a registry ID + URL slug. Empty/all-
// non-alphanumeric input returns "" — caller falls back to "custom".
func slugify(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevHyphen := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen {
				b.WriteRune('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// CompleteAuth is POST /auth — only reachable when NO OIDC providers are
// configured (the template hides the form otherwise). Once providers are
// configured, /auth/start + the provider callback is the only authentication
// path; this endpoint rejects any attempt to bypass it.
func (h *H) CompleteAuth(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.Role == "" {
		h.redirect(w, r, "/")
		return
	}
	if h.AuthReg != nil && len(h.AuthReg.All()) > 0 {
		h.errorToast(w, r, "Pick an identity provider to sign in")
		return
	}
	sess.AuthOK = true
	next := authNextFor(sess.Role)
	h.redirect(w, r, next)
}

func authNextFor(role string) string {
	return map[string]string{
		"issuer":   "/issuer/dpg",
		"holder":   "/holder/dpg",
		"verifier": "/verifier/dpg",
	}[role]
}

// StartAuth kicks off an OIDC Authorization Code + PKCE handshake. Called by
// the provider buttons on /auth: HTMX POST with provider=<id>. The handler
// stores state + PKCE verifier on the session and returns HX-Redirect to the
// provider's authorize URL.
func (h *H) StartAuth(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.Role == "" {
		h.redirect(w, r, "/")
		return
	}
	if h.AuthReg == nil {
		h.errorToast(w, r, "No identity providers configured")
		return
	}
	id := r.FormValue("provider")
	p := h.AuthReg.Lookup(id)
	if p == nil {
		h.errorToast(w, r, "Unknown provider")
		return
	}
	state := oidcNewState()
	verifier := oidcNewPKCEVerifier()
	sess.PendingProvider = p.ID()
	sess.PendingState = state
	sess.PendingPKCE = verifier
	redirect := publicBase(r) + "/auth/callback"
	url, err := p.AuthorizeURL(r.Context(), state, verifier, redirect)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.redirect(w, r, url)
}

// AuthCallback receives the code from the provider after login. Exchanges it
// for tokens, stores them on the session, and routes to the role-specific
// next page.
func (h *H) AuthCallback(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	q := r.URL.Query()
	if errMsg := q.Get("error"); errMsg != "" {
		h.errorToast(w, r, "Auth error: "+errMsg)
		return
	}
	if q.Get("state") != sess.PendingState {
		h.errorToast(w, r, "Auth state mismatch (CSRF?)")
		return
	}
	p := h.AuthReg.Lookup(sess.PendingProvider)
	if p == nil {
		h.errorToast(w, r, "Auth provider no longer configured")
		return
	}
	redirect := publicBase(r) + "/auth/callback"
	tok, err := p.Exchange(r.Context(), q.Get("code"), sess.PendingPKCE, redirect)
	if err != nil {
		h.errorToast(w, r, "Token exchange: "+err.Error())
		return
	}
	sess.AccessToken = tok.AccessToken
	sess.RefreshToken = tok.RefreshToken
	sess.IDToken = tok.IDToken
	sess.AuthProvider = p.ID()
	sess.AuthOK = true
	sess.PendingState = ""
	sess.PendingPKCE = ""
	sess.PendingProvider = ""
	if ui, err := p.UserInfo(r.Context(), tok.AccessToken); err == nil {
		sess.UserEmail = ui.Email
		sess.UserSubject = ui.Subject
	}
	// The upstream wallet account the app talks to is partitioned per
	// authenticated user (see waltid.ensureWalletSession + holderCtx).
	// Any cached wallet-state on this session belongs to whoever was
	// logged in *before* this callback — invalidate it so the next
	// /holder/wallet fetch pulls this user's credentials instead.
	sess.WalletCreds = nil
	sess.WalletPending = nil
	sess.WalletUserKey = ""
	h.redirect(w, r, authNextFor(sess.Role))
}

// Logout wipes the session's authenticated identity + wallet key + any
// cached wallet state, so the next holderCtx re-derives against a clean
// slate. We keep the session cookie itself so the browser's role +
// language selections survive, but everything identity-linked is cleared.
// Used from the topbar "Sign out" button — the primary escape hatch when
// a user has been bounced between OIDC providers and ended up pointing
// at a wallet partition they don't recognise.
func (h *H) Logout(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	sess.AuthProvider = ""
	sess.AuthOK = false
	sess.AccessToken = ""
	sess.RefreshToken = ""
	sess.IDToken = ""
	sess.UserEmail = ""
	sess.UserSubject = ""
	sess.PendingProvider = ""
	sess.PendingState = ""
	sess.PendingPKCE = ""
	sess.WalletCreds = nil
	sess.WalletPending = nil
	sess.WalletUserKey = ""
	h.redirect(w, r, "/")
}

// The following are thin indirections through the oidc subpackage so this
// file doesn't need to import it directly. Wired by main via SetOIDCHelpers.
var (
	oidcNewState        = func() string { return "" }
	oidcNewPKCEVerifier = func() string { return "" }
	// oidcBuildProvider is the hook for AddCustomProvider. Returns an
	// auth.Provider built from the user-supplied OIDC parameters, or an
	// error if discovery fails (issuer doesn't serve
	// /.well-known/openid-configuration, network error, etc.). The handler
	// surfaces that error verbatim as a toast so the operator sees the
	// real reason — usually "this isn't an OIDC server".
	oidcBuildProvider = func(_ context.Context, _ CustomProviderInput) (auth.Provider, error) {
		return nil, fmt.Errorf("oidc helpers not wired")
	}
)

// CustomProviderInput captures the form fields submitted by /auth/custom.
// Mirrors auth.ProviderConfig but kept package-local so the wiring hook
// signature doesn't drag the auth package's full config shape into every
// caller. Display name is what shows on the picker tile.
type CustomProviderInput struct {
	ID                 string
	DisplayName        string
	IssuerURL          string
	ClientID           string
	ClientSecret       string
	Scopes             []string
	InsecureSkipVerify bool
	// Source labels the resulting registry entry. Admin-UI callers pass
	// auth.SourceUser; the legacy /auth/custom POST leaves it empty so
	// the build hook treats it as auth.SourceRuntime.
	Source string
}

// SetOIDCHelpers installs the state, PKCE verifier, and runtime-provider
// builder. Must be called before StartAuth or AddCustomProvider serve any
// request.
func SetOIDCHelpers(state, pkce func() string, build func(context.Context, CustomProviderInput) (auth.Provider, error)) {
	if state != nil {
		oidcNewState = state
	}
	if pkce != nil {
		oidcNewPKCEVerifier = pkce
	}
	if build != nil {
		oidcBuildProvider = build
	}
}

// redirect issues a response appropriate to HTMX vs. plain browser.
// For HTMX we use HX-Redirect so the browser does a full nav; for plain
// requests we issue a 303 See Other.
func (h *H) redirect(w http.ResponseWriter, r *http.Request, to string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// --- DPG selection (shared across roles) ---

// ShowIssuerDpgs / ShowHolderDpgs / ShowVerifierDpgs render the DPG-pick page.
// PickIssuerDpg / PickHolderDpg / PickVerifierDpg handle POSTed selections.

func (h *H) ShowIssuerDpgs(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "issuer" {
		h.redirect(w, r, "/")
		return
	}
	dpgs, err := h.Adapter.ListIssuerDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.render(w, r, "issuer_dpg", h.pageData(sess, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedIssuerDpg,
	}))
}

// ToggleIssuerDpg expands/collapses a DPG card. Expanding also selects it.
func (h *H) ToggleIssuerDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "issuer" {
		h.redirect(w, r, "/")
		return
	}
	vendor := r.FormValue("vendor")
	if sess.ExpandedIssuerDpg == vendor {
		sess.ExpandedIssuerDpg = ""
	} else {
		sess.ExpandedIssuerDpg = vendor
	}
	dpgs, err := h.Adapter.ListIssuerDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.renderFragments(w, r, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedIssuerDpg,
	}, "fragment_issuer_dpg_grid", "fragment_issuer_dpg_continue_oob")
}

// PickIssuerDpg commits the currently-expanded DPG and moves forward.
// DPGs that declare Redirect=true hand the operator off to their own UI
// instead of the inline schema picker — same pattern used by holder and
// verifier pickers.
func (h *H) PickIssuerDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.ExpandedIssuerDpg == "" {
		h.errorToast(w, r, "Select a DPG first")
		return
	}
	dpgs, err := h.Adapter.ListIssuerDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	dpg, ok := dpgs[sess.ExpandedIssuerDpg]
	if !ok {
		http.Error(w, "unknown vendor", 400)
		return
	}
	sess.IssuerDpg = sess.ExpandedIssuerDpg
	if dpg.InAppPath != "" {
		h.redirect(w, r, dpg.InAppPath)
		return
	}
	if dpg.Redirect {
		h.render(w, r, "redirect_notice", h.pageData(sess, dpg))
		return
	}
	h.redirect(w, r, "/issuer/schema")
}

func (h *H) ShowHolderDpgs(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "holder" {
		h.redirect(w, r, "/")
		return
	}
	dpgs, err := h.Adapter.ListHolderDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.render(w, r, "holder_dpg", h.pageData(sess, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedHolderDpg,
	}))
}

func (h *H) ToggleHolderDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "holder" {
		h.redirect(w, r, "/")
		return
	}
	vendor := r.FormValue("vendor")
	if sess.ExpandedHolderDpg == vendor {
		sess.ExpandedHolderDpg = ""
	} else {
		sess.ExpandedHolderDpg = vendor
	}
	dpgs, err := h.Adapter.ListHolderDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.renderFragments(w, r, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedHolderDpg,
	}, "fragment_holder_dpg_grid", "fragment_holder_dpg_continue_oob")
}

func (h *H) PickHolderDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.ExpandedHolderDpg == "" {
		h.errorToast(w, r, "Select a wallet first")
		return
	}
	dpgs, err := h.Adapter.ListHolderDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	dpg, ok := dpgs[sess.ExpandedHolderDpg]
	if !ok {
		http.Error(w, "unknown vendor", 400)
		return
	}
	sess.HolderDpg = sess.ExpandedHolderDpg
	if dpg.InAppPath != "" {
		h.redirect(w, r, dpg.InAppPath)
		return
	}
	if dpg.Redirect {
		h.render(w, r, "redirect_notice", h.pageData(sess, dpg))
		return
	}
	h.redirect(w, r, "/holder/wallet")
}

func (h *H) ShowVerifierDpgs(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "verifier" {
		h.redirect(w, r, "/")
		return
	}
	dpgs, err := h.Adapter.ListVerifierDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.render(w, r, "verifier_dpg", h.pageData(sess, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedVerifierDpg,
	}))
}

func (h *H) ToggleVerifierDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.AuthOK || sess.Role != "verifier" {
		h.redirect(w, r, "/")
		return
	}
	vendor := r.FormValue("vendor")
	if sess.ExpandedVerifierDpg == vendor {
		sess.ExpandedVerifierDpg = ""
	} else {
		sess.ExpandedVerifierDpg = vendor
	}
	dpgs, err := h.Adapter.ListVerifierDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.renderFragments(w, r, map[string]any{
		"Dpgs":     dpgs,
		"Expanded": sess.ExpandedVerifierDpg,
	}, "fragment_verifier_dpg_grid", "fragment_verifier_dpg_continue_oob")
}

func (h *H) PickVerifierDpg(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.ExpandedVerifierDpg == "" {
		h.errorToast(w, r, "Select a verifier first")
		return
	}
	dpgs, err := h.Adapter.ListVerifierDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	dpg, ok := dpgs[sess.ExpandedVerifierDpg]
	if !ok {
		http.Error(w, "unknown vendor", 400)
		return
	}
	sess.VerifierDpg = sess.ExpandedVerifierDpg
	if dpg.Redirect {
		h.render(w, r, "redirect_notice", h.pageData(sess, dpg))
		return
	}
	h.redirect(w, r, "/verifier/verify")
}

// errorToast sets the HX-Trigger header so the client shows a toast, and 200s.
// HX-Reswap: none tells HTMX not to swap the target — otherwise the empty
// response body replaces the target's content and the page appears to wipe.
// For non-HTMX it renders a plain error page.
//
// HX-Trigger MUST be valid JSON of the form `{"event":"detail"}` for htmx to
// dispatch `event` with `detail` attached. The older `event:detail` shorthand
// parses as a single event named literally "event:detail" — which won't match
// the `toast` listener, so the user sees nothing. That was the silent-failure
// symptom on Send presentation and Check for holder response.
func (h *H) errorToast(w http.ResponseWriter, r *http.Request, msg string) {
	h.errorToastStatus(w, r, http.StatusUnprocessableEntity, msg)
}

// errorToastStatus is errorToast with an explicit HTTP status for the
// non-HTMX fallback. Use this for input validation / upstream errors that
// shouldn't surface as 500 to scripts/curl callers; reserve plain
// errorToast (now 422) for that operator-input default.
func (h *H) errorToastStatus(w http.ResponseWriter, r *http.Request, status int, msg string) {
	slog.Warn("handler error", "method", r.Method, "path", r.URL.Path, "msg", msg)
	if isHTMX(r) {
		payload, err := json.Marshal(map[string]string{"toast": msg})
		if err != nil {
			// json.Marshal of a simple map[string]string doesn't realistically
			// fail, but fall back to a plain event so something still fires.
			payload = []byte(`{"toast":"server error"}`)
		}
		w.Header().Set("HX-Trigger", string(payload))
		w.Header().Set("HX-Reswap", "none")
		w.WriteHeader(200)
		return
	}
	http.Error(w, msg, status)
}

// --- Schema browser + builder (issuer only) ---
//
// Split into separate files for readability: schema.go, issuance.go, wallet.go, verifier.go.
