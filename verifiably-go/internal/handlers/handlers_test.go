package handlers

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/storage/injiwallet"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── fixtures (private to handlers.go tests; prefix hdl) ─────────────────────

// hdlAdapter serves canned DPG maps per role; unexpected calls panic via the
// nil embedded backend.Adapter.
type hdlAdapter struct {
	backend.Adapter
	issuer, holder, verifier          map[string]vctypes.DPG
	issuerErr, holderErr, verifierErr error
}

func (a *hdlAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.issuer, a.issuerErr
}
func (a *hdlAdapter) ListHolderDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.holder, a.holderErr
}
func (a *hdlAdapter) ListVerifierDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.verifier, a.verifierErr
}

// hdlProv is stubProv with injectable outcomes for the OIDC round-trip.
type hdlProv struct {
	stubProv
	authorizeURL string
	authorizeErr error
	token        auth.Token
	exchangeErr  error
	userInfo     auth.UserInfo
	userInfoErr  error
	gotRedirect  string
}

func (p *hdlProv) AuthorizeURL(_ context.Context, _, _, redirect string) (string, error) {
	p.gotRedirect = redirect
	return p.authorizeURL, p.authorizeErr
}
func (p *hdlProv) Exchange(_ context.Context, _, _, redirect string) (auth.Token, error) {
	p.gotRedirect = redirect
	return p.token, p.exchangeErr
}
func (p *hdlProv) UserInfo(context.Context, string) (auth.UserInfo, error) {
	return p.userInfo, p.userInfoErr
}

// hdlRestoreOIDC snapshots the package-level OIDC hooks and restores them.
func hdlRestoreOIDC(t *testing.T) {
	t.Helper()
	st, pk, bp := oidcNewState, oidcNewPKCEVerifier, oidcBuildProvider
	t.Cleanup(func() { oidcNewState, oidcNewPKCEVerifier, oidcBuildProvider = st, pk, bp })
}

func hdlGET(path string, htmx bool, cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if htmx {
		req.Header.Set("HX-Request", "true")
		req.Header.Set("HX-Target", "main")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func hdlLangCookie(code string) *http.Cookie {
	return &http.Cookie{Name: "verifiably_lang", Value: code}
}

// ─── externalScheme / externalHost / publicBase ──────────────────────────────

func TestExternalSchemeHostAndPublicBase(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "")
	req := httptest.NewRequest(http.MethodGet, "http://internal:8080/x", nil)
	if got := externalScheme(req); got != "http" {
		t.Fatalf("plain scheme = %q", got)
	}
	if got := publicBase(req); got != "http://internal:8080" {
		t.Fatalf("plain base = %q", got)
	}
	req.TLS = &tls.ConnectionState{}
	if got := externalScheme(req); got != "https" {
		t.Fatalf("tls scheme = %q", got)
	}
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Host", " public.example , other.example")
	if got := publicBase(req); got != "https://public.example" {
		t.Fatalf("forwarded base = %q", got)
	}
	req.Header.Set("X-Forwarded-Proto", " http ")
	if got := externalScheme(req); got != "http" {
		t.Fatalf("single forwarded scheme = %q", got)
	}
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example/")
	if got := publicBase(req); got != "https://portal.example" {
		t.Fatalf("env base = %q", got)
	}
}

// ─── render / renderFragment / renderFragments / MakeTranslateFunc ───────────

func TestRenderTranslatingPaths(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "redirect_notice"), Translator: &i18nUpperTranslator{}}
	dpg := vctypes.DPG{Vendor: "Example DPG", Version: "v1"}
	sess := &Session{}

	// Non-English HTMX render: translated body.
	req := hdlGET("/x", true, nil)
	req.AddCookie(hdlLangCookie("es"))
	rr := httptest.NewRecorder()
	h.render(rr, req, "redirect_notice", h.pageData(sess, dpg))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "EXAMPLE DPG") {
		t.Fatalf("translated render: %d %q", rr.Code, rr.Body.String())
	}
	// Non-English full page: layout wraps content and title falls back to titleFor.
	req = hdlGET("/x", false, nil)
	req.AddCookie(hdlLangCookie("es"))
	rr = httptest.NewRecorder()
	h.render(rr, req, "redirect_notice", h.pageData(sess, dpg))
	if !strings.Contains(rr.Body.String(), "<!DOCTYPE html>") || !strings.Contains(rr.Body.String(), "EXAMPLE DPG") {
		t.Fatalf("translated layout: %q", rr.Body.String()[:200])
	}
	// Non-English HTMX render of an unknown page → 500 from the buffered path.
	rr = httptest.NewRecorder()
	req = hdlGET("/x", true, nil)
	req.AddCookie(hdlLangCookie("es"))
	h.render(rr, req, "no_such_page", h.pageData(sess, nil))
	if rr.Code != 500 {
		t.Fatalf("translated missing template: %d", rr.Code)
	}
	// English HTMX render of an unknown page → 500 from the direct path.
	rr = httptest.NewRecorder()
	h.render(rr, hdlGET("/x", true, nil), "no_such_page", h.pageData(sess, nil))
	if rr.Code != 500 {
		t.Fatalf("missing template: %d", rr.Code)
	}
	// Explicit Lang/Title/Crumb in data are honoured (no cookie).
	rr = httptest.NewRecorder()
	pd := h.pageData(sess, dpg)
	pd.Lang, pd.Title, pd.Crumb = "en", "Custom title", "custom crumb"
	h.render(rr, hdlGET("/x", true, nil), "redirect_notice", pd)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Example DPG") {
		t.Fatalf("explicit lang render: %d", rr.Code)
	}
}

func TestRenderFragmentAndFragments(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_dpg"), Translator: &i18nUpperTranslator{}}
	data := map[string]any{"Dpgs": map[string]vctypes.DPG{"Example DPG": {Vendor: "Example DPG"}}, "Expanded": ""}

	en := hdlGET("/x", true, nil)
	es := hdlGET("/x", true, nil)
	es.AddCookie(hdlLangCookie("es"))

	rr := httptest.NewRecorder()
	h.renderFragment(rr, en, "fragment_issuer_dpg_grid", data)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Example DPG") {
		t.Fatalf("fragment en: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.renderFragment(rr, en, "no_such_fragment", data)
	if rr.Code != 500 {
		t.Fatalf("fragment en missing: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.renderFragment(rr, es, "fragment_issuer_dpg_grid", data)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "EXAMPLE DPG") {
		t.Fatalf("fragment es: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.renderFragment(rr, es, "no_such_fragment", data)
	if rr.Code != 500 {
		t.Fatalf("fragment es missing: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.renderFragments(rr, en, data, "fragment_issuer_dpg_grid", "fragment_issuer_dpg_continue_oob")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hx-swap-oob") {
		t.Fatalf("fragments en: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.renderFragments(rr, en, data, "no_such_fragment", "fragment_issuer_dpg_grid")
	if rr.Code != 500 {
		t.Fatalf("fragments en missing: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.renderFragments(rr, es, data, "fragment_issuer_dpg_grid", "fragment_issuer_dpg_continue_oob")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "EXAMPLE DPG") {
		t.Fatalf("fragments es: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.renderFragments(rr, es, data, "no_such_fragment")
	if rr.Code != 500 {
		t.Fatalf("fragments es missing: %d", rr.Code)
	}
}

func TestMakeTranslateFunc(t *testing.T) {
	if got := MakeTranslateFunc(nil)("Hello", "es"); got != "Hello" {
		t.Fatalf("nil translator: %q", got)
	}
	tr := &i18nUpperTranslator{}
	fn := MakeTranslateFunc(tr)
	if got := fn("Hello", "en"); got != "Hello" {
		t.Fatalf("en: %q", got)
	}
	if got := fn("Hello", ""); got != "Hello" {
		t.Fatalf("empty lang: %q", got)
	}
	if got := fn("Hello", "es"); got != "HELLO" {
		t.Fatalf("es: %q", got)
	}
}

// ─── SetLang ─────────────────────────────────────────────────────────────────

func TestSetLang(t *testing.T) {
	h := &H{Sessions: NewStore()}
	rr := httptest.NewRecorder()
	req := postFormReq(http.MethodPost, "/lang", url.Values{"lang": {"es"}})
	req.Header.Set("Referer", "https://evil.example/issuer/issue?x=1#frag")
	h.SetLang(rr, req)
	if rr.Code != 200 || rr.Header().Get("HX-Redirect") != "/issuer/issue?x=1" {
		t.Fatalf("htmx: %d %q", rr.Code, rr.Header().Get("HX-Redirect"))
	}
	var langCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "verifiably_lang" {
			langCookie = c
		}
	}
	if langCookie == nil || langCookie.Value != "es" || langCookie.Path != "/" {
		t.Fatalf("lang cookie = %+v", langCookie)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/lang?lang=fr", nil)
	req.Header.Set("Referer", "://bad")
	h.SetLang(rr, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
		t.Fatalf("plain: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/lang?lang=fr", nil)
	req.Header.Set("Referer", "https://portal.example")
	h.SetLang(rr, req)
	if rr.Header().Get("Location") != "/" {
		t.Fatalf("referer without path: %q", rr.Header().Get("Location"))
	}

	// No lang anywhere (form or query): the cookie is still set, but empty,
	// which the lang lookup treats as "default language".
	rr = httptest.NewRecorder()
	h.SetLang(rr, httptest.NewRequest(http.MethodGet, "/lang", nil))
	var empty *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "verifiably_lang" {
			empty = c
		}
	}
	if empty == nil || empty.Value != "" || rr.Header().Get("Location") != "/" {
		t.Fatalf("no lang: cookie=%+v loc=%q", empty, rr.Header().Get("Location"))
	}
}

// ─── Landing / allDPGs / PickRole ────────────────────────────────────────────

func TestLandingAndAllDPGs(t *testing.T) {
	ad := &hdlAdapter{
		issuer:   map[string]vctypes.DPG{"a": {Vendor: "Alpha", Version: "1"}},
		holder:   map[string]vctypes.DPG{"a": {Vendor: "Alpha", Version: "1"}, "b": {Vendor: "Beta", Version: "2"}},
		verifier: map[string]vctypes.DPG{"c": {Vendor: "Gamma", Version: "3"}},
	}
	h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, "landing"), ShowIssuer: true, ShowHolder: true, ShowVerifier: true}
	rr := httptest.NewRecorder()
	h.Landing(rr, hdlGET("/", true, nil))
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("landing: %d %s", rr.Code, body)
	}
	for _, want := range []string{"Alpha 1", "Beta 2", "Gamma 3"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing missing %q", want)
		}
	}
	if strings.Count(body, "Alpha 1") != 1 {
		t.Errorf("Alpha not deduped: %d", strings.Count(body, "Alpha 1"))
	}

	rr = httptest.NewRecorder()
	h.Landing(rr, hdlGET("/nope", false, nil))
	if rr.Code != 404 {
		t.Fatalf("non-root path: %d", rr.Code)
	}

	errAd := &hdlAdapter{issuerErr: errors.New("i"), holderErr: errors.New("h"), verifierErr: errors.New("v")}
	h.Adapter = errAd
	if got := h.allDPGs(hdlGET("/", false, nil)); len(got) != 0 {
		t.Fatalf("allDPGs with errors = %+v", got)
	}
}

func TestPickRole(t *testing.T) {
	h := &H{Sessions: NewStore()}
	rr := httptest.NewRecorder()
	h.PickRole(rr, postFormReq(http.MethodPost, "/role", url.Values{"role": {"admin"}}))
	if rr.Code != 400 {
		t.Fatalf("invalid role: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	req := postFormReq(http.MethodPost, "/role", url.Values{"role": {"holder"}})
	h.PickRole(rr, req)
	if rr.Code != 200 || rr.Header().Get("HX-Redirect") != "/auth" {
		t.Fatalf("pick: %d %q", rr.Code, rr.Header().Get("HX-Redirect"))
	}
	if sessionOf(h, hdlGET("/", false, rr.Result().Cookies())).Role != "holder" {
		t.Fatal("role not stored on session")
	}
}

// ─── Auth page / CompleteAuth / authNextFor ──────────────────────────────────

func TestAuthPage(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "auth")}
	rr := httptest.NewRecorder()
	h.Auth(rr, hdlGET("/auth", true, nil))
	if rr.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("no role should redirect: %q", rr.Header().Get("HX-Redirect"))
	}

	// Registry with a provider: tiles render, AuthOK is cleared.
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "corp-idp"})
	h.AuthReg = reg
	cookies := seedSession(t, h, func(s *Session) { s.Role = "issuer"; s.AuthOK = true })
	rr = httptest.NewRecorder()
	req := hdlGET("/auth", true, cookies)
	h.Auth(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "corp-idp") {
		t.Fatalf("auth page: %d %s", rr.Code, rr.Body.String())
	}
	if sessionOf(h, req).AuthOK {
		t.Fatal("AuthOK not cleared")
	}

	// Empty registry + store → FirstRun branch promotes the form.
	h.AuthReg = auth.NewRegistry()
	h.AuthStore = auth.NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	h.AuthAdminMode = "ro"
	rr = httptest.NewRecorder()
	h.Auth(rr, hdlGET("/auth", true, cookies))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "issuer_url") {
		t.Fatalf("first-run page lacks the add form: %d", rr.Code)
	}
}

func TestCompleteAuthAndAuthNextFor(t *testing.T) {
	if authNextFor("issuer") != "/issuer/dpg" || authNextFor("holder") != "/holder/dpg" || authNextFor("verifier") != "/verifier/dpg" || authNextFor("x") != "" {
		t.Fatal("authNextFor table")
	}
	h := &H{Sessions: NewStore()}
	rr := httptest.NewRecorder()
	h.CompleteAuth(rr, postFormReq(http.MethodPost, "/auth", nil))
	if rr.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("no role: %q", rr.Header().Get("HX-Redirect"))
	}
	cookies := seedSession(t, h, func(s *Session) { s.Role = "verifier" })
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "corp-idp"})
	h.AuthReg = reg
	rr = httptest.NewRecorder()
	h.CompleteAuth(rr, formPost("/auth", nil, cookies...))
	if !strings.Contains(rr.Header().Get("HX-Trigger"), "Pick an identity provider") {
		t.Fatalf("providers configured: %q", rr.Header().Get("HX-Trigger"))
	}
	h.AuthReg = nil
	rr = httptest.NewRecorder()
	req := formPost("/auth", nil, cookies...)
	h.CompleteAuth(rr, req)
	if rr.Header().Get("HX-Redirect") != "/verifier/dpg" || !sessionOf(h, req).AuthOK {
		t.Fatalf("complete: %q", rr.Header().Get("HX-Redirect"))
	}
}

// ─── AddCustomProvider / persistProviderFromForm / SetOIDCHelpers ────────────

func TestAddCustomProviderAndPersist(t *testing.T) {
	hdlRestoreOIDC(t)
	form := func(extra url.Values) url.Values {
		v := url.Values{"display_name": {"Corp IdP"}, "issuer_url": {"https://idp.example"}, "client_id": {"cid"}}
		for k, vs := range extra {
			v[k] = vs
		}
		return v
	}
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

	// Anonymous with a non-empty registry → redirect home.
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "sys-idp", source: auth.SourceSystem})
	h := &H{Sessions: NewStore(), AuthReg: reg}
	rr := httptest.NewRecorder()
	h.AddCustomProvider(rr, postFormReq(http.MethodPost, "/auth/custom", form(nil)))
	if rr.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("anonymous: %q", rr.Header().Get("HX-Redirect"))
	}
	// Role set but admin mode ro → refused.
	cookies := seedSession(t, h, func(s *Session) { s.Role = "issuer" })
	h.AuthAdminMode = "ro"
	rr = httptest.NewRecorder()
	h.AddCustomProvider(rr, formPost("/auth/custom", form(nil), cookies...))
	if !strings.Contains(trig(rr), "disabled by the administrator") {
		t.Fatalf("ro: %q", trig(rr))
	}
	// Nil registry (registry empty ⇒ anonymous allowed) → "Auth registry unavailable".
	h2 := &H{Sessions: NewStore()}
	rr = httptest.NewRecorder()
	h2.AddCustomProvider(rr, postFormReq(http.MethodPost, "/auth/custom", form(nil)))
	if !strings.Contains(trig(rr), "Auth registry unavailable") {
		t.Fatalf("nil registry: %q", trig(rr))
	}
	// Empty registry but no store → persistence unconfigured.
	h2.AuthReg = auth.NewRegistry()
	rr = httptest.NewRecorder()
	h2.AddCustomProvider(rr, postFormReq(http.MethodPost, "/auth/custom", form(nil)))
	if !strings.Contains(trig(rr), "persistence is unconfigured") {
		t.Fatalf("nil store: %q", trig(rr))
	}
	// Missing required fields.
	h.AuthAdminMode = "rw"
	h.AuthStore = auth.NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	rr = httptest.NewRecorder()
	h.AddCustomProvider(rr, formPost("/auth/custom", url.Values{"display_name": {"x"}}, cookies...))
	if !strings.Contains(trig(rr), "are required") {
		t.Fatalf("missing fields: %q", trig(rr))
	}
	// Build hook fails.
	var got CustomProviderInput
	SetOIDCHelpers(nil, nil, func(_ context.Context, in CustomProviderInput) (auth.Provider, error) {
		got = in
		return nil, errors.New("not an OIDC server")
	})
	rr = httptest.NewRecorder()
	h.AddCustomProvider(rr, formPost("/auth/custom", form(url.Values{"scopes": {"openid, email ,"}, "insecure_skip_verify": {"on"}}), cookies...))
	if !strings.Contains(trig(rr), "Could not register OIDC provider: not an OIDC server") {
		t.Fatalf("build error: %q", trig(rr))
	}
	if got.ID != "corp-idp" || !got.InsecureSkipVerify || strings.Join(got.Scopes, ",") != "openid,email" || got.Source != auth.SourceUser {
		t.Fatalf("hook input = %+v", got)
	}
	// Store write fails (path is a directory).
	SetOIDCHelpers(nil, nil, func(_ context.Context, in CustomProviderInput) (auth.Provider, error) {
		return stubProv{id: in.ID, source: in.Source}, nil
	})
	h.AuthStore = auth.NewUserStore(t.TempDir())
	rr = httptest.NewRecorder()
	h.AddCustomProvider(rr, formPost("/auth/custom", form(nil), cookies...))
	if !strings.Contains(trig(rr), "Could not persist provider") {
		t.Fatalf("store error: %q", trig(rr))
	}
	// Success: default scopes, slug fallback to "custom", registered + persisted.
	store := auth.NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	h.AuthStore = store
	rr = httptest.NewRecorder()
	h.AddCustomProvider(rr, formPost("/auth/custom", form(url.Values{"display_name": {"!!!"}}), cookies...))
	if rr.Header().Get("HX-Redirect") != "/auth" {
		t.Fatalf("success: %d %q", rr.Code, trig(rr))
	}
	if h.AuthReg.Lookup("custom") == nil {
		t.Fatal("provider not registered as custom")
	}
	cfgs, err := store.Load()
	if err != nil || len(cfgs) != 1 || cfgs[0].ID != "custom" || strings.Join(cfgs[0].Scopes, ",") != "openid,profile,email" {
		t.Fatalf("persisted = %+v (%v)", cfgs, err)
	}
}

func TestSetOIDCHelpers_NilKeepsCurrent(t *testing.T) {
	hdlRestoreOIDC(t)
	// Before main wires the helpers, the package defaults are the unwired
	// stubs: empty state / verifier (no test in this package ever leaves a
	// replacement installed — every caller restores via hdlRestoreOIDC).
	if oidcNewState() != "" || oidcNewPKCEVerifier() != "" {
		t.Fatalf("unwired defaults: state=%q pkce=%q", oidcNewState(), oidcNewPKCEVerifier())
	}
	SetOIDCHelpers(func() string { return "S" }, func() string { return "V" }, nil)
	if oidcNewState() != "S" || oidcNewPKCEVerifier() != "V" {
		t.Fatal("state/pkce not installed")
	}
	if _, err := oidcBuildProvider(context.Background(), CustomProviderInput{}); err == nil {
		t.Fatal("default build hook should still error")
	}
	SetOIDCHelpers(nil, nil, nil)
	if oidcNewState() != "S" || oidcNewPKCEVerifier() != "V" {
		t.Fatal("nil args must keep current hooks")
	}
}

// ─── StartAuth / AuthCallback / Logout ───────────────────────────────────────

func TestStartAuth(t *testing.T) {
	hdlRestoreOIDC(t)
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example")
	SetOIDCHelpers(func() string { return "state-1" }, func() string { return "pkce-1" }, nil)
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

	h := &H{Sessions: NewStore()}
	rr := httptest.NewRecorder()
	h.StartAuth(rr, postFormReq(http.MethodPost, "/auth/start", nil))
	if rr.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("no role: %q", rr.Header().Get("HX-Redirect"))
	}
	cookies := seedSession(t, h, func(s *Session) { s.Role = "holder" })
	rr = httptest.NewRecorder()
	h.StartAuth(rr, formPost("/auth/start", nil, cookies...))
	if !strings.Contains(trig(rr), "No identity providers configured") {
		t.Fatalf("nil registry: %q", trig(rr))
	}
	p := &hdlProv{stubProv: stubProv{id: "corp-idp"}, authorizeErr: errors.New("discovery down")}
	reg := auth.NewRegistry()
	reg.Register(p)
	h.AuthReg = reg
	rr = httptest.NewRecorder()
	h.StartAuth(rr, formPost("/auth/start", url.Values{"provider": {"ghost"}}, cookies...))
	if !strings.Contains(trig(rr), "Unknown provider") {
		t.Fatalf("unknown provider: %q", trig(rr))
	}
	rr = httptest.NewRecorder()
	h.StartAuth(rr, formPost("/auth/start", url.Values{"provider": {"corp-idp"}}, cookies...))
	if !strings.Contains(trig(rr), "discovery down") {
		t.Fatalf("authorize error: %q", trig(rr))
	}
	p.authorizeErr, p.authorizeURL = nil, "https://idp.example/authorize?state=state-1"
	rr = httptest.NewRecorder()
	req := formPost("/auth/start", url.Values{"provider": {"corp-idp"}}, cookies...)
	h.StartAuth(rr, req)
	if rr.Header().Get("HX-Redirect") != p.authorizeURL || p.gotRedirect != "https://portal.example/auth/callback" {
		t.Fatalf("redirect = %q, callback = %q", rr.Header().Get("HX-Redirect"), p.gotRedirect)
	}
	s := sessionOf(h, req)
	if s.PendingProvider != "corp-idp" || s.PendingState != "state-1" || s.PendingPKCE != "pkce-1" {
		t.Fatalf("pending session = %+v", s)
	}
}

func TestAuthCallback(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example")
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	wallet, err := injiwallet.NewStore(filepath.Join(t.TempDir(), "wallet.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.Add("corp-idp|sub-1", injiwallet.HeldCred{VCID: "vc-1", VC: `{"id":"vc-1"}`, HolderKey: "PEM"}); err != nil {
		t.Fatal(err)
	}
	if err := wallet.Add("corp-idp|sub-1", injiwallet.HeldCred{VCID: "vc-2", VC: `{"id":"vc-2"}`}); err != nil {
		t.Fatal(err)
	}
	p := &hdlProv{stubProv: stubProv{id: "corp-idp"}}
	reg := auth.NewRegistry()
	reg.Register(p)
	h := &H{Sessions: NewStore(), AuthReg: reg, InjiWallet: wallet}
	cookies := seedSession(t, h, func(s *Session) {
		s.Role = "holder"
		s.PendingProvider = "corp-idp"
		s.PendingState = "state-1"
		s.PendingPKCE = "pkce-1"
		s.WalletCreds = []vctypes.Credential{{ID: "old"}}
		s.WalletUserKey = "previous-user"
	})
	cb := func(q string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+q, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return req
	}

	rr := httptest.NewRecorder()
	h.AuthCallback(rr, cb("error=access_denied"))
	if rr.Code != 422 || !strings.Contains(rr.Body.String(), "Auth error: access_denied") {
		t.Fatalf("provider error: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.AuthCallback(rr, cb("state=other&code=c"))
	if !strings.Contains(rr.Body.String(), "state mismatch") {
		t.Fatalf("state mismatch: %q", rr.Body.String())
	}
	reg.Remove("corp-idp")
	rr = httptest.NewRecorder()
	h.AuthCallback(rr, cb("state=state-1&code=c"))
	if !strings.Contains(rr.Body.String(), "no longer configured") {
		t.Fatalf("provider gone: %q", rr.Body.String())
	}
	reg.Register(p)
	p.exchangeErr = errors.New("bad code")
	rr = httptest.NewRecorder()
	h.AuthCallback(rr, cb("state=state-1&code=c"))
	if !strings.Contains(rr.Body.String(), "Token exchange: bad code") || p.gotRedirect != "https://portal.example/auth/callback" {
		t.Fatalf("exchange error: %q (redirect %q)", rr.Body.String(), p.gotRedirect)
	}
	_ = trig

	// Success with userinfo failing: identity fields stay empty but AuthOK is set.
	p.exchangeErr = nil
	p.token = auth.Token{AccessToken: "at", RefreshToken: "rt", IDToken: "it"}
	p.userInfoErr = errors.New("userinfo down")
	rr = httptest.NewRecorder()
	req := cb("state=state-1&code=c")
	req.Header.Set("HX-Request", "true")
	h.AuthCallback(rr, req)
	s := sessionOf(h, req)
	if rr.Header().Get("HX-Redirect") != "/holder/dpg" || !s.AuthOK || s.AccessToken != "at" || s.UserSubject != "" || s.PendingState != "" || s.WalletCreds != nil {
		t.Fatalf("session after callback = %+v", s)
	}
	if len(s.InjiClaimedVCs) != 0 {
		t.Fatalf("wallet for unknown user should be empty: %v", s.InjiClaimedVCs)
	}

	// Success with userinfo: durable wallet re-hydrated for provider|sub.
	s.PendingState, s.PendingPKCE, s.PendingProvider = "state-2", "pkce-2", "corp-idp"
	s.WalletUserKey = "stale"
	p.userInfoErr = nil
	p.userInfo = auth.UserInfo{Subject: "sub-1", Email: "holder@example", Claims: map[string]string{"k": "v"}}
	rr = httptest.NewRecorder()
	req = cb("state=state-2&code=c")
	h.AuthCallback(rr, req)
	s = sessionOf(h, req)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/holder/dpg" {
		t.Fatalf("plain redirect: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if s.UserEmail != "holder@example" || s.UserSubject != "sub-1" || s.UserClaims["k"] != "v" || s.WalletUserKey != "corp-idp|sub-1" {
		t.Fatalf("identity = %+v", s)
	}
	if len(s.InjiClaimedVCs) != 2 || s.InjiHolderKeys["vc-1"] != "PEM" || len(s.InjiHolderKeys) != 1 {
		t.Fatalf("wallet rehydrated = %v keys=%v", s.InjiClaimedVCs, s.InjiHolderKeys)
	}
}

func TestLogout(t *testing.T) {
	h := &H{Sessions: NewStore()}
	cookies := seedSession(t, h, func(s *Session) {
		s.Role = "holder"
		s.AuthOK = true
		s.AuthProvider = "corp-idp"
		s.AccessToken, s.RefreshToken, s.IDToken = "a", "r", "i"
		s.UserEmail, s.UserSubject = "e", "s"
		s.UserClaims = map[string]string{"k": "v"}
		s.PendingProvider, s.PendingState, s.PendingPKCE = "p", "st", "pk"
		s.WalletCreds = []vctypes.Credential{{ID: "c"}}
		s.WalletUserKey = "corp-idp|s"
		s.InjiClaimedVCs = []string{"vc"}
		s.InjiHolderKeys = map[string]string{"vc": "PEM"}
	})
	rr := httptest.NewRecorder()
	req := formPost("/logout", nil, cookies...)
	h.Logout(rr, req)
	if rr.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("redirect: %q", rr.Header().Get("HX-Redirect"))
	}
	s := sessionOf(h, req)
	if s.Role != "holder" {
		t.Fatal("role must survive logout")
	}
	if s.AuthOK || s.AuthProvider != "" || s.AccessToken != "" || s.RefreshToken != "" || s.IDToken != "" || s.UserEmail != "" || s.UserSubject != "" || s.UserClaims != nil ||
		s.PendingProvider != "" || s.PendingState != "" || s.PendingPKCE != "" || s.WalletCreds != nil || s.WalletPending != nil || s.WalletUserKey != "" ||
		s.InjiClaimedVCs != nil || s.InjiHolderKeys != nil {
		t.Fatalf("session not wiped: %+v", s)
	}
}

// ─── DPG pick / toggle (issuer, holder, verifier) ────────────────────────────

func TestDpgShowToggleAndPick(t *testing.T) {
	type role struct {
		name, page, expandedField, dest, selectMsg string
		show, toggle, pick                         func(h *H) http.HandlerFunc
		list                                       func(ad *hdlAdapter, m map[string]vctypes.DPG, err error)
		expanded, chosen                           func(s *Session) string
		setExpanded                                func(s *Session, v string)
	}
	roles := []role{
		{name: "issuer", page: "issuer_dpg", dest: "/issuer/schema", selectMsg: "Select a DPG first",
			show: func(h *H) http.HandlerFunc { return h.ShowIssuerDpgs }, toggle: func(h *H) http.HandlerFunc { return h.ToggleIssuerDpg }, pick: func(h *H) http.HandlerFunc { return h.PickIssuerDpg },
			list:     func(ad *hdlAdapter, m map[string]vctypes.DPG, err error) { ad.issuer, ad.issuerErr = m, err },
			expanded: func(s *Session) string { return s.ExpandedIssuerDpg }, chosen: func(s *Session) string { return s.IssuerDpg },
			setExpanded: func(s *Session, v string) { s.ExpandedIssuerDpg = v }},
		{name: "holder", page: "holder_dpg", dest: "/holder/wallet", selectMsg: "Select a wallet first",
			show: func(h *H) http.HandlerFunc { return h.ShowHolderDpgs }, toggle: func(h *H) http.HandlerFunc { return h.ToggleHolderDpg }, pick: func(h *H) http.HandlerFunc { return h.PickHolderDpg },
			list:     func(ad *hdlAdapter, m map[string]vctypes.DPG, err error) { ad.holder, ad.holderErr = m, err },
			expanded: func(s *Session) string { return s.ExpandedHolderDpg }, chosen: func(s *Session) string { return s.HolderDpg },
			setExpanded: func(s *Session, v string) { s.ExpandedHolderDpg = v }},
		{name: "verifier", page: "verifier_dpg", dest: "/verifier/verify", selectMsg: "Select a verifier first",
			show: func(h *H) http.HandlerFunc { return h.ShowVerifierDpgs }, toggle: func(h *H) http.HandlerFunc { return h.ToggleVerifierDpg }, pick: func(h *H) http.HandlerFunc { return h.PickVerifierDpg },
			list:     func(ad *hdlAdapter, m map[string]vctypes.DPG, err error) { ad.verifier, ad.verifierErr = m, err },
			expanded: func(s *Session) string { return s.ExpandedVerifierDpg }, chosen: func(s *Session) string { return s.VerifierDpg },
			setExpanded: func(s *Session, v string) { s.ExpandedVerifierDpg = v }},
	}
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	for _, rl := range roles {
		t.Run(rl.name, func(t *testing.T) {
			dpgs := map[string]vctypes.DPG{
				"Example DPG": {Vendor: "Example DPG", Version: "v1"},
				"Remote DPG":  {Vendor: "Remote DPG", Version: "v2", Redirect: true, UIURL: "https://remote.example"},
				"InApp DPG":   {Vendor: "InApp DPG", Version: "v3", InAppPath: "/holder/inji"},
			}
			ad := &hdlAdapter{}
			rl.list(ad, dpgs, nil)
			h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, rl.page, "holder_dpg", "redirect_notice")}

			// Unauthenticated → redirect home for show + toggle.
			anon := seedSession(t, h, func(s *Session) { s.Role = rl.name })
			for _, fn := range []http.HandlerFunc{rl.show(h), rl.toggle(h)} {
				rr := httptest.NewRecorder()
				fn(rr, hdlGET("/x", true, anon))
				if rr.Header().Get("HX-Redirect") != "/" {
					t.Fatalf("unauthenticated: %q", rr.Header().Get("HX-Redirect"))
				}
			}
			cookies := seedSession(t, h, func(s *Session) { s.Role = rl.name; s.AuthOK = true })

			// Show renders every vendor.
			rr := httptest.NewRecorder()
			rl.show(h)(rr, hdlGET("/x", true, cookies))
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Example DPG") || !strings.Contains(rr.Body.String(), "Remote DPG") {
				t.Fatalf("show: %d %s", rr.Code, rr.Body.String())
			}
			// Pick with nothing expanded.
			rr = httptest.NewRecorder()
			rl.pick(h)(rr, formPost("/x", nil, cookies...))
			if !strings.Contains(trig(rr), rl.selectMsg) {
				t.Fatalf("pick unselected: %q", trig(rr))
			}
			// Toggle expands, toggling again collapses.
			rr = httptest.NewRecorder()
			req := formPost("/x", url.Values{"vendor": {"Example DPG"}}, cookies...)
			rl.toggle(h)(rr, req)
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hx-swap-oob") || rl.expanded(sessionOf(h, req)) != "Example DPG" {
				t.Fatalf("toggle expand: %d expanded=%q", rr.Code, rl.expanded(sessionOf(h, req)))
			}
			// Pick → forward to the role's next page.
			rr = httptest.NewRecorder()
			req = formPost("/x", nil, cookies...)
			rl.pick(h)(rr, req)
			if rr.Header().Get("HX-Redirect") != rl.dest || rl.chosen(sessionOf(h, req)) != "Example DPG" {
				t.Fatalf("pick: %q chosen=%q", rr.Header().Get("HX-Redirect"), rl.chosen(sessionOf(h, req)))
			}
			rr = httptest.NewRecorder()
			req = formPost("/x", url.Values{"vendor": {"Example DPG"}}, cookies...)
			rl.toggle(h)(rr, req)
			if rl.expanded(sessionOf(h, req)) != "" {
				t.Fatal("toggle should collapse")
			}
			// Redirect DPG → redirect_notice page.
			rl.setExpanded(sessionOf(h, req), "Remote DPG")
			rr = httptest.NewRecorder()
			rl.pick(h)(rr, hdlGET("/x", true, cookies))
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), "https://remote.example") {
				t.Fatalf("redirect notice: %d %s", rr.Code, rr.Body.String())
			}
			// InAppPath DPG (issuer/holder) → in-app redirect; verifier ignores it.
			rl.setExpanded(sessionOf(h, req), "InApp DPG")
			rr = httptest.NewRecorder()
			rl.pick(h)(rr, hdlGET("/x", true, cookies))
			wantInApp := "/holder/inji"
			if rl.name == "verifier" {
				wantInApp = rl.dest
			}
			if rr.Header().Get("HX-Redirect") != wantInApp {
				t.Fatalf("in-app pick: %q", rr.Header().Get("HX-Redirect"))
			}
			// Unknown vendor expanded → 400.
			rl.setExpanded(sessionOf(h, req), "Ghost DPG")
			rr = httptest.NewRecorder()
			rl.pick(h)(rr, hdlGET("/x", false, cookies))
			if rr.Code != 400 {
				t.Fatalf("unknown vendor: %d", rr.Code)
			}
			// Adapter errors surface as toasts for show/toggle/pick.
			rl.list(ad, nil, errors.New("backend down"))
			for _, fn := range []http.HandlerFunc{rl.show(h), rl.toggle(h), rl.pick(h)} {
				rr := httptest.NewRecorder()
				fn(rr, formPost("/x", url.Values{"vendor": {"Example DPG"}}, cookies...))
				if !strings.Contains(trig(rr), "backend down") {
					t.Fatalf("adapter error: %q", trig(rr))
				}
			}
		})
	}
}

// ─── errorToast / errorToastStatus ───────────────────────────────────────────

func TestErrorToastStatus(t *testing.T) {
	h := &H{}
	rr := httptest.NewRecorder()
	h.errorToast(rr, hdlGET("/x", true, nil), `it's "broken"`)
	if rr.Code != 200 || rr.Body.Len() != 0 || rr.Header().Get("HX-Reswap") != "none" || rr.Header().Get("HX-Trigger") != `{"toast":"it's \"broken\""}` {
		t.Fatalf("htmx toast: %d %q %q", rr.Code, rr.Body.String(), rr.Header().Get("HX-Trigger"))
	}
	rr = httptest.NewRecorder()
	h.errorToast(rr, hdlGET("/x", false, nil), "bad input")
	if rr.Code != 422 || strings.TrimSpace(rr.Body.String()) != "bad input" {
		t.Fatalf("plain toast: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.errorToastStatus(rr, hdlGET("/x", false, nil), 502, "upstream")
	if rr.Code != 502 {
		t.Fatalf("explicit status: %d", rr.Code)
	}
}
