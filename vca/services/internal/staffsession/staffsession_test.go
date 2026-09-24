// SPDX-License-Identifier: Apache-2.0

package staffsession_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

const login = "https://issuer-waltid.example/auth/"

var now = time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)

// echo answers with the subject of the session and, on a page request,
// with the hidden CSRF field.
func echo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := staffsession.User(r.Context())
		if !ok {
			http.Error(w, "no session", http.StatusInternalServerError)
			return
		}
		anyval.DiscardWrite(io.WriteString(w, s.Subject+"\n"+string(staffsession.HiddenField(r.Context()))))
	})
}

func guard(t *testing.T, issuer *staffsessiontest.Issuer, edit func(*staffsession.Options)) *staffsession.Guard {
	t.Helper()
	opts := staffsession.Options{
		Keys:     issuer.Keys(),
		Audience: staffsession.IssuerAudience,
		Cookie:   staffsession.IssuerCookie,
		LoginURL: login,
		Now:      func() time.Time { return now },
	}
	if edit != nil {
		edit(&opts)
	}
	g, err := staffsession.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func get(h http.Handler, path string, cookie string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: cookie})
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func post(h http.Handler, path, cookie string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: cookie})
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuardRedirectsWithoutSession(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	h := guard(t, issuer, nil).Wrap(echo())

	rec := get(h, "/portal/schemas/abc?notice=published", "", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", rec.Code)
	}
	want := login + "?return_to=" + url.QueryEscape("/portal/schemas/abc?notice=published")
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("location %q, want %q", got, want)
	}

	// A bad token counts as no session.
	rec = get(h, "/portal/", "not.a.token", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bad token: status %d, want 303", rec.Code)
	}

	// An htmx request cannot follow a redirect into its target, so it
	// gets 401 and the HX-Redirect header.
	rec = get(h, "/portal/", "", map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("htmx: status %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("HX-Redirect"); !strings.HasPrefix(got, login) {
		t.Fatalf("htmx: HX-Redirect %q", got)
	}

	// A POST without a session gets 401 and no redirect.
	rec = post(h, "/portal/schemas/abc/publish", "", url.Values{"version": {"1"}}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("post: status %d, want 401", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("post: a redirect")
	}

	// Without a login URL a page request gets 401 too.
	h = guard(t, issuer, func(o *staffsession.Options) { o.LoginURL = "" }).Wrap(echo())
	if rec = get(h, "/portal/", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no login url: status %d, want 401", rec.Code)
	}
}

func TestGuardAcceptsValidToken(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	h := guard(t, issuer, nil).Wrap(echo())
	token := issuer.Token(t, "kc|alice", "issuer-operator")

	rec := get(h, "/portal/", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie: status %d body %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(rec.Body.String(), "kc|alice\n") {
		t.Fatalf("body %q", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `name="`+staffsession.Field+`"`) {
		t.Fatalf("no hidden field in %q", rec.Body)
	}

	rec = get(h, "/portal/", "", map[string]string{"Authorization": "Bearer " + token})
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer: status %d", rec.Code)
	}
}

func TestGuardRejectsWrongAudience(t *testing.T) {
	verifier := staffsessiontest.New(t, staffsession.VerifierAudience, now)
	h := guard(t, verifier, nil).Wrap(echo())
	rec := get(h, "/portal/", verifier.Token(t, "kc|bob", "verifier-viewer"), nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", rec.Code)
	}
	_, err := guard(t, verifier, nil).Verify(context.Background(), verifier.Token(t, "kc|bob"))
	if !errors.Is(err, staffsession.ErrNoSession) {
		t.Fatalf("err %v", err)
	}
}

func TestGuardRejectsExpired(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	token := issuer.Token(t, "kc|alice")
	late := guard(t, issuer, func(o *staffsession.Options) {
		o.Now = func() time.Time { return now.Add(staffsessiontest.TTL + time.Second) }
	})
	if rec := get(late.Wrap(echo()), "/portal/", token, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", rec.Code)
	}
	_, err := late.Verify(context.Background(), token)
	if !errors.Is(err, staffsession.ErrNoSession) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err %v", err)
	}
}

func TestGuardRejectsOtherIssuerAndRevokedKey(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	other := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	g := guard(t, issuer, func(o *staffsession.Options) { o.Issuer = issuer.Issuer })
	if _, err := g.Verify(context.Background(), other.Token(t, "kc|eve")); !errors.Is(err, staffsession.ErrNoSession) {
		t.Fatalf("another key: %v", err)
	}
	stranger := staffsessiontest.NewWithIssuer(t, "https://other.example", staffsession.IssuerAudience, now)
	g = guard(t, stranger, func(o *staffsession.Options) { o.Issuer = issuer.Issuer })
	if _, err := g.Verify(context.Background(), stranger.Token(t, "kc|eve")); !errors.Is(err, staffsession.ErrNoSession) {
		t.Fatalf("another issuer: %v", err)
	}
	if _, err := g.Verify(context.Background(), ""); !errors.Is(err, staffsession.ErrNoSession) {
		t.Fatalf("empty: %v", err)
	}
}

func TestGuardLeavesPublicPathsOpen(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { anyval.DiscardWrite(io.WriteString(w, "open")) })
	h := guard(t, issuer, func(o *staffsession.Options) {
		o.Public = []string{"/verify", "/catalog", "/.well-known/openid-credential-issuer"}
	}).Wrap(next)
	for _, path := range []string{"/verify/", "/verify", "/catalog", "/catalog/types", "/.well-known/openid-credential-issuer"} {
		if rec := get(h, path, "", nil); rec.Code != http.StatusOK || rec.Body.String() != "open" {
			t.Fatalf("%s: status %d body %q", path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/portal/", "/verifyme", "/catalogue"} {
		if rec := get(h, path, "", nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
	}
}

func TestPostNeedsCSRF(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	g := guard(t, issuer, nil)
	h := g.Wrap(echo())
	token := issuer.Token(t, "kc|alice")

	// A POST with a session but no token is refused.
	rec := post(h, "/portal/x", token, url.Values{"version": {"1"}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no token: status %d, want 403", rec.Code)
	}

	// The token of a page request works once in the form field.
	page := get(h, "/portal/", token, nil)
	csrf := fieldValue(t, page.Body.String())
	rec = post(h, "/portal/x", token, url.Values{staffsession.Field: {csrf}}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("form token: status %d body %s", rec.Code, rec.Body)
	}

	// The header works for a script.
	rec = post(h, "/portal/x", token, nil, map[string]string{staffsession.Header: csrf})
	if rec.Code != http.StatusOK {
		t.Fatalf("header token: status %d", rec.Code)
	}

	// A token of another session does not work.
	otherPage := get(h, "/portal/", issuer.Token(t, "kc|mallory"), nil)
	rec = post(h, "/portal/x", token, url.Values{staffsession.Field: {fieldValue(t, otherPage.Body.String())}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign token: status %d, want 403", rec.Code)
	}

	// A body over the cap is refused before the token check.
	small := guard(t, issuer, func(o *staffsession.Options) { o.MaxFormBytes = 16 })
	rec = post(small.Wrap(echo()), "/portal/x", token, url.Values{"pad": {strings.Repeat("x", 64)}}, nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: status %d, want 413", rec.Code)
	}

	// A multipart form carries the token as a field too.
	body := "--b\r\nContent-Disposition: form-data; name=\"" + staffsession.Field + "\"\r\n\r\n" + csrf + "\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/portal/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart: status %d body %s", rec.Code, rec.Body)
	}
}

// fieldValue reads the value of the hidden field out of a page.
func fieldValue(t *testing.T, page string) string {
	t.Helper()
	_, after, ok := strings.Cut(page, `value="`)
	if !ok {
		t.Fatalf("no hidden field in %q", page)
	}
	value, _, _ := strings.Cut(after, `"`)
	return value
}

func TestHelpersWithoutSession(t *testing.T) {
	if _, ok := staffsession.User(context.Background()); ok {
		t.Fatal("a bare context has a session")
	}
	if got := staffsession.HiddenField(context.Background()); got != "" {
		t.Fatalf("hidden field %q", got)
	}
	_, err := staffsession.Require(context.Background())
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeUnauthenticated {
		t.Fatalf("require: %v", err)
	}
	s := staffsession.Session{Subject: "kc|alice", Roles: []string{"issuer-admin"}}
	ctx := staffsession.With(context.Background(), s)
	if got, err := staffsession.Require(ctx); err != nil || got.Subject != "kc|alice" || !got.HasRole("issuer-admin") || got.HasRole("issuer-viewer") {
		t.Fatalf("require: %+v %v", got, err)
	}
}

func TestNewChecksOptions(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	cases := map[string]staffsession.Options{
		"no keys":     {Audience: "a", Cookie: "c"},
		"no audience": {Keys: issuer.Keys(), Cookie: "c"},
		"no cookie":   {Keys: issuer.Keys(), Audience: "a"},
		"short key":   {Keys: issuer.Keys(), Audience: "a", Cookie: "c", CSRFKey: []byte("short")},
	}
	for name, opts := range cases {
		if _, err := staffsession.New(opts); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A configured key makes tokens that survive a restart of the
	// process, so two guards with the same key agree.
	key := []byte("0123456789abcdef0123456789abcdef")
	a := guard(t, issuer, func(o *staffsession.Options) { o.CSRFKey = key })
	b := guard(t, issuer, func(o *staffsession.Options) { o.CSRFKey = key })
	s := staffsession.Session{Subject: "kc|alice", ID: "sid-1"}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set(staffsession.Header, a.Token(s))
	if err := b.Check(req, s); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := b.Check(httptest.NewRequest(http.MethodPost, "/x", nil), s); !errors.Is(err, staffsession.ErrCSRF) {
		t.Fatalf("missing: %v", err)
	}
}

func TestRealmOf(t *testing.T) {
	issuer, ok := staffsession.RealmOf(commonv1.Role_ROLE_ISSUER)
	if !ok || issuer.Audience != staffsession.IssuerAudience || issuer.Cookie != staffsession.IssuerCookie {
		t.Fatalf("issuer %+v %v", issuer, ok)
	}
	verifier, ok := staffsession.RealmOf(commonv1.Role_ROLE_VERIFIER)
	if !ok || verifier.Audience != staffsession.VerifierAudience || verifier.Cookie != staffsession.VerifierCookie {
		t.Fatalf("verifier %+v %v", verifier, ok)
	}
	if _, ok := staffsession.RealmOf(commonv1.Role_ROLE_HOLDER); ok {
		t.Fatal("the holder has no staff realm")
	}
}

func TestCachedKeysRefetchAfterRotation(t *testing.T) {
	first := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	second := staffsessiontest.NewWithIssuer(t, first.Issuer, staffsession.IssuerAudience, now)
	var current atomic.Pointer[staffsessiontest.Issuer]
	current.Store(first)
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		oidcflow.WriteJSON(w, http.StatusOK, current.Load().JWKS())
	}))
	defer srv.Close()

	clock := now
	keys := staffsession.CachedKeys(srv.URL+"/.well-known/jwks.json", 10*time.Minute, srv.Client(), func() time.Time { return clock })
	g, err := staffsession.New(staffsession.Options{
		Keys: keys, Audience: staffsession.IssuerAudience, Cookie: staffsession.IssuerCookie,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := g.Verify(ctx, first.Token(t, "kc|a")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Verify(ctx, first.Token(t, "kc|a")); err != nil {
		t.Fatal(err)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches %d, want 1 within the TTL", n)
	}
	// The auth service rotated its key. The first miss refetches once.
	current.Store(second)
	clock = clock.Add(time.Minute)
	if _, err := g.Verify(ctx, second.Token(t, "kc|b")); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches %d, want 2 after a rotation", n)
	}
	// A flood of bad tokens does not refetch again inside the hold time.
	for range 3 {
		if _, err := g.Verify(ctx, "x.y.z"); err == nil {
			t.Fatal("garbage verified")
		}
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches %d, want 2 within the hold time", n)
	}
	// A key set that fails to load is an error, not an open door.
	srv.Close()
	clock = clock.Add(time.Hour)
	if _, err := g.Verify(ctx, second.Token(t, "kc|b")); !errors.Is(err, staffsession.ErrNoSession) {
		t.Fatalf("unreachable keys: %v", err)
	}
}

func TestFileAndStaticKeys(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	path := issuer.JWKSFile(t)
	keys, err := staffsession.FileKeys(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	set, err := keys(context.Background(), false)
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("file keys: %v %d", err, len(set.Keys))
	}
	if _, err := staffsession.FileKeys(path+".missing", nil); err == nil {
		t.Fatal("a missing file loads")
	}
	bad := func(string) ([]byte, error) { return []byte("{"), nil }
	if _, err := staffsession.FileKeys(path, bad); err == nil {
		t.Fatal("a broken file loads")
	}
	static := staffsession.StaticKeys(jose.JWKS{})
	if set, err := static(context.Background(), true); err != nil || len(set.Keys) != 0 {
		t.Fatalf("static: %v", err)
	}
}

func TestGuardEdgeCases(t *testing.T) {
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	token := issuer.Token(t, "kc|alice")

	t.Run("a login URL with a query gets return_to appended", func(t *testing.T) {
		h := guard(t, issuer, func(o *staffsession.Options) { o.LoginURL = login + "?stack=waltid" }).Wrap(echo())
		rec := get(h, "/portal/", "", nil)
		if got := rec.Header().Get("Location"); got != login+"?stack=waltid&return_to=%2Fportal%2F" {
			t.Fatalf("location %q", got)
		}
	})

	t.Run("a return_to that is not a plain path falls back to the root", func(t *testing.T) {
		h := guard(t, issuer, nil).Wrap(echo())
		req := httptest.NewRequest(http.MethodGet, "http://host//evil.example/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Location"); got != login+"?return_to=%2F" {
			t.Fatalf("location %q", got)
		}
	})

	t.Run("an empty public entry matches nothing", func(t *testing.T) {
		h := guard(t, issuer, func(o *staffsession.Options) { o.Public = []string{"", "/"} }).Wrap(echo())
		if rec := get(h, "/portal/", "", nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("a token without a subject is no session", func(t *testing.T) {
		_, err := guard(t, issuer, nil).Verify(context.Background(), issuer.Token(t, ""))
		if !errors.Is(err, staffsession.ErrNoSession) || !strings.Contains(err.Error(), "subject") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("a session without an id binds its token to the subject", func(t *testing.T) {
		g := guard(t, issuer, nil)
		s := staffsession.Session{Subject: "kc|alice"}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set(staffsession.Header, g.Token(s))
		if err := g.Check(req, s); err != nil {
			t.Fatal(err)
		}
		if err := g.Check(req, staffsession.Session{Subject: "kc|bob"}); err == nil {
			t.Fatal("another subject passed")
		}
	})

	t.Run("a body that is not a form needs the header", func(t *testing.T) {
		h := guard(t, issuer, nil).Wrap(echo())
		req := httptest.NewRequest(http.MethodPost, "/portal/x", strings.NewReader(`{"a":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("json: status %d, want 403", rec.Code)
		}
		req = httptest.NewRequest(http.MethodPost, "/portal/x", strings.NewReader("x"))
		req.Header.Set("Content-Type", "not a type")
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("bad type: status %d, want 403", rec.Code)
		}
	})

	t.Run("a form that does not parse is a bad request", func(t *testing.T) {
		h := guard(t, issuer, nil).Wrap(echo())
		req := httptest.NewRequest(http.MethodPost, "/portal/x", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
	})
}

func TestCachedKeysReportsBadAnswers(t *testing.T) {
	var body atomic.Value
	body.Store("{")
	status := atomic.Int32{}
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		anyval.DiscardWrite(io.WriteString(w, anyval.As[string](body.Load())))
	}))
	defer srv.Close()
	keys := staffsession.CachedKeys(srv.URL, 0, nil, nil)
	if _, err := keys(context.Background(), false); err == nil || !strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("broken json: %v", err)
	}
	status.Store(http.StatusInternalServerError)
	if _, err := keys(context.Background(), false); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("status 500: %v", err)
	}
	if _, err := staffsession.CachedKeys("::bad url", 0, nil, nil)(context.Background(), false); err == nil {
		t.Fatal("a bad URL fetched")
	}
	// The refresh path reports a fetch failure too.
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	calls := 0
	flaky := func(_ context.Context, refresh bool) (jose.JWKS, error) {
		calls++
		if refresh {
			return jose.JWKS{}, errors.New("down")
		}
		return jose.JWKS{}, nil
	}
	g, err := staffsession.New(staffsession.Options{Keys: flaky, Audience: staffsession.IssuerAudience, Cookie: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Verify(context.Background(), issuer.Token(t, "kc|a")); !errors.Is(err, staffsession.ErrNoSession) || calls != 2 {
		t.Fatalf("refresh failure: %v after %d calls", err, calls)
	}
}
