// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// quiet drops the log messages of the tests.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// settings returns a configuration for the tests.
func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	base := map[string]string{"VCA_INGEST_STATE_DIR": filepath.Join(t.TempDir(), "state")}
	for k, v := range values {
		base[k] = v
	}
	cfg, err := config.Load(func(name string) string { return base[name] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// keyPEM writes one ES256 key as a PKCS 8 PEM file.
func keyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

var now = time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)

// staff stands in for verifier-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.VerifierAudience, now)
}

// serve answers one request, with the session cookie when token is set.
func serve(a *app.App, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.VerifierCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

func TestBuildAndServe(t *testing.T) {
	auth := staff(t)
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Service.Ready() {
		t.Fatal("the wiring returns a ready service")
	}
	s := httptest.NewServer(a.Mux)
	defer s.Close()
	for _, path := range []string{"/scan/", "/scan/static/scanner.js", "/static/vca.css"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(auth.Cookie(staffsession.VerifierCookie, auth.Token(t, "kc|carol", "verifier-operator")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s answered %d", path, resp.StatusCode)
		}
	}
}

// TestPortalNeedsSession proves the camera page answers only with a
// session (ADR-036 decision 2), and that every post of the page needs
// the form token, in the field or in the header the script sends.
func TestPortalNeedsSession(t *testing.T) {
	auth := staff(t)
	cfg := settings(t, map[string]string{"VCA_INGEST_LOGIN_URL": "https://verifier-waltid.example/auth/"})
	a, err := app.Build(cfg, app.Deps{Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/scan/", "/scan/static/scanner.js"} {
		rec := serve(a, http.MethodGet, path, "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Auth.LoginURL+"?return_to="+url.QueryEscape(path) {
			t.Fatalf("%s: location %q", path, got)
		}
	}
	if rec := serve(a, http.MethodPost, "/scan/ingest", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post: status %d, want 401", rec.Code)
	}
	token := auth.Token(t, "kc|carol", "verifier-operator")
	if rec := serve(a, http.MethodPost, "/scan/ingest", token); rec.Code != http.StatusForbidden {
		t.Fatalf("post without token: status %d, want 403", rec.Code)
	}
	page := serve(a, http.MethodGet, "/scan/", token)
	if page.Code != http.StatusOK {
		t.Fatalf("page: status %d", page.Code)
	}
	if n := strings.Count(page.Body.String(), `name="`+staffsession.Field+`"`); n != 3 {
		t.Fatalf("the page has %d form tokens, want one per form", n)
	}
	_, after, _ := strings.Cut(page.Body.String(), `name="`+staffsession.Field+`" value="`)
	csrf, _, _ := strings.Cut(after, `"`)
	// The script posts multipart data with the token in the header.
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("payload", "not a credential"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/scan/ingest", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(staffsession.Header, csrf)
	req.AddCookie(auth.Cookie(staffsession.VerifierCookie, token))
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scripted post: status %d body %s", rec.Code, rec.Body)
	}
	// The upload form posts multipart data with the token as a field.
	body.Reset()
	form = multipart.NewWriter(&body)
	if err := form.WriteField(staffsession.Field, csrf); err != nil {
		t.Fatal(err)
	}
	if err := form.WriteField("payload", "not a credential"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/scan/ingest", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.AddCookie(auth.Cookie(staffsession.VerifierCookie, token))
	rec = httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload post: status %d body %s", rec.Code, rec.Body)
	}
	// A session of the issuer realm does not open the verifier page.
	other := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	if rec := serve(a, http.MethodGet, "/scan/", other.Token(t, "kc|alice")); rec.Code != http.StatusSeeOther {
		t.Fatalf("issuer session: status %d, want 303", rec.Code)
	}
}

// TestPublicEndpointsStayOpen proves the OID4VP endpoints of the wallet
// need no session (ADR-036 decision 2).
func TestPublicEndpointsStayOpen(t *testing.T) {
	cfg := settings(t, map[string]string{"VCA_INGEST_LOGIN_URL": "https://verifier-waltid.example/auth/"})
	a, err := app.Build(cfg, app.Deps{Log: quiet(), SessionKeys: staff(t).Keys()})
	if err != nil {
		t.Fatal(err)
	}
	// An unknown transaction is 404, not a redirect to the chooser.
	if rec := serve(a, http.MethodGet, "/oid4vp/request/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("request object: status %d, want 404", rec.Code)
	}
	rec := serve(a, http.MethodPost, "/oid4vp/response", "")
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusSeeOther || rec.Code == http.StatusForbidden {
		t.Fatalf("direct post: status %d", rec.Code)
	}
	if rec := serve(a, http.MethodGet, "/static/vca.css", ""); rec.Code != http.StatusOK {
		t.Fatalf("assets: status %d", rec.Code)
	}
	// Without a key source the service starts and lets nobody in.
	bare, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(bare, http.MethodGet, "/scan/", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key source: status %d, want 401", rec.Code)
	}
	cfg.Auth.JWKSFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err == nil {
		t.Fatal("a missing key set file built")
	}
}

func TestBuildWithSigningKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, keyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()}); err != nil {
		t.Fatalf("a PEM key file must load: %v", err)
	}
}

func TestBuildKeyErrors(t *testing.T) {
	cases := map[string]func(string) []byte{
		"missing file": nil,
		"no key block": func(string) []byte { return []byte("not a pem file") },
		"broken key":   func(string) []byte { return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}) },
		"other block": func(string) []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if write != nil {
				if err := os.WriteFile(path, write(path), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()})
			if err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestBuildRejectsBadStateDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_STATE_DIR": file}), app.Deps{Log: quiet()}); err == nil {
		t.Error("a state directory that is a file wants an error")
	}
}

func TestBuildWithDiscoveryURLAndDefaults(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{
		"VCA_INGEST_DISCOVERY_URL": "http://127.0.0.1:1",
		"VCA_INGEST_XML_ENCODING":  "base64",
		"VCA_INGEST_XML_PATH":      "root.vc",
	}), app.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Config.XMLEncoding != "base64" {
		t.Errorf("config = %+v", a.Config)
	}
}

func TestPrune(t *testing.T) {
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.PruneInterval = 5 * time.Millisecond
	if serr := a.Store.Put(context.Background(), txn.Transaction{ID: "old", CreatedAt: time.Unix(0, 0).UTC()}); serr != nil {
		t.Fatal(serr)
	}
	if serr := a.Store.Put(context.Background(), txn.Transaction{ID: "new", CreatedAt: time.Now()}); serr != nil {
		t.Fatal(serr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	a.Prune(ctx, quiet())
	list, err := a.Store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "new" {
		t.Errorf("the job removed the old transaction only, got %+v", list)
	}
}

func TestPruneOff(t *testing.T) {
	a, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.Config.TransactionTTL = 0
	// The job returns at once, so the test does not block.
	a.Prune(context.Background(), quiet())
}

func TestPruneLogsFailure(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_INGEST_STATE_DIR": ""}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	a.PruneInterval = 5 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	a.Prune(ctx, quiet())
}

func TestParsePEMRejectsKeyThatCannotSign(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": path}), app.Deps{Log: quiet()}); err == nil {
		t.Error("a key that cannot sign wants an error")
	}
}

func TestBuildReadFileInjection(t *testing.T) {
	_, err := app.Build(settings(t, map[string]string{"VCA_INGEST_SIGNING_KEY_FILE": "/keys/ingest.pem"}), app.Deps{
		Log:      quiet(),
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("no such file") },
	})
	if err == nil {
		t.Error("a read error wants an error")
	}
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, nil)
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{Log: quiet()})
	uikittest.AssertBadThemeError(t, err, path)
}
