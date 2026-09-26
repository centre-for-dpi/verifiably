// SPDX-License-Identifier: Apache-2.0

package example

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

func get(t *testing.T, h http.Handler, path string, hx bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestKitPageIsAccessible(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<title>vca UI kit</title>`, `<h1>Every component,<em>one page.</em></h1>`, `<span class="role">UI kit</span>`, `<section class="card"`, "<dialog", "<details", `<img class="qr"`,
		"<table", "badge-ok", `aria-expanded="true"`, `<label for="text-field">`, `<select id="select-field"`,
		`hx-get="/toast?t=now"`, `data-open-dialog="confirm"`, `toast-info`, "htmx 2.0.10",
		// The kit page uses the portal shell.
		`<body data-role="issuer" class="has-shell">`, `<span class="role-chip">Issuer</span>`, `aria-label="Stack"`,
		`aria-current="true"`, `stack-starting`, `name="csrf_token"`, `>Sign out</button>`, `<nav aria-label="Portal">`,
		// The nine content components.
		`<section class="hero">`, `<ul class="tiles">`, `<ol class="steps">`, `aria-current="step"`, `<section class="checklist"`,
		`<div class="stats">`, `<span class="stat-value">`, `<ol class="stepper"`, `<fieldset class="choice"`, `<legend>`, `<fieldset class="fieldset"`, `data-dcapi-offer=`,
		`<figure class="code"`, `<div class="empty">`, `<nav class="tabs" aria-label="Kit views">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("kit page missing %q", want)
		}
	}
	for _, name := range components.Names {
		if name == "layout" || name == "page" {
			continue
		}
		if !strings.Contains(doc, name) {
			t.Errorf("kit page has no trace of component %q", name)
		}
	}

	rec = get(t, h, "/", true)
	if rec.Header().Get("HX-Title") != "vca UI kit" || strings.Contains(rec.Body.String(), "<html") {
		t.Error("htmx request should get the partial with HX-Title")
	}

	rec = get(t, h, "/toast?t=now", false)
	if !strings.Contains(rec.Body.String(), `hx-swap-oob="beforeend:#toasts"`) {
		t.Errorf("toast = %q", rec.Body.String())
	}

	for _, path := range []string{"/static/vca.css", "/static/htmx.min.js"} {
		if rec = get(t, h, path, false); rec.Code != http.StatusOK {
			t.Errorf("%s status %d", path, rec.Code)
		}
	}
}

// TestSignInPageIsAccessible renders the sign in chooser of the kit:
// the block carries the one h1 and every part of the board.
func TestSignInPageIsAccessible(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/signin", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<title>Sign in</title>`, `<section class="signin">`, `<h1>Sign in as an admin.</h1>`, `<span class="signin-meta">Provider meta 1</span>`,
		`<div class="signin-callout">`, `<section class="card" id="bootstrap"`, `<span>or</span>`, `>Register a new account</a>`, `<p class="signin-note">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("sign in page missing %q", want)
		}
	}
	if _, err := SignInPage(&components.Kit{}); !errors.Is(err, components.ErrNoTemplates) {
		t.Errorf("empty kit err = %v", err)
	}
	if rec := get(t, Mux(http.NotFoundHandler(), &components.Kit{}, KitPage), "/signin", false); rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", rec.Code)
	}
}

func TestEmptyKitFails(t *testing.T) {
	if _, err := KitPage(&components.Kit{}); !errors.Is(err, components.ErrNoTemplates) {
		t.Errorf("empty kit err = %v", err)
	}
	h := Mux(http.NotFoundHandler(), &components.Kit{}, KitPage)
	for _, path := range []string{"/", "/toast"} {
		if rec := get(t, h, path, false); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s status %d, want 500", path, rec.Code)
		}
	}
}

func TestRenderFailureAfterBuild(t *testing.T) {
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	bad := func(*components.Kit) (components.Page, error) { return components.Page{}, nil }
	h := Mux(http.NotFoundHandler(), kit, bad)
	if rec := get(t, h, "/", false); rec.Code != http.StatusInternalServerError {
		t.Errorf("page without title: status %d, want 500", rec.Code)
	}
}

// bannedWords reads testdata/banned-words.txt.
func bannedWords(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "banned-words.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatal("testdata/banned-words.txt names no word")
	}
	return out
}

// TestKitPageNamesNoPersonOrIssuer: the kit page shows the names of the
// components as content. It shows no person, no issuer, no credential
// and no placeholder account (ADR-050 decision 1).
func TestKitPageNamesNoPersonOrIssuer(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatal(err)
	}
	words := bannedWords(t)
	for _, path := range []string{"/", "/signin", "/toast?t=now"} {
		body := strings.ToLower(get(t, h, path, false).Body.String())
		for _, w := range words {
			if strings.Contains(body, strings.ToLower(w)) {
				t.Errorf("%s shows %q", path, w)
			}
		}
	}
	if doc := get(t, h, "/", false).Body.String(); !strings.Contains(doc, "Kit page") {
		t.Error("the shell user is not the kit page")
	}
}

// TestNoServiceImportsTheKitPage: the kit page is a page of the kit, not
// of a deployment. No service binary and no CLI imports it, and the ui
// packages they use are the ones testdata/service-deps.txt names.
func TestNoServiceImportsTheKitPage(t *testing.T) {
	if testing.Short() {
		t.Skip("go list reads every service package")
	}
	cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", "./services/...", "./cmd/...") // #nosec G204 -- fixed arguments
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const module = "github.com/centre-for-dpi/vc-adapters/"
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimPrefix(strings.TrimSpace(line), module)
		if pkg == strings.TrimSpace(line) || pkg != "ui" && !strings.HasPrefix(pkg, "ui/") {
			continue
		}
		if strings.HasPrefix(pkg, "ui/example") {
			t.Errorf("a service imports %s", pkg)
		}
		seen[pkg] = true
	}
	got := make([]string, 0, len(seen))
	for pkg := range seen {
		got = append(got, pkg)
	}
	sort.Strings(got)
	raw, err := os.ReadFile(filepath.Join("testdata", "service-deps.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(raw))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the services use the ui packages\n%s\nwant testdata/service-deps.txt\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
