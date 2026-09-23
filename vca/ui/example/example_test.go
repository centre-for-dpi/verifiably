// SPDX-License-Identifier: Apache-2.0

package example

import (
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestDemoPageIsAccessible(t *testing.T) {
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
		"<h1>vca UI kit demo</h1>", `<p class="pg-header-label">UI kit</p>`, `<section class="card"`, "<dialog", "<details", `<img class="qr"`,
		"<table", "badge-ok", `aria-expanded="true"`, `<label for="issuer">`, `<select id="kind"`,
		`hx-get="/toast?t=now"`, `data-open-dialog="confirm"`, `toast-info`, "htmx 2.0.10",
		// The demo page uses the portal shell.
		`<body data-role="issuer" class="has-shell">`, `<span class="role-chip">Issuer</span>`, `aria-label="Stack"`,
		`aria-current="true"`, `stack-starting`, `name="csrf_token"`, `>Sign out</button>`, `<nav aria-label="Portal">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("demo page missing %q", want)
		}
	}
	for _, name := range components.Names {
		if name == "layout" || name == "page" {
			continue
		}
		if !strings.Contains(doc, name) {
			t.Errorf("demo page has no trace of component %q", name)
		}
	}

	rec = get(t, h, "/", true)
	if rec.Header().Get("HX-Title") != "vca UI kit demo" || strings.Contains(rec.Body.String(), "<html") {
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

func TestEmptyKitFails(t *testing.T) {
	if _, err := DemoPage(&components.Kit{}); !errors.Is(err, components.ErrNoTemplates) {
		t.Errorf("empty kit err = %v", err)
	}
	h := Mux(http.NotFoundHandler(), &components.Kit{}, DemoPage)
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
