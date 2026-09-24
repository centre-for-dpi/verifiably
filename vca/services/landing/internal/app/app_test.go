// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/config"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestWiringServesTheAssets(t *testing.T) {
	cfg := settings(t, map[string]string{})
	a, err := app.Build(cfg, app.Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.Prober == nil {
		t.Fatal("no prober")
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/vca.css", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("assets: status = %d", rec.Code)
	}
	// With no peer the landing still renders, with no stack and no call
	// to action, and the descriptor is empty.
	rec = httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("landing: status = %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	if !strings.Contains(rec.Body.String(), "No stack runs yet.") || strings.Contains(rec.Body.String(), "btn-primary") {
		t.Errorf("landing with no peer:\n%s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/vca.json", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":"latest"`) {
		t.Errorf("descriptor: %d %s", rec.Code, rec.Body.String())
	}
	if a.Pages == nil {
		t.Error("the pages are wired")
	}
}

func TestWiringUsesTheDefaultLogger(t *testing.T) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(previous)
	if _, err := app.Build(settings(t, map[string]string{}), app.Deps{}); err != nil {
		t.Errorf("build: %v", err)
	}
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, map[string]string{})
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{})
	uikittest.AssertBadThemeError(t, err, path)
}
