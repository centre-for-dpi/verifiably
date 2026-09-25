// SPDX-License-Identifier: Apache-2.0

package qrscan_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/qrscan"
)

func TestHandlerServesTheScanner(t *testing.T) {
	h := http.StripPrefix("/static/", qrscan.Handler())
	for _, name := range []string{qrscan.Reader, qrscan.Script} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/"+name, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") == "" ||
			rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %v", name, rec.Code, rec.Header())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/"+qrscan.Script, nil))
	// The scanner follows a redirect the service names, so a wallet can
	// open the next step after a scan.
	if !strings.Contains(rec.Body.String(), "HX-Redirect") {
		t.Fatal("the scanner does not follow HX-Redirect")
	}
	missing := httptest.NewRecorder()
	h.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/static/nope.js", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", missing.Code)
	}
}
