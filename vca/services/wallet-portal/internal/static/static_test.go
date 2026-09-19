// SPDX-License-Identifier: Apache-2.0

package static_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/static"
)

func TestScriptCarriesTheWalletFunctions(t *testing.T) {
	body, err := static.Script()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"SPDX-License-Identifier: Apache-2.0",
		"A256GCM", "HKDF-SHA256", "vca-wallet-blob-v1", "vca-wallet-portal",
		"AES-GCM", "deriveBits", "wallet-file", "wallet-paste", "/blobs",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("wallet.js misses %q", want)
		}
	}
	if strings.Contains(text, "—") || strings.Contains(text, "–") {
		t.Fatal("wallet.js must hold no dash characters")
	}
}

func TestHandlerServesTheScript(t *testing.T) {
	h, err := static.Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, static.Path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/javascript") {
		t.Fatalf("content type = %q", got)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("want an ETag")
	}
	cached := httptest.NewRequest(http.MethodGet, static.Path, nil)
	cached.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, cached)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("cached status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, static.Path, nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("head = %d %d", rec.Code, rec.Body.Len())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, static.Path, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post = %d", rec.Code)
	}
}
