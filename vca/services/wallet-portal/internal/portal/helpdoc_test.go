// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestHelpRendersTheHolderDocuments is the help menu of the holder: the
// help page lists the documents of the role, and each opens as a page
// of the wallet.
func TestHelpRendersTheHolderDocuments(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	help := h.get(t, "/wallet/help").Body.String()
	for _, want := range []string{`id="documents"`, `href="/wallet/help/doc/wallet-portal"`, `href="/wallet/help/doc/glossary"`} {
		if !strings.Contains(help, want) {
			t.Errorf("the help page lacks %q", want)
		}
	}
	rec := h.get(t, "/wallet/help/doc/wallet-portal")
	doc := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"<h1>Wallet portal</h1>", `<article class="doc">`, "<h2>", `href="/wallet/help"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the wallet document lacks %q", want)
		}
	}
	for _, path := range []string{"/wallet/help/doc/admin", "/wallet/help/doc/nothing"} {
		if got := h.get(t, path); got.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, got.Code)
		}
	}
}
