// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestHelpRendersTheIssuerDocuments is the help menu of the issuer:
// the help page lists the documents of the role, and each opens as a
// page of the portal.
func TestHelpRendersTheIssuerDocuments(t *testing.T) {
	h := newHarness(t)
	help := body(t, h.get(t, "/help/"))
	for _, want := range []string{`id="documents"`, `href="/help/doc/issuance"`, `href="/help/doc/issued-credentials"`, `href="/help/doc/data-source"`} {
		if !strings.Contains(help, want) {
			t.Errorf("the help page lacks %q", want)
		}
	}
	doc := body(t, h.get(t, "/help/doc/issuance"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"<h1>Issuance service</h1>", `<article class="doc">`, "<h2>", `href="/help/"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the issuance document lacks %q", want)
		}
	}
	for _, path := range []string{"/help/doc/admin", "/help/doc/nothing"} {
		if rec := h.get(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, rec.Code)
		}
	}
}
