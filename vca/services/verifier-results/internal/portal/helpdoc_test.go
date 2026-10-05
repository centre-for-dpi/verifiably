// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestHelpRendersTheVerifierDocuments is the help menu of the verifier:
// the help page lists the documents of the role, and each opens as a
// page of the portal.
func TestHelpRendersTheVerifierDocuments(t *testing.T) {
	f := newShellFixture(t)
	help := ok(t, f.get(t, DefaultPrefix+"/help/"))
	for _, want := range []string{`id="documents"`, `href="/portal/help/doc/verifier-results"`, `href="/portal/help/doc/verifier-ingest"`, `href="/portal/help/doc/verifier-policy"`} {
		if !strings.Contains(help, want) {
			t.Errorf("the help page lacks %q", want)
		}
	}
	doc := ok(t, f.get(t, DefaultPrefix+"/help/doc/verifier-results"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"<h1>Verifier presentation results</h1>", `<article class="doc">`, "<h3>Trust words</h3>", `href="/portal/help/"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the results document lacks %q", want)
		}
	}
	for _, path := range []string{"/help/doc/admin", "/help/doc/nothing"} {
		if rec := f.get(t, DefaultPrefix+path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, rec.Code)
		}
	}
}
