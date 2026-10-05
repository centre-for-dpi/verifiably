// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestHelpRendersTheAdminDocuments is the help menu of the admin (spec
// admin, review finding 5): the help page lists the documents of the
// role, and each opens as a page of the portal.
func TestHelpRendersTheAdminDocuments(t *testing.T) {
	h := newHarness(t, true)
	help := h.page(t, "/admin/help")
	for _, want := range []string{`id="documents"`, `href="/admin/help/doc/admin"`, `href="/admin/help/doc/trust-registry"`, `href="/admin/help/doc/glossary"`} {
		if !strings.Contains(help, want) {
			t.Errorf("the help page lacks %q", want)
		}
	}
	doc := h.page(t, "/admin/help/doc/admin")
	for _, want := range []string{"<h1>admin: super admin API and portal</h1>", `<article class="doc">`, "<h2>", "GetServiceHealth", `href="/admin/help"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the admin document lacks %q", want)
		}
	}
	for _, path := range []string{"/admin/help/doc/wallet-portal", "/admin/help/doc/nothing"} {
		if status, _ := h.get(t, path); status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, status)
		}
	}
}
