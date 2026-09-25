// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestIssuerShellNav opens every page of the issuance service and checks
// the shell: every rolenav issuer page in the side navigation, the page
// itself marked current, and an accessible document.
func TestIssuerShellNav(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/issuer/", "/identity/", "/issue/", "/notifications/", "/help/"} {
		doc := body(t, h.get(t, path))
		a11ytest.AssertPage(t, doc)
		for _, page := range rolenav.Paths(commonv1.Role_ROLE_ISSUER) {
			if !strings.Contains(doc, `href="`+page+`"`) {
				t.Errorf("%s: the side navigation lacks %s", path, page)
			}
		}
		if !strings.Contains(doc, `href="`+path+`" aria-current="page"`) {
			t.Errorf("%s: the page is not current in the side navigation", path)
		}
		if !strings.Contains(doc, `<span class="role-chip">Issuer</span>`) || !strings.Contains(doc, `data-role="issuer"`) {
			t.Errorf("%s: the role chip is missing", path)
		}
		if !strings.Contains(doc, "Wanjiru Kamau") || !strings.Contains(doc, `action="`+pages.SignOutPath+`"`) {
			t.Errorf("%s: the user menu is missing", path)
		}
	}
}

// TestStackSwitcherListsLiveIssuerPairs checks that the switcher links
// the live issuer pairs by the names their adapters report, marks this
// pair, and shows a starting pair as text.
func TestStackSwitcherListsLiveIssuerPairs(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issuer/"))
	for _, want := range []string{
		`<a href="https://issuer-waltid.labs.example/issuer/" aria-current="true">First stack</a>`,
		`<a href="https://issuer-inji.labs.example/issuer/">Second stack</a>`,
		`<span class="stack-starting">credebl`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the switcher lacks %q", want)
		}
	}
}

// TestPagesSendTheActor checks that every call of the pages to the
// issued credentials service names the staff member (ADR-039 decision 1).
func TestPagesSendTheActor(t *testing.T) {
	h := newHarness(t)
	body(t, h.get(t, "/issuer/"))
	if len(h.issued.actors) == 0 {
		t.Fatal("the overview did not read the issued credentials")
	}
	for _, a := range h.issued.actors {
		if a != session.Subject {
			t.Errorf("actor %q, want %q", a, session.Subject)
		}
	}
}

func TestHelpPageListsTheIssuerRPCs(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/help/"))
	for _, want := range []string{"IssueBatch", "Publish", "Revoke"} {
		if !strings.Contains(doc, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	h := newHarness(t)
	if rec := h.get(t, "/issuer/nothing"); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}
