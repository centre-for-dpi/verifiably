// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
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

func TestIssuePageListsPublishedSchemasAndStackChannels(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issue/"))
	// No schema: the empty state leads to the builder.
	if !strings.Contains(doc, "No schema yet.") || !strings.Contains(doc, `href="/builder/"`) {
		t.Error("the empty state is missing")
	}
	// The channels come from the adapter: pre-authorized and
	// authorization code, no PDF.
	if !strings.Contains(doc, "OID4VCI, pre-authorized code") || !strings.Contains(doc, "OID4VCI, authorization code") {
		t.Error("the stack channels are missing")
	}
	if strings.Contains(doc, "QR on a PDF") {
		t.Error("the page offers a channel the stack lacks")
	}
	h.schemas.published = []*schemav1.Schema{{Id: "farmer", Version: 2, Type: "FarmerCredential", Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display: []*schemav1.Display{{Name: "Farmer registration", Locale: "en"}}}}
	doc = body(t, h.get(t, "/issue/"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "Farmer registration") || !strings.Contains(doc, `href="/portal/schemas/farmer"`) {
		t.Error("the published schema is missing")
	}
}

func TestNotificationsPageNeverSaysSoon(t *testing.T) {
	h := newHarness(t)
	doc := strings.ToLower(body(t, h.get(t, "/notifications/")))
	if strings.Contains(doc, "soon") || strings.Contains(doc, "coming") {
		t.Error("the page says soon")
	}
	if !strings.Contains(doc, "not built in this release.") {
		t.Error("the page does not name the state of the VCA channels")
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
