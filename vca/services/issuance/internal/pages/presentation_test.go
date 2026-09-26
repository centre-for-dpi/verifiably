// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestOptionOnlyWithFeature offers "Ask the holder to present a
// credential first" only on a stack whose adapter lists the feature,
// shows it on the review, and passes it to the issuance service.
func TestOptionOnlyWithFeature(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, `id="presentation"`) {
		t.Fatal("the option shows on a stack that lacks the feature")
	}
	h.caps.caps.Features = append(h.caps.caps.Features, backendv1.Feature_FEATURE_PRESENTATION_DURING_ISSUANCE)
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{`<select id="presentation" name="presentation"`, "Before the stack issues",
		"Presentation first", "Issue at once"} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	form := with(goodClaims(), "channel", "CHANNEL_OID4VCI_PREAUTH", "presentation", "yes")
	doc = body(t, h.post(t, "/issue/review", form))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, `<input type="hidden" name="presentation" value="yes">`) || !strings.Contains(doc, "Presentation first") {
		t.Errorf("the review does not carry the option\n%s", doc)
	}
	h.issuance.next = &issuancev1.Offer{Id: "offer-p"}
	if rec := h.post(t, "/issue/offers", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if !h.issuance.requests[0].GetRequirePresentation() {
		t.Fatal("the request lacks the option")
	}
	// The document channel cannot ask for a presentation.
	doc = body(t, h.post(t, "/issue/review", with(goodClaims(), "channel", "CHANNEL_PDF", "presentation", "yes")))
	if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "A presentation first needs an OID4VCI channel.") {
		t.Errorf("the page accepts a presentation on the document channel\n%s", doc)
	}
	// Without the feature the posted option does nothing.
	h.caps.caps.Features = nil
	h.post(t, "/issue/offers", form)
	if h.issuance.requests[1].GetRequirePresentation() {
		t.Fatal("the option reached the service on a stack that lacks it")
	}
}
