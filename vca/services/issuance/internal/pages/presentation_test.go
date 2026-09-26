// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"net/http"
	"net/url"
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
		"Presentation first", "Issue at once", `id="presentation_claim"`, `value="vcaSubject"`, "Identity claim to present",
		`<select id="presentation_source" name="presentation_source"`, "Claim with that value", `<option value="farmerID">`} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	// Only a text claim can hold the value.
	if strings.Contains(doc, `<option value="hectares">`) || strings.Contains(doc, `<option value="organic">`) {
		t.Error("the holder list offers a claim that is not text")
	}
	form := with(goodClaims(), "channel", "CHANNEL_OID4VCI_PREAUTH", "presentation", "yes",
		"presentation_claim", "vcaSubject", "presentation_source", "farmerID")
	doc = body(t, h.post(t, "/issue/review", form))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{`<input type="hidden" name="presentation" value="yes">`, "Presentation first",
		`<input type="hidden" name="presentation_source" value="farmerID">`, "vcaSubject equals FM-0042."} {
		if !strings.Contains(doc, want) {
			t.Errorf("the review lacks %q\n%s", want, doc)
		}
	}
	h.issuance.next = &issuancev1.Offer{Id: "offer-p"}
	if rec := h.post(t, "/issue/offers", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if !h.issuance.requests[0].GetRequirePresentation() {
		t.Fatal("the request lacks the option")
	}
	if got := h.issuance.requests[0].GetPresentationSubject(); got.GetClaim() != "vcaSubject" || got.GetValue() != "FM-0042" {
		t.Fatalf("the request names the holder %v", got)
	}
	// Without a claim with a value the page asks again, on the review
	// and on the last post.
	for _, path := range []string{"/issue/review", "/issue/offers"} {
		for _, bad := range []url.Values{
			with(form, "presentation_source", "email"),
			with(form, "presentation_claim", " "),
		} {
			doc = body(t, h.post(t, path, bad))
			if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "A presentation first needs the identity claim and a claim with a value.") {
				t.Errorf("%s accepts a form without a holder", path)
			}
		}
	}
	if len(h.issuance.requests) != 1 {
		t.Fatalf("a form without a holder reached the service: %d requests", len(h.issuance.requests))
	}
	// The document channel cannot ask for a presentation.
	doc = body(t, h.post(t, "/issue/review", with(goodClaims(), "channel", "CHANNEL_PDF", "presentation", "yes")))
	if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "A presentation first needs an OID4VCI channel.") {
		t.Errorf("the page accepts a presentation on the document channel\n%s", doc)
	}
	// Without the feature the posted option does nothing.
	h.caps.caps.Features = nil
	h.post(t, "/issue/offers", form)
	if h.issuance.requests[1].GetRequirePresentation() || h.issuance.requests[1].GetPresentationSubject() != nil {
		t.Fatal("the option reached the service on a stack that lacks it")
	}
}
