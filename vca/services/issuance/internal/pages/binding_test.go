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

// TestAuthCodeStepAsksWhoMayClaim: an offer of the authorization code
// channel goes to the holder whose sign in matches the credential
// (ADR-052 decision 3). The delivery step asks for the claim of the
// sign in and the claim of the credential that must hold the same
// value, the review shows the rule, and the request carries it.
func TestAuthCodeStepAsksWhoMayClaim(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Sign in claim", `<select id="binding_token" name="binding_token"`, `<option value="email" selected>`,
		`<option value="preferred_username">`, `<option value="sub">`, `<option value="phone_number">`,
		`id="binding_token_other"`, `<select id="binding_subject" name="binding_subject"`, `<option value="farmerID">`,
		`<option value="email" selected>Email`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	if strings.Contains(doc, `<option value="hectares">`) {
		t.Error("the rule offers a claim that is not text")
	}
	form := with(goodClaims(), "channel", "CHANNEL_OID4VCI_AUTHCODE", "binding_token", "preferred_username",
		"binding_subject", "farmerID")
	doc = body(t, h.post(t, "/issue/review", form))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<input type="hidden" name="binding_token" value="preferred_username">`,
		`<input type="hidden" name="binding_subject" value="farmerID">`,
		"Who can claim", "The preferred_username of the sign in equals the farmerID of this credential.",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the review lacks %q", want)
		}
	}
	h.issuance.next = &issuancev1.Offer{Id: "offer-b"}
	if rec := h.post(t, "/issue/offers", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	rule := h.issuance.requests[0].GetBindingRule()
	if rule.GetTokenClaim() != "preferred_username" || rule.GetSubjectClaim() != "farmerID" {
		t.Fatalf("the request names the rule %v", rule)
	}
	// Another claim of the sign in wins over the list.
	h.post(t, "/issue/offers", with(form, "binding_token_other", " national_id "))
	if got := h.issuance.requests[1].GetBindingRule().GetTokenClaim(); got != "national_id" {
		t.Fatalf("token claim = %q", got)
	}
	// A claim without a value cannot bind anybody, so the page asks again.
	for _, path := range []string{"/issue/review", "/issue/offers"} {
		for _, bad := range []url.Values{
			with(form, "binding_subject", "email"),
			with(form, "binding_subject", ""),
			with(form, "binding_token", "", "binding_token_other", ""),
			with(form, "binding_token_other", "a claim"),
		} {
			doc = body(t, h.post(t, path, bad))
			if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "The authorization code channel needs a sign in claim and a claim with a value.") {
				t.Errorf("%s accepts a form without a rule", path)
			}
		}
	}
	if len(h.issuance.requests) != 2 {
		t.Fatalf("a form without a rule reached the service: %d requests", len(h.issuance.requests))
	}
	// The other channels carry no rule.
	h.post(t, "/issue/offers", with(form, "channel", "CHANNEL_OID4VCI_PREAUTH"))
	if h.issuance.requests[2].GetBindingRule() != nil {
		t.Fatal("the pre-authorized offer carries a rule")
	}
	// A stack without the channel shows no rule.
	h.caps.caps.Channels = []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH}
	h.snap.Peers[0].Capabilities = h.caps.caps
	if doc = body(t, h.post(t, "/issue/delivery", goodClaims())); strings.Contains(doc, `id="binding_token"`) {
		t.Error("the rule shows on a stack without the authorization code channel")
	}
}
