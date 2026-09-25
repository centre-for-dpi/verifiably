// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// farmerJSONSchema has every shape the claim form draws: text with a
// rule, a date, a whole number, a choice from a list, a yes or no
// value, a list, and a nested object.
const farmerJSONSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "fullName": {"type": "string", "minLength": 2},
    "farmerID": {"type": "string", "description": "The number on the registration card."},
    "dateOfBirth": {"type": "string", "format": "date"},
    "hectares": {"type": "integer", "minimum": 1},
    "crop": {"type": "string", "enum": ["maize", "tea", "coffee"]},
    "organic": {"type": "boolean"},
    "email": {"type": "string", "format": "email"},
    "cooperatives": {"type": "array", "items": {"type": "string"}},
    "address": {"type": "object", "title": "Farm address",
      "properties": {"county": {"type": "string"}, "town": {"type": "string"}},
      "required": ["county"]}
  },
  "required": ["fullName", "farmerID", "dateOfBirth", "address"]
}`

// farmer is the published schema of the issue tests.
func farmer() *schemav1.Schema {
	return &schemav1.Schema{
		Id: "farmer", Version: 2, Type: "FarmerCredential", State: schemav1.State_STATE_PUBLISHED,
		JsonSchema: farmerJSONSchema,
		Formats:    []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display:    []*schemav1.Display{{Name: "Farmer registration", Locale: "en"}},
		ClaimMappings: []*schemav1.ClaimMapping{{Claim: "fullName",
			Labels: []*schemav1.ClaimLabel{{Locale: "en", Label: "Full name"}}}},
	}
}

// goodClaims is a form that passes the schema.
func goodClaims() url.Values {
	return url.Values{
		"schema":               {"farmer@2"},
		"claim.fullName":       {"Wanjiku Njeri"},
		"claim.farmerID":       {"FM-0042"},
		"claim.dateOfBirth":    {"1984-03-12"},
		"claim.hectares":       {"12"},
		"claim.crop":           {"tea"},
		"claim.organic":        {"true"},
		"claim.email":          {""},
		"claim.cooperatives":   {"Kiambu Tea\r\nLimuru Growers\r\n"},
		"claim.address.county": {"Kiambu"},
		"claim.address.town":   {""},
	}
}

// with returns a copy of v with more values.
func with(v url.Values, pairs ...string) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		out.Set(pairs[i], pairs[i+1])
	}
	return out
}

// currentStep returns the name of the current step of the stepper.
func currentStep(t *testing.T, doc string) string {
	t.Helper()
	m := regexp.MustCompile(`aria-current="step"><span class="stepper-num" aria-hidden="true">\d</span><span class="stepper-name">([^<]+)</span>`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("no current step\n%s", doc)
	}
	return m[1]
}

// TestIssueStepperFlow walks the wizard from the schema to the result:
// schema, source, claims, delivery, review, then the offer.
func TestIssueStepperFlow(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}

	doc := body(t, h.get(t, "/issue/"))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Schema" {
		t.Error("the first step is the schema")
	}
	for _, want := range []string{
		`<ol class="stepper" aria-label="Issue progress">`, `<form method="get" action="/issue/source">`,
		`name="schema" value="farmer@2"`, "Farmer registration", "Version 2, FarmerCredential.", "dc&#43;sd-jwt",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("schema step lacks %q", want)
		}
	}

	// Without a data source on the pair the source step is the form.
	doc = body(t, h.get(t, "/issue/source?schema=farmer%402"))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Source" {
		t.Error("the claim form belongs to the source step")
	}
	for _, want := range []string{
		`<form method="post" action="/issue/delivery">`, `name="csrf_token" value="csrf-1"`,
		`<input type="hidden" name="schema" value="farmer@2">`, `href="/issue/"`, `name="claim.fullName"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("claim form lacks %q", want)
		}
	}
	if strings.Contains(doc, "Bulk from data sources") {
		t.Error("the page offers a bulk source the pair does not run")
	}

	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Delivery" {
		t.Fatalf("a good form leads to the delivery step\n%s", doc)
	}
	for _, want := range []string{
		`<form method="post" action="/issue/review">`, `<input type="hidden" name="claim.fullName" value="Wanjiku Njeri">`,
		`name="channel" value="CHANNEL_OID4VCI_PREAUTH" aria-describedby="channel-hint" checked`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery step lacks %q", want)
		}
	}

	form := with(goodClaims(), "channel", "CHANNEL_OID4VCI_PREAUTH")
	doc = body(t, h.post(t, "/issue/review", form))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Review" {
		t.Fatalf("the delivery step leads to the review\n%s", doc)
	}
	for _, want := range []string{
		`<form method="post" action="/issue/offers">`, "Wanjiku Njeri", "Kiambu", "OID4VCI, pre-authorized code",
		"First stack", "Farmer registration", `formaction="/issue/delivery"`, ">Issue credential</button>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("review step lacks %q", want)
		}
	}
	if len(h.issuance.requests) != 0 {
		t.Fatal("the review issued a credential")
	}

	rec := h.post(t, "/issue/offers", form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issue/offers/offer-1" {
		t.Fatalf("issue: status %d location %q\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(h.issuance.requests) != 1 {
		t.Fatalf("issue requests %d", len(h.issuance.requests))
	}
	req := h.issuance.requests[0]
	if req.GetSchemaId() != "farmer" || req.GetSchemaVersion() != 2 ||
		req.GetDelivery().GetChannel() != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		t.Errorf("request %v", req)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(req.GetSubjectData()), &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"fullName": "Wanjiku Njeri", "farmerID": "FM-0042", "dateOfBirth": "1984-03-12", "hectares": float64(12),
		"crop": "tea", "organic": true, "cooperatives": []any{"Kiambu Tea", "Limuru Growers"},
		"address": map[string]any{"county": "Kiambu"},
	}
	if got := mustJSON(t, claims); string(got) != string(mustJSON(t, want)) {
		t.Errorf("subject data %s, want %s", got, mustJSON(t, want))
	}
	if h.issuance.actors[0] != session.Subject {
		t.Errorf("actor %q, want %q", h.issuance.actors[0], session.Subject)
	}
	for _, a := range h.schemas.actors {
		if a != session.Subject {
			t.Errorf("schema read with actor %q", a)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestClaimFormFollowsTheSchema checks that the form comes from the JSON
// Schema: types, required names, lists as selects, formats, and nested
// objects as fieldsets.
func TestClaimFormFollowsTheSchema(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	doc := body(t, h.get(t, "/issue/source?schema=farmer%402&source=single"))
	for _, want := range []string{
		// The label comes from the claim mapping, then the title, then the name.
		`<label for="claim-fullName">Full name <span class="required" aria-hidden="true">*</span></label>`,
		`<input type="text" id="claim-fullName" name="claim.fullName" value="" required minlength="2">`,
		`<label for="claim-farmerID">Farmer ID`, `<p class="hint" id="claim-farmerID-hint">The number on the registration card.</p>`,
		`<input type="date" id="claim-dateOfBirth" name="claim.dateOfBirth" value="" required`,
		`<input type="number" id="claim-hectares" name="claim.hectares" value="" aria-describedby="claim-hectares-hint" inputmode="numeric" min="1" step="1">`,
		`<select id="claim-crop" name="claim.crop">`, `<option value="">Select</option>`, `<option value="tea">tea</option>`,
		`<select id="claim-organic" name="claim.organic">`, `<option value="true">Yes</option>`, `<option value="false">No</option>`,
		`<input type="email" id="claim-email" name="claim.email"`,
		`<textarea id="claim-cooperatives" name="claim.cooperatives"`, "One value on each line.",
		`<fieldset class="fieldset" id="claim-address">`, `<legend>Farm address</legend>`,
		`<input type="text" id="claim-address-county" name="claim.address.county" value="" required>`,
		`<input type="text" id="claim-address-town" name="claim.address.town" value="">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("claim form lacks %q", want)
		}
	}
	a11ytest.AssertPage(t, doc)
}

// TestFormRejectsMissingRequiredClaim checks the server side check: a
// missing claim, a nested missing claim, and a bad number each get an
// error that the field names through aria-describedby.
func TestFormRejectsMissingRequiredClaim(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	form := with(goodClaims(), "claim.fullName", "", "claim.address.county", " ", "claim.hectares", "twelve", "claim.crop", "rice")
	doc := body(t, h.post(t, "/issue/delivery", form))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Source" {
		t.Fatal("a bad form stays on the form")
	}
	for _, want := range []string{
		`aria-describedby="claim-fullName-error" aria-invalid="true"`,
		`<p class="error" id="claim-fullName-error">Type a value. The schema needs this claim.</p>`,
		`id="claim-address-county" name="claim.address.county" value=" " required aria-describedby="claim-address-county-error" aria-invalid="true"`,
		`<p class="error" id="claim-hectares-error">Type a whole number.</p>`,
		`<p class="error" id="claim-crop-error">Pick one of the values in the list.</p>`,
		// The summary names every error and links its field.
		`<a href="#claim-fullName">Full name</a>`, `<a href="#claim-address-county">County</a>`,
		`name="claim.farmerID" value="FM-0042"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("error form lacks %q", want)
		}
	}
	// The same check runs again before the stack issues.
	rec := h.post(t, "/issue/offers", with(form, "channel", "CHANNEL_OID4VCI_PREAUTH"))
	if rec.Code != http.StatusOK || currentStep(t, rec.Body.String()) != "Source" {
		t.Fatalf("issue with a bad form: status %d", rec.Code)
	}
	if len(h.issuance.requests) != 0 {
		t.Fatal("the page issued a credential with a bad form")
	}
}

// TestDeliveryOptionsFollowCapabilities checks that the delivery cards
// come from the channels of the adapter of the pair, with the document
// channel of VCA on every stack (ADR-043 decision 2).
func TestDeliveryOptionsFollowCapabilities(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	doc := body(t, h.post(t, "/issue/delivery", goodClaims()))
	for _, want := range []string{"CHANNEL_OID4VCI_PREAUTH", "CHANNEL_OID4VCI_AUTHCODE", "CHANNEL_PDF", "This stack shows only the options it can do."} {
		if !strings.Contains(doc, want) {
			t.Errorf("delivery lacks %q", want)
		}
	}
	h.caps.caps.Channels = []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH}
	h.snap.Peers[0].Capabilities = h.caps.caps
	doc = body(t, h.post(t, "/issue/delivery", goodClaims()))
	if strings.Contains(doc, "CHANNEL_OID4VCI_AUTHCODE") || !strings.Contains(doc, "CHANNEL_PDF") {
		t.Error("the cards do not follow the adapter")
	}
	// A channel the stack lacks goes back to the delivery step.
	doc = body(t, h.post(t, "/issue/review", with(goodClaims(), "channel", "CHANNEL_OID4VCI_AUTHCODE")))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, "Pick one of the delivery channels.") {
		t.Errorf("a lacking channel is accepted\n%s", doc)
	}
	rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_SMS"))
	if currentStep(t, rec.Body.String()) != "Delivery" || len(h.issuance.requests) != 0 {
		t.Error("the page issued over a channel it does not offer")
	}
}

// TestResultShowsQRCodeAndHandoff checks the result page: the QR code
// named for the schema and the issuer, the transaction code, the link,
// the document, and the wallets of the live holder pairs.
func TestResultShowsQRCodeAndHandoff(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	h.identity.identity = &backendv1.IssuerIdentity{Identifiers: []string{"did:web:issuer.example"},
		Metadata: &backendv1.IssuerIdentity_Metadata{DisplayName: "Ministry of Agriculture"}}
	h.issuance.next = &issuancev1.Offer{Id: "offer-7", State: issuancev1.Offer_STATE_PENDING,
		OfferUri: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F7",
		Pin:      "493817", PdfRef: "ref-7"}
	if rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_PDF")); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	doc := body(t, h.get(t, "/issue/offers/offer-7"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<img class="qr" src="data:image/svg&#43;xml;base64,`,
		`alt="QR code of the Farmer registration credential offer from Ministry of Agriculture."`,
		`<code>493817</code>`, `<code>openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F7</code>`,
		`href="openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F7"`,
		`href="/issuance/pdf/ref-7"`, "QR on a PDF", "Waiting for the wallet",
		`href="https://holder-waltid.labs.example/wallet/"`, `href="https://holder-inji.labs.example/wallet/"`,
		"First stack", "Second stack", `href="/issue/"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("result lacks %q", want)
		}
	}
	if strings.Contains(doc, "holder-credebl") {
		t.Error("the handoff names a holder pair that does not run")
	}
	// Without a live holder pair the page says so.
	var keep []int
	for i, st := range h.snap.Peers {
		if st.Peer.Role == commonv1.Role_ROLE_HOLDER {
			keep = append(keep, i)
		}
	}
	for _, i := range keep {
		h.snap.Peers[i].State = 0
	}
	doc = body(t, h.get(t, "/issue/offers/offer-7"))
	if !strings.Contains(doc, "No holder wallet runs on this deployment.") {
		t.Error("the page does not say that no wallet runs")
	}
	if rec := h.get(t, "/issue/offers/nothing"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown offer: status %d", rec.Code)
	}
}

// TestIssueNeedsOperatorRole checks that a viewer sees the wizard
// closed and cannot issue (staffsession roles).
func TestIssueNeedsOperatorRole(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	h.sess.Roles = []string{"issuer-viewer"}
	doc := body(t, h.get(t, "/issue/"))
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, "<form method=\"get\" action=\"/issue/source\"") || !strings.Contains(doc, "Only an issuer operator issues credentials.") {
		t.Error("a viewer gets the wizard")
	}
	for _, path := range []string{"/issue/delivery", "/issue/review", "/issue/offers"} {
		rec := h.post(t, path, with(goodClaims(), "channel", "CHANNEL_PDF"))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as a viewer: status %d", path, rec.Code)
		}
	}
	if rec := h.get(t, "/issue/source?schema=farmer%402"); rec.Code != http.StatusForbidden {
		t.Errorf("source step as a viewer: status %d", rec.Code)
	}
	if len(h.issuance.requests) != 0 {
		t.Fatal("a viewer issued a credential")
	}
	h.sess.Roles = []string{staffsession.IssuerAdminRole}
	if rec := h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_PDF")); rec.Code != http.StatusSeeOther {
		t.Errorf("an issuer admin issues: status %d", rec.Code)
	}
}

// TestBulkSourceOnlyWithDataSource checks that the bulk source shows
// when the data source service runs on the pair, and leads to it.
func TestBulkSourceOnlyWithDataSource(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{farmer()}
	h.peers[0].Services["data-source"] = "http://issuer-waltid-data-source:8083"
	h.snap.Peers[0].Peer = h.peers[0]
	h.build(t)
	doc := body(t, h.get(t, "/issue/source?schema=farmer%402"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<form method="get" action="/issue/source">`, `name="source" value="single" checked`, `name="source" value="bulk"`,
		"Bulk from data sources",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("source step lacks %q", want)
		}
	}
	if strings.Contains(doc, `name="claim.fullName"`) {
		t.Error("the form shows before the source is picked")
	}
	rec := h.get(t, "/issue/source?schema=farmer%402&source=bulk")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sources/?schema=farmer%402" {
		t.Errorf("bulk: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	if doc := body(t, h.get(t, "/issue/source?schema=farmer%402&source=single")); !strings.Contains(doc, `name="claim.fullName"`) {
		t.Error("single leads to the form")
	}
}

// TestIssueStepsFailSafely checks the answers to a missing schema, a
// stack failure, and an empty registry.
func TestIssueStepsFailSafely(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/issue/"))
	if !strings.Contains(doc, "No schema yet.") || !strings.Contains(doc, `href="/builder/"`) {
		t.Error("the empty state is missing")
	}
	if rec := h.get(t, "/issue/source?schema=nothing%401"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown schema: status %d", rec.Code)
	}
	if rec := h.get(t, "/issue/source"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issue/" {
		t.Errorf("no schema: status %d", rec.Code)
	}
	h.schemas.published = []*schemav1.Schema{farmer()}
	h.issuance.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	doc = body(t, h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_PDF")))
	a11ytest.AssertPage(t, doc)
	if currentStep(t, doc) != "Review" || !strings.Contains(doc, "The stack did not issue the credential. Try again.") {
		t.Errorf("a stack failure is not on the review\n%s", doc)
	}
	h.issuance.err = connect.NewError(connect.CodeInvalidArgument, errors.New("/fullName: bad"))
	doc = body(t, h.post(t, "/issue/offers", with(goodClaims(), "channel", "CHANNEL_PDF")))
	if !strings.Contains(doc, "The stack refused the claims.") {
		t.Errorf("a refusal is not on the review\n%s", doc)
	}
	h.schemas.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if rec := h.get(t, "/issue/"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "The schema registry does not answer.") {
		t.Errorf("registry down: status %d", rec.Code)
	}
}
