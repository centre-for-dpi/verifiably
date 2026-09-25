// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// permitJSONSchema has the rarer shapes: a $ref, a date and time, a
// link, number ranges, a list of numbers, a list of yes or no values,
// an enum of numbers, a type list, names that clash as element ids,
// and a required name without a property.
const permitJSONSchema = `{
  "$defs": {"place": {"type": "object", "properties": {"plot": {"type": "string", "format": "uri"}}, "required": ["plot"]}},
  "type": "object",
  "properties": {
    "issued": {"type": "string", "format": "date-time"},
    "site": {"$ref": "#/$defs/place"},
    "yield": {"type": "number", "minimum": 0, "maximum": 100},
    "age": {"type": "integer", "maximum": 120},
    "weight": {"type": "number"},
    "count": {"type": "integer"},
    "grade": {"type": "integer", "enum": [1, 2, 3]},
    "counts": {"type": "array", "items": {"type": "integer"}},
    "ratios": {"type": "array", "items": {"type": "number"}},
    "flags": {"type": "array", "items": {"type": "boolean"}},
    "note": {"type": ["string", "null"]},
    "a b": {"type": "string"},
    "a_b": {"type": "string"},
    "contact": {"type": "string", "format": "email"},
    "birth": {"type": "string", "format": "date"},
    "code": {"type": "string", "pattern": "^[A-Z]+$"}
  },
  "required": ["ghost"]
}`

func permit() *schemav1.Schema {
	return &schemav1.Schema{Id: "permit", Version: 1, JsonSchema: permitJSONSchema,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT}}
}

// TestClaimFormCoversEverySchemaShape checks the rarer shapes of a
// schema, their errors, and a form that the schema cannot accept at
// all.
func TestClaimFormCoversEverySchemaShape(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{permit()}
	doc := body(t, h.get(t, "/issue/source?schema=permit"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`type="datetime-local" id="claim-issued"`, "The page reads the time as UTC.",
		`<fieldset class="fieldset" id="claim-site">`, `type="url" id="claim-site-plot"`,
		"A number from 0 to 100.", "A whole number of at most 120.", "A number.", "A whole number.",
		`<option value="2">2</option>`, `id="claim-a_b"`, `id="claim-a_b-2"`, `type="email" id="claim-contact"`,
		// The table names the schema by its id when it has no name.
		"<td>permit</td>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("form lacks %q", want)
		}
	}
	bad := url.Values{"schema": {"permit@1"}, "claim.yield": {"lots"}, "claim.counts": {"1\nmany"}, "claim.flags": {"maybe"},
		"claim.contact": {"nobody"}, "claim.birth": {"31/01/2024"}, "claim.site.plot": {"field nine"}, "claim.count": {"1.5"},
		"claim.code": {"abc"}, "claim.grade": {"7"}}
	doc = body(t, h.post(t, "/issue/delivery", bad))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Type a number.", "Type a whole number.", "Pick yes or no.", "Type an email address such as name@example.org.",
		"Type a date such as 2024-01-31.", "Type a full address that starts with https.", "Pick one of the values in the list.",
		"The schema does not accept this value: the text must match the pattern ^[A-Z]&#43;$.",
		"Whole form", "/ghost: the property ghost is required",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("errors lack %q", want)
		}
	}
	// The ghost claim has no field, so the form never passes. A schema
	// without it leads on, with typed claims and a format choice.
	s := permit()
	s.JsonSchema = strings.Replace(permitJSONSchema, `"required": ["ghost"]`, `"additionalProperties": false`, 1)
	h.schemas.published = []*schemav1.Schema{s}
	h.caps.caps.Formats = []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT}
	good := url.Values{"schema": {"permit@1"}, "claim.issued": {"2026-09-25T10:30"}, "claim.yield": {"42.5"}, "claim.counts": {"3\n4"},
		"claim.ratios": {"0.5"}, "claim.flags": {"true\nfalse"}, "claim.grade": {"2"}, "claim.note": {"kept"}, "claim.site.plot": {"https://plots.example/9"}}
	doc = body(t, h.post(t, "/issue/delivery", good))
	if currentStep(t, doc) != "Delivery" || !strings.Contains(doc, `<select id="format" name="format"`) {
		t.Fatalf("a good form with two formats leads to the delivery with a format list\n%s", doc)
	}
	doc = body(t, h.post(t, "/issue/review", with(good, "channel", "CHANNEL_OID4VCI_PREAUTH", "format", "FORMAT_VC_SD_JWT")))
	for _, want := range []string{"vc&#43;sd-jwt", "2026-09-25T10:30:00Z", "3, 4", "true, false", "Site, Plot"} {
		if !strings.Contains(doc, want) {
			t.Errorf("review lacks %q", want)
		}
	}
	if rec := h.post(t, "/issue/offers", with(good, "channel", "CHANNEL_OID4VCI_PREAUTH", "format", "FORMAT_VC_SD_JWT")); rec.Code != http.StatusSeeOther {
		t.Fatalf("issue: status %d", rec.Code)
	}
	req := h.issuance.requests[0]
	if req.GetFormat() != commonv1.Format_FORMAT_VC_SD_JWT || !strings.Contains(req.GetSubjectData(), `"yield":42.5`) ||
		!strings.Contains(req.GetSubjectData(), `"counts":[3,4]`) || !strings.Contains(req.GetSubjectData(), `"issued":"2026-09-25T10:30:00Z"`) {
		t.Errorf("request %v", req)
	}
	// Back from the delivery step keeps the posted claims in the form.
	doc = body(t, h.post(t, "/issue/source", good))
	if !strings.Contains(doc, `name="claim.yield" value="42.5"`) {
		t.Error("back loses the claims")
	}
}

// TestClaimFormEdges checks a schema with no JSON Schema, a broken one,
// and a reference that does not parse.
func TestClaimFormEdges(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = []*schemav1.Schema{{Id: "plain", Version: 1, Type: "PlainCredential"}, {Id: "broken", Version: 1, JsonSchema: "{"}}
	doc := body(t, h.get(t, "/issue/source?schema=plain%401"))
	if !strings.Contains(doc, "This schema holds no JSON Schema, so the form has no fields.") || !strings.Contains(doc, "PlainCredential") {
		t.Error("a schema without a JSON Schema has no note")
	}
	if doc := body(t, h.post(t, "/issue/delivery", url.Values{"schema": {"plain@1"}})); currentStep(t, doc) != "Delivery" {
		t.Error("an empty form of a schema without rules leads on")
	}
	if rec := h.get(t, "/issue/source?schema=broken%401"); rec.Code != http.StatusBadRequest {
		t.Errorf("broken schema: status %d", rec.Code)
	}
	for _, ref := range []string{"plain%40x", "plain%400", "%401"} {
		if rec := h.get(t, "/issue/source?schema="+ref); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", ref, rec.Code)
		}
	}
	h.opts.Schemas = nil
	h.build(t)
	if rec := h.get(t, "/issue/source?schema=plain%401"); rec.Code != http.StatusNotFound {
		t.Errorf("no registry: status %d", rec.Code)
	}
	if doc := body(t, h.get(t, "/issue/")); !strings.Contains(doc, "No schema yet.") {
		t.Error("no registry shows the empty state")
	}
	h.opts.Issuance = nil
	h.build(t)
	if rec := h.get(t, "/issue/offers/offer-1"); rec.Code != http.StatusNotFound {
		t.Errorf("no issuance: status %d", rec.Code)
	}
}

// TestResultStatesAndNames checks the state words of an offer and the
// names the result page falls back to.
func TestResultStatesAndNames(t *testing.T) {
	h := newHarness(t)
	h.issuance.offers = map[string]*issuancev1.Offer{}
	for id, state := range map[string]issuancev1.Offer_State{
		"delivered": issuancev1.Offer_STATE_DELIVERED, "deferred": issuancev1.Offer_STATE_DEFERRED,
		"expired": issuancev1.Offer_STATE_EXPIRED, "failed": issuancev1.Offer_STATE_FAILED,
	} {
		h.issuance.offers[id] = &issuancev1.Offer{Id: id, State: state, SchemaId: "gone", OfferUri: "openid-credential-offer://?x=" + strings.Repeat("a", 3500)}
	}
	h.identity.identity = &backendv1.IssuerIdentity{Identifiers: []string{"did:web:issuer.example"}}
	for id, want := range map[string]string{"delivered": "Delivered", "deferred": "Deferred", "expired": "Expired", "failed": "Failed"} {
		doc := body(t, h.get(t, "/issue/offers/"+id))
		if !strings.Contains(doc, `<span class="block-meta">`+want+`</span>`) {
			t.Errorf("%s: state word missing", id)
		}
		if strings.Contains(doc, `class="qr"`) || !strings.Contains(doc, "The gone credential waits") {
			t.Errorf("%s: a payload too long for a QR code draws none, and the schema falls back to its id", id)
		}
	}
	// The issuer falls back to its identifier, then to the stack. A
	// holder pair without an answer shows its pair name.
	h.issuance.offers["delivered"].OfferUri = "openid-credential-offer://?x=1"
	h.snap.Peers[len(h.snap.Peers)-1].State = topology.Live
	doc := body(t, h.get(t, "/issue/offers/delivered"))
	if !strings.Contains(doc, "credential offer from did:web:issuer.example.") || !strings.Contains(doc, "holder-credebl wallet") {
		t.Error("the fallback names are missing")
	}
	h.identity.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	doc = body(t, h.get(t, "/issue/offers/delivered"))
	if !strings.Contains(doc, "credential offer from First stack.") {
		t.Error("the stack name is missing")
	}
}
