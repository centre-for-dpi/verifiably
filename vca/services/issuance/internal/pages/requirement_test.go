// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// fakeRequirement keeps the credential to present, as the adapter does.
type fakeRequirement struct {
	mu       sync.Mutex
	stored   *backendv1.SetPresentationRequirementRequest
	sets     []*backendv1.SetPresentationRequirementRequest
	identity []string
	err      error
}

func (f *fakeRequirement) GetPresentationRequirement(context.Context, *connect.Request[backendv1.GetPresentationRequirementRequest]) (*connect.Response[backendv1.GetPresentationRequirementResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.GetPresentationRequirementResponse{Requirement: f.stored, IdentityClaims: f.identity}), nil
}

func (f *fakeRequirement) SetPresentationRequirement(_ context.Context, req *connect.Request[backendv1.SetPresentationRequirementRequest]) (*connect.Response[backendv1.SetPresentationRequirementResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, req.Msg)
	if req.Msg.GetClear() {
		f.stored = nil
		return connect.NewResponse(&backendv1.SetPresentationRequirementResponse{IdentityClaims: f.identity}), nil
	}
	if req.Msg.GetFormat() == commonv1.Format_FORMAT_MSO_MDOC {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a presentation during issuance takes an ldp_vc or an SD-JWT VC"))
	}
	f.stored = req.Msg
	return connect.NewResponse(&backendv1.SetPresentationRequirementResponse{DefinitionJson: "{}", IdentityClaims: f.identity}), nil
}

// presentationHarness is a harness whose adapter asks for a
// presentation during issuance, with one published schema.
func presentationHarness(t *testing.T) (*harness, *fakeRequirement) {
	t.Helper()
	h := newHarness(t, backendv1.Feature_FEATURE_PRESENTATION_DURING_ISSUANCE)
	req := &fakeRequirement{identity: []string{"vcaSubject", "memberNumber"}}
	h.opts.Presentation = req
	h.schemas.published = []*schemav1.Schema{{
		Id: "membership", Version: 1, Type: "MembershipCard", State: schemav1.State_STATE_PUBLISHED,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}, Display: []*schemav1.Display{{Name: "Membership card", Locale: "en"}},
	}}
	h.build(t)
	return h, req
}

// TestPresentationCardSavesTheRequirement proves the issuer sets the
// credential to present from the identity page: the card lists the
// published types, the formats a presentation takes, and the identity
// claims of the stack, and a save calls SetPresentationRequirement.
func TestPresentationCardSavesTheRequirement(t *testing.T) {
	h, req := presentationHarness(t)
	doc := body(t, h.get(t, "/identity/"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Presentation during issuance", `<option value="MembershipCard"`, `<option value="ldp_vc"`, "sd-jwt</option>",
		`<option value="vcaSubject"`, `<option value="memberNumber"`, "vca setup, then vca deploy",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	if strings.Contains(doc, `<option value="mso_mdoc"`) {
		t.Error("the card offers a format a presentation cannot take")
	}
	rec := h.post(t, "/identity/presentation", form(map[string]string{
		"credential_type": "MembershipCard", "format": "ldp_vc", "identity_claim": "memberNumber",
		"other_claims": "region, ", "purpose": "Show your membership card.",
	}))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=presentation_saved") {
		t.Fatalf("save: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	got := req.sets[0]
	if got.GetCredentialType() != "MembershipCard" || got.GetFormat() != commonv1.Format_FORMAT_LDP_VC ||
		strings.Join(got.GetRequiredClaims(), ",") != "memberNumber,region" || got.GetPurpose() != "Show your membership card." {
		t.Fatalf("requirement = %v", got)
	}
	doc = body(t, h.get(t, rec.Header().Get("Location")))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"The stack asks for this credential before it issues.", `<option value="memberNumber" selected`, "Stop the presentation"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the saved card lacks %q", want)
		}
	}
	// Another type than the published ones goes in the text field.
	rec = h.post(t, "/identity/presentation", form(map[string]string{
		"credential_type": "", "other_type": "https://id.example/residence", "format": "vc+sd-jwt", "identity_claim": "vcaSubject",
	}))
	if rec.Code != http.StatusSeeOther || req.sets[1].GetCredentialType() != "https://id.example/residence" || req.sets[1].GetFormat() != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Fatalf("other type: %d %v", rec.Code, req.sets[1])
	}
	rec = h.post(t, "/identity/presentation", form(map[string]string{"action": "clear"}))
	if rec.Code != http.StatusSeeOther || !req.sets[2].GetClear() || req.stored != nil {
		t.Fatalf("clear: %d %v", rec.Code, req.sets)
	}
	page, err := h.audit.Query(context.Background(), auditlog.Filter{})
	if err != nil || len(page.Records) != 3 || page.Records[0].Action != "issuance.SetPresentationRequirement" {
		t.Fatalf("audit = %+v %v", page.Records, err)
	}
}

// TestPresentationCardRefusals proves the card explains a missing type,
// an identity claim the stack does not accept, a refusal of the stack,
// and a viewer who may not change it.
func TestPresentationCardRefusals(t *testing.T) {
	h, req := presentationHarness(t)
	rec := h.post(t, "/identity/presentation", form(map[string]string{"format": "ldp_vc", "identity_claim": "vcaSubject"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Choose the credential to present") {
		t.Fatalf("no type: %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	rec = h.post(t, "/identity/presentation", form(map[string]string{"credential_type": "MembershipCard", "format": "ldp_vc", "identity_claim": "nickname"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "vca setup, then vca deploy") {
		t.Fatalf("an identity claim the stack does not accept: %d", rec.Code)
	}
	rec = h.post(t, "/identity/presentation", form(map[string]string{"credential_type": "MembershipCard", "format": "mso_mdoc", "identity_claim": "vcaSubject"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "The stack refused") {
		t.Fatalf("a refusal of the stack: %d", rec.Code)
	}
	if len(req.sets) != 0 {
		t.Fatalf("the adapter got a refused format: %v", req.sets)
	}
	h.sess = staffsession.Session{Subject: "kc|viewer", CSRF: session.CSRF, Roles: []string{"issuer-viewer"}}
	rec = h.post(t, "/identity/presentation", form(map[string]string{"credential_type": "MembershipCard", "format": "ldp_vc", "identity_claim": "vcaSubject"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer: %d", rec.Code)
	}
	h.sess = session
	req.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if doc := body(t, h.get(t, "/identity/")); !strings.Contains(doc, "cannot read the presentation") {
		t.Error("the card hides an adapter that does not answer")
	}
}

// TestPresentationCardNeedsTheFeature proves the card shows only for a
// stack that asks for a presentation during issuance.
func TestPresentationCardNeedsTheFeature(t *testing.T) {
	h := newHarness(t)
	h.opts.Presentation = &fakeRequirement{}
	h.build(t)
	if doc := body(t, h.get(t, "/identity/")); strings.Contains(doc, "Presentation during issuance") {
		t.Error("a stack without the feature shows the card")
	}
	if rec := h.post(t, "/identity/presentation", form(map[string]string{"action": "clear"})); rec.Code != http.StatusNotFound {
		t.Fatalf("a post without the feature: %d", rec.Code)
	}
}
