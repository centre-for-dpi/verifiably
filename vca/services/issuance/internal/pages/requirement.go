// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// ActionSetPresentation is the audit action of the presentation card.
const ActionSetPresentation = "issuance.SetPresentationRequirement"

// PresentationPath takes the form of the presentation card.
const PresentationPath = IdentityPath + "presentation"

// MaxPurposeLength caps the purpose the wallet shows to the holder.
const MaxPurposeLength = 200

// Presentation reads and sets the credential a holder presents before
// the stack issues (ADR-051 decision 6). The issuer backend client of
// the pair fits it.
type Presentation interface {
	GetPresentationRequirement(context.Context, *connect.Request[backendv1.GetPresentationRequirementRequest]) (
		*connect.Response[backendv1.GetPresentationRequirementResponse], error)
	SetPresentationRequirement(context.Context, *connect.Request[backendv1.SetPresentationRequirementRequest]) (
		*connect.Response[backendv1.SetPresentationRequirementResponse], error)
}

// presentationFormats are the formats a presentation during issuance
// takes, with their OID4VCI identifiers.
var presentationFormats = []struct {
	value  string
	format commonv1.Format
}{
	{"ldp_vc", commonv1.Format_FORMAT_LDP_VC},
	{"vc+sd-jwt", commonv1.Format_FORMAT_VC_SD_JWT},
	{"dc+sd-jwt", commonv1.Format_FORMAT_DC_SD_JWT},
}

// presentationView is what the card shows: the stored requirement, the
// identity claims of the stack, the published types, and a posted form.
type presentationView struct {
	stored   *backendv1.SetPresentationRequirementRequest
	identity []string
	types    []*schemav1.Schema
	down     bool
	form     url.Values
	errs     map[string]string
	problem  string
}

// presentationOn reports whether the card shows: the stack asks for a
// presentation during issuance and the pages reach its settings.
func (p *Pages) presentationOn(caps *backendv1.GetCapabilitiesResponse) bool {
	return p.opts.Presentation != nil && has(caps, backendv1.Feature_FEATURE_PRESENTATION_DURING_ISSUANCE)
}

// presentationState reads the stored requirement and the published
// types. A failure of the adapter shows as a note on the card.
func (p *Pages) presentationState(pg page) presentationView {
	ctx := pg.r.Context()
	v := presentationView{}
	got, err := p.opts.Presentation.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	if err != nil {
		v.down = true
		return v
	}
	v.stored, v.identity = got.Msg.GetRequirement(), got.Msg.GetIdentityClaims()
	if p.opts.Schemas != nil {
		if list, lerr := p.opts.Schemas.List(ctx, connect.NewRequest(&schemav1.ListRequest{State: schemav1.State_STATE_PUBLISHED})); lerr == nil {
			v.types = list.Msg.GetSchemas()
		}
	}
	return v
}

// presentationBlock draws the card "Presentation during issuance".
func (p *Pages) presentationBlock(b *blocks, v presentationView, csrf template.HTML) template.HTML {
	block := components.Block{ID: "presentation", Title: msg.T("issuer.presentation.label"), Lead: msg.T("issuer.presentation.lead")}
	if v.down {
		block.Body = b.add("note", components.Note{Label: msg.T("issuer.signin.problem.label"), Text: msg.T("issuer.presentation.down")})
		return b.add("block", block)
	}
	value := func(name, stored string) string {
		if v.form != nil {
			return v.form.Get(name)
		}
		return stored
	}
	storedType, storedFormat, storedIdentity, storedOther, storedPurpose := "", "ldp_vc", "", "", ""
	if s := v.stored; s != nil {
		storedType, storedPurpose = s.GetCredentialType(), s.GetPurpose()
		for _, f := range presentationFormats {
			if f.format == s.GetFormat() {
				storedFormat = f.value
			}
		}
		var others []string
		for _, c := range s.GetRequiredClaims() {
			if storedIdentity == "" && slices.Contains(v.identity, c) {
				storedIdentity = c
				continue
			}
			others = append(others, c)
		}
		storedOther = strings.Join(others, ", ")
	}
	typ := value("credential_type", storedType)
	otherType := value("other_type", "")
	typeOptions := []components.Option{{Value: "", Text: msg.T("issuer.presentation.type.none.label"), Selected: typ == ""}}
	known := false
	for _, m := range v.types {
		t := m.GetType()
		if slices.ContainsFunc(typeOptions, func(o components.Option) bool { return o.Value == t }) {
			continue
		}
		known = known || t == typ
		typeOptions = append(typeOptions, components.Option{Value: t, Text: schemaName(m) + " (" + t + ")", Selected: t == typ})
	}
	if typ != "" && !known && v.form == nil {
		// A stored type that no published schema names shows in the text field.
		typeOptions[0].Selected, otherType = true, typ
	}
	formatValue := value("format", storedFormat)
	formatOptions := make([]components.Option, 0, len(presentationFormats))
	for _, f := range presentationFormats {
		formatOptions = append(formatOptions, components.Option{Value: f.value, Text: f.value, Selected: f.value == formatValue})
	}
	identity := value("identity_claim", storedIdentity)
	identityOptions := make([]components.Option, 0, len(v.identity))
	for _, c := range v.identity {
		identityOptions = append(identityOptions, components.Option{Value: c, Text: c, Selected: c == identity})
	}
	var parts []template.HTML
	if v.stored != nil {
		parts = append(parts, b.add("note", components.Note{Label: msg.T("issuer.presentation.current.label"), Text: msg.T("issuer.presentation.current", v.stored.GetCredentialType())}))
	}
	if v.problem != "" {
		parts = append(parts, b.add("note", components.Note{Label: msg.T("issuer.presentation.refused.label"), Text: v.problem}))
	}
	fields := components.Join(
		b.add("field", components.Field{ID: "credential_type", Label: msg.T("issuer.presentation.type.label"), Type: "select", Options: typeOptions,
			Hint: msg.T("issuer.presentation.type.hint"), Error: v.errs["credential_type"]}),
		b.add("field", components.Field{ID: "other_type", Label: msg.T("issuer.presentation.other_type.label"), Value: otherType,
			Hint: msg.T("issuer.presentation.other_type.hint"), Attrs: map[string]string{"placeholder": "[CREDENTIAL TYPE]", "maxlength": "200"}}),
		b.add("field", components.Field{ID: "format", Label: msg.T("issuer.presentation.format.label"), Type: "select", Options: formatOptions,
			Hint: msg.T("issuer.presentation.format.hint")}),
		b.add("field", components.Field{ID: "identity_claim", Label: msg.T("issuer.presentation.identity.label"), Type: "select", Options: identityOptions,
			Hint: msg.T("issuer.presentation.identity.hint"), Error: v.errs["identity_claim"], Required: true}),
		b.add("field", components.Field{ID: "other_claims", Label: msg.T("issuer.presentation.claims.label"), Value: value("other_claims", storedOther),
			Hint: msg.T("issuer.presentation.claims.hint"), Attrs: map[string]string{"maxlength": "500"}}),
		b.add("field", components.Field{ID: "purpose", Label: msg.T("issuer.presentation.purpose.label"), Value: value("purpose", storedPurpose),
			Hint: msg.T("issuer.presentation.purpose.hint"), Attrs: map[string]string{"maxlength": "200"}}),
	)
	// The two buttons share the form and one row. "Stop" sends
	// action=clear, and the handler reads it before any field.
	actions := []template.HTML{template.HTML(`<div class="dialog-actions">`),
		b.add("button", components.Button{Text: msg.T("issuer.presentation.save.label"), Type: "submit", Variant: "primary"})}
	if v.stored != nil {
		actions = append(actions, b.add("button", components.Button{Text: msg.T("issuer.presentation.clear.label"), Type: "submit",
			Variant: "danger", Name: "action", Value: "clear"}))
	}
	actions = append(actions, template.HTML(`</div>`))
	parts = append(parts, formHTML(PresentationPath, csrf, components.Join(fields, components.Join(actions...))))
	block.Body = components.Join(parts...)
	return b.add("block", block)
}

// savePresentation stores or removes the credential to present. An
// issuer operator or admin may change it.
func (p *Pages) savePresentation(pg page) error {
	caps := p.caps(pg)
	if !p.presentationOn(caps) {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack asks for no presentation during issuance"))
	}
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	f, err := readForm(pg)
	if err != nil {
		return err
	}
	ctx := pg.r.Context()
	if f.Get("action") == "clear" {
		_, cerr := p.opts.Presentation.SetPresentationRequirement(ctx, connect.NewRequest(&backendv1.SetPresentationRequirementRequest{Clear: true}))
		p.audit(ctx, ActionSetPresentation, "clear", cerr)
		if cerr != nil {
			return cerr
		}
		http.Redirect(pg.w, pg.r, IdentityPath+"?notice=presentation_cleared", http.StatusSeeOther)
		return nil
	}
	v := p.presentationState(pg)
	v.form, v.errs = f, map[string]string{}
	typ := strings.TrimSpace(f.Get("other_type"))
	if typ == "" {
		typ = strings.TrimSpace(f.Get("credential_type"))
	}
	if typ == "" {
		v.errs["credential_type"] = msg.T("issuer.presentation.error.type")
	}
	identity := strings.TrimSpace(f.Get("identity_claim"))
	if !slices.Contains(v.identity, identity) {
		v.errs["identity_claim"] = msg.T("issuer.presentation.error.identity", strings.Join(v.identity, ", "))
	}
	format := commonv1.Format_FORMAT_UNSPECIFIED
	for _, pf := range presentationFormats {
		if pf.value == f.Get("format") {
			format = pf.format
		}
	}
	if format == commonv1.Format_FORMAT_UNSPECIFIED {
		v.problem = msg.T("issuer.presentation.error.stack")
	}
	if len(v.errs) > 0 || v.problem != "" {
		return p.renderPresentationError(pg, v)
	}
	claims := []string{identity}
	for _, c := range strings.Split(f.Get("other_claims"), ",") {
		if c = strings.TrimSpace(c); c != "" && !slices.Contains(claims, c) {
			claims = append(claims, c)
		}
	}
	purpose := strings.TrimSpace(f.Get("purpose"))
	if len(purpose) > MaxPurposeLength {
		purpose = purpose[:MaxPurposeLength]
	}
	_, err = p.opts.Presentation.SetPresentationRequirement(ctx, connect.NewRequest(&backendv1.SetPresentationRequirementRequest{
		CredentialType: typ, Format: format, RequiredClaims: claims, Purpose: purpose,
	}))
	p.audit(ctx, ActionSetPresentation, typ, err)
	if err != nil {
		v.problem = msg.T("issuer.presentation.error.stack")
		return p.renderPresentationError(pg, v)
	}
	http.Redirect(pg.w, pg.r, IdentityPath+"?notice=presentation_saved", http.StatusSeeOther)
	return nil
}

// renderPresentationError draws the identity page with the card and its
// problems, with status 400.
func (p *Pages) renderPresentationError(pg page, v presentationView) error {
	iv := p.identityView(pg)
	iv.presentation = &v
	pg.w = &statusWriter{ResponseWriter: pg.w, status: http.StatusBadRequest}
	return p.renderIdentity(pg, iv)
}

// presentationCard returns the card for the identity page, or nothing
// when the stack asks for no presentation.
func (p *Pages) presentationCard(pg page, b *blocks, iv identityView) template.HTML {
	if !p.presentationOn(iv.caps) {
		return ""
	}
	v := iv.presentation
	if v == nil {
		state := p.presentationState(pg)
		v = &state
	}
	return p.presentationBlock(b, *v, staffsession.HiddenField(pg.r.Context()))
}
