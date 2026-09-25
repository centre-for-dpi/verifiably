// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The paths of the issue wizard (board Issuer-Issue). Every step after
// the schema posts the claims it carries, so no claim lands in a URL or
// in a log line of the proxy.
const (
	IssueSourcePath   = "/issue/source"
	IssueDeliveryPath = "/issue/delivery"
	IssueReviewPath   = "/issue/review"
	IssueOffersPath   = "/issue/offers"
	// SourcesPath is the page of the data sources of the pair (P3-08).
	SourcesPath = "/sources/"
)

// dataSourceService names the data source service in the peer list.
const dataSourceService = "data-source"

// Issuance issues through the IssuanceService of this service. The pages
// call it in process, so the proxy never publishes it (ADR-047).
type Issuance interface {
	Issue(context.Context, *connect.Request[issuancev1.IssueRequest]) (*connect.Response[issuancev1.IssueResponse], error)
	GetOffer(context.Context, *connect.Request[issuancev1.GetOfferRequest]) (*connect.Response[issuancev1.GetOfferResponse], error)
}

// The steps of the wizard, counted from 1.
const (
	stepSchema = iota + 1
	stepSource
	stepDelivery
	stepReview
)

// channels lists the delivery channels the wizard can offer, in the
// order of board Issuer-Issue, with the catalogue key of each.
var channels = []struct {
	channel backendv1.Channel
	key     string
}{
	{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, "issuer.issue.pre_auth"},
	{backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE, "issuer.issue.auth_code"},
	{backendv1.Channel_CHANNEL_DC_API, "issuer.issue.dc_api"},
	{backendv1.Channel_CHANNEL_PDF, "issuer.issue.pdf"},
}

// maxSchemas caps the published schemas the issue page lists.
const maxSchemas = 100

// canIssue reports whether the staff member may issue: an issuer
// operator or an issuer admin (ADR-012 decision 3).
func canIssue(ctx context.Context) bool {
	s, ok := staffsession.User(ctx)
	return ok && (s.HasRole(staffsession.IssuerOperatorRole) || s.HasRole(staffsession.IssuerAdminRole))
}

// errForbidden answers a step that the role of the staff member does
// not allow.
var errForbidden = connect.NewError(connect.CodePermissionDenied, errors.New("the role cannot issue"))

// wizard is what one step of the wizard shows.
type wizard struct {
	step   int
	schema *schemav1.Schema
	ref    string
	form   url.Values
	claims claimForm
	values formValues
	caps   *backendv1.GetCapabilitiesResponse
	toasts []components.Toast
}

// issue draws the first step: the published schemas to pick from.
func (p *Pages) issue(pg page) error {
	b := p.blocks()
	if !canIssue(pg.r.Context()) {
		note := b.add("block", components.Block{ID: "role", Title: msg.T("issuer.issue.role.label"), Lead: msg.T("issuer.issue.role.text")})
		if b.err != nil {
			return b.err
		}
		return p.renderIssue(pg, wizard{step: stepSchema}, note)
	}
	schemas, down, err := p.published(pg.r.Context())
	if err != nil {
		return err
	}
	var body template.HTML
	switch {
	case down:
		body = b.add("block", components.Block{ID: "published", Title: msg.T("issuer.issue.schemas.label"), Lead: msg.T("issuer.issue.registry.down")})
	case len(schemas) == 0:
		body = b.add("empty", components.Empty{
			Title: msg.T("issuer.schemas.empty.title"), Text: msg.T("issuer.schemas.empty.text"),
			Action: components.Button{Text: msg.T("issuer.schemas.build.label"), Href: BuilderPath, Variant: "primary"},
		})
	default:
		options := make([]components.ChoiceOption, 0, len(schemas))
		for i, s := range schemas {
			options = append(options, components.ChoiceOption{
				Value: schemaRef(s), Title: schemaName(s), Checked: i == 0,
				Text: msg.T("issuer.issue.schema.version", strconv.Itoa(int(s.GetVersion())), s.GetType()),
				Meta: formats(s.GetFormats()),
			})
		}
		fields := components.Join(
			b.add("choice", components.Choice{ID: "schema", Legend: msg.T("issuer.issue.schema.legend.label"), Hint: msg.T("issuer.issue.schemas.lead"), Options: options}),
			p.actions(b, components.Button{Text: msg.T("common.continue.label"), Type: "submit", Variant: "primary"}),
		)
		body = template.HTML(`<form method="get" action="`+IssueSourcePath+`">`) + fields + template.HTML(`</form>`) //nolint:gosec // a constant action around kit parts
	}
	if b.err != nil {
		return b.err
	}
	return p.renderIssue(pg, wizard{step: stepSchema}, body)
}

// published lists the published schemas. down is true when the schema
// registry does not answer.
func (p *Pages) published(ctx context.Context) ([]*schemav1.Schema, bool, error) {
	if p.opts.Schemas == nil {
		return nil, false, nil
	}
	res, err := p.opts.Schemas.List(ctx, staffshell.AsActor(ctx, &schemav1.ListRequest{
		State: schemav1.State_STATE_PUBLISHED, Page: &commonv1.Pagination{PageSize: maxSchemas},
	}))
	switch {
	case connect.CodeOf(err) == connect.CodeUnavailable:
		return nil, true, nil
	case err != nil:
		return nil, false, err
	}
	return res.Msg.GetSchemas(), false, nil
}

// schemaRef names one schema version in a form: the id and the version.
func schemaRef(s *schemav1.Schema) string { return s.GetId() + "@" + strconv.Itoa(int(s.GetVersion())) }

// parseRef reads a schema reference. A reference without a version
// selects the latest published version.
func parseRef(ref string) (string, int32, bool) {
	ref = strings.TrimSpace(ref)
	id, version := ref, int32(0)
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		n, err := strconv.ParseInt(ref[i+1:], 10, 32)
		if err != nil || n < 1 || n > math.MaxInt32 {
			return "", 0, false
		}
		id, version = ref[:i], int32(n)
	}
	return id, version, id != ""
}

// wizardFor reads the schema of a request and builds its claim form.
func (p *Pages) wizardFor(pg page, form url.Values, step int) (wizard, error) {
	w := wizard{step: step, form: form, caps: p.caps(pg)}
	id, version, ok := parseRef(form.Get("schema"))
	if !ok || p.opts.Schemas == nil {
		return w, connect.NewError(connect.CodeNotFound, errors.New("no schema"))
	}
	ctx := pg.r.Context()
	res, err := p.opts.Schemas.Get(ctx, staffshell.AsActor(ctx, &schemav1.GetRequest{Id: id, Version: version}))
	if err != nil {
		return w, err
	}
	w.schema = res.Msg.GetSchema()
	if w.schema == nil {
		return w, connect.NewError(connect.CodeNotFound, errors.New("no schema"))
	}
	w.ref = schemaRef(w.schema)
	claims, err := newClaimForm(w.schema)
	if err != nil {
		return w, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	w.claims = claims
	return w, nil
}

// source draws the second step: the source of the claims, then the
// claim form of the schema.
func (p *Pages) source(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	q := pg.r.URL.Query()
	if pg.r.Method == http.MethodPost {
		f, err := readForm(pg)
		if err != nil {
			return err
		}
		q = f
	}
	if q.Get("schema") == "" {
		http.Redirect(pg.w, pg.r, IssuePath, http.StatusSeeOther)
		return nil
	}
	w, err := p.wizardFor(pg, q, stepSource)
	if err != nil {
		return err
	}
	bulk := p.bulkRuns(pg)
	switch {
	case bulk && q.Get("source") == "bulk":
		http.Redirect(pg.w, pg.r, SourcesPath+"?"+url.Values{"schema": {w.ref}}.Encode(), http.StatusSeeOther)
		return nil
	case bulk && q.Get("source") == "" && pg.r.Method == http.MethodGet:
		return p.renderSourceChoice(pg, w)
	}
	return p.renderClaims(pg, w)
}

// bulkRuns reports whether the data source service runs on the pair.
func (p *Pages) bulkRuns(pg page) bool {
	own, ok := pg.f.Own()
	return ok && own.Peer.Services[dataSourceService] != ""
}

// renderSourceChoice draws the choice between one credential and a
// bulk run from a data source.
func (p *Pages) renderSourceChoice(pg page, w wizard) error {
	b := p.blocks()
	fields := components.Join(
		template.HTML(hiddenInput("schema", w.ref)), //nolint:gosec // the input is escaped
		b.add("choice", components.Choice{ID: "source", Legend: msg.T("issuer.issue.step.source.label"), Options: []components.ChoiceOption{
			{Value: "single", Title: msg.T("issuer.issue.single.label"), Text: msg.T("issuer.issue.single.text"), Checked: true},
			{Value: "bulk", Title: msg.T("issuer.issue.bulk.label"), Text: msg.T("issuer.issue.bulk.text")},
		}}),
		p.actions(b,
			components.Button{Text: msg.T("common.continue.label"), Type: "submit", Variant: "primary"},
			components.Button{Text: msg.T("common.back.label"), Href: IssuePath, Variant: "ghost"}),
	)
	body := template.HTML(`<form method="get" action="`+IssueSourcePath+`">`) + fields + template.HTML(`</form>`) //nolint:gosec // a constant action around kit parts
	if b.err != nil {
		return b.err
	}
	return p.renderIssue(pg, w, p.chosen(b, w), body)
}

// renderClaims draws the claim form, with the errors of a posted form.
func (p *Pages) renderClaims(pg page, w wizard) error {
	b := p.blocks()
	var summary template.HTML
	if rows := w.claims.errorRows(w.values); len(rows) > 0 {
		summary = b.add("block", components.Block{ID: "errors", Title: msg.T("issuer.issue.errors.label"), Lead: msg.T("issuer.issue.errors.text"),
			Body: b.add("table", components.Table{ID: "error-list", Caption: msg.T("issuer.issue.errors.caption.label", strconv.Itoa(len(rows))),
				Columns: []string{msg.T("issuer.issue.column.claim.label"), msg.T("issuer.issue.column.problem.label")}, Rows: rows})})
	}
	var fields template.HTML
	if len(w.claims.fields) == 0 {
		fields = b.add("note", components.Note{Text: msg.T("issuer.issue.claims.none")})
	} else {
		fields = w.claims.html(b, w.form, w.values.errs)
	}
	body := p.postForm(pg, IssueDeliveryPath, w, components.Join(
		b.add("block", components.Block{ID: "claims", Title: msg.T("issuer.issue.claims.label"), Lead: msg.T("issuer.issue.claims.lead"), Body: fields}),
		p.actions(b,
			components.Button{Text: msg.T("common.continue.label"), Type: "submit", Variant: "primary"},
			components.Button{Text: msg.T("common.back.label"), Href: IssuePath, Variant: "ghost"}),
	), false)
	if b.err != nil {
		return b.err
	}
	return p.renderIssue(pg, w, p.chosen(b, w), summary, body)
}

// postForm wraps the parts of a step in a POST form with the token, the
// schema, and, when carry is true, the claims of the form so far.
func (p *Pages) postForm(pg page, action string, w wizard, parts template.HTML, carry bool) template.HTML {
	hidden := template.HTML(hiddenInput("schema", w.ref)) //nolint:gosec // the input is escaped
	if carry {
		hidden += w.claims.hidden(w.form)
	}
	return formHTML(action, staffsession.HiddenField(pg.r.Context())+hidden, parts)
}

// actions returns a row of buttons. The primary button comes first, so
// the Enter key of a field submits it.
func (p *Pages) actions(b *blocks, buttons ...components.Button) template.HTML {
	parts := make([]template.HTML, 0, len(buttons))
	for _, btn := range buttons {
		parts = append(parts, b.add("button", btn))
	}
	return actionRow(parts...)
}

// actionRow puts buttons from the kit in one row.
func actionRow(parts ...template.HTML) template.HTML {
	return template.HTML(`<div class="form-actions">`) + components.Join(parts...) + template.HTML(`</div>`)
}

// chosen names the schema of the wizard in one table row, with a link
// to change it (board Issuer-Issue: the schema step folds to one line).
func (p *Pages) chosen(b *blocks, w wizard) template.HTML {
	return b.add("table", components.Table{
		ID: "chosen", Caption: msg.T("issuer.issue.chosen.caption.label"),
		Columns: []string{msg.T("issuer.issue.step.schema.label"), msg.T("common.version.label"), msg.T("issuer.issue.formats.label"), msg.T("issuer.issue.column.action.label")},
		Rows: []components.Row{{
			{Text: schemaName(w.schema)}, {Text: strconv.Itoa(int(w.schema.GetVersion()))},
			{Text: formats(w.schema.GetFormats())}, {HTML: link(IssuePath, msg.T("common.change.label"))},
		}},
	})
}

// posted reads a step form: the role, the schema, and the claims. A
// form that fails the schema goes back to the claim form.
func (p *Pages) posted(pg page, step int) (wizard, bool, error) {
	if !canIssue(pg.r.Context()) {
		return wizard{}, false, errForbidden
	}
	f, err := readForm(pg)
	if err != nil {
		return wizard{}, false, err
	}
	w, err := p.wizardFor(pg, f, step)
	if err != nil {
		return w, false, err
	}
	w.values = w.claims.read(f, w.schema)
	if !w.values.ok() {
		w.step = stepSource
		return w, false, p.renderClaims(pg, w)
	}
	return w, true, nil
}

// delivery draws the third step: the channels the stack offers.
func (p *Pages) delivery(pg page) error {
	w, ok, err := p.posted(pg, stepDelivery)
	if !ok {
		return err
	}
	return p.renderDelivery(pg, w)
}

// offered lists the channels the wizard offers on the pair: the
// channels its adapter lists, and the two channels that VCA gives every
// stack (ADR-043 decision 2). The document channel works on every
// stack. The Digital Credentials API channel hands the pre-authorized
// offer of the stack to the browser.
func offered(caps *backendv1.GetCapabilitiesResponse) []backendv1.Channel {
	var out []backendv1.Channel
	for _, c := range channels {
		switch {
		case c.channel == backendv1.Channel_CHANNEL_PDF, offers(caps, c.channel),
			c.channel == backendv1.Channel_CHANNEL_DC_API && offers(caps, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH):
			out = append(out, c.channel)
		}
	}
	return out
}

// channelKey returns the catalogue key of a channel.
func channelKey(c backendv1.Channel) string {
	for _, x := range channels {
		if x.channel == c {
			return x.key
		}
	}
	return ""
}

// pickChannel reads the channel of a form. ok is false when the pair
// does not offer it.
func pickChannel(caps *backendv1.GetCapabilitiesResponse, form url.Values) (backendv1.Channel, bool) {
	c := backendv1.Channel(backendv1.Channel_value[form.Get("channel")])
	for _, o := range offered(caps) {
		if o == c {
			return c, true
		}
	}
	return backendv1.Channel_CHANNEL_UNSPECIFIED, false
}

// renderDelivery draws the channel cards.
func (p *Pages) renderDelivery(pg page, w wizard) error {
	b := p.blocks()
	current, _ := pickChannel(w.caps, w.form)
	list := offered(w.caps)
	options := make([]components.ChoiceOption, 0, len(list))
	for i, c := range list {
		key := channelKey(c)
		options = append(options, components.ChoiceOption{
			Value: c.String(), Title: msg.T(key + ".label"), Text: msg.T(key + ".text"),
			Meta: p.channelMeta(c, w.caps), Checked: c == current || (current == backendv1.Channel_CHANNEL_UNSPECIFIED && i == 0),
		})
	}
	parts := []template.HTML{
		b.add("choice", components.Choice{ID: "channel", Legend: msg.T("issuer.issue.step.delivery.label"), Hint: msg.T("issuer.issue.hidden_note"), Options: options}),
	}
	if fs := formatsOn(w.schema, w.caps); len(fs) > 1 {
		opts := make([]components.Option, 0, len(fs))
		for _, f := range fs {
			opts = append(opts, components.Option{Value: f.String(), Text: formatName(f), Selected: f.String() == w.form.Get("format")})
		}
		parts = append(parts, b.add("field", components.Field{ID: "format", Label: msg.T("issuer.issue.format.label"), Type: "select",
			Options: opts, Hint: msg.T("issuer.issue.format.hint")}))
	}
	parts = append(parts, p.actions(b,
		components.Button{Text: msg.T("issuer.issue.review.label"), Type: "submit", Variant: "primary"},
		components.Button{Text: msg.T("common.back.label"), Type: "submit", Variant: "ghost", Attrs: map[string]string{"formaction": IssueSourcePath}}))
	body := p.postForm(pg, IssueReviewPath, w, components.Join(parts...), true)
	if b.err != nil {
		return b.err
	}
	return p.renderIssue(pg, w, p.chosen(b, w), body)
}

// channelMeta names where a channel comes from: the stack of the pair,
// or VCA on every stack.
func (p *Pages) channelMeta(c backendv1.Channel, caps *backendv1.GetCapabilitiesResponse) string {
	if offers(caps, c) {
		return stackName(caps)
	}
	return msg.T("issuer.issue.every_stack.label")
}

// formatsOn lists the formats of the schema that the stack issues.
func formatsOn(s *schemav1.Schema, caps *backendv1.GetCapabilitiesResponse) []commonv1.Format {
	var out []commonv1.Format
	for _, f := range s.GetFormats() {
		for _, c := range caps.GetFormats() {
			if f == c {
				out = append(out, f)
			}
		}
	}
	return out
}

// pickFormat reads the format of a form. Unspecified lets the service
// choose from the schema.
func pickFormat(w wizard) commonv1.Format {
	f := commonv1.Format(commonv1.Format_value[w.form.Get("format")])
	for _, x := range formatsOn(w.schema, w.caps) {
		if x == f {
			return f
		}
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// review draws the fourth step: what the stack will issue.
func (p *Pages) review(pg page) error {
	w, ok, err := p.posted(pg, stepReview)
	if !ok {
		return err
	}
	if _, ok := pickChannel(w.caps, w.form); !ok {
		return p.badChannel(pg, w)
	}
	return p.renderReview(pg, w)
}

// badChannel sends a form with a channel the pair lacks back to the
// delivery step.
func (p *Pages) badChannel(pg page, w wizard) error {
	w.step = stepDelivery
	w.toasts = []components.Toast{{Level: "bad", Text: msg.T("issuer.issue.error.channel")}}
	return p.renderDelivery(pg, w)
}

// renderReview draws the review table and the issue button.
func (p *Pages) renderReview(pg page, w wizard) error {
	b := p.blocks()
	channel, _ := pickChannel(w.caps, w.form)
	format := pickFormat(w)
	formatText := formats(w.schema.GetFormats())
	if format != commonv1.Format_FORMAT_UNSPECIFIED {
		formatText = formatName(format)
	}
	rows := []components.Row{
		{{Text: msg.T("issuer.issue.step.schema.label")}, {Text: msg.T("issuer.issue.review.schema", schemaName(w.schema), strconv.Itoa(int(w.schema.GetVersion())))}},
		{{Text: msg.T("issuer.issue.format.label")}, {Text: formatText}},
		{{Text: msg.T("issuer.issue.review.stack.label")}, {Text: stackName(w.caps)}},
		{{Text: msg.T("issuer.issue.step.delivery.label")}, {Text: msg.T(channelKey(channel) + ".label")}},
	}
	rows = append(rows, w.claims.rows(w.values.claims)...)
	hidden := template.HTML(hiddenInput("channel", w.form.Get("channel")) + hiddenInput("format", w.form.Get("format"))) //nolint:gosec // the inputs are escaped
	body := p.postForm(pg, IssueOffersPath, w, components.Join(
		hidden,
		b.add("block", components.Block{ID: "review", Title: msg.T("issuer.issue.review.title.label"), Lead: msg.T("issuer.issue.review.lead"),
			Body: b.add("table", components.Table{ID: "review-table", Caption: msg.T("issuer.issue.review.caption.label"),
				Columns: []string{msg.T("issuer.identity.column.item.label"), msg.T("issuer.identity.column.value.label")}, Rows: rows})}),
		p.actions(b,
			components.Button{Text: msg.T("issuer.issue.submit.label"), Type: "submit", Variant: "primary"},
			components.Button{Text: msg.T("common.back.label"), Type: "submit", Variant: "ghost", Attrs: map[string]string{"formaction": IssueDeliveryPath}}),
	), true)
	if b.err != nil {
		return b.err
	}
	return p.renderIssue(pg, w, body)
}

// create issues the credential through the IssuanceService, as the
// staff member, then sends the browser to the result.
func (p *Pages) create(pg page) error {
	w, ok, err := p.posted(pg, stepReview)
	if !ok {
		return err
	}
	channel, ok := pickChannel(w.caps, w.form)
	if !ok {
		return p.badChannel(pg, w)
	}
	if p.opts.Issuance == nil {
		return connect.NewError(connect.CodeNotFound, errors.New("no issuance service"))
	}
	data, err := json.Marshal(w.values.claims)
	if err != nil {
		return err
	}
	ctx := pg.r.Context()
	res, err := p.opts.Issuance.Issue(ctx, staffshell.AsActor(ctx, &issuancev1.IssueRequest{
		SchemaId: w.schema.GetId(), SchemaVersion: w.schema.GetVersion(), SubjectData: string(data),
		Format: pickFormat(w), Delivery: &issuancev1.Delivery{Channel: channel, Locale: "en"},
	}))
	if err != nil {
		text := msg.T("issuer.issue.error.stack")
		if code := connect.CodeOf(err); code == connect.CodeInvalidArgument || code == connect.CodeFailedPrecondition {
			text = msg.T("issuer.issue.error.refused")
		}
		w.toasts = []components.Toast{{Level: "bad", Text: text}}
		return p.renderReview(pg, w)
	}
	http.Redirect(pg.w, pg.r, IssueOffersPath+"/"+url.PathEscape(res.Msg.GetOffer().GetId()), http.StatusSeeOther)
	return nil
}

// renderIssue writes one step inside the issuer frame, with the stepper
// on top.
func (p *Pages) renderIssue(pg page, w wizard, parts ...template.HTML) error {
	b := p.blocks()
	stepper := b.add("stepper", components.Stepper{
		Label: msg.T("issuer.issue.progress.label"), Current: w.step,
		Steps: []string{msg.T("issuer.issue.step.schema.label"), msg.T("issuer.issue.step.source.label"),
			msg.T("issuer.issue.step.delivery.label"), msg.T("issuer.issue.step.review.label")},
	})
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.issue.label"), Lead: msg.T("issuer.issue.lead"), Description: msg.T("issuer.issue.lead"),
		Content: components.Join(append([]template.HTML{stepper}, parts...)...), Toasts: w.toasts,
	})
}

// offers reports whether the adapter lists a channel.
func offers(caps *backendv1.GetCapabilitiesResponse, c backendv1.Channel) bool {
	for _, got := range caps.GetChannels() {
		if got == c {
			return true
		}
	}
	return false
}

// schemaName is the display name of a schema in English, or its type.
func schemaName(s *schemav1.Schema) string {
	for _, d := range s.GetDisplay() {
		if d.GetName() != "" && (d.GetLocale() == "" || strings.HasPrefix(d.GetLocale(), "en")) {
			return d.GetName()
		}
	}
	if s.GetType() != "" {
		return s.GetType()
	}
	return s.GetId()
}

// wireNames maps each format onto its OID4VCI format identifier.
var wireNames = map[commonv1.Format]string{
	commonv1.Format_FORMAT_VC_SD_JWT:   "vc+sd-jwt",
	commonv1.Format_FORMAT_DC_SD_JWT:   "dc+sd-jwt",
	commonv1.Format_FORMAT_JWT_VC_JSON: "jwt_vc_json",
	commonv1.Format_FORMAT_LDP_VC:      "ldp_vc",
	commonv1.Format_FORMAT_MSO_MDOC:    "mso_mdoc",
	commonv1.Format_FORMAT_LDP_VC_BBS:  "ldp_vc bbs",
	commonv1.Format_FORMAT_ANONCREDS:   "anoncreds",
}

// formatName names one wire format as OID4VCI does.
func formatName(f commonv1.Format) string {
	if n, ok := wireNames[f]; ok {
		return n
	}
	return strings.ToLower(strings.TrimPrefix(f.String(), "FORMAT_"))
}

// formats names the wire formats of a schema, joined with commas.
func formats(fs []commonv1.Format) string {
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, formatName(f))
	}
	return strings.Join(names, ", ")
}
