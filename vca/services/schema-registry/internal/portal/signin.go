// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// HolderSignInRole is the role of the holder authorization server on
// the issue rule of a data source. A source that names it lets a holder
// who signs in find their row (ADR-052 decision 3).
const HolderSignInRole = "holder-sign-in"

// DefaultSourcesURL is the data source pages of the pair.
const DefaultSourcesURL = "/sources/"

// SignIn is the part of the issuer backend the tab calls. The
// generated Connect client fits it.
type SignIn interface {
	GetHolderSignInSource(context.Context, *connect.Request[backendv1.GetHolderSignInSourceRequest]) (
		*connect.Response[backendv1.GetHolderSignInSourceResponse], error)
	SetHolderSignInSource(context.Context, *connect.Request[backendv1.SetHolderSignInSourceRequest]) (
		*connect.Response[backendv1.SetHolderSignInSourceResponse], error)
}

// Sources is the part of the data source service the tab calls with
// the session of the staff member. The generated client fits it.
type Sources interface {
	List(context.Context, *connect.Request[datasourcev1.ListRequest]) (*connect.Response[datasourcev1.ListResponse], error)
	Get(context.Context, *connect.Request[datasourcev1.GetRequest]) (*connect.Response[datasourcev1.GetResponse], error)
	Update(context.Context, *connect.Request[datasourcev1.UpdateRequest]) (*connect.Response[datasourcev1.UpdateResponse], error)
	PreviewFields(context.Context, *connect.Request[datasourcev1.PreviewFieldsRequest]) (*connect.Response[datasourcev1.PreviewFieldsResponse], error)
	GetFieldMap(context.Context, *connect.Request[datasourcev1.GetFieldMapRequest]) (*connect.Response[datasourcev1.GetFieldMapResponse], error)
	Lookup(context.Context, *connect.Request[datasourcev1.LookupRequest]) (*connect.Response[datasourcev1.LookupResponse], error)
}

// signInURL returns the tab of one version.
func (p *Portal) signInURL(id string, version int32) string {
	u := p.opts.Prefix + "/schemas/" + url.PathEscape(id) + "/signin"
	if version > 0 {
		u += "?version=" + strconv.Itoa(int(version))
	}
	return u
}

// signInOn reports whether the own stack takes a claim without an
// offer and the portal can reach both services the tab needs.
func (p *Portal) signInOn(f staffshell.Frame) bool {
	if p.opts.SignIn == nil || p.opts.Sources == nil {
		return false
	}
	own, ok := f.Own()
	return ok && own.Has(backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE)
}

// schemaTabs are the views of one published version: the detail and
// the claims by sign in. The tabs show only when the stack takes a
// claim without an offer.
func (p *Portal) schemaTabs(f staffshell.Frame, m *schemav1.Schema, current string) (template.HTML, error) {
	if !p.signInOn(f) || m.GetState() != schemav1.State_STATE_PUBLISHED {
		return "", nil
	}
	return p.opts.Kit.HTML("tabs", components.Tabs{Label: msg.T("issuer.signin.tabs.label"), Links: []components.Link{
		{Href: p.detailURL(m.GetId(), m.GetVersion()), Text: msg.T("issuer.signin.tab.detail.label"), Current: current == "detail"},
		{Href: p.signInURL(m.GetId(), m.GetVersion()), Text: msg.T("issuer.signin.tab.label"), Current: current == "signin"},
	}})
}

// sourceCall builds a data source request that carries the session of
// the staff member, so the data source checks the rules of that person.
func sourceCall[T any](r *http.Request, m *T) *connect.Request[T] {
	req := connect.NewRequest(m)
	if token := oidcflow.TokenFromRequest(r, staffsession.IssuerCookie); token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

// configurationIDs lists the configuration ids of a version in format
// order, so every format of the credential takes the same source.
func configurationIDs(m *schemav1.Schema) []string {
	keys := make([]string, 0, len(m.GetConfigurationIds()))
	for k := range m.GetConfigurationIds() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.GetConfigurationIds()[k])
	}
	return out
}

// signInForm is the state of the tab: what the adapter holds, what the
// staff member picked, and the problems to show.
type signInForm struct {
	stored  *backendv1.HolderSignInSource
	vouched []string
	sources []*datasourcev1.Source
	source  string
	field   string
	claim   string
	fields  []string
	mapped  bool
	opened  bool
	errs    map[string]string
	problem string
	result  template.HTML
}

// signInPage renders the tab of one version.
func (p *Portal) signInPage(w http.ResponseWriter, r *http.Request) error {
	m, f, err := p.signInSchema(r)
	if err != nil {
		return err
	}
	state := signInForm{source: strings.TrimSpace(r.URL.Query().Get("source"))}
	return p.renderSignIn(w, r, f, m, state, http.StatusOK)
}

// signInSchema reads the version the tab shows and the shell probe.
func (p *Portal) signInSchema(r *http.Request) (*schemav1.Schema, staffshell.Frame, error) {
	v := version(r)
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, staffshell.Frame{}, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if n, err := strconv.ParseInt(r.PostFormValue("version"), 10, 32); err == nil && n > 0 {
			v = int32(n)
		}
	}
	resp, err := p.opts.Client.Get(r.Context(), connect.NewRequest(&schemav1.GetRequest{Id: r.PathValue("id"), Version: v}))
	if err != nil {
		return nil, staffshell.Frame{}, err
	}
	return resp.Msg.GetSchema(), p.frame(r), nil
}

// load fills the form with what the adapter and the data source hold.
// A service that does not answer becomes a problem on the page.
func (p *Portal) load(r *http.Request, m *schemav1.Schema, form *signInForm) {
	ctx := r.Context()
	got, err := p.opts.SignIn.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: configurationIDs(m)}))
	if err != nil {
		form.problem = msg.T("issuer.signin.error.adapter")
		return
	}
	form.stored, form.vouched = got.Msg.GetSource(), got.Msg.GetVouchedClaims()
	if form.source == "" && form.stored != nil {
		form.source = form.stored.GetSourceId()
	}
	if form.field == "" && form.stored != nil && form.stored.GetSourceId() == form.source {
		form.field = form.stored.GetField()
	}
	if form.claim == "" && form.stored != nil {
		form.claim = form.stored.GetTokenClaim()
	}
	list, err := p.opts.Sources.List(ctx, sourceCall(r, &datasourcev1.ListRequest{}))
	if err != nil {
		form.problem = msg.T("issuer.signin.error.sources")
		return
	}
	form.sources = list.Msg.GetSources()
	if form.source == "" {
		return
	}
	for _, src := range form.sources {
		if src.GetId() == form.source {
			form.opened = slices.Contains(src.GetAccess().GetIssue(), HolderSignInRole)
		}
	}
	if fields, ferr := p.opts.Sources.PreviewFields(ctx, sourceCall(r, &datasourcev1.PreviewFieldsRequest{SourceId: form.source})); ferr == nil {
		for _, fd := range fields.Msg.GetFields() {
			form.fields = append(form.fields, fd.GetName())
		}
	}
	_, merr := p.opts.Sources.GetFieldMap(ctx, sourceCall(r, &datasourcev1.GetFieldMapRequest{SourceId: form.source, SchemaId: m.GetId()}))
	form.mapped = merr == nil
}

// renderSignIn draws the tab with the form state.
func (p *Portal) renderSignIn(w http.ResponseWriter, r *http.Request, f staffshell.Frame, m *schemav1.Schema, form signInForm, status int) error {
	var content template.HTML
	switch {
	case !p.signInOn(f):
		c, err := p.opts.Kit.HTML("card", components.Card{ID: "signin-off", Title: msg.T("issuer.signin.tab.label"), Text: msg.T("issuer.signin.off")})
		if err != nil {
			return err
		}
		content = c
	case m.GetState() != schemav1.State_STATE_PUBLISHED || len(m.GetConfigurationIds()) == 0:
		c, err := p.opts.Kit.HTML("card", components.Card{ID: "signin-draft", Title: msg.T("issuer.signin.tab.label"), Text: msg.T("issuer.signin.draft")})
		if err != nil {
			return err
		}
		content = c
	default:
		p.load(r, m, &form)
		tabs, err := p.schemaTabs(f, m, "signin")
		if err != nil {
			return err
		}
		body, err := p.signInCards(r, m, form)
		if err != nil {
			return err
		}
		content = components.Join(tabs, body)
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	return p.renderFrame(w, r, f, components.Page{
		Title:       Name(m) + ", " + strings.ToLower(msg.T("issuer.signin.tab.label")),
		Heading:     Name(m),
		Lead:        msg.T("issuer.signin.lead"),
		Description: msg.T("issuer.signin.description"),
		Content:     content,
		Toasts:      signInNotice(r.URL.Query().Get("notice")),
	})
}

// signInNotice returns the toast of a notice code of the tab.
func signInNotice(code string) []components.Toast {
	switch code {
	case "signin-saved":
		return []components.Toast{{Level: "ok", Text: msg.T("issuer.signin.saved")}}
	case "signin-cleared":
		return []components.Toast{{Level: "ok", Text: msg.T("issuer.signin.cleared")}}
	}
	return nil
}

// signInCards draws the current source, the pick of a source, the form
// of the field and the claim, and the test.
func (p *Portal) signInCards(r *http.Request, m *schemav1.Schema, form signInForm) (template.HTML, error) {
	b := &blocks{kit: p.opts.Kit}
	action := p.signInURL(m.GetId(), 0)
	csrf := staffsession.HiddenField(r.Context())
	hidden := template.HTML(`<input type="hidden" name="version" value="` + strconv.Itoa(int(m.GetVersion())) + `">`) //nolint:gosec // the value is a number
	var parts []template.HTML
	if form.problem != "" {
		parts = append(parts, b.add("note", components.Note{Label: msg.T("issuer.signin.problem.label"), Text: form.problem}))
	}
	if form.stored != nil {
		parts = append(parts, b.add("card", components.Card{
			ID: "signin-current", Title: msg.T("issuer.signin.current.label"),
			Text: msg.T("issuer.signin.current", form.stored.GetTokenClaim(), form.stored.GetField(), sourceName(form.sources, form.stored.GetSourceId())),
			Body: components.Join(template.HTML(`<form action="`+template.HTMLEscapeString(action)+`" method="post">`), csrf, hidden, //nolint:gosec // the action is escaped
				template.HTML(`<input type="hidden" name="action" value="clear">`),
				b.add("button", components.Button{Text: msg.T("issuer.signin.clear.label"), Type: "submit", Variant: "danger"}),
				template.HTML(`</form>`)),
		}))
	}
	if form.problem != "" && form.sources == nil {
		return components.Join(parts...), b.err
	}
	// Step 1 picks the source with a plain GET, so the page lists its
	// fields without script.
	sourceOptions := []components.Option{{Value: "", Text: msg.T("issuer.signin.source.none.label"), Selected: form.source == ""}}
	for _, src := range form.sources {
		sourceOptions = append(sourceOptions, components.Option{Value: src.GetId(), Text: src.GetDisplayName(), Selected: src.GetId() == form.source})
	}
	pick := components.Join(
		template.HTML(`<form action="`+template.HTMLEscapeString(action)+`" method="get">`),                 //nolint:gosec // the action is escaped
		template.HTML(`<input type="hidden" name="version" value="`+strconv.Itoa(int(m.GetVersion()))+`">`), //nolint:gosec // the value is a number
		b.add("field", components.Field{ID: "source", Label: msg.T("issuer.signin.source.label"), Type: "select", Options: sourceOptions,
			Hint: msg.T("issuer.signin.source.hint"), Error: form.errs["source"]}),
		b.add("button", components.Button{Text: msg.T("issuer.signin.fields.label"), Type: "submit"}),
		template.HTML(`</form>`))
	parts = append(parts, b.add("card", components.Card{ID: "signin-source", Title: msg.T("issuer.signin.step.source.label"), Body: pick}))
	if form.source == "" {
		return components.Join(parts...), b.err
	}
	var notes []template.HTML
	if !form.mapped {
		notes = append(notes, b.add("note", components.Note{Label: msg.T("issuer.signin.unmapped.label"), Text: msg.T("issuer.signin.unmapped")}),
			link(p.sourcesURL()+url.PathEscape(form.source)+"/map?schema="+url.QueryEscape(m.GetId()), msg.T("issuer.signin.map.label")))
	}
	if !form.opened {
		notes = append(notes, b.add("note", components.Note{Label: msg.T("issuer.signin.access.label"), Text: msg.T("issuer.signin.access")}))
	}
	fieldOptions := []components.Option{{Value: "", Text: msg.T("issuer.signin.field.none.label"), Selected: form.field == ""}}
	for _, name := range form.fields {
		fieldOptions = append(fieldOptions, components.Option{Value: name, Text: name, Selected: name == form.field})
	}
	claimOptions := make([]components.Option, 0, len(form.vouched))
	for _, c := range form.vouched {
		claimOptions = append(claimOptions, components.Option{Value: c, Text: claimLabel(c), Selected: c == form.claim})
	}
	save := components.Join(append(notes,
		template.HTML(`<form id="signin-save" action="`+template.HTMLEscapeString(action)+`" method="post">`), csrf, hidden, //nolint:gosec // the action is escaped
		template.HTML(`<input type="hidden" name="source" value="`+template.HTMLEscapeString(form.source)+`">`), //nolint:gosec // the value is escaped
		b.add("field", components.Field{ID: "field", Label: msg.T("issuer.signin.field.label"), Type: "select", Options: fieldOptions,
			Hint: msg.T("issuer.signin.field.hint"), Error: form.errs["field"], Required: true}),
		b.add("field", components.Field{ID: "claim", Label: msg.T("issuer.signin.claim.label"), Type: "select", Options: claimOptions,
			Hint: msg.T("issuer.signin.claim.hint"), Error: form.errs["claim"], Required: true}),
		b.add("button", components.Button{Text: msg.T("issuer.signin.save.label"), Type: "submit", Variant: "primary"}),
		template.HTML(`</form>`))...)
	parts = append(parts, b.add("card", components.Card{ID: "signin-field", Title: msg.T("issuer.signin.step.field.label"), Body: save}))
	parts = append(parts, p.testCard(b, action, form))
	return components.Join(parts...), b.err
}

// testCard draws the test of the source. Its value and its button
// belong to the form of step 2 through the form attribute, so a test
// takes the field that the staff member picked there, saved or not.
func (p *Portal) testCard(b *blocks, action string, form signInForm) template.HTML {
	target := action + "/test"
	body := components.Join(
		b.add("field", components.Field{ID: "value", Label: msg.T("issuer.signin.value.label"), Hint: msg.T("issuer.signin.value.hint"),
			Attrs: map[string]string{"placeholder": "[NATIONAL ID]", "autocomplete": "off", "maxlength": "512", "form": "signin-save"}}),
		b.add("button", components.Button{Text: msg.T("issuer.signin.test.label"), Type: "submit", Attrs: map[string]string{
			"form": "signin-save", "formaction": target,
			"hx-post": target, "hx-include": "#signin-save", "hx-target": "#signin-test-result", "hx-swap": "innerHTML",
		}}),
		template.HTML(`<div id="signin-test-result" aria-live="polite">`), form.result, template.HTML(`</div>`),
	)
	return b.add("card", components.Card{ID: "signin-test", Title: msg.T("issuer.signin.step.test.label"), Text: msg.T("issuer.signin.test.text"), Body: body})
}

// claimLabel names an ID token claim for the staff member.
func claimLabel(c string) string {
	if text, ok := msg.Lookup("issuer.signin.claim." + c + ".label"); ok {
		return text
	}
	return c
}

func sourceName(list []*datasourcev1.Source, id string) string {
	for _, src := range list {
		if src.GetId() == id {
			return src.GetDisplayName()
		}
	}
	return id
}

func (p *Portal) sourcesURL() string {
	if p.opts.SourcesURL != "" {
		return strings.TrimRight(p.opts.SourcesURL, "/") + "/"
	}
	return DefaultSourcesURL
}

// saveSignIn stores the source of the version, or removes it. Before it
// stores, it lets the holder sign in read the source: the staff member
// adds the role to the issue rule with their own session.
func (p *Portal) saveSignIn(w http.ResponseWriter, r *http.Request) error {
	m, f, err := p.signInSchema(r)
	if err != nil {
		return err
	}
	if !p.signInOn(f) {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("portal: the stack takes no claim without an offer"))
	}
	ctx := r.Context()
	ids := configurationIDs(m)
	if r.PostFormValue("action") == "clear" {
		if _, cerr := p.opts.SignIn.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{ConfigurationIds: ids, Clear: true})); cerr != nil {
			return cerr
		}
		p.signInRedirect(w, r, m, "signin-cleared")
		return nil
	}
	form := signInForm{
		source: strings.TrimSpace(r.PostFormValue("source")), field: strings.TrimSpace(r.PostFormValue("field")),
		claim: strings.TrimSpace(r.PostFormValue("claim")), errs: map[string]string{},
	}
	for name, value := range map[string]string{"source": form.source, "field": form.field, "claim": form.claim} {
		if value == "" {
			form.errs[name] = msg.T("issuer.signin.error.required")
		}
	}
	if len(form.errs) > 0 {
		return p.renderSignIn(w, r, f, m, form, http.StatusBadRequest)
	}
	got, err := p.opts.SignIn.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{ConfigurationIds: ids}))
	if err != nil {
		return err
	}
	if !slices.Contains(got.Msg.GetVouchedClaims(), form.claim) {
		form.errs["claim"] = msg.T("issuer.signin.error.vouch", form.claim)
		return p.renderSignIn(w, r, f, m, form, http.StatusBadRequest)
	}
	if problem := p.openSource(r, form.source); problem != "" {
		form.errs["source"] = problem
		return p.renderSignIn(w, r, f, m, form, http.StatusBadRequest)
	}
	_, err = p.opts.SignIn.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{
		ConfigurationIds: ids,
		Source: &backendv1.HolderSignInSource{
			SourceId: form.source, Field: form.field, TokenClaim: form.claim, SchemaId: m.GetId(), SchemaVersion: m.GetVersion(),
		},
	}))
	if err != nil {
		return err
	}
	p.signInRedirect(w, r, m, "signin-saved")
	return nil
}

// openSource adds the role of the holder sign in to the issue rule of
// the source when the rule lacks it. It returns the problem to show.
func (p *Portal) openSource(r *http.Request, id string) string {
	got, err := p.opts.Sources.Get(r.Context(), sourceCall(r, &datasourcev1.GetRequest{Id: id}))
	if err != nil {
		return msg.T("issuer.signin.error.source")
	}
	src := got.Msg.GetSource()
	if slices.Contains(src.GetAccess().GetIssue(), HolderSignInRole) {
		return ""
	}
	if src.Access == nil {
		src.Access = &datasourcev1.Source_Access{}
	}
	src.Access.Issue = append(src.Access.Issue, HolderSignInRole)
	if _, err := p.opts.Sources.Update(r.Context(), sourceCall(r, &datasourcev1.UpdateRequest{Source: src})); err != nil {
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			return msg.T("issuer.signin.error.access")
		}
		return msg.T("issuer.signin.error.source")
	}
	return ""
}

// signInRedirect sends the browser back to the tab with a notice.
func (p *Portal) signInRedirect(w http.ResponseWriter, r *http.Request, m *schemav1.Schema, code string) {
	target := p.signInURL(m.GetId(), m.GetVersion()) + "&notice=" + code
	if components.IsHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// testSignIn looks one value up in the source with the session of the
// staff member, who sees masked values only. An htmx request gets the
// result card; any other request gets the whole tab.
func (p *Portal) testSignIn(w http.ResponseWriter, r *http.Request) error {
	m, f, err := p.signInSchema(r)
	if err != nil {
		return err
	}
	if !p.signInOn(f) {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("portal: the stack takes no claim without an offer"))
	}
	form := signInForm{source: strings.TrimSpace(r.PostFormValue("source")), field: strings.TrimSpace(r.PostFormValue("field"))}
	result, err := p.testResult(r, m, form.source, form.field, r.PostFormValue("value"))
	if err != nil {
		return err
	}
	if components.IsHTMX(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte(result))
		return err
	}
	form.result = result
	return p.renderSignIn(w, r, f, m, form, http.StatusOK)
}

// testResult runs the lookup and draws its outcome as a card.
func (p *Portal) testResult(r *http.Request, m *schemav1.Schema, source, field, value string) (template.HTML, error) {
	b := &blocks{kit: p.opts.Kit}
	card := func(text string, body template.HTML) template.HTML {
		return b.add("card", components.Card{ID: "signin-test-outcome", Title: msg.T("issuer.signin.result.label"), Text: text, Body: body})
	}
	switch {
	case strings.TrimSpace(value) == "":
		return card(msg.T("issuer.signin.result.empty"), ""), b.err
	case source == "" || field == "":
		return card(msg.T("issuer.signin.result.nofield"), ""), b.err
	}
	res, err := p.opts.Sources.Lookup(r.Context(), sourceCall(r, &datasourcev1.LookupRequest{
		SourceId: source, Field: field, Value: value, SchemaId: m.GetId(), SchemaVersion: m.GetVersion(),
	}))
	switch {
	case connect.CodeOf(err) == connect.CodePermissionDenied:
		return card(msg.T("issuer.signin.result.denied"), ""), b.err
	case connect.CodeOf(err) == connect.CodeFailedPrecondition:
		return card(msg.T("issuer.signin.unmapped"), ""), b.err
	case err != nil:
		return card(msg.T("issuer.signin.result.failed"), ""), b.err
	case res.Msg.GetAmbiguous():
		return card(msg.T("issuer.signin.result.ambiguous"), ""), b.err
	case !res.Msg.GetFound():
		return card(msg.T("issuer.signin.result.none"), ""), b.err
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(res.Msg.GetSubjectData()), &claims); err != nil {
		return card(msg.T("issuer.signin.result.failed"), ""), b.err
	}
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	sort.Strings(names)
	rows := make([]components.Row, 0, len(names))
	for _, k := range names {
		rows = append(rows, components.Row{{Text: k}, {Text: toText(claims[k])}})
	}
	table := b.add("table", components.Table{ID: "signin-test-claims", Caption: msg.T("issuer.signin.result.caption.label"),
		Columns: []string{msg.T("issuer.signin.result.claim.label"), msg.T("issuer.signin.result.value.label")}, Rows: rows})
	return card(msg.T("issuer.signin.result.found"), table), b.err
}

// toText shows a claim value: a string as is, anything else as JSON.
func toText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}
