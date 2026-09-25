// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultIssueURL is the issue page of the issuer (ADR-044 decision 1).
const DefaultIssueURL = "/issue/"

// MaxUploadBytes caps the body of the publish form: the largest JSON
// Schema document the registry takes, plus the other fields.
const MaxUploadBytes = record.MaxSchemaSize + 64<<10

// frame reads the probe of the issuer shell once for a page. Without a
// shell it is empty, so the pages act as before the probe existed.
func (p *Portal) frame(r *http.Request) staffshell.Frame {
	if p.opts.Shell == nil {
		return staffshell.Frame{}
	}
	return p.opts.Shell.Frame(r.Context())
}

// target is the stack a publish of this pair registers with: the stack
// of the own pair (ADR-013 decision 3). The adapter answer decides what
// the pages offer (ADR-034 decision 5).
type target struct {
	// known is true when the probe answered for the own pair.
	known bool
	// name is the stack name the adapter reports.
	name string
	// live is true when the own pair is live.
	live bool
	// takes is true when the adapter lists FEATURE_CREDENTIAL_CONFIG_API.
	takes bool
	// formats are the formats the adapter issues.
	formats []commonv1.Format
}

// targetOf returns the publish target of the own pair.
func targetOf(f staffshell.Frame) target {
	own, ok := f.Own()
	if !ok {
		return target{formats: Formats}
	}
	t := target{known: true, name: f.Snapshot().StackName(own.Peer.Dpg), live: own.State == topology.Live}
	t.takes = t.live && own.Has(backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API)
	for _, fm := range Formats {
		for _, got := range own.Capabilities.GetFormats() {
			if got == fm {
				t.formats = append(t.formats, fm)
			}
		}
	}
	return t
}

// canPublish reports whether a publish can go to the target. Without a
// probe the registry tries, and the adapter answer decides.
func (t target) canPublish() bool { return !t.known || t.takes }

// blocked says why a draft cannot publish on the target, or reports ok.
func (t target) blocked(m *schemav1.Schema) (string, bool) {
	switch {
	case t.known && !t.live:
		return msg.T("issuer.schemas.target.starting"), false
	case !t.canPublish():
		return msg.T("issuer.schemas.target.none", t.name), false
	}
	if missing := t.missing(m); len(missing) > 0 {
		return msg.T("issuer.schemas.target.formats", t.name, strings.Join(missing, ", ")), false
	}
	return "", true
}

// missing returns the formats of m that the target does not issue.
func (t target) missing(m *schemav1.Schema) []string {
	if !t.known {
		return nil
	}
	var out []string
	for _, f := range m.GetFormats() {
		if !hasFormat(t.formats, f) {
			out = append(out, FormatValue(f))
		}
	}
	return out
}

func hasFormat(list []commonv1.Format, f commonv1.Format) bool {
	for _, got := range list {
		if got == f {
			return true
		}
	}
	return false
}

// otherTarget is another live issuer stack whose adapter takes schemas.
type otherTarget struct {
	name string
	href string
}

// others lists the other live issuer stacks that take schemas, in stack
// order. Each publishes from the schema pages of its own pair.
func (p *Portal) others(f staffshell.Frame) []otherTarget {
	own, _ := f.Own()
	var out []otherTarget
	for _, st := range f.Live(commonv1.Role_ROLE_ISSUER) {
		if st.Peer.Pair == own.Peer.Pair || !st.Has(backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API) {
			continue
		}
		out = append(out, otherTarget{
			name: f.Snapshot().StackName(st.Peer.Dpg),
			href: strings.TrimRight(st.Peer.PublicURL, "/") + p.opts.Prefix + "/publish",
		})
	}
	return out
}

// FormatLabel returns the reader facing name of a format.
func FormatLabel(f commonv1.Format) string {
	key := strings.NewReplacer("+", "_", "-", "_").Replace(FormatValue(f))
	if key == "" {
		return ""
	}
	return msg.T("schema.format." + key + ".label")
}

// FormatLabels joins the reader facing names of the formats of m.
func FormatLabels(m *schemav1.Schema) string {
	out := make([]string, 0, len(m.GetFormats()))
	for _, f := range m.GetFormats() {
		out = append(out, FormatLabel(f))
	}
	return strings.Join(out, ", ")
}

// Updated returns the time of the last change of a version: the retire
// time, else the publish time, else the creation time.
func Updated(m *schemav1.Schema) time.Time {
	for _, ts := range []*timestamppb.Timestamp{m.GetRetiredAt(), m.GetPublishedAt(), m.GetCreatedAt()} {
		if ts != nil {
			return ts.AsTime()
		}
	}
	return time.Time{}
}

// dateCell renders a date in a time element, or a dash.
func dateCell(t time.Time) components.Cell {
	if t.IsZero() {
		return components.Cell{Text: "-"}
	}
	return components.Cell{HTML: template.HTML(`<time datetime="` + t.UTC().Format(time.RFC3339) + `">` + //nolint:gosec // both parts are formatted times
		t.UTC().Format("2006-01-02") + `</time>`)}
}

// issuedCount asks the issued credentials service how many credentials
// of a schema it holds, in the name of the staff member. It returns a
// dash when the service is not set or does not answer.
func (p *Portal) issuedCount(r *http.Request, id string) string {
	if p.opts.Issued == nil {
		return "-"
	}
	ctx := r.Context()
	res, err := p.opts.Issued.List(ctx, staffshell.AsActor(ctx, &issuedv1.ListRequest{
		Page: &commonv1.Pagination{PageSize: 1}, Filter: &issuedv1.Filter{SchemaId: id},
	}))
	if err != nil {
		return "-"
	}
	return strconv.FormatInt(res.Msg.GetPage().GetTotalSize(), 10)
}

// builderURL returns the builder page that opens a schema for its next
// version, or "" when the deployment has no builder.
func (p *Portal) builderURL(id string) string {
	if p.opts.BuilderURL == "" {
		return ""
	}
	sep := "?"
	if strings.Contains(p.opts.BuilderURL, "?") {
		sep = "&"
	}
	return p.opts.BuilderURL + sep + "id=" + url.QueryEscape(id)
}

// rowActions renders the actions the state of a row allows: a new
// version always; delete for a draft; issue and retire for a published
// version. A published version retires and only a draft deletes.
func (p *Portal) rowActions(b *blocks, m *schemav1.Schema, csrf template.HTML) template.HTML {
	parts := []template.HTML{template.HTML(`<div class="row-actions">`)} //nolint:gosec // a literal wrapper
	if href := p.builderURL(m.GetId()); href != "" {
		parts = append(parts, b.add("button", components.Button{Text: msg.T("issuer.schemas.action.version.label"), Href: href}))
	}
	if m.GetState() != schemav1.State_STATE_RETIRED {
		parts = append(parts, b.add("button", components.Button{Text: msg.T("issuer.schemas.action.mapping.label"), Href: p.mappingURL(m.GetId(), m.GetVersion())}))
	}
	switch m.GetState() {
	case schemav1.State_STATE_DRAFT:
		parts = append(parts, p.postForm(m.GetId(), "delete", csrf, m.GetVersion(),
			b.add("button", components.Button{Text: msg.T("issuer.schemas.action.delete.label"), Type: "submit", Variant: "danger"})))
	case schemav1.State_STATE_PUBLISHED:
		parts = append(parts,
			b.add("button", components.Button{Text: msg.T("issuer.schemas.action.issue.label"), Variant: "primary",
				Href: p.opts.IssueURL + "?schema=" + url.QueryEscape(m.GetId())}),
			b.add("button", components.Button{Text: msg.T("issuer.schemas.action.retire.label"), Variant: "danger",
				Href: p.detailURL(m.GetId(), m.GetVersion()) + "#actions"}))
	}
	return components.Join(append(parts, template.HTML(`</div>`))...)
}

// postForm wraps a button in a POST form to one action of a version.
func (p *Portal) postForm(id, action string, csrf template.HTML, version int32, button template.HTML) template.HTML {
	return components.Join(
		template.HTML(`<form action="`+template.HTMLEscapeString(p.opts.Prefix+"/schemas/"+url.PathEscape(id)+"/"+action)+`" method="post">`), //nolint:gosec // the action is escaped
		csrf, template.HTML(`<input type="hidden" name="version" value="`+strconv.Itoa(int(version))+`">`), //nolint:gosec // the value is a number
		button, template.HTML(`</form>`))
}

// blocks renders components and keeps the first error, so a page builds
// its whole body and checks the error once.
type blocks struct {
	kit *components.Kit
	err error
}

// add renders one component.
func (b *blocks) add(name string, data any) template.HTML {
	h, err := b.kit.HTML(name, data)
	if err != nil && b.err == nil {
		b.err = err
	}
	return h
}

// schemaCell renders the name of a schema as a link to its version and
// the id under it.
func (p *Portal) schemaCell(m *schemav1.Schema) template.HTML {
	return link(p.detailURL(m.GetId(), m.GetVersion()), Name(m)) +
		template.HTML(`<br><span class="hint"><code>`+template.HTMLEscapeString(m.GetId())+`</code></span>`) //nolint:gosec // the id is escaped
}

// deleteDraft removes one draft version and returns to the list.
func (p *Portal) deleteDraft(w http.ResponseWriter, r *http.Request) error {
	v, err := formVersion(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := p.opts.Client.DeleteDraft(ctx, staffshell.AsActor(ctx, &schemav1.DeleteDraftRequest{Id: r.PathValue("id"), Version: v})); err != nil {
		return err
	}
	target := p.opts.Prefix + "/?notice=deleted"
	if components.IsHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return nil
}

// upload is the state of the publish form.
type upload struct {
	typ     string
	name    string
	formats []commonv1.Format
	target  string
	errText string
	fileErr string
}

// publishPage renders the publish from a file page.
func (p *Portal) publishPage(w http.ResponseWriter, r *http.Request) error {
	f := p.frame(r)
	t := targetOf(f)
	u := upload{target: "draft"}
	if t.canPublish() {
		u.target = "publish"
	}
	u.formats = defaultFormat(t.formats)
	return p.renderPublish(w, r, f, t, u)
}

// defaultFormat picks the format the form checks first: dc+sd-jwt when
// the stack issues it, else the first format of the stack.
func defaultFormat(list []commonv1.Format) []commonv1.Format {
	if hasFormat(list, commonv1.Format_FORMAT_DC_SD_JWT) {
		return []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}
	}
	if len(list) > 0 {
		return list[:1]
	}
	return nil
}

// renderPublish writes the publish page with the state of the form.
func (p *Portal) renderPublish(w http.ResponseWriter, r *http.Request, f staffshell.Frame, t target, u upload) error {
	b := &blocks{kit: p.opts.Kit}
	stackName := t.name
	if stackName == "" {
		stackName = msg.T("issuer.stack.this.label")
	}
	formats := make([]components.ChoiceOption, 0, len(t.formats))
	for _, fm := range t.formats {
		formats = append(formats, components.ChoiceOption{
			Value: FormatValue(fm), Title: FormatLabel(fm), Meta: FormatValue(fm), Checked: hasFormat(u.formats, fm),
		})
	}
	targets := []components.ChoiceOption{}
	if t.canPublish() {
		targets = append(targets, components.ChoiceOption{Value: "publish", Title: msg.T("issuer.schemas.target.publish.label", stackName),
			Text: msg.T("issuer.schemas.target.publish.text"), Checked: u.target == "publish"})
	}
	targets = append(targets, components.ChoiceOption{Value: "draft", Title: msg.T("issuer.schemas.target.draft.label"),
		Text: msg.T("issuer.schemas.target.draft.text"), Checked: u.target != "publish"})
	fields := []template.HTML{
		template.HTML(`<form action="` + template.HTMLEscapeString(p.opts.Prefix+"/publish") + `" method="post" enctype="multipart/form-data">`), //nolint:gosec // the action is escaped
		staffsession.HiddenField(r.Context()),
		b.add("field", components.Field{ID: "file", Label: msg.T("issuer.schemas.upload.file.label"), Type: "file", Required: true,
			Hint: msg.T("issuer.schemas.upload.file.hint"), Error: u.fileErr, Attrs: map[string]string{"accept": "application/json,.json"}}),
		b.add("field", components.Field{ID: "type", Label: msg.T("issuer.schemas.upload.type.label"), Value: u.typ,
			Hint: msg.T("issuer.schemas.upload.type.hint"), Attrs: map[string]string{"autocomplete": "off"}}),
		b.add("field", components.Field{ID: "name", Label: msg.T("issuer.schemas.upload.name.label"), Value: u.name,
			Hint: msg.T("issuer.schemas.upload.name.hint"), Attrs: map[string]string{"autocomplete": "off"}}),
	}
	if len(formats) > 0 {
		fields = append(fields, b.add("choice", components.Choice{ID: "formats", Legend: msg.T("issuer.schemas.upload.formats.label"),
			Hint: msg.T("issuer.schemas.upload.formats.hint", stackName), Options: formats, Multiple: true}))
	}
	fields = append(fields,
		b.add("choice", components.Choice{ID: "target", Legend: msg.T("issuer.schemas.target.legend.label"), Options: targets}),
		b.add("button", components.Button{Text: msg.T("issuer.schemas.upload.submit.label"), Type: "submit", Variant: "primary"}),
		template.HTML(`</form>`))
	text := msg.T("issuer.schemas.upload.lead")
	switch {
	case t.known && !t.live:
		text += " " + msg.T("issuer.schemas.target.starting")
	case t.known && !t.takes:
		text += " " + msg.T("issuer.schemas.target.none", stackName)
	}
	parts := []template.HTML{b.add("card", components.Card{ID: "upload", Title: msg.T("issuer.schemas.upload.card.label"), Text: text,
		Body: components.Join(fields...)})}
	if others := p.others(f); len(others) > 0 {
		links := make([]template.HTML, 0, len(others)+2)
		links = append(links, template.HTML(`<div class="row-actions">`)) //nolint:gosec // a literal wrapper
		for _, o := range others {
			links = append(links, b.add("button", components.Button{Text: msg.T("issuer.schemas.others.link.label", o.name), Href: o.href}))
		}
		links = append(links, template.HTML(`</div>`))
		parts = append(parts, b.add("card", components.Card{ID: "others", Title: msg.T("issuer.schemas.others.label"),
			Text: msg.T("issuer.schemas.others.text"), Body: components.Join(links...)}))
	}
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if u.errText != "" {
		toasts = []components.Toast{{Level: "bad", Text: u.errText}}
	}
	return p.renderFrame(w, r, f, components.Page{
		Title:   msg.T("issuer.schemas.publish.label"),
		Lead:    msg.T("issuer.schemas.lead"),
		Content: components.Join(parts...),
		Toasts:  toasts,
	})
}

// publishFile stores an uploaded JSON Schema document as version 1 and
// publishes it on the own stack when the form asks and the stack takes
// schemas. A bad upload renders the form again with the reason.
func (p *Portal) publishFile(w http.ResponseWriter, r *http.Request) error {
	f := p.frame(r)
	t := targetOf(f)
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	if err := r.ParseMultipartForm(MaxUploadBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	u := upload{typ: strings.TrimSpace(r.PostFormValue("type")), name: strings.TrimSpace(r.PostFormValue("name")),
		target: r.PostFormValue("target")}
	for _, v := range r.PostForm["formats"] {
		if fm := ParseFormat(v); fm != commonv1.Format_FORMAT_UNSPECIFIED && hasFormat(t.formats, fm) {
			u.formats = append(u.formats, fm)
		} else {
			u.errText = msg.T("issuer.schemas.upload.error.formats")
		}
	}
	doc, fileErr := uploaded(r)
	switch {
	case fileErr != nil:
		u.fileErr = msg.T("issuer.schemas.upload.error.file")
		u.errText = u.fileErr
	case len(u.formats) == 0 || u.errText != "":
		u.errText = msg.T("issuer.schemas.upload.error.formats")
	case u.target == "publish" && !t.canPublish():
		u.errText = msg.T("issuer.schemas.upload.error.target")
	}
	if u.errText != "" {
		return p.renderPublish(w, r, f, t, u)
	}
	parsed, err := jsonschema.Parse(doc)
	if err != nil {
		u.fileErr = msg.T("issuer.schemas.upload.error.document") + " " + err.Error()
		u.errText = u.fileErr
		return p.renderPublish(w, r, f, t, u)
	}
	title := documentText(parsed, "title")
	typ, name := u.typ, u.name
	if typ == "" {
		typ = TypeFromTitle(title)
	}
	if name == "" {
		name = title
	}
	if typ == "" {
		u.errText = msg.T("issuer.schemas.upload.error.type")
		return p.renderPublish(w, r, f, t, u)
	}
	if name == "" {
		name = typ
	}
	ctx := r.Context()
	created, err := p.opts.Client.Create(ctx, staffshell.AsActor(ctx, &schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: typ, JsonSchema: string(doc), Formats: u.formats, CreatedBy: staffshell.Actor(ctx),
		Display: []*schemav1.Display{{Name: name, Locale: "en", Description: documentText(parsed, "description")}},
	}}))
	if err != nil {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			return err
		}
		u.errText = msg.T("issuer.schemas.upload.error.stored") + " " + message(err)
		return p.renderPublish(w, r, f, t, u)
	}
	m := created.Msg.GetSchema()
	if u.target != "publish" {
		p.redirect(w, r, m.GetId(), m.GetVersion(), "uploaded")
		return nil
	}
	if _, err := p.opts.Client.Publish(ctx, staffshell.AsActor(ctx, &schemav1.PublishRequest{Id: m.GetId(), Version: m.GetVersion()})); err != nil {
		return err
	}
	p.redirect(w, r, m.GetId(), m.GetVersion(), "published")
	return nil
}

// uploaded reads the file of the publish form.
func uploaded(r *http.Request) ([]byte, error) {
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck // a read only part of the form
	data, err := io.ReadAll(io.LimitReader(file, record.MaxSchemaSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("portal: the file is empty")
	}
	return data, nil
}

// documentText returns one top level string of a JSON Schema document,
// such as its title, or "".
func documentText(s jsonschema.Schema, key string) string {
	root, ok := s.Root().(map[string]any)
	if !ok {
		return ""
	}
	text, ok := root[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

// TypeFromTitle turns a title into a credential type: each word with a
// capital, joined, with every character that is not a letter or a
// digit dropped. "Farmer credential" gives FarmerCredential.
func TypeFromTitle(title string) string {
	var b strings.Builder
	upper := true
	for _, c := range title {
		switch {
		case unicode.IsLetter(c) && c < unicode.MaxASCII, unicode.IsDigit(c) && c < unicode.MaxASCII:
			if upper {
				c = unicode.ToUpper(c)
			}
			b.WriteRune(c)
			upper = false
		default:
			upper = true
		}
	}
	return b.String()
}

// message returns the sentence of a Connect error, without the code.
func message(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}
