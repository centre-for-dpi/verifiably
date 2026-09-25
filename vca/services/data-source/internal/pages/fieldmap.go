// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The transforms the field map offers, in order. Each one is a pure
// transform of core/mapping with fixed parameters.
var transforms = []string{"copy", "trim", "upper", "lower", "date_dmy", "date_mdy", "constant", "concat"}

// The layouts of the two date transforms and of the output of each.
const (
	layoutDMY      = "02/01/2006"
	layoutMDY      = "01/02/2006"
	layoutDate     = "2006-01-02"
	joinSeparator  = " "
	maxMapSchemas  = 100
	fieldPrefix    = "field."
	transformField = "transform."
	valuePrefix    = "value."
)

// idChars matches the characters an element id cannot hold.
var idChars = regexp.MustCompile(`[^A-Za-z0-9_]`)

// mapForm is the field map of one source onto one schema version, with
// the values of each claim and the error of each field.
type mapForm struct {
	src    *datasourcev1.Source
	schema *schemav1.Schema
	leaves []jsonschema.Leaf
	fields []string
	values url.Values
	errs   map[string]string
	toast  string
}

// fieldMap draws the map of a source onto the claims of a schema. A
// request without a schema first asks for one.
func (p *Pages) fieldMap(pg page) error {
	src, err := p.source(pg)
	if err != nil {
		return err
	}
	ctx := pg.ctx()
	schema, ok, err := p.schemaOf(ctx, pg.r.URL.Query().Get("schema"))
	if err != nil {
		return err
	}
	if !ok {
		return p.pickSchema(pg, src)
	}
	f, err := p.mapFormOf(pg, src, schema)
	if err != nil {
		return err
	}
	saved, err := p.opts.Sources.GetFieldMap(ctx, connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: src.GetId(), SchemaId: schema.GetId()}))
	switch {
	case err == nil:
		f.values = valuesOf(service.FieldMapFromProto(saved.Msg.GetFieldMap()))
	case connect.CodeOf(err) == connect.CodeNotFound:
		f.values = suggest(f.leaves, f.fields)
	default:
		return err
	}
	return p.renderMap(pg, f)
}

// mapFormOf reads the claims of the schema and the fields of the source.
func (p *Pages) mapFormOf(pg page, src *datasourcev1.Source, schema *schemav1.Schema) (mapForm, error) {
	f := mapForm{src: src, schema: schema, values: url.Values{}, errs: map[string]string{}}
	if raw := strings.TrimSpace(schema.GetJsonSchema()); raw != "" {
		parsed, err := jsonschema.Parse([]byte(raw))
		if err != nil {
			return f, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		f.leaves = parsed.Leaves()
	}
	res, err := p.opts.Sources.PreviewFields(pg.ctx(), connect.NewRequest(&datasourcev1.PreviewFieldsRequest{SourceId: src.GetId()}))
	if roleDenied(err) {
		return f, err
	}
	if err == nil {
		for _, field := range res.Msg.GetFields() {
			f.fields = append(f.fields, field.GetName())
		}
	} else {
		// The page still draws the claims; no source field fills them
		// until the source answers again.
		f.toast = msg.T("issuer.sources.read.failed")
	}
	return f, nil
}

// pickSchema asks for the schema of the map: the published schemas as
// radio cards, sent back to the same page.
func (p *Pages) pickSchema(pg page, src *datasourcev1.Source) error {
	b := p.blocks()
	var body template.HTML
	var list []*schemav1.Schema
	if p.opts.Schemas != nil {
		ctx := pg.ctx()
		res, err := p.opts.Schemas.List(ctx, staffshell.AsActor(ctx, &schemav1.ListRequest{
			State: schemav1.State_STATE_PUBLISHED, Page: &commonv1.Pagination{PageSize: maxMapSchemas},
		}))
		if err != nil {
			return err
		}
		list = res.Msg.GetSchemas()
	}
	if len(list) == 0 {
		body = b.add("block", components.Block{ID: "schema", Title: msg.T("issuer.sources.schema.label"), Lead: msg.T("issuer.sources.schema.none")})
	} else {
		options := make([]components.ChoiceOption, 0, len(list))
		for i, s := range list {
			options = append(options, components.ChoiceOption{Value: schemaRef(s), Title: schemaName(s), Checked: i == 0,
				Text: msg.T("issuer.issue.schema.version", strconv.Itoa(int(s.GetVersion())), s.GetType())})
		}
		body = template.HTML(`<form method="get" action="`+template.HTMLEscapeString(sourcePath(src.GetId(), "/map", ""))+`">`) + //nolint:gosec // the action is escaped
			b.add("choice", components.Choice{ID: "schema", Legend: msg.T("issuer.sources.schema.label"), Hint: msg.T("issuer.sources.schema.hint"), Options: options}) +
			actionRow(b.add("button", components.Button{Text: msg.T("common.continue.label"), Type: "submit", Variant: "primary"})) +
			template.HTML(`</form>`)
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{Title: msg.T("issuer.sources.map.title.label"), Lead: msg.T("issuer.sources.map.lead", src.GetDisplayName()), Content: body})
}

// valuesOf turns a saved field map into the values of the form.
func valuesOf(fm mapping.FieldMap) url.Values {
	v := url.Values{}
	for _, r := range fm.Rules {
		first := ""
		if len(r.SourceFields) > 0 {
			first = r.SourceFields[0]
		}
		transform, value := "copy", ""
		switch r.Transform {
		case mapping.Trim, mapping.Upper, mapping.Lower:
			transform = string(r.Transform)
		case mapping.DateFormat:
			transform = "date_dmy"
			if r.Params[mapping.ParamInputLayout] == layoutMDY {
				transform = "date_mdy"
			}
		case mapping.Constant:
			transform, value = "constant", r.Params[mapping.ParamValue]
		case mapping.Concat:
			transform, value = "concat", strings.Join(r.SourceFields[1:], ", ")
		}
		v.Set(fieldPrefix+r.Property, first)
		v.Set(transformField+r.Property, transform)
		v.Set(valuePrefix+r.Property, value)
	}
	return v
}

// simpleName lowers a name and keeps its letters and digits, so
// "Full Name", "full_name" and "fullName" match.
func simpleName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// suggest fills a new map: each claim takes the source field with the
// same simple name as the claim or as its last part, trimmed.
func suggest(leaves []jsonschema.Leaf, fields []string) url.Values {
	v := url.Values{}
	for _, l := range leaves {
		for _, f := range fields {
			sf := simpleName(f)
			if sf == simpleName(l.Name()) || sf == simpleName(l.Path[len(l.Path)-1]) {
				v.Set(fieldPrefix+l.Name(), f)
				v.Set(transformField+l.Name(), "trim")
				break
			}
		}
	}
	return v
}

// renderMap draws one fieldset per claim: the source field, the
// transform, and its setting.
func (p *Pages) renderMap(pg page, f mapForm) error {
	b := p.blocks()
	ref := schemaRef(f.schema)
	parts := []template.HTML{p.stepper(b, stepMap), p.chosen(b, f.schema)}
	if len(f.errs) > 0 {
		parts = append(parts, b.add("block", components.Block{ID: "errors", Title: msg.T("issuer.sources.map.errors.label"),
			Lead: msg.T("issuer.sources.map.errors.text", strconv.Itoa(len(f.errs)))}))
	}
	var body template.HTML
	if len(f.leaves) == 0 {
		body = b.add("note", components.Note{Text: msg.T("issuer.issue.claims.none")})
	} else {
		sets := make([]template.HTML, 0, len(f.leaves)+2)
		sets = append(sets, hiddenInput("schema", ref))
		for i, l := range f.leaves {
			sets = append(sets, p.claimSet(b, f, i, l))
		}
		sets = append(sets, actionRow(
			b.add("button", components.Button{Text: msg.T("issuer.sources.map.save.label"), Type: "submit", Variant: "primary"}),
			b.add("button", components.Button{Text: msg.T("common.back.label"), Href: sourcePath(f.src.GetId(), "", ref), Variant: "ghost"}),
		))
		body = form(pg, sourcePath(f.src.GetId(), "/map", ""), false, sets...)
	}
	parts = append(parts, b.add("block", components.Block{ID: "map", Title: msg.T("issuer.sources.map.claims.label"),
		Lead: msg.T("issuer.sources.map.claims.lead") + " " + msg.T("issuer.sources.map.value.hint"), Meta: msg.T("issuer.sources.map.meta.label", strconv.Itoa(len(f.fields))), Body: body}))
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if f.toast != "" {
		toasts = []components.Toast{{Level: "bad", Text: f.toast}}
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.sources.map.title.label"), Lead: msg.T("issuer.sources.map.lead", f.src.GetDisplayName()),
		Content: components.Join(parts...), Toasts: toasts,
	})
}

// claimSet is the fieldset of one claim.
func (p *Pages) claimSet(b *blocks, f mapForm, i int, l jsonschema.Leaf) template.HTML {
	name := l.Name()
	id := "claim-" + strconv.Itoa(i+1) + "-" + idChars.ReplaceAllString(name, "_")
	chosen := f.values.Get(fieldPrefix + name)
	fieldOptions := []components.Option{{Value: "", Text: msg.T("issuer.sources.map.no_field.label")}}
	for _, sf := range f.fields {
		fieldOptions = append(fieldOptions, components.Option{Value: sf, Text: sf, Selected: sf == chosen})
	}
	transform := f.values.Get(transformField + name)
	transformOptions := make([]components.Option, 0, len(transforms))
	for _, t := range transforms {
		transformOptions = append(transformOptions, components.Option{Value: t, Text: msg.T("issuer.sources.transform." + t + ".label"), Selected: t == transform})
	}
	body := template.HTML(`<div class="field-row">`) + components.Join(
		b.add("field", components.Field{ID: id + "-field", Name: fieldPrefix + name, Label: msg.T("issuer.sources.map.field.label"),
			Type: "select", Options: fieldOptions, Error: f.errs[fieldPrefix+name]}),
		b.add("field", components.Field{ID: id + "-transform", Name: transformField + name, Label: msg.T("issuer.sources.map.transform.label"),
			Type: "select", Options: transformOptions}),
		b.add("field", components.Field{ID: id + "-value", Name: valuePrefix + name, Label: msg.T("issuer.sources.map.value.label"),
			Value: f.values.Get(valuePrefix + name), Error: f.errs[valuePrefix+name]}),
	) + template.HTML(`</div>`)
	return b.add("fieldset", components.Fieldset{ID: id, Legend: claimLegend(l), Hint: claimHint(l), Body: body})
}

// claimLegend names a claim: its title and its path.
func claimLegend(l jsonschema.Leaf) string {
	if t := strings.TrimSpace(l.Title); t != "" && t != l.Name() {
		return msg.T("issuer.sources.map.legend.label", t, l.Name())
	}
	return l.Name()
}

// claimHint names the type of a claim and whether the schema needs it.
func claimHint(l jsonschema.Leaf) string {
	key := "issuer.sources.claim.type." + l.Type
	if _, ok := msg.Lookup(key); !ok {
		key = "issuer.sources.claim.type.string"
	}
	text := msg.T(key)
	if l.Format == "date" {
		text = msg.T("issuer.sources.claim.type.date")
	}
	if l.Required {
		text += " " + msg.T("issuer.sources.claim.required")
	}
	return text
}

// saveFieldMap reads the posted map, checks it against the claims and
// the fields, and keeps it through the service.
func (p *Pages) saveFieldMap(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if err := pg.r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	src, err := p.source(pg)
	if err != nil {
		return err
	}
	schema, ok, err := p.schemaOf(pg.ctx(), pg.r.PostForm.Get("schema"))
	if err != nil {
		return err
	}
	if !ok {
		return connect.NewError(connect.CodeInvalidArgument, errNoSchema)
	}
	f, err := p.mapFormOf(pg, src, schema)
	if err != nil {
		return err
	}
	f.values = pg.r.PostForm
	rules := f.rules()
	if len(f.errs) > 0 {
		return p.renderMap(pg, f)
	}
	_, err = p.opts.Sources.SetFieldMap(pg.ctx(), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: service.FieldMapToProto(mapping.FieldMap{
		SourceID: src.GetId(), SchemaID: schema.GetId(), SchemaVersion: int(schema.GetVersion()), Rules: rules,
	})}))
	switch {
	case connect.CodeOf(err) == connect.CodeInvalidArgument:
		f.toast = msg.T("issuer.sources.map.refused")
		return p.renderMap(pg, f)
	case err != nil:
		return err
	}
	http.Redirect(pg.w, pg.r, sourcePath(src.GetId(), "/run", schemaRef(schema)), http.StatusSeeOther)
	return nil
}

// rules turns the posted values into the rules of core/mapping. It sets
// the error of each field that cannot become a rule.
func (f *mapForm) rules() []mapping.Rule {
	known := map[string]bool{}
	for _, sf := range f.fields {
		known[sf] = true
	}
	var out []mapping.Rule
	for _, l := range f.leaves {
		name := l.Name()
		field := f.values.Get(fieldPrefix + name)
		value := strings.TrimSpace(f.values.Get(valuePrefix + name))
		transform := f.values.Get(transformField + name)
		if transform == "constant" {
			if value == "" {
				f.errs[valuePrefix+name] = msg.T("issuer.sources.map.error.value")
				continue
			}
			out = append(out, mapping.Rule{Property: name, Transform: mapping.Constant, Params: map[string]string{mapping.ParamValue: value}})
			continue
		}
		switch {
		case field == "" && l.Required:
			f.errs[fieldPrefix+name] = msg.T("issuer.sources.map.error.required")
			continue
		case field == "":
			continue
		case !known[field]:
			f.errs[fieldPrefix+name] = msg.T("issuer.sources.map.error.field")
			continue
		}
		rule := mapping.Rule{Property: name, SourceFields: []string{field}}
		switch transform {
		case "trim", "upper", "lower":
			rule.Transform = mapping.Transform(transform)
		case "date_dmy", "date_mdy":
			input := layoutDMY
			if transform == "date_mdy" {
				input = layoutMDY
			}
			output := layoutDate
			if l.Format == "date-time" {
				output = time.RFC3339
			}
			rule.Transform, rule.Params = mapping.DateFormat, map[string]string{mapping.ParamInputLayout: input, mapping.ParamOutputLayout: output}
		case "concat":
			for _, extra := range strings.Split(value, ",") {
				extra = strings.TrimSpace(extra)
				if extra == "" {
					continue
				}
				if !known[extra] {
					f.errs[valuePrefix+name] = msg.T("issuer.sources.map.error.join")
					break
				}
				rule.SourceFields = append(rule.SourceFields, extra)
			}
			rule.Transform, rule.Params = mapping.Concat, map[string]string{mapping.ParamSeparator: joinSeparator}
		}
		out = append(out, rule)
	}
	return out
}
