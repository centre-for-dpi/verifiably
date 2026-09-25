// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// mappingURL returns the mapping page of one version.
func (p *Portal) mappingURL(id string, version int32) string {
	u := p.opts.Prefix + "/schemas/" + url.PathEscape(id) + "/mapping"
	if version > 0 {
		u += "?version=" + strconv.Itoa(int(version))
	}
	return u
}

// mappingForm is the state of the mapping form: the values a staff
// member typed and the problems of each field.
type mappingForm struct {
	contexts string
	mappings []record.ClaimMapping
	problems []metadata.Problem
	toast    string
}

// problem returns the texts of the problems of one field, joined.
func (f mappingForm) problem(fields ...string) string {
	var out []string
	for _, pr := range f.problems {
		for _, field := range fields {
			if pr.Field == field {
				out = append(out, pr.Text)
			}
		}
	}
	return strings.Join(out, " ")
}

// locales returns the display locales of a version, or en without one.
func locales(m *schemav1.Schema) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range m.GetDisplay() {
		if l := strings.TrimSpace(d.GetLocale()); l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = []string{"en"}
	}
	return out
}

// currentMapping returns the form state of the mapping a version holds.
func currentMapping(m *schemav1.Schema) mappingForm {
	return mappingForm{contexts: strings.Join(m.GetContexts(), "\n"), mappings: record.MappingsFromProto(m.GetClaimMappings())}
}

// mappingPage renders the mapping page of one version (spec IS4).
func (p *Portal) mappingPage(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.Get(r.Context(), connect.NewRequest(&schemav1.GetRequest{Id: r.PathValue("id"), Version: version(r)}))
	if err != nil {
		return err
	}
	m := resp.Msg.GetSchema()
	return p.renderMapping(w, r, m, currentMapping(m))
}

// labelOf returns the label and the description a claim shows in one
// locale: the mapping, else the title and the description of the
// property.
func labelOf(f mappingForm, c metadata.Claim, locale string) (string, string) {
	for _, m := range f.mappings {
		if m.Claim != c.Name {
			continue
		}
		for _, l := range m.Labels {
			if l.Locale == locale {
				return l.Label, l.Description
			}
		}
		return "", ""
	}
	return c.Title, c.Description
}

// iriOf returns the term IRI of a claim in the form.
func iriOf(f mappingForm, claim string) string {
	for _, m := range f.mappings {
		if m.Claim == claim {
			return m.IRI
		}
	}
	return ""
}

// renderMapping writes the mapping page with the state of the form.
func (p *Portal) renderMapping(w http.ResponseWriter, r *http.Request, m *schemav1.Schema, f mappingForm) error {
	rec, err := record.FromProto(m)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	b := &blocks{kit: p.opts.Kit}
	parts := []template.HTML{
		template.HTML(`<form action="` + template.HTMLEscapeString(p.mappingURL(m.GetId(), 0)) + `" method="post">`), //nolint:gosec // the action is escaped
		staffsession.HiddenField(r.Context()),
		template.HTML(`<input type="hidden" name="version" value="` + strconv.Itoa(int(m.GetVersion())) + `">`), //nolint:gosec // the value is a number
		b.add("card", components.Card{ID: "contexts-card", Title: msg.T("issuer.mapping.contexts.label"), Text: msg.T("issuer.mapping.contexts.text"),
			Body: components.Join(
				b.add("code", components.Code{ID: "base-context", Label: msg.T("issuer.mapping.base.label"), Text: metadata.VCDMContext}),
				b.add("field", components.Field{ID: "contexts", Label: msg.T("issuer.mapping.contexts.field.label"), Type: "textarea", Value: f.contexts,
					Hint: msg.T("issuer.mapping.contexts.hint"), Error: f.problem("contexts"), Attrs: map[string]string{"rows": "4", "spellcheck": "false"}}),
			)}),
	}
	langs := locales(m)
	for i, c := range metadata.Claims(rec) {
		n := strconv.Itoa(i)
		fields := []template.HTML{
			template.HTML(`<input type="hidden" name="claim.` + n + `.name" value="` + template.HTMLEscapeString(c.Name) + `">`), //nolint:gosec // the name is escaped
			b.add("field", components.Field{ID: "claim-" + n + "-iri", Name: "claim." + n + ".iri", Label: msg.T("issuer.mapping.iri.label"),
				Value: iriOf(f, c.Name), Hint: msg.T("issuer.mapping.iri.hint"),
				Error: f.problem("claim."+c.Name, "claim."+c.Name+".iri"), Attrs: map[string]string{"autocomplete": "off", "spellcheck": "false", "inputmode": "url"}}),
		}
		for j, locale := range langs {
			label, description := labelOf(f, c, locale)
			labelErr := ""
			if j == 0 {
				labelErr = f.problem("claim." + c.Name + ".labels")
			}
			fields = append(fields,
				template.HTML(`<div class="field-row">`), //nolint:gosec // a literal wrapper
				b.add("field", components.Field{ID: "claim-" + n + "-label-" + locale, Name: "claim." + n + ".label." + locale,
					Label: msg.T("issuer.mapping.label.label", locale), Value: label, Error: labelErr}),
				b.add("field", components.Field{ID: "claim-" + n + "-description-" + locale, Name: "claim." + n + ".description." + locale,
					Label: msg.T("issuer.mapping.description.label", locale), Value: description}),
				template.HTML(`</div>`))
		}
		kind := claimType(rec, c.Name)
		if kind == "" {
			kind = "any"
		}
		parts = append(parts, b.add("card", components.Card{ID: "claim-" + n, Title: c.Title,
			Text: msg.T("issuer.mapping.claim.text", c.Name, kind), Body: components.Join(fields...)}))
	}
	parts = append(parts,
		b.add("card", components.Card{ID: "save", Title: msg.T("issuer.mapping.save.label"), Text: msg.T("issuer.mapping.save.text"),
			Body: components.Join(template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
				b.add("button", components.Button{Text: msg.T("issuer.mapping.save.label"), Type: "submit", Variant: "primary"}),
				b.add("button", components.Button{Text: msg.T("issuer.mapping.back.label"), Href: p.detailURL(m.GetId(), m.GetVersion())}),
				template.HTML(`</div>`))}),
		template.HTML(`</form>`))
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if f.toast != "" {
		toasts = []components.Toast{{Level: "bad", Text: f.toast}}
	}
	return p.render(w, r, "mapping", components.Page{
		Title:   msg.T("issuer.mapping.title.label") + ", " + Name(m) + ", version " + strconv.Itoa(int(m.GetVersion())),
		Heading: msg.T("issuer.mapping.title.label"),
		Label:   Name(m) + ", v" + strconv.Itoa(int(m.GetVersion())),
		Lead:    msg.T("issuer.mapping.lead"),
		Content: components.Join(parts...),
		Toasts:  toasts,
	})
}

// claimType returns the JSON Schema type of one top level property.
func claimType(r record.Record, name string) string {
	for _, c := range Claims(r.JSONSchema) {
		if c.Name == name {
			return c.Type
		}
	}
	return ""
}

// readMapping reads the posted mapping form. A claim with no term and no
// label gets no mapping. Every value loses its surrounding spaces.
func readMapping(r *http.Request, langs []string) mappingForm {
	f := mappingForm{contexts: strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("contexts"), "\r\n", "\n"))}
	for i := 0; ; i++ {
		n := "claim." + strconv.Itoa(i) + "."
		name, ok := r.PostForm[n+"name"]
		if !ok || len(name) == 0 {
			break
		}
		m := record.ClaimMapping{Claim: strings.TrimSpace(name[0]), IRI: strings.TrimSpace(r.PostFormValue(n + "iri"))}
		for _, locale := range langs {
			label := strings.TrimSpace(r.PostFormValue(n + "label." + locale))
			description := strings.TrimSpace(r.PostFormValue(n + "description." + locale))
			if label != "" || description != "" {
				m.Labels = append(m.Labels, record.ClaimLabel{Locale: locale, Label: label, Description: description})
			}
		}
		if m.IRI != "" || len(m.Labels) > 0 {
			f.mappings = append(f.mappings, m)
		}
	}
	return f
}

// contextList splits the context box into one IRI per line.
func contextList(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// saveMapping checks the posted mapping and saves it as the next draft
// version of the schema. A mapping that breaks a rule renders the page
// again with the reason next to each field.
func (p *Portal) saveMapping(w http.ResponseWriter, r *http.Request) error {
	v, err := formVersion(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	resp, err := p.opts.Client.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: r.PathValue("id"), Version: v}))
	if err != nil {
		return err
	}
	m := resp.Msg.GetSchema()
	f := readMapping(r, locales(m))
	rec, err := record.FromProto(m)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	rec.Contexts, rec.ClaimMappings = contextList(f.contexts), f.mappings
	if f.problems = metadata.CheckMapping(rec); len(f.problems) > 0 {
		f.toast = msg.T("issuer.mapping.error.form")
		return p.renderMapping(w, r, m, f)
	}
	next, ok := proto.Clone(m).(*schemav1.Schema)
	if !ok {
		return connect.NewError(connect.CodeInternal, nil)
	}
	next.Contexts, next.ClaimMappings, next.CreatedBy = rec.Contexts, record.MappingsToProto(rec.ClaimMappings), staffshell.Actor(ctx)
	saved, err := p.opts.Client.Update(ctx, staffshell.AsActor(ctx, &schemav1.UpdateRequest{Schema: next}))
	if err != nil {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			return err
		}
		f.toast = message(err)
		return p.renderMapping(w, r, m, f)
	}
	p.redirect(w, r, m.GetId(), saved.Msg.GetSchema().GetVersion(), "mapped")
	return nil
}
