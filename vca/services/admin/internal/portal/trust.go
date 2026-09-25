// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DateFormat is how a table column with little room prints a day.
const DateFormat = "2006-01-02"

// Identifier kinds of the trust forms.
const (
	kindDID  = "did"
	kindX509 = "x509"
)

// errNotADID reports a DID kind with a value that is not a DID.
var errNotADID = errors.New("portal: the identifier type is DID, but the value has no did prefix")

// registerTrust adds the trust list pages (board Admin-Trust, ADR-011).
func (p *Portal) registerTrust(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/trust", p.guarded(p.trust))
	mux.HandleFunc("POST "+at+"/trust", p.posted(p.addTrust))
	mux.HandleFunc("POST "+at+"/trust/delete", p.posted(p.deleteTrust))
	mux.HandleFunc("POST "+at+"/trust/approve", p.posted(p.approveTrust))
	mux.HandleFunc("POST "+at+"/trust/reject", p.posted(p.rejectTrust))
	p.registerRegistries(mux)
}

// trust renders the trust list: the entries with the pending ones first,
// each pending entry with approve and reject, and the add form.
func (p *Portal) trust(w http.ResponseWriter, r *http.Request, s session) error {
	b := p.blocks()
	q := r.URL.Query()
	res, err := p.opts.Client.ListTrustEntries(r.Context(), call(s, &adminv1.ListTrustEntriesRequest{
		Role: service.RoleValue(q.Get("role")), Status: statusValue(q.Get("status")),
		Page: &commonv1.Pagination{PageSize: service.MaxPageSize},
	}))
	var table template.HTML
	switch {
	case err != nil && connect.CodeOf(err) == connect.CodeFailedPrecondition:
		table = b.add("card", components.Card{
			ID: "no-registry", Title: msg.T("admin.trust.no_registry.label"), Text: msg.T("admin.trust.no_registry"),
		})
	case err != nil:
		return err
	default:
		table = p.trustTable(b, res.Msg.GetEntries(), s.CSRF)
	}
	add := p.trustForm(b, s.CSRF)
	tabs := p.trustTabs(b, "list")
	actions := p.trustHeaderActions(b)
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       msg.T("admin.trust.tab.list.label"),
		Heading:     msg.T("admin.trust.heading.label"),
		Lead:        msg.T("admin.trust.lead"),
		Actions:     actions,
		Description: msg.T("admin.trust.lead"),
		Content:     components.Join(tabs, table, add),
		Toasts:      notice(q.Get("notice")),
	})
}

// trustTable lists the entries: pending first, then by display name.
func (p *Portal) trustTable(b *blocks, entries []*trustv1.TrustEntry, csrf string) template.HTML {
	sorted := append([]*trustv1.TrustEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, pj := sorted[i].GetStatus() == trustv1.Status_STATUS_PENDING, sorted[j].GetStatus() == trustv1.Status_STATUS_PENDING
		if pi != pj {
			return pi
		}
		return strings.ToLower(sorted[i].GetDisplayName()) < strings.ToLower(sorted[j].GetDisplayName())
	})
	pending := 0
	rows := make([]components.Row, 0, len(sorted))
	for _, e := range sorted {
		if e.GetStatus() == trustv1.Status_STATUS_PENDING {
			pending++
		}
		var updated template.HTML
		if e.GetUpdatedAt() != nil {
			at := e.GetUpdatedAt().AsTime().UTC()
			updated = template.HTML(`<time datetime="` + at.Format(time.RFC3339) + `">` + at.Format(DateFormat) + `</time>`) //nolint:gosec // both parts are formatted times
		}
		rows = append(rows, components.Row{
			{Text: e.GetDisplayName()},
			{HTML: template.HTML(`<code>` + template.HTMLEscapeString(identifierText(e.GetIdentifier())) + `</code>`)}, //nolint:gosec // the value is escaped
			{Text: methodText(e.GetIdentifier())},
			{Text: roleLabel(e.GetRole())},
			{HTML: b.add("badge", components.Badge{Status: statusBadge(e.GetStatus()), Text: statusText(e.GetStatus())})},
			{HTML: updated},
			{HTML: p.trustActions(b, e, csrf)},
		})
	}
	caption := msg.T("admin.trust.caption.label", strconv.Itoa(len(rows)))
	if pending > 0 {
		caption += ", " + msg.T("admin.trust.pending_count.label", strconv.Itoa(pending))
	}
	return b.add("table", components.Table{
		ID: "entries", Caption: caption,
		Columns: []string{
			msg.T("admin.trust.column.entity.label"), msg.T("admin.trust.column.id.label"),
			msg.T("admin.trust.column.method.label"), msg.T("admin.trust.column.role.label"),
			msg.T("admin.trust.column.status.label"), msg.T("admin.trust.column.updated.label"),
			msg.T("admin.trust.column.actions.label"),
		},
		Rows: rows, Empty: msg.T("admin.trust.empty"),
	})
}

// trustActions are the row buttons: approve and reject for a pending
// entry, remove for every other entry. Each is a POST form with the
// synchronizer token that names the entry by kind and value.
func (p *Portal) trustActions(b *blocks, e *trustv1.TrustEntry, csrf string) template.HTML {
	at := p.opts.Prefix
	target := identifierInputs(e.GetIdentifier())
	if e.GetStatus() != trustv1.Status_STATUS_PENDING {
		return components.Join(
			template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
			form(at+"/trust/delete", csrf, target,
				b.add("button", components.Button{Text: msg.T("admin.trust.remove.label"), Type: "submit", Variant: "danger"})),
			template.HTML(`</div>`),
		)
	}
	return components.Join(
		template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
		form(at+"/trust/approve", csrf, target,
			b.add("button", components.Button{Text: msg.T("admin.trust.approve.label"), Type: "submit", Variant: "primary"})),
		form(at+"/trust/reject", csrf, target,
			b.add("button", components.Button{Text: msg.T("admin.trust.reject.label"), Type: "submit", Variant: "danger"})),
		template.HTML(`</div>`),
	)
}

// identifierInputs are the hidden fields that name one entry.
func identifierInputs(id *trustv1.TrustEntry_Identifier) template.HTML {
	kind := kindDID
	if id.GetDid() == "" {
		kind = kindX509
	}
	return template.HTML(`<input type="hidden" name="kind" value="` + kind + `">` + //nolint:gosec // the kind is a constant and the value is escaped
		`<input type="hidden" name="identifier" value="` + template.HTMLEscapeString(identifierText(id)) + `">`)
}

// trustForm is the add form: the identifier type beside the identifier,
// so a DID and an X.509 subject sit in one form (ADR-011 decision 6).
func (p *Portal) trustForm(b *blocks, csrf string) template.HTML {
	fields := components.Join(
		b.add("choice", components.Choice{ID: "kind", Legend: msg.T("admin.trust.kind.label"), Options: []components.ChoiceOption{
			{Value: kindDID, Title: msg.T("admin.trust.kind.did.label"), Text: msg.T("admin.trust.kind.did.text"), Checked: true},
			{Value: kindX509, Title: msg.T("admin.trust.kind.x509.label"), Text: msg.T("admin.trust.kind.x509.text")},
		}}),
		b.add("field", components.Field{ID: "identifier", Label: msg.T("admin.trust.identifier.label"), Required: true,
			Hint: msg.T("admin.trust.identifier.hint")}),
		b.add("field", components.Field{ID: "display_name", Label: msg.T("admin.trust.display_name.label"), Required: true}),
		b.add("field", components.Field{ID: "role", Label: msg.T("admin.trust.role.label"), Type: "select", Options: []components.Option{
			{Value: "issuer", Text: msg.T("role.issuer.label"), Selected: true},
			{Value: "verifier", Text: msg.T("role.verifier.label")},
			{Value: "holder", Text: msg.T("role.holder.label")},
		}}),
		b.add("field", components.Field{ID: "status", Label: msg.T("admin.trust.status.label"), Type: "select", Options: []components.Option{
			{Value: "active", Text: statusText(trustv1.Status_STATUS_ACTIVE), Selected: true},
			{Value: "pending", Text: statusText(trustv1.Status_STATUS_PENDING)},
			{Value: "suspended", Text: statusText(trustv1.Status_STATUS_SUSPENDED)},
			{Value: "revoked", Text: statusText(trustv1.Status_STATUS_REVOKED)},
		}}),
		b.add("field", components.Field{ID: "service_endpoint", Label: msg.T("admin.trust.endpoint.label"), Type: "url"}),
		b.add("button", components.Button{Text: msg.T("admin.trust.save.label"), Type: "submit", Variant: "primary"}),
	)
	return b.add("card", components.Card{
		ID: "add-entry", Title: msg.T("admin.trust.new.label"), Text: msg.T("admin.trust.new.text"),
		Body: form(p.opts.Prefix+"/trust", csrf, fields),
	})
}

// addTrust creates or replaces one trust entry.
func (p *Portal) addTrust(w http.ResponseWriter, r *http.Request, s session) error {
	id, err := identifierFrom(r.PostFormValue("kind"), r.PostFormValue("identifier"))
	if err != nil {
		return err
	}
	entry := &trustv1.TrustEntry{
		Identifier:      id,
		DisplayName:     strings.TrimSpace(r.PostFormValue("display_name")),
		Role:            service.RoleValue(r.PostFormValue("role")),
		Status:          statusValue(r.PostFormValue("status")),
		ServiceEndpoint: strings.TrimSpace(r.PostFormValue("service_endpoint")),
	}
	if _, err := p.opts.Client.UpsertTrustEntry(r.Context(), call(s, &adminv1.UpsertTrustEntryRequest{Entry: entry})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-saved")
	return nil
}

// deleteTrust removes one trust entry.
func (p *Portal) deleteTrust(w http.ResponseWriter, r *http.Request, s session) error {
	id, err := identifierFrom(r.PostFormValue("kind"), r.PostFormValue("identifier"))
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.DeleteTrustEntry(r.Context(), call(s, &adminv1.DeleteTrustEntryRequest{Identifier: id})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-deleted")
	return nil
}

// approveTrust sets one pending entry active. The admin service writes
// the audit record.
func (p *Portal) approveTrust(w http.ResponseWriter, r *http.Request, s session) error {
	id, err := identifierFrom(r.PostFormValue("kind"), r.PostFormValue("identifier"))
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.ApproveTrustEntry(r.Context(), call(s, &adminv1.ApproveTrustEntryRequest{Identifier: id})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-approved")
	return nil
}

// rejectTrust removes one pending entry. The admin service writes the
// audit record.
func (p *Portal) rejectTrust(w http.ResponseWriter, r *http.Request, s session) error {
	id, err := identifierFrom(r.PostFormValue("kind"), r.PostFormValue("identifier"))
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.RejectTrustEntry(r.Context(), call(s, &adminv1.RejectTrustEntryRequest{Identifier: id})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-rejected")
	return nil
}

// identifierFrom returns the trust identifier of a form. The kind x509
// names a subject and the kind did names a DID. A form without a kind
// reads a value that starts with did: as a DID, the way the older form
// and the CLI scripts post it.
func identifierFrom(kind, value string) (*trustv1.TrustEntry_Identifier, error) {
	value = strings.TrimSpace(value)
	switch kind {
	case kindX509:
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: value}}, nil
	case kindDID:
		if !strings.HasPrefix(value, "did:") {
			return nil, connect.NewError(connect.CodeInvalidArgument, errNotADID)
		}
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: value}}, nil
	}
	if strings.HasPrefix(value, "did:") {
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: value}}, nil
	}
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: value}}, nil
}

// identifierText returns the reader facing identifier of an entry.
func identifierText(id *trustv1.TrustEntry_Identifier) string {
	if id.GetDid() != "" {
		return id.GetDid()
	}
	return id.GetX509Subject()
}

// methodText names how the identifier resolves: the DID method, such
// as did:web, or X.509 for a certificate subject.
func methodText(id *trustv1.TrustEntry_Identifier) string {
	d := id.GetDid()
	if d == "" {
		return msg.T("admin.trust.x509.label")
	}
	parts := strings.SplitN(d, ":", 3)
	if len(parts) < 3 {
		return d
	}
	return parts[0] + ":" + parts[1]
}

// roleLabel returns the label of an entity role.
func roleLabel(r commonv1.Role) string {
	if name := service.RoleName(r); name != "" {
		return msg.T("role." + name + ".label")
	}
	return ""
}

// statusValue returns the trust status of a form or query value.
func statusValue(value string) trustv1.Status {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active":
		return trustv1.Status_STATUS_ACTIVE
	case "suspended":
		return trustv1.Status_STATUS_SUSPENDED
	case "revoked":
		return trustv1.Status_STATUS_REVOKED
	case "pending":
		return trustv1.Status_STATUS_PENDING
	}
	return trustv1.Status_STATUS_UNSPECIFIED
}

// statusText returns the reader facing words of a trust status.
func statusText(s trustv1.Status) string {
	switch s {
	case trustv1.Status_STATUS_ACTIVE:
		return msg.T("admin.trust.status.active.label")
	case trustv1.Status_STATUS_PENDING:
		return msg.T("admin.trust.status.pending.label")
	case trustv1.Status_STATUS_SUSPENDED:
		return msg.T("admin.trust.status.suspended.label")
	case trustv1.Status_STATUS_REVOKED:
		return msg.T("admin.trust.status.revoked.label")
	}
	return msg.T("admin.trust.status.unknown.label")
}

// statusBadge returns the badge status of a trust status.
func statusBadge(s trustv1.Status) string {
	switch s {
	case trustv1.Status_STATUS_ACTIVE:
		return "ok"
	case trustv1.Status_STATUS_SUSPENDED, trustv1.Status_STATUS_PENDING:
		return "warn"
	case trustv1.Status_STATUS_REVOKED:
		return "bad"
	}
	return "info"
}
