// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// SyncPath is the page that reads the ledger of the stack. It exists
// only while the adapter lists FEATURE_ISSUED_LEDGER.
const SyncPath = "/issued/sync"

// syncForm is the sync form as the browser sent it, with its errors.
type syncForm struct {
	query  service.SyncQuery
	errors map[string]string
}

// readSync reads the three fields and marks each empty one.
func readSync(r *http.Request) syncForm {
	f := syncForm{errors: map[string]string{}, query: service.SyncQuery{
		CredentialType: strings.TrimSpace(r.PostFormValue("type")),
		Attribute:      strings.TrimSpace(r.PostFormValue("attribute")),
		Value:          strings.TrimSpace(r.PostFormValue("value")),
	}}
	for name, v := range map[string]string{"type": f.query.CredentialType, "attribute": f.query.Attribute, "value": f.query.Value} {
		if v == "" {
			f.errors[name] = msg.T("issuer.issued.sync.required")
		}
	}
	return f
}

// syncButton is the list action that opens the sync page, when the
// adapter keeps a ledger.
func (p *Pages) syncButton(pg page, b *blocks) template.HTML {
	if !p.has(pg.r.Context(), backendv1.Feature_FEATURE_ISSUED_LEDGER) {
		return ""
	}
	return b.add("button", components.Button{Text: msg.T("issuer.issued.sync.action.label"), Href: SyncPath})
}

// syncPage draws the sync form. The adapter must list the ledger.
func (p *Pages) syncPage(pg page) error {
	if !p.has(pg.r.Context(), backendv1.Feature_FEATURE_ISSUED_LEDGER) {
		return connect.NewError(connect.CodeNotFound, errNoLedger)
	}
	return p.renderSync(pg, syncForm{errors: map[string]string{}}, nil, nil, http.StatusOK)
}

// sync runs one sync and shows what it did with each entry. Only a
// staff member who changes statuses may add records to the log.
func (p *Pages) sync(pg page) error {
	ctx := pg.ctx()
	if !p.has(ctx, backendv1.Feature_FEATURE_ISSUED_LEDGER) {
		return connect.NewError(connect.CodeNotFound, errNoLedger)
	}
	if !canAct(ctx) {
		return errForbidden
	}
	form := readSync(pg.r)
	if len(form.errors) > 0 {
		return p.renderSync(pg, form, nil, nil, http.StatusBadRequest)
	}
	rows, err := p.opts.Records.Sync(ctx, form.query)
	if err != nil {
		text := msg.T("issuer.issued.sync.failed")
		if connect.CodeOf(err) == connect.CodeInvalidArgument {
			text = msg.T("issuer.issued.sync.refused")
		}
		return p.renderSync(pg, form, nil, []components.Toast{{Level: "bad", Text: text}}, statusOf(err))
	}
	added := 0
	for _, r := range rows {
		if r.Added {
			added++
		}
	}
	toasts := []components.Toast{{Level: "ok", Text: msg.T("issuer.issued.sync.notice", strconv.Itoa(added), strconv.Itoa(len(rows)))}}
	return p.renderSync(pg, form, rows, toasts, http.StatusOK)
}

// errNoLedger reports a sync on a stack whose adapter keeps no ledger.
var errNoLedger = errors.New("the adapter of the pair keeps no ledger")

// renderSync draws the sync page: the form, then the result of a sync.
func (p *Pages) renderSync(pg page, form syncForm, rows []service.SyncRow, toasts []components.Toast, status int) error {
	ctx := pg.r.Context()
	stack := p.stackName(ctx)
	b := p.blocks()
	q := form.query
	body := components.Join(
		template.HTML(`<form method="post" action="`+SyncPath+`">`), //nolint:gosec // a constant path
		staffsession.HiddenField(ctx),
		template.HTML(`<div class="field-row">`),
		b.add("field", components.Field{ID: "type", Label: msg.T("issuer.issued.sync.type.label"), Value: q.CredentialType,
			Hint: msg.T("issuer.issued.sync.type.hint"), Error: form.errors["type"], Required: true}),
		b.add("field", components.Field{ID: "attribute", Label: msg.T("issuer.issued.sync.attribute.label"), Value: q.Attribute,
			Hint: msg.T("issuer.issued.sync.attribute.hint"), Error: form.errors["attribute"], Required: true}),
		b.add("field", components.Field{ID: "value", Label: msg.T("issuer.issued.sync.value.label"), Value: q.Value,
			Hint: msg.T("issuer.issued.sync.value.hint"), Error: form.errors["value"], Required: true, Autocomplete: "off"}),
		template.HTML(`</div><div class="form-actions">`),
		b.add("button", components.Button{Text: msg.T("issuer.issued.sync.submit.label", stack), Type: "submit", Variant: "primary"}),
		template.HTML(`</div></form>`),
	)
	parts := []template.HTML{b.add("block", components.Block{
		ID: "sync-form", Title: msg.T("issuer.issued.sync.form.label"), Lead: msg.T("issuer.issued.sync.form.lead"), Body: body,
	})}
	if rows != nil || (status == http.StatusOK && len(toasts) > 0) {
		parts = append(parts, p.syncResult(b, stack, rows))
	}
	if b.err != nil {
		return b.err
	}
	if status != http.StatusOK {
		pg.w = &statusWriter{ResponseWriter: pg.w, status: status}
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.issued.sync.page.label"), Lead: msg.T("issuer.issued.sync.lead", stack),
		Actions: b.add("button", components.Button{Text: msg.T("issuer.nav.issued.label"), Href: Prefix}),
		Content: components.Join(parts...), Toasts: toasts,
	})
}

// syncResult is the table of the ledger entries of one sync.
func (p *Pages) syncResult(b *blocks, stack string, rows []service.SyncRow) template.HTML {
	out := make([]components.Row, 0, len(rows))
	for _, r := range rows {
		e := r.Entry
		result := components.Badge{Status: "info", Text: msg.T("issuer.issued.sync.kept.label")}
		if r.Added {
			result = components.Badge{Status: "ok", Text: msg.T("issuer.issued.sync.added.label")}
		}
		out = append(out, components.Row{
			{HTML: code(e.GetCredentialId())},
			{Text: e.GetIssuedAt().AsTime().UTC().Format(dateText)},
			{HTML: link(recordPath(r.RecordID, nil), shortID(r.RecordID))},
			{HTML: b.add("badge", result)},
		})
	}
	return b.add("block", components.Block{
		ID: "sync-result", Title: msg.T("issuer.issued.sync.result.label"), Lead: msg.T("issuer.issued.sync.result.lead"),
		Body: b.add("table", components.Table{
			ID: "sync-entries", Caption: msg.T("issuer.issued.sync.caption.label", strconv.Itoa(len(rows)), stack),
			Columns: []string{
				msg.T("issuer.issued.sync.column.ledger.label"), msg.T("issuer.issued.column.issued.label"),
				msg.T("issuer.issued.sync.column.record.label"), msg.T("issuer.issued.sync.column.result.label"),
			},
			Rows: out, Empty: msg.T("issuer.issued.sync.none"),
		}),
	})
}
