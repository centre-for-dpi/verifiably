// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The status actions of a record. Each needs a reason (ADR-017
// decision 3).
const (
	actSuspend   = "suspend"
	actRevoke    = "revoke"
	actReinstate = "reinstate"
)

// dialogID is the id of the reason dialog.
const dialogID = "status-dialog"

// notices maps the notice of a redirect to its toast.
var notices = map[string]string{
	"suspended":  "issuer.issued.notice.suspended",
	"revoked":    "issuer.issued.notice.revoked",
	"reinstated": "issuer.issued.notice.reinstated",
}

// view is one render of the detail page: the dialog to open, its reason
// and error, and the toast of the last change.
type view struct {
	action    string
	reason    string
	reasonErr string
	toasts    []components.Toast
	status    int
	// ledger is true for a record that came from the stack ledger.
	ledger bool
}

// detail draws one record. ?action= opens the reason dialog of an
// action, and ?notice= shows the result of the last change.
func (p *Pages) detail(pg page) error {
	v := view{action: pg.r.URL.Query().Get("action")}
	if key, ok := notices[pg.r.URL.Query().Get("notice")]; ok {
		v.toasts = []components.Toast{{Level: "ok", Text: msg.T(key)}}
	}
	return p.renderDetail(pg, pg.r.PathValue("id"), v)
}

// change runs one status action with its reason and returns to the
// record. An empty reason opens the dialog again with the error on its
// field. A refusal of the service shows on the record.
func (p *Pages) change(pg page) error {
	id, action := pg.r.PathValue("id"), pg.r.PathValue("action")
	if action != actSuspend && action != actRevoke && action != actReinstate {
		return connect.NewError(connect.CodeNotFound, errNoAction)
	}
	ctx := pg.ctx()
	if !canAct(ctx) {
		return errForbidden
	}
	reason := strings.TrimSpace(pg.r.PostFormValue("reason"))
	if reason == "" {
		return p.renderDetail(pg, id, view{action: action, reasonErr: msg.T("issuer.issued.reason.error"), status: http.StatusBadRequest})
	}
	var err error
	switch action {
	case actSuspend:
		_, err = p.opts.Records.Revoke(ctx, staffshell.AsActor(ctx, &issuedv1.RevokeRequest{Id: id, Status: issuedv1.Status_STATUS_SUSPENDED, Reason: reason}))
	case actRevoke:
		_, err = p.opts.Records.Revoke(ctx, staffshell.AsActor(ctx, &issuedv1.RevokeRequest{Id: id, Status: issuedv1.Status_STATUS_REVOKED, Reason: reason}))
	default:
		_, err = p.opts.Records.Reinstate(ctx, staffshell.AsActor(ctx, &issuedv1.ReinstateRequest{Id: id, Reason: reason}))
	}
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		return err
	case err != nil:
		return p.renderDetail(pg, id, view{
			toasts: []components.Toast{{Level: "bad", Text: failure(err)}}, status: statusOf(err),
		})
	}
	notice := map[string]string{actSuspend: "suspended", actRevoke: "revoked", actReinstate: "reinstated"}[action]
	http.Redirect(pg.w, pg.r, recordPath(id, url.Values{"notice": {notice}}), http.StatusSeeOther)
	return nil
}

// failure is the sentence of a status change the service refused.
func failure(err error) string {
	switch connect.CodeOf(err) {
	case connect.CodeFailedPrecondition, connect.CodeInvalidArgument:
		return msg.T("issuer.issued.failed.precondition")
	case connect.CodeUnavailable:
		return msg.T("issuer.issued.failed.unavailable")
	}
	return msg.T("issuer.issued.failed.other")
}

// errNoAction reports a path that names no status action.
var errNoAction = errors.New("no such status action")

// renderDetail draws the page of one record.
func (p *Pages) renderDetail(pg page, id string, v view) error {
	ctx := pg.ctx()
	res, err := p.opts.Records.Get(ctx, staffshell.AsActor(ctx, &issuedv1.GetRequest{Id: id}))
	if err != nil {
		return err
	}
	r := res.Msg.GetRecord()
	history, err := p.opts.Records.History(ctx, id)
	if err != nil {
		return err
	}
	b := p.blocks()
	var actions []string
	if r.GetStatusBinding() != nil {
		actions = allowed(r.GetStatus())
	}
	act := canAct(ctx)
	var buttons []template.HTML
	if act {
		for _, a := range actions {
			buttons = append(buttons, b.add("button", components.Button{
				Text: msg.T("issuer.issued.action." + a + ".label"), Href: recordPath(id, url.Values{"action": {a}}), Variant: variant(a),
			}))
		}
	}
	var parts []template.HTML
	if !act {
		parts = append(parts, b.add("card", components.Card{ID: "read-only", Title: msg.T("issuer.issued.role.label"), Text: msg.T("issuer.issued.role.text")}))
	}
	if act && contains(actions, v.action) {
		v.ledger = r.GetDpgCredentialId() != ""
		parts = append(parts, p.dialog(ctx, b, pg, id, v))
	}
	status := p.statusBadge(ctx, b, r, p.has(ctx, backendv1.Feature_FEATURE_ISSUANCE_STATUS))
	parts = append(parts, p.fields(b, r), p.recordBlock(b, r, status), p.history(b, r, history))
	if b.err != nil {
		return b.err
	}
	if v.status != 0 {
		pg.w = &statusWriter{ResponseWriter: pg.w, status: v.status}
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.issued.detail.label", shortID(id)),
		Lead: msg.T("issuer.issued.detail.lead", r.GetSchemaId(), strconv.Itoa(int(r.GetSchemaVersion())),
			r.GetIssuedAt().AsTime().UTC().Format(dateText)),
		Actions: components.Join(buttons...), Content: components.Join(parts...), Toasts: v.toasts,
	})
}

// allowed returns the actions of a status, in the order of the page.
func allowed(s issuedv1.Status) []string {
	switch s {
	case issuedv1.Status_STATUS_ACTIVE:
		return []string{actSuspend, actRevoke}
	case issuedv1.Status_STATUS_SUSPENDED:
		return []string{actReinstate, actRevoke}
	}
	return nil
}

// variant is the button look of an action: a revoke is the danger.
func variant(action string) string {
	switch action {
	case actRevoke:
		return "danger"
	case actReinstate:
		return "primary"
	}
	return "secondary"
}

// contains reports whether list holds v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// dialog is the open reason dialog of one action: what the action
// does, and the POST form with the reason and the synchronizer token.
func (p *Pages) dialog(ctx context.Context, b *blocks, pg page, id string, v view) template.HTML {
	text := msg.T("issuer.issued.dialog." + v.action + ".text")
	if v.action == actRevoke && v.ledger && p.has(ctx, backendv1.Feature_FEATURE_REVOCATION) {
		text = msg.T("issuer.issued.dialog.revoke.stack", p.stackName(ctx))
	}
	action := Prefix + url.PathEscape(id) + "/" + v.action
	form := components.Join(
		template.HTML(`<form method="post" action="`+template.HTMLEscapeString(action)+`">`), //nolint:gosec // the action is escaped
		staffsession.HiddenField(pg.r.Context()),
		b.add("field", components.Field{
			ID: "reason", Label: msg.T("issuer.issued.reason.label"), Type: "textarea", Required: true,
			Value: v.reason, Hint: msg.T("issuer.issued.reason.hint"), Error: v.reasonErr,
		}),
		template.HTML(`<div class="dialog-actions">`),
		b.add("button", components.Button{Text: msg.T("issuer.issued.confirm." + v.action + ".label"), Type: "submit", Variant: variant(v.action)}),
		template.HTML(`</div></form>`),
	)
	return b.add("dialog", components.Dialog{
		ID: dialogID, Title: msg.T("issuer.issued.dialog." + v.action + ".label"), Text: text,
		Body: form, CloseText: msg.T("common.cancel.label"), Open: true,
	})
}

// fields is the block of the stored fields (ADR-017 decision 2).
func (p *Pages) fields(b *blocks, r *issuedv1.IssuedRecord) template.HTML {
	claims := r.GetSearchableClaims()
	rows := make([]components.Row, 0, len(claims))
	for _, name := range sortedKeys(claims) {
		rows = append(rows, components.Row{{HTML: code(name)}, {Text: claims[name]}})
	}
	return b.add("block", components.Block{
		ID: "fields", Title: msg.T("issuer.issued.fields.label"), Lead: msg.T("issuer.issued.fields.lead"),
		Body: b.add("table", components.Table{
			ID: "stored-fields", Caption: msg.T("issuer.issued.fields.caption.label"),
			Columns: []string{msg.T("issuer.issued.column.field.label"), msg.T("issuer.issued.column.value.label")},
			Rows:    rows, Empty: msg.T("issuer.issued.fields.none"),
		}),
	})
}

// recordBlock is the block of the log entry: the status, ids, format,
// adapter, status list entry, validity, last reason, hash, retention.
func (p *Pages) recordBlock(b *blocks, r *issuedv1.IssuedRecord, status template.HTML) template.HTML {
	entry := msg.T("issuer.issued.record.no_status_list")
	if sb := r.GetStatusBinding(); sb != nil {
		kind := strings.ToLower(strings.TrimPrefix(sb.GetKind().String(), "KIND_"))
		entry = msg.T("issuer.issued.record.status_list.value.label", kind, sb.GetListId(), strconv.FormatInt(sb.GetIndex(), 10))
	}
	rows := []components.Row{
		{{Text: msg.T("issuer.issued.column.status.label")}, {HTML: status}},
		{{Text: msg.T("issuer.issued.record.id.label")}, {HTML: code(r.GetId())}},
		{{Text: msg.T("issuer.issued.record.format.label")}, {Text: formatText(r)}},
		{{Text: msg.T("issuer.issued.record.adapter.label")}, {Text: r.GetDpg()}},
		{{Text: msg.T("issuer.issued.record.status_list.label")}, {Text: entry}},
	}
	optional := []struct {
		key   string
		value string
		code  bool
	}{
		{"issuer.issued.record.valid_until.label", day(r.GetValidity().GetValidUntil()), false},
		{"issuer.issued.record.reason.label", r.GetStatusReason(), false},
		{"issuer.issued.record.offer.label", r.GetOfferId(), true},
		{"issuer.issued.record.ledger.label", r.GetDpgCredentialId(), true},
		{"issuer.issued.record.hash.label", r.GetHash(), true},
		{"issuer.issued.record.retain.label", day(r.GetRetainUntil()), false},
	}
	for _, o := range optional {
		if o.value == "" {
			continue
		}
		cell := components.Cell{Text: o.value}
		if o.code {
			cell = components.Cell{HTML: code(o.value)}
		}
		rows = append(rows, components.Row{{Text: msg.T(o.key)}, cell})
	}
	return b.add("block", components.Block{
		ID: "record", Title: msg.T("issuer.issued.record.label"), Lead: msg.T("issuer.issued.record.lead"),
		Body: b.add("table", components.Table{
			ID: "record-fields", Caption: msg.T("issuer.issued.record.caption.label"),
			Columns: []string{msg.T("issuer.issued.column.field.label"), msg.T("issuer.issued.column.value.label")},
			Rows:    rows,
		}),
	})
}

// formatText names the wire format of a record.
func formatText(r *issuedv1.IssuedRecord) string {
	if name := service.FormatName(r.GetFormat()); name != "" {
		return name
	}
	return msg.T("common.unknown.label")
}

// day is the day of a time stamp, or "" for none.
func day(t *timestamppb.Timestamp) string {
	if t == nil || !t.IsValid() || t.AsTime().IsZero() {
		return ""
	}
	return t.AsTime().UTC().Format(dateText)
}

// history is the block of the life of the record: the issuance, then
// every event of the audit log of this service for the record.
func (p *Pages) history(b *blocks, r *issuedv1.IssuedRecord, events []auditlog.Record) template.HTML {
	rows := []components.Row{{
		{Text: r.GetIssuedAt().AsTime().UTC().Format(timeText)},
		{Text: msg.T("issuer.issued.event.issued.label")},
		{Text: msg.T("issuer.issued.actor.none.label")},
		{Text: msg.T("issuer.issued.event.issued.detail")},
		{HTML: b.add("badge", components.Badge{Status: "ok", Text: msg.T("issuer.issued.result.ok.label")})},
	}}
	for _, e := range events {
		actor := e.Actor
		if actor == "" {
			actor = msg.T("issuer.issued.actor.none.label")
		}
		result := components.Badge{Status: "ok", Text: msg.T("issuer.issued.result.ok.label")}
		if !e.OK {
			result = components.Badge{Status: "bad", Text: msg.T("issuer.issued.result.failed.label")}
		}
		rows = append(rows, components.Row{
			{Text: e.At.UTC().Format(timeText)},
			{Text: eventText(e.Action)},
			{HTML: code(actor)},
			{Text: e.Detail},
			{HTML: b.add("badge", result)},
		})
	}
	return b.add("block", components.Block{
		ID: "history", Title: msg.T("issuer.issued.history.label"), Lead: msg.T("issuer.issued.history.lead"),
		Body: b.add("table", components.Table{
			ID: "history-events", Caption: msg.T("issuer.issued.history.caption.label"),
			Columns: []string{
				msg.T("common.when.label"), msg.T("common.event.label"), msg.T("issuer.issued.column.actor.label"),
				msg.T("issuer.issued.column.detail.label"), msg.T("issuer.issued.column.result.label"),
			},
			Rows: rows,
		}),
	})
}

// eventText names the action of an audit event.
func eventText(action string) string {
	switch action {
	case service.ActionSuspend:
		return msg.T("issuer.issued.event.suspend.label")
	case service.ActionRevoke:
		return msg.T("issuer.issued.event.revoke.label")
	case service.ActionReinstate:
		return msg.T("issuer.issued.event.reinstate.label")
	}
	return action
}
