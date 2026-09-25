// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/auditfed"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// AuditPageSize is the number of events one audit page shows.
const AuditPageSize = 50

// AuditExportSize is the number of events one export holds at most.
const AuditExportSize = auditlog.MaxPageSize

// The time of an event shows as the day with the time to the second
// under it, so the column stays narrow.
const (
	auditDayFormat  = "2006-01-02"
	auditHourFormat = "15:04:05 UTC"
)

// dateFormat is the value of a date field.
const dateFormat = "2006-01-02"

// errNoAudit reports a portal without the audit federation.
var errNoAudit = connect.NewError(connect.CodeFailedPrecondition, errors.New("portal: the audit log is not wired"))

// errRetention reports a retention outside the allowed days.
var errRetention = connect.NewError(connect.CodeInvalidArgument, auditlog.ErrRetention)

// registerAudit adds the federated audit log (ADR-039 decision 2).
func (p *Portal) registerAudit(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/audit", p.guarded(p.auditLog))
	mux.HandleFunc("GET "+at+"/audit/export.csv", p.guarded(p.auditExport))
	mux.HandleFunc("POST "+at+"/audit/retention", p.posted(p.setRetention))
}

// auditQuery is the filter of the page as the browser sent it.
type auditQuery struct {
	values  url.Values
	filter  auditfed.Filter
	dateErr map[string]bool
}

// readAuditQuery reads the filters of a request. A date that does not
// parse filters nothing and marks its field.
func readAuditQuery(q url.Values) auditQuery {
	out := auditQuery{values: url.Values{}, dateErr: map[string]bool{}}
	for _, name := range []string{"from", "to", "actor", "action", "outcome", "source"} {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			out.values.Set(name, v)
		}
	}
	f := &out.filter
	f.Actor, f.Action = out.values.Get("actor"), out.values.Get("action")
	f.Outcome = auditlog.OutcomeOf(out.values.Get("outcome"))
	f.Service = out.values.Get("source")
	for _, name := range []string{"from", "to"} {
		v := out.values.Get(name)
		if v == "" {
			continue
		}
		day, err := time.Parse(dateFormat, v)
		if err != nil {
			out.dateErr[name] = true
			continue
		}
		if name == "from" {
			f.From = day
		} else {
			f.To = day.Add(24*time.Hour - time.Nanosecond)
		}
	}
	if before, err := time.Parse(time.RFC3339Nano, q.Get("before")); err == nil {
		f.Before = before
	}
	return out
}

// auditLog renders the events of this admin and of every live peer,
// newest first, with the filters, the export, and the retention.
func (p *Portal) auditLog(w http.ResponseWriter, r *http.Request, s session) error {
	if p.opts.Audit == nil {
		return errNoAudit
	}
	q := readAuditQuery(r.URL.Query())
	res := p.opts.Audit.Query(r.Context(), s.Token, q.filter, AuditPageSize)
	b := p.blocks()
	sources := map[string]auditfed.Source{}
	for _, src := range res.Sources {
		sources[src.Pair+"/"+src.Service] = src
	}
	rows := make([]components.Row, 0, len(res.Events))
	for _, e := range res.Events {
		rows = append(rows, components.Row{
			{HTML: timeCell(e.GetTime().AsTime())},
			{HTML: sourceCell(e, sources[e.GetPair()+"/"+e.GetSourceService()])},
			{Text: actorText(e.GetActor())},
			{HTML: actionCell(e)},
			{HTML: targetCell(e.GetTarget())},
			{HTML: b.add("badge", outcomeBadge(e.GetOutcome()))},
		})
	}
	table := b.add("table", components.Table{
		ID: "audit", Caption: msg.T("admin.audit.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.audit.column.time.label"), msg.T("admin.audit.column.source.label"),
			msg.T("admin.audit.column.actor.label"), msg.T("admin.audit.column.action.label"),
			msg.T("admin.audit.column.target.label"), msg.T("admin.audit.column.result.label"),
		},
		Rows: rows, Empty: msg.T("admin.audit.empty"),
	})
	var older template.HTML
	if res.More && len(res.Events) > 0 {
		next := cloneValues(q.values)
		next.Set("before", res.Events[len(res.Events)-1].GetTime().AsTime().UTC().Format(time.RFC3339Nano))
		older = b.add("button", components.Button{Text: msg.T("admin.audit.older.label"), Href: p.opts.Prefix + "/audit?" + next.Encode()})
	}
	lead := msg.T("admin.audit.sources", strconv.Itoa(res.Asked-len(res.Failed)), strconv.Itoa(res.Asked))
	content := components.Join(
		p.auditMissing(b, res.Failed),
		p.auditFilters(b, q),
		b.add("block", components.Block{ID: "events", Title: msg.T("admin.audit.events.label"), Lead: lead, Body: components.Join(table, older)}),
		p.retentionBlock(r.Context(), b, s),
	)
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       msg.T("admin.nav.audit.label"),
		Lead:        msg.T("admin.audit.lead"),
		Description: msg.T("admin.audit.lead"),
		Content:     content,
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// auditMissing names each store that did not answer, so the page shows
// the rest instead of failing.
func (p *Portal) auditMissing(b *blocks, failed []auditfed.Failure) template.HTML {
	if len(failed) == 0 {
		return ""
	}
	var items strings.Builder
	items.WriteString(`<ul>`)
	for _, f := range failed {
		items.WriteString(`<li>` + template.HTMLEscapeString(msg.T("admin.audit.missing.item", f.Source.Service, pairName(f.Source))+" "+failReason(f.Err)) + `</li>`)
	}
	items.WriteString(`</ul>`)
	return b.add("card", components.Card{
		ID: "missing", Title: msg.T("admin.audit.missing.label"), Text: msg.T("admin.audit.missing.text"),
		Body: components.Join(
			b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.audit.missing.count.label", strconv.Itoa(len(failed)))}),
			template.HTML(items.String()), //nolint:gosec // every item is escaped
		),
	})
}

// pairName returns the pair of a source, or the service for this admin
// when the snapshot names no pair.
func pairName(s auditfed.Source) string {
	if s.Pair == "" {
		return auditfed.LocalService
	}
	return s.Pair
}

// failReason returns the reader facing reason of a store that did not
// answer. It names the Connect code, never the text of the error.
func failReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), connect.CodeOf(err) == connect.CodeDeadlineExceeded:
		return msg.T("admin.audit.reason.timeout")
	case connect.CodeOf(err) == connect.CodeUnauthenticated, connect.CodeOf(err) == connect.CodePermissionDenied:
		return msg.T("admin.audit.reason.denied")
	default:
		return msg.T("admin.audit.reason.code", connect.CodeOf(err).String())
	}
}

// auditFilters is the filter form with the export action.
func (p *Portal) auditFilters(b *blocks, q auditQuery) template.HTML {
	v := q.values
	dateField := func(name, label string) template.HTML {
		f := components.Field{ID: name, Label: label, Type: "date", Value: v.Get(name)}
		if q.dateErr[name] {
			f.Error = msg.T("admin.audit.date.error")
		}
		return b.add("field", f)
	}
	outcomes := []components.Option{{Value: "", Text: msg.T("admin.audit.filter.any.label")}}
	for _, o := range []string{auditlog.OutcomeSuccess, auditlog.OutcomeFailure} {
		outcomes = append(outcomes, components.Option{Value: o, Text: msg.T("admin.audit.outcome." + o + ".label"), Selected: v.Get("outcome") == o})
	}
	sources := []components.Option{{Value: "", Text: msg.T("admin.audit.filter.any.label")}}
	for _, name := range auditfed.Services {
		sources = append(sources, components.Option{Value: name, Text: name, Selected: v.Get("source") == name})
	}
	export := p.opts.Prefix + "/audit/export.csv"
	if len(v) > 0 {
		export += "?" + v.Encode()
	}
	return b.add("block", components.Block{
		ID: "filters", Title: msg.T("admin.audit.filters.label"), Lead: msg.T("admin.audit.filters.lead"),
		Body: getForm(p.opts.Prefix+"/audit",
			dateField("from", msg.T("admin.audit.filter.from.label")),
			dateField("to", msg.T("admin.audit.filter.to.label")),
			b.add("field", components.Field{ID: "actor", Label: msg.T("admin.audit.filter.actor.label"), Value: v.Get("actor")}),
			b.add("field", components.Field{ID: "action", Label: msg.T("admin.audit.filter.action.label"), Value: v.Get("action"),
				Hint: msg.T("admin.audit.filter.action.hint")}),
			b.add("field", components.Field{ID: "outcome", Label: msg.T("admin.audit.filter.outcome.label"), Type: "select", Options: outcomes}),
			b.add("field", components.Field{ID: "source", Label: msg.T("admin.audit.filter.source.label"), Type: "select", Options: sources}),
			b.add("button", components.Button{Text: msg.T("admin.audit.filter.apply.label"), Type: "submit", Variant: "primary"}),
			b.add("button", components.Button{Text: msg.T("admin.audit.export.label"), Href: export}),
		),
	})
}

// retentionBlock shows the retention of this store and the form that
// sets it in every store.
func (p *Portal) retentionBlock(ctx context.Context, b *blocks, s session) template.HTML {
	current := msg.T("admin.audit.retention.forever")
	value := "0"
	if p.opts.Retention != nil {
		days, err := p.opts.Retention(ctx)
		switch {
		case err != nil:
			current = msg.T("admin.audit.retention.unknown")
		case days > 0:
			current, value = msg.T("admin.audit.retention.current", strconv.Itoa(days)), strconv.Itoa(days)
		}
	}
	return b.add("block", components.Block{
		ID: "retention", Title: msg.T("admin.audit.retention.label"), Lead: msg.T("admin.audit.retention.lead"), Meta: current,
		Body: form(p.opts.Prefix+"/audit/retention", s.CSRF,
			b.add("field", components.Field{
				ID: "days", Label: msg.T("admin.audit.retention.days.label"), Type: "number", Value: value, Required: true,
				Hint:  msg.T("admin.audit.retention.days.hint"),
				Attrs: map[string]string{"min": "0", "max": strconv.Itoa(auditlog.MaxRetentionDays), "step": "1", "inputmode": "numeric"},
			}),
			b.add("button", components.Button{Text: msg.T("admin.audit.retention.save.label"), Type: "submit"}),
		),
	})
}

// auditExport writes the events that match the filters as a CSV file.
func (p *Portal) auditExport(w http.ResponseWriter, r *http.Request, s session) error {
	if p.opts.Audit == nil {
		return errNoAudit
	}
	q := readAuditQuery(r.URL.Query())
	res := p.opts.Audit.Query(r.Context(), s.Token, q.filter, AuditExportSize)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="vca-audit.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	// The headers are gone once the body starts, so a write fault only
	// cuts the file short and has no remedy.
	anyval.Discard(auditfed.WriteCSV(w, res.Events))
	return nil
}

// setRetention sets the retention days in every store.
func (p *Portal) setRetention(w http.ResponseWriter, r *http.Request, s session) error {
	if p.opts.Audit == nil {
		return errNoAudit
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("days")))
	if err != nil || days < 0 || days > auditlog.MaxRetentionDays {
		return errRetention
	}
	res := p.opts.Audit.SetRetention(r.Context(), s.Token, int32(days)) //nolint:gosec // the check above caps days at 3650
	code := "retention-saved"
	if len(res.Failed) > 0 {
		code = "retention-partial"
	}
	p.redirect(w, r, "/audit", code)
	return nil
}

// sourceCell names the service and, under it, the pair and the stack.
func sourceCell(e *auditv1.AuditEvent, src auditfed.Source) template.HTML {
	lines := template.HTMLEscapeString(e.GetPair())
	if src.Stack != "" {
		lines += "<br>" + template.HTMLEscapeString(src.Stack)
	}
	return components.Join(code(e.GetSourceService()), template.HTML(`<p class="hint">`+lines+`</p>`)) //nolint:gosec // both parts are escaped
}

// timeCell shows the day of an event with the time under it.
func timeCell(t time.Time) template.HTML {
	t = t.UTC()
	return components.Join(template.HTML(template.HTMLEscapeString(t.Format(auditDayFormat))), hint(t.Format(auditHourFormat))) //nolint:gosec // the text is escaped
}

// actionCell shows the action with the detail of the event under it.
// The detail is a short reason or note and never a claim value.
func actionCell(e *auditv1.AuditEvent) template.HTML {
	action := template.HTML(template.HTMLEscapeString(e.GetAction())) //nolint:gosec // the text is escaped
	if e.GetDetail() == "" {
		return action
	}
	return components.Join(action, hint(e.GetDetail()))
}

// targetCell shows a target in the monospace face.
func targetCell(v string) template.HTML {
	if v == "" {
		return ""
	}
	return shortCode(v)
}

// actorText names the actor, or says that the caller named none.
func actorText(v string) string {
	if v == "" {
		return msg.T("admin.audit.actor.none.label")
	}
	return v
}

// outcomeBadge is the result badge of an event.
func outcomeBadge(o auditv1.Outcome) components.Badge {
	if o == auditv1.Outcome_OUTCOME_SUCCESS {
		return components.Badge{Status: "ok", Text: msg.T("admin.audit.outcome.success.label")}
	}
	return components.Badge{Status: "bad", Text: msg.T("admin.audit.outcome.failure.label")}
}

// cloneValues copies query values.
func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
