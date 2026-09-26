// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"html/template"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The layouts of a day: the value of a date field, and the text of a
// table cell.
const (
	dateField = "2006-01-02"
	dateText  = "2 Jan 2006"
	timeText  = "2 Jan 2006 15:04 UTC"
)

// statuses are the values of the status filter, in the order of the
// list, with the status each one selects.
var statuses = []struct {
	value  string
	status issuedv1.Status
}{
	{"active", issuedv1.Status_STATUS_ACTIVE},
	{"suspended", issuedv1.Status_STATUS_SUSPENDED},
	{"revoked", issuedv1.Status_STATUS_REVOKED},
	{"expired", issuedv1.Status_STATUS_EXPIRED},
}

// listQuery is the search and the filters of the list as the browser
// sent them.
type listQuery struct {
	// values holds the filters the page keeps in its links, without the
	// page token.
	values url.Values
	text   string
	filter *issuedv1.Filter
	page   string
	// badDate names the date fields that did not parse.
	badDate map[string]bool
}

// readQuery reads the search and the filters of a request. A date that
// does not parse filters nothing and marks its field.
func readQuery(q url.Values) listQuery {
	out := listQuery{values: url.Values{}, filter: &issuedv1.Filter{}, badDate: map[string]bool{}}
	for _, name := range []string{"q", "schema", "status", "from", "to"} {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			out.values.Set(name, v)
		}
	}
	out.text = out.values.Get("q")
	out.page = strings.TrimSpace(q.Get("page"))
	out.filter.SchemaId = out.values.Get("schema")
	for _, s := range statuses {
		if s.value == out.values.Get("status") {
			out.filter.Status = s.status
		}
	}
	for _, name := range []string{"from", "to"} {
		v := out.values.Get(name)
		if v == "" {
			continue
		}
		day, err := time.Parse(dateField, v)
		if err != nil {
			out.badDate[name] = true
			continue
		}
		if name == "from" {
			out.filter.From = timestamppb.New(day)
		} else {
			out.filter.To = timestamppb.New(day.Add(24*time.Hour - time.Nanosecond))
		}
	}
	return out
}

// filtered reports whether the search or a filter narrows the list.
func (q listQuery) filtered() bool { return len(q.values) > 0 }

// list draws the search, the filters, and one page of the records,
// newest first.
func (p *Pages) list(pg page) error {
	ctx := pg.ctx()
	q := readQuery(pg.r.URL.Query())
	res, err := p.opts.Records.Search(ctx, staffshell.AsActor(ctx, &issuedv1.SearchRequest{
		Query: q.text, Filter: q.filter, Page: &commonv1.Pagination{PageSize: int32(p.opts.PageSize), PageToken: q.page}, //nolint:gosec // the page size is a small setting
	}))
	if err != nil {
		return err
	}
	b := p.blocks()
	records := res.Msg.GetRecords()
	var content template.HTML
	if len(records) == 0 && !q.filtered() && q.page == "" {
		content = b.add("empty", components.Empty{
			Title: msg.T("issuer.issued.empty.title"), Text: msg.T("issuer.issued.empty.text"),
			Action: components.Button{Text: msg.T("issuer.issued.empty.action.label"), Href: IssuePath, Variant: "primary"},
		})
	} else {
		content = components.Join(p.filters(b, q), p.table(ctx, b, q, records, res.Msg.GetPage()))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.issued.label"), Lead: msg.T("issuer.issued.lead"),
		Actions: components.Join(p.syncButton(pg, b), p.exportButtons(b, q)), Content: content,
	})
}

// exportButtons returns the two export links with the search and the
// filters of the page.
func (p *Pages) exportButtons(b *blocks, q listQuery) template.HTML {
	query := ""
	if len(q.values) > 0 {
		query = "?" + q.values.Encode()
	}
	return components.Join(
		b.add("button", components.Button{Text: msg.T("issuer.issued.export.csv.label"), Href: ExportCSVPath + query}),
		b.add("button", components.Button{Text: msg.T("issuer.issued.export.json.label"), Href: ExportJSONPath + query}),
	)
}

// filters is the GET form of the search and the filters.
func (p *Pages) filters(b *blocks, q listQuery) template.HTML {
	schemas := []components.Option{{Value: "", Text: msg.T("issuer.issued.schema.any.label")}}
	for _, id := range p.opts.Records.SchemaIDs() {
		schemas = append(schemas, components.Option{Value: id, Text: vc.TypeTitle(id), Selected: id == q.values.Get("schema")})
	}
	states := []components.Option{{Value: "", Text: msg.T("issuer.issued.status.any.label")}}
	for _, s := range statuses {
		states = append(states, components.Option{Value: s.value, Text: msg.T("issuer.issued.status." + s.value + ".label"), Selected: s.value == q.values.Get("status")})
	}
	dateErr := func(name string) string {
		if q.badDate[name] {
			return msg.T("issuer.issued.date.error")
		}
		return ""
	}
	// Two rows of fields: the search with the schema and the status,
	// then the range of days. The button closes the form.
	open := template.HTML(`<form method="get" action="` + Prefix + `"><div class="field-row">`) //nolint:gosec // a constant path
	return components.Join(open,
		b.add("field", components.Field{ID: "q", Label: msg.T("issuer.issued.search.label"), Type: "search", Value: q.text, Hint: msg.T("issuer.issued.search.hint")}),
		b.add("field", components.Field{ID: "schema", Label: msg.T("issuer.issued.schema.label"), Type: "select", Options: schemas}),
		b.add("field", components.Field{ID: "status", Label: msg.T("issuer.issued.status.label"), Type: "select", Options: states}),
		template.HTML(`</div><div class="field-row">`),
		b.add("field", components.Field{ID: "from", Label: msg.T("issuer.issued.from.label"), Type: "date", Value: q.values.Get("from"), Error: dateErr("from")}),
		b.add("field", components.Field{ID: "to", Label: msg.T("issuer.issued.to.label"), Type: "date", Value: q.values.Get("to"), Error: dateErr("to")}),
		template.HTML(`</div><div class="form-actions">`),
		b.add("button", components.Button{Text: msg.T("issuer.issued.apply.label"), Type: "submit", Variant: "primary"}),
		template.HTML(`</div></form>`),
	)
}

// table is the block of the records of one page, with the page links.
func (p *Pages) table(ctx context.Context, b *blocks, q listQuery, records []*issuedv1.IssuedRecord, pr *commonv1.PageResult) template.HTML {
	offered := p.has(ctx, backendv1.Feature_FEATURE_ISSUANCE_STATUS)
	rows := make([]components.Row, 0, len(records))
	for _, r := range records {
		rows = append(rows, components.Row{
			{HTML: link(recordPath(r.GetId(), nil), shortID(r.GetId()))},
			{Text: subjectText(r)},
			{Text: schemaText(r.GetSchemaId(), r.GetSchemaVersion())},
			{Text: r.GetIssuedAt().AsTime().UTC().Format(dateText)},
			{HTML: p.statusBadge(ctx, b, r, offered)},
		})
	}
	table := b.add("table", components.Table{
		ID: "issued-list", Caption: msg.T("issuer.issued.caption.label", strconv.Itoa(len(rows)), strconv.FormatInt(pr.GetTotalSize(), 10)),
		Columns: []string{
			msg.T("issuer.issued.column.credential.label"), msg.T("issuer.issued.column.subject.label"),
			msg.T("issuer.issued.column.schema.label"), msg.T("issuer.issued.column.issued.label"),
			msg.T("issuer.issued.column.status.label"),
		},
		Rows: rows, Empty: msg.T("issuer.issued.none"),
	})
	var links []template.HTML
	if q.page != "" {
		links = append(links, b.add("button", components.Button{Text: msg.T("issuer.issued.first.label"), Href: listPath(q.values, "")}))
	}
	if next := pr.GetNextPageToken(); next != "" {
		links = append(links, b.add("button", components.Button{Text: msg.T("issuer.issued.next.label"), Href: listPath(q.values, next)}))
	}
	var more template.HTML
	if len(links) > 0 {
		more = template.HTML(`<div class="form-actions">`) + components.Join(links...) + template.HTML(`</div>`)
	}
	return b.add("block", components.Block{
		ID: "credentials", Title: msg.T("issuer.issued.list.label"), Lead: msg.T("issuer.issued.list.lead"),
		Body: components.Join(table, more),
	})
}

// listPath returns the path of one list page with the filters.
func listPath(values url.Values, token string) string {
	q := url.Values{}
	for k, v := range values {
		q[k] = v
	}
	if token != "" {
		q.Set("page", token)
	}
	if len(q) == 0 {
		return Prefix
	}
	return Prefix + "?" + q.Encode()
}

// statusBadge is the status of one record as a badge. An active record
// whose offer no wallet claimed shows "Offered, not claimed" when the
// adapter lists FEATURE_ISSUANCE_STATUS.
func (p *Pages) statusBadge(ctx context.Context, b *blocks, r *issuedv1.IssuedRecord, offered bool) template.HTML {
	status, text := "ok", msg.T("issuer.issued.status.active.label")
	switch r.GetStatus() {
	case issuedv1.Status_STATUS_SUSPENDED:
		status, text = "warn", msg.T("issuer.issued.status.suspended.label")
	case issuedv1.Status_STATUS_REVOKED:
		status, text = "bad", msg.T("issuer.issued.status.revoked.label")
	case issuedv1.Status_STATUS_EXPIRED:
		status, text = "info", msg.T("issuer.issued.status.expired.label")
	default:
		if offered && r.GetDpgOfferId() != "" && p.opts.Stack.Pending(ctx, r.GetDpgOfferId()) {
			status, text = "info", msg.T("issuer.issued.status.offered.label")
		}
	}
	return b.add("badge", components.Badge{Status: status, Text: text})
}

// sortedKeys returns the keys of m in order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
