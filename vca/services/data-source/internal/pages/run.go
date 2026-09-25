// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// errNoSchema answers a form that names no published schema.
var errNoSchema = errors.New("the request names no published schema")

// methodNative selects the bulk import of the stack (ADR-043 decision 4).
const methodNative = "native"

// batchPage is the page size of the rows of a run.
const batchPage = 50

// maxExportPages caps the pages the CSV export reads.
const maxExportPages = 1000

// bulkChannels lists the channels a bulk run offers, in the order of the
// issue wizard. A bulk run has no browser of the holder, so the Digital
// Credentials API is not one of them.
var bulkChannels = []struct {
	channel backendv1.Channel
	key     string
}{
	{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, "issuer.issue.pre_auth"},
	{backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE, "issuer.issue.auth_code"},
	{backendv1.Channel_CHANNEL_PDF, "issuer.issue.pdf"},
}

// offered lists the channels of a bulk run on the pair: the channels
// its adapter lists, and the document channel that VCA gives every
// stack (ADR-043 decision 2).
func offered(c *backendv1.GetCapabilitiesResponse) []backendv1.Channel {
	var out []backendv1.Channel
	for _, bc := range bulkChannels {
		if bc.channel == backendv1.Channel_CHANNEL_PDF || lists(c, bc.channel) {
			out = append(out, bc.channel)
		}
	}
	return out
}

// lists reports whether the adapter lists a channel.
func lists(c *backendv1.GetCapabilitiesResponse, ch backendv1.Channel) bool {
	for _, got := range c.GetChannels() {
		if got == ch {
			return true
		}
	}
	return false
}

// channelKey returns the catalogue key of a channel.
func channelKey(c backendv1.Channel) string {
	for _, bc := range bulkChannels {
		if bc.channel == c {
			return bc.key
		}
	}
	return ""
}

// runSetup is what the run form and the start of a run read: the source,
// the schema, and the saved field map.
type runSetup struct {
	src    *datasourcev1.Source
	schema *schemav1.Schema
	fm     mapping.FieldMap
	claims int
}

// setup reads the source, the schema, and the field map of a run. ok is
// false when the page sent the browser to the step that is missing.
func (p *Pages) setup(pg page, ref string) (runSetup, bool, error) {
	src, err := p.source(pg)
	if err != nil {
		return runSetup{}, false, err
	}
	ctx := pg.ctx()
	schema, ok, err := p.schemaOf(ctx, ref)
	if err != nil {
		return runSetup{}, false, err
	}
	if !ok {
		http.Redirect(pg.w, pg.r, sourcePath(src.GetId(), "/map", ""), http.StatusSeeOther)
		return runSetup{}, false, nil
	}
	saved, err := p.opts.Sources.GetFieldMap(ctx, connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: src.GetId(), SchemaId: schema.GetId()}))
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		http.Redirect(pg.w, pg.r, sourcePath(src.GetId(), "/map", schemaRef(schema)), http.StatusSeeOther)
		return runSetup{}, false, nil
	case err != nil:
		return runSetup{}, false, err
	}
	s := runSetup{src: src, schema: schema, fm: service.FieldMapFromProto(saved.Msg.GetFieldMap())}
	if raw := strings.TrimSpace(schema.GetJsonSchema()); raw != "" {
		if parsed, perr := jsonschema.Parse([]byte(raw)); perr == nil {
			s.claims = len(parsed.Leaves())
		}
	}
	return s, true, nil
}

// runForm draws the last step: what the run reads and how the holders
// get their credentials.
func (p *Pages) runForm(pg page) error {
	s, ok, err := p.setup(pg, pg.r.URL.Query().Get("schema"))
	if !ok {
		return err
	}
	return p.renderRun(pg, s, url.Values{}, "")
}

// renderRun draws the run form, with a toast when the last start failed.
func (p *Pages) renderRun(pg page, s runSetup, values url.Values, toast string) error {
	b := p.blocks()
	ref := schemaRef(s.schema)
	c := caps(pg.f)
	rows := msg.T("common.unknown.label")
	if res, err := p.opts.Sources.PreviewRows(pg.ctx(), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: s.src.GetId(), Limit: 1})); err == nil {
		rows = strconv.FormatInt(res.Msg.GetTotalRows(), 10)
	}
	summary := b.add("table", components.Table{ID: "run-summary", Caption: msg.T("issuer.sources.run.caption.label"),
		Columns: []string{msg.T("issuer.identity.column.item.label"), msg.T("issuer.identity.column.value.label")},
		Rows: []components.Row{
			{{Text: msg.T("issuer.sources.step.source.label")}, {Text: s.src.GetDisplayName() + ", " + kindLabel(s.src)}},
			{{Text: msg.T("issuer.issue.step.schema.label")}, {Text: msg.T("issuer.issue.review.schema", schemaName(s.schema), strconv.Itoa(int(s.schema.GetVersion())))}},
			{{Text: msg.T("issuer.sources.run.rows.label")}, {Text: rows}},
			{{Text: msg.T("issuer.sources.run.mapped.label")}, {Text: msg.T("issuer.sources.run.mapped", strconv.Itoa(len(s.fm.Rules)), strconv.Itoa(s.claims))}},
			{{Text: msg.T("issuer.issue.review.stack.label")}, {Text: stackName(c)}},
		}})
	var fields []template.HTML
	fields = append(fields, hiddenInput("schema", ref))
	if pg.f.Has(backendv1.Feature_FEATURE_BULK_NATIVE) {
		method := values.Get("method")
		fields = append(fields, b.add("choice", components.Choice{ID: "method", Legend: msg.T("issuer.sources.run.method.label"), Options: []components.ChoiceOption{
			{Value: "vca", Title: msg.T("issuer.sources.run.vca.label"), Text: msg.T("issuer.sources.run.vca.text"), Meta: msg.T("issuer.issue.every_stack.label"), Checked: method != methodNative},
			{Value: methodNative, Title: msg.T("issuer.sources.run.native.label", stackName(c)), Text: msg.T("issuer.sources.run.native.text"), Meta: stackName(c), Checked: method == methodNative},
		}}))
	}
	channelHint := msg.T("issuer.sources.run.channel.hint")
	if pg.f.Has(backendv1.Feature_FEATURE_BULK_NATIVE) {
		channelHint += " " + msg.T("issuer.sources.run.channel.native")
	}
	current := values.Get("channel")
	channelOptions := make([]components.ChoiceOption, 0, len(bulkChannels))
	for i, ch := range offered(c) {
		key := channelKey(ch)
		meta := msg.T("issuer.issue.every_stack.label")
		if lists(c, ch) {
			meta = stackName(c)
		}
		channelOptions = append(channelOptions, components.ChoiceOption{Value: ch.String(), Title: msg.T(key + ".label"), Text: msg.T(key + ".text"),
			Meta: meta, Checked: ch.String() == current || (current == "" && i == 0)})
	}
	fields = append(fields, b.add("choice", components.Choice{ID: "channel", Legend: msg.T("issuer.issue.step.delivery.label"),
		Hint: channelHint, Options: channelOptions}))
	if fs := formatsOn(s.schema, c); len(fs) > 1 {
		opts := make([]components.Option, 0, len(fs))
		for _, f := range fs {
			opts = append(opts, components.Option{Value: f.String(), Text: formatName(f), Selected: f.String() == values.Get("format")})
		}
		fields = append(fields, b.add("field", components.Field{ID: "format", Label: msg.T("issuer.issue.format.label"), Type: "select",
			Options: opts, Hint: msg.T("issuer.issue.format.hint")}))
	}
	var start template.HTML
	if p.opts.Issuance == nil {
		start = b.add("note", components.Note{Text: msg.T("issuer.sources.run.no_issuance")})
	} else {
		fields = append(fields, actionRow(
			b.add("button", components.Button{Text: msg.T("issuer.sources.run.start.label"), Type: "submit", Variant: "primary"}),
			b.add("button", components.Button{Text: msg.T("issuer.sources.map.change.label"), Href: sourcePath(s.src.GetId(), "/map", ref), Variant: "ghost"}),
		))
		start = form(pg, sourcePath(s.src.GetId(), "/run", ""), false, fields...)
	}
	content := components.Join(p.stepper(b, stepRun),
		b.add("block", components.Block{ID: "run", Title: msg.T("issuer.sources.run.title.label"), Lead: msg.T("issuer.sources.run.lead"), Body: summary + start}))
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if toast != "" {
		toasts = []components.Toast{{Level: "bad", Text: toast}}
	}
	return p.render(pg, components.Page{Title: msg.T("issuer.sources.run.page.label"), Lead: msg.T("issuer.sources.run.page.lead"),
		Content: content, Toasts: toasts})
}

// startRun reads every row of the source, fills the claims through the
// field map with their JSON types, and starts the batch at the issuance
// service as the staff member. The browser goes to the progress page.
func (p *Pages) startRun(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if err := pg.r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	values := pg.r.PostForm
	s, ok, err := p.setup(pg, values.Get("schema"))
	if !ok {
		return err
	}
	if p.opts.Issuance == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("no issuance service"))
	}
	req, err := p.batchRequest(pg, s, values)
	var r refusal
	if errors.As(err, &r) {
		return p.renderRun(pg, s, values, string(r))
	}
	if err != nil {
		return err
	}
	job, err := p.launch(pg, req)
	if err != nil {
		return p.renderRun(pg, s, values, msg.T("issuer.sources.run.error.start"))
	}
	http.Redirect(pg.w, pg.r, sourcePath(s.src.GetId(), "/runs/"+url.PathEscape(job), schemaRef(s.schema)), http.StatusSeeOther)
	return nil
}

// refusal is the sentence of a run that cannot start. The run page shows
// it as a toast.
type refusal string

func (r refusal) Error() string { return string(r) }

// batchRequest builds the batch of a run. A run that cannot start gives
// a refusal.
func (p *Pages) batchRequest(pg page, s runSetup, values url.Values) (*issuancev1.IssueBatchRequest, error) {
	c := caps(pg.f)
	req := &issuancev1.IssueBatchRequest{SchemaId: s.schema.GetId(), SchemaVersion: s.schema.GetVersion(), Format: pickFormat(s.schema, c, values)}
	if values.Get("method") == methodNative && pg.f.Has(backendv1.Feature_FEATURE_BULK_NATIVE) {
		req.Native, req.Channel = true, backendv1.Channel_CHANNEL_PDF
	} else {
		ch := backendv1.Channel(backendv1.Channel_value[values.Get("channel")])
		found := false
		for _, o := range offered(c) {
			found = found || o == ch
		}
		if !found {
			return nil, refusal(msg.T("issuer.issue.error.channel"))
		}
		req.Channel = ch
	}
	tb, err := p.opts.Sources.IssueRows(pg.ctx(), s.src.GetId())
	switch {
	case roleDenied(err):
		return nil, err
	case err != nil:
		return nil, refusal(msg.T("issuer.sources.read.failed"))
	case len(tb.Rows) == 0:
		return nil, refusal(msg.T("issuer.sources.run.error.empty"))
	}
	// A schema without a JSON Schema keeps every claim as text; the
	// issuance service checks nothing then either.
	var parsed jsonschema.Schema
	if raw := strings.TrimSpace(s.schema.GetJsonSchema()); raw != "" {
		if parsed, err = jsonschema.Parse([]byte(raw)); err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
	}
	for i, row := range tb.Rows {
		flat, lerr := mapping.Lenient(row, s.fm)
		if lerr != nil {
			return nil, refusal(msg.T("issuer.sources.map.refused"))
		}
		data, merr := json.Marshal(parsed.Typed(flat))
		if merr != nil {
			return nil, merr
		}
		req.Items = append(req.Items, &issuancev1.IssueBatchRequest_Item{Row: int64(i + 1), SubjectData: string(data)})
	}
	return req, nil
}

// launch starts the batch and returns its job id once the issuance
// service sent the first progress message. The run goes on after the
// request ends; a goroutine reads the stream to its end, so the
// issuance service keeps its context. It carries the staff member in
// the actor header (ADR-039 decision 1).
func (p *Pages) launch(pg page, req *issuancev1.IssueBatchRequest) (string, error) {
	ctx := pg.r.Context()
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.opts.RunTimeout)
	stream, err := p.opts.Issuance.IssueBatch(runCtx, staffshell.AsActor(ctx, req))
	if err != nil {
		cancel()
		return "", err
	}
	if !stream.Receive() {
		err := stream.Err()
		anyval.Discard(stream.Close())
		cancel()
		if err == nil {
			err = errors.New("the issuance service sent no progress")
		}
		return "", err
	}
	job := stream.Msg().GetJobId()
	go func() {
		defer cancel()
		last := stream.Msg()
		for stream.Receive() {
			last = stream.Msg()
		}
		if serr := stream.Err(); serr != nil {
			p.opts.Log.Warn("the bulk run stopped before its end", "job", job, "processed", last.GetProcessed(), "error", serr)
		}
		anyval.Discard(stream.Close())
	}()
	return job, nil
}

// formatsOn lists the formats of the schema that the stack issues.
func formatsOn(s *schemav1.Schema, c *backendv1.GetCapabilitiesResponse) []commonv1.Format {
	var out []commonv1.Format
	for _, f := range s.GetFormats() {
		for _, got := range c.GetFormats() {
			if f == got {
				out = append(out, f)
			}
		}
	}
	return out
}

// pickFormat reads the format of a form. Unspecified lets the issuance
// service choose from the schema.
func pickFormat(s *schemav1.Schema, c *backendv1.GetCapabilitiesResponse, values url.Values) commonv1.Format {
	f := commonv1.Format(commonv1.Format_value[values.Get("format")])
	for _, x := range formatsOn(s, c) {
		if x == f {
			return f
		}
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// wireNames maps each format onto its OID4VCI format identifier.
var wireNames = map[commonv1.Format]string{
	commonv1.Format_FORMAT_VC_SD_JWT:   "vc+sd-jwt",
	commonv1.Format_FORMAT_DC_SD_JWT:   "dc+sd-jwt",
	commonv1.Format_FORMAT_JWT_VC_JSON: "jwt_vc_json",
	commonv1.Format_FORMAT_LDP_VC:      "ldp_vc",
	commonv1.Format_FORMAT_MSO_MDOC:    "mso_mdoc",
}

// formatName names one wire format as OID4VCI does.
func formatName(f commonv1.Format) string {
	if n, ok := wireNames[f]; ok {
		return n
	}
	return strings.ToLower(strings.TrimPrefix(f.String(), "FORMAT_"))
}

// runPath returns the path of the progress page of a job, or of one of
// its parts.
func runPath(pg page, suffix string) string {
	return Prefix + url.PathEscape(pg.r.PathValue("id")) + "/runs/" + url.PathEscape(pg.r.PathValue("job")) + suffix
}

// batch reads one page of the rows of the job of the request.
func (p *Pages) batch(pg page, token string, failedOnly bool) (*issuancev1.GetBatchResponse, error) {
	if p.opts.Issuance == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no issuance service"))
	}
	ctx := pg.r.Context()
	res, err := p.opts.Issuance.GetBatch(ctx, staffshell.AsActor(ctx, &issuancev1.GetBatchRequest{
		JobId: pg.r.PathValue("job"), FailedOnly: failedOnly, Page: &commonv1.Pagination{PageSize: batchPage, PageToken: token},
	}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// progress draws a run: the progress block, which htmx refreshes every
// two seconds while the run goes on, and the result of each row.
func (p *Pages) progress(pg page) error {
	src, err := p.source(pg)
	if err != nil {
		return err
	}
	b := p.blocks()
	block, err := p.progressBlock(pg, b)
	if err != nil {
		return err
	}
	all, err := p.batch(pg, pg.r.URL.Query().Get("page"), false)
	if err != nil {
		return err
	}
	rows := make([]components.Row, 0, len(all.GetRows()))
	for _, r := range all.GetRows() {
		rows = append(rows, resultRow(r))
	}
	var more template.HTML
	if next := all.GetPage().GetNextPageToken(); next != "" {
		q := url.Values{"page": {next}}
		if ref := pg.r.URL.Query().Get("schema"); ref != "" {
			q.Set("schema", ref)
		}
		more = actionRow(b.add("button", components.Button{Text: msg.T("issuer.sources.runs.more.label"), Href: runPath(pg, "") + "?" + q.Encode()}))
	}
	results := b.add("block", components.Block{ID: "results", Title: msg.T("issuer.sources.runs.results.label"), Lead: msg.T("issuer.sources.runs.results.lead"),
		Body: b.add("table", components.Table{ID: "result-rows", Caption: msg.T("issuer.sources.runs.results.caption.label"),
			Columns: []string{msg.T("issuer.sources.column.row.label"), msg.T("issuer.sources.column.label.label"),
				msg.T("issuer.sources.column.result.label"), msg.T("issuer.sources.column.offer.label")},
			Rows: rows, Empty: msg.T("issuer.sources.runs.results.empty")}) + more})
	lead := msg.T("issuer.sources.runs.lead", src.GetDisplayName())
	if schema, ok, serr := p.schemaOf(pg.ctx(), pg.r.URL.Query().Get("schema")); serr == nil && ok {
		lead = msg.T("issuer.sources.runs.lead.schema", src.GetDisplayName(), schemaName(schema))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{Title: msg.T("issuer.sources.runs.title.label"), Lead: lead,
		Content: components.Join(block, results)})
}

// progressFragment answers the htmx refresh with the progress block
// alone.
func (p *Pages) progressFragment(pg page) error {
	b := p.blocks()
	block, err := p.progressBlock(pg, b)
	if err != nil {
		return err
	}
	pg.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pg.w.Header().Set("Cache-Control", "no-store")
	_, err = pg.w.Write([]byte(block))
	return err
}

// progressBlock is the counts of a run, the rows that failed, and the
// next action. While the run goes on, the block asks htmx to load it
// again every two seconds, and a link loads the whole page for a
// browser without JavaScript.
func (p *Pages) progressBlock(pg page, b *blocks) (template.HTML, error) {
	failed, err := p.batch(pg, "", true)
	if err != nil {
		return "", err
	}
	pr := failed.GetProgress()
	stats := template.HTML(`<div class="stats">`) + components.Join(
		b.add("stat", components.Stat{Label: msg.T("issuer.sources.runs.total.label"), Value: strconv.FormatInt(pr.GetTotal(), 10),
			Text: msg.T("issuer.sources.runs.done", strconv.FormatInt(pr.GetProcessed(), 10))}),
		b.add("stat", components.Stat{Label: msg.T("issuer.sources.runs.issued.label"), Value: strconv.FormatInt(pr.GetAccepted(), 10)}),
		b.add("stat", components.Stat{Label: msg.T("issuer.sources.runs.failed.label"), Value: strconv.FormatInt(pr.GetRejected(), 10)}),
	) + template.HTML(`</div>`)
	rows := make([]components.Row, 0, len(failed.GetRows()))
	for _, r := range failed.GetRows() {
		rows = append(rows, components.Row{{Text: strconv.FormatInt(r.GetRow(), 10)}, {Text: r.GetLabel()}, {Text: r.GetError().GetMessage()}})
	}
	failures := b.add("table", components.Table{ID: "failed-rows", Caption: msg.T("issuer.sources.runs.failed.caption.label"),
		Columns: []string{msg.T("issuer.sources.column.row.label"), msg.T("issuer.sources.column.label.label"), msg.T("issuer.issue.column.problem.label")},
		Rows:    rows, Empty: msg.T("issuer.sources.runs.failed.none")})
	block := components.Block{ID: "progress", Title: msg.T("issuer.sources.runs.progress.label"),
		Meta: msg.T("issuer.sources.runs.meta.label", strconv.FormatInt(pr.GetProcessed(), 10), strconv.FormatInt(pr.GetTotal(), 10))}
	var action template.HTML
	if pr.GetDone() {
		block.Lead = msg.T("issuer.sources.runs.finished", strconv.FormatInt(pr.GetAccepted(), 10), strconv.FormatInt(pr.GetRejected(), 10))
		action = b.add("button", components.Button{Text: msg.T("issuer.sources.runs.export.label"), Href: runPath(pg, "/offers.csv"), Variant: "primary"})
	} else {
		block.Lead = msg.T("issuer.sources.runs.running")
		block.Attrs = map[string]string{"hx-get": runPath(pg, "/progress"), "hx-trigger": "every 2s", "hx-swap": "outerHTML"}
		action = b.add("button", components.Button{Text: msg.T("issuer.sources.runs.refresh.label"), Href: runPath(pg, "")})
	}
	block.Body = stats + failures + actionRow(action)
	return b.add("block", block), b.err
}

// resultRow is one row of the result table.
func resultRow(r *issuancev1.BatchRow) components.Row {
	row := components.Row{{Text: strconv.FormatInt(r.GetRow(), 10)}, {Text: r.GetLabel()}}
	if r.GetError() != nil {
		return append(row, components.Cell{Text: msg.T("issuer.sources.runs.row.failed.label")}, components.Cell{Text: r.GetError().GetMessage()})
	}
	offer := r.GetOffer()
	cell := components.Cell{Text: msg.T("issuer.sources.runs.no_offer")}
	if offer.GetId() != "" {
		cell = components.Cell{HTML: link(OffersPath+url.PathEscape(offer.GetId()), msg.T("issuer.sources.runs.open_offer.label"))}
	}
	return append(row, components.Cell{Text: msg.T("issuer.sources.runs.row.issued.label")}, cell)
}

// exportOffers writes every row of a run as CSV: the offer link, the
// transaction code, and the document link of each issued row, and the
// problem of each failed row. The file goes to the staff member only.
func (p *Pages) exportOffers(pg page) error {
	var rows []*issuancev1.BatchRow
	token := ""
	for i := 0; i < maxExportPages; i++ {
		res, err := p.batch(pg, token, false)
		if err != nil {
			return err
		}
		rows = append(rows, res.GetRows()...)
		if token = res.GetPage().GetNextPageToken(); token == "" {
			break
		}
	}
	pg.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	pg.w.Header().Set("Content-Disposition", `attachment; filename="offers-`+safeName(pg.r.PathValue("job"))+`.csv"`)
	pg.w.Header().Set("Cache-Control", "no-store")
	out := csv.NewWriter(pg.w)
	records := [][]string{{"row", "label", "result", "offer_id", "offer_link", "transaction_code", "document_link", "problem"}}
	for _, r := range rows {
		result := "issued"
		if r.GetError() != nil {
			result = "failed"
		}
		o := r.GetOffer()
		records = append(records, []string{
			strconv.FormatInt(r.GetRow(), 10), cell(r.GetLabel()), result, cell(o.GetId()), cell(o.GetOfferUri()),
			cell(o.GetPin()), cell(o.GetLink()), cell(r.GetError().GetMessage()),
		})
	}
	return out.WriteAll(records)
}

// cell keeps a spreadsheet from reading a value as a formula: a value
// that starts with =, +, -, @, a tab, or a carriage return gets a
// leading quote.
func cell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// safeName keeps the letters, digits, and hyphens of a job id for a
// file name.
func safeName(v string) string {
	return strings.Map(func(r rune) rune {
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || r == '-' {
			return r
		}
		return -1
	}, v)
}
