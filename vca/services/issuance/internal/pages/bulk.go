// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The stack bulk import (P6-C4, ADR-060). A stack whose bulk import
// mails each holder an offer takes a CSV file: the template names the
// columns, the upload hands the file to the stack, the preview shows its
// rows, and the issue starts it. The history lists the issued files and
// their rows, and the retry issues the failed rows again.

// The paths of the stack bulk import.
const (
	// IssueBulkPath is the page of the import of one schema.
	IssueBulkPath    = "/issue/bulk/"
	bulkTemplatePath = IssueBulkPath + "template"
	bulkUploadPath   = IssueBulkPath + "upload"
	bulkUploadsPath  = IssueBulkPath + "uploads/"
	// BulkFilesPath is the history of the issued files.
	BulkFilesPath = IssueBulkPath + "files"
)

// MaxBulkFileBytes caps one CSV file of the stack bulk import. The guard
// of the pages reads a form of this size for its token.
const MaxBulkFileBytes = 4 << 20

// bulkFormSlack is the room of the other fields of an upload form.
const bulkFormSlack = 64 << 10

// bulkPageSize is the number of rows on one page of the preview and of
// the history.
const bulkPageSize = 20

// The audit actions of the stack bulk import (ADR-039 decision 1).
const (
	ActionBulkUpload = "issuance.BulkUpload"
	ActionBulkIssue  = "issuance.BulkIssue"
	ActionBulkRetry  = "issuance.BulkRetry"
)

// BulkImport runs the CSV bulk import of the adapter of the pair. The
// generated Connect client fits it.
type BulkImport interface {
	GetBulkTemplate(context.Context, *connect.Request[backendv1.GetBulkTemplateRequest]) (
		*connect.Response[backendv1.GetBulkTemplateResponse], error)
	UploadBulkFile(context.Context, *connect.Request[backendv1.UploadBulkFileRequest]) (
		*connect.Response[backendv1.UploadBulkFileResponse], error)
	PreviewBulkFile(context.Context, *connect.Request[backendv1.PreviewBulkFileRequest]) (
		*connect.Response[backendv1.PreviewBulkFileResponse], error)
	IssueBulkFile(context.Context, *connect.Request[backendv1.IssueBulkFileRequest]) (
		*connect.Response[backendv1.IssueBulkFileResponse], error)
	ListBulkFiles(context.Context, *connect.Request[backendv1.ListBulkFilesRequest]) (
		*connect.Response[backendv1.ListBulkFilesResponse], error)
	ListBulkFileRows(context.Context, *connect.Request[backendv1.ListBulkFileRowsRequest]) (
		*connect.Response[backendv1.ListBulkFileRowsResponse], error)
	RetryBulkFile(context.Context, *connect.Request[backendv1.RetryBulkFileRequest]) (
		*connect.Response[backendv1.RetryBulkFileResponse], error)
}

// registerBulk adds the routes of the stack bulk import.
func (p *Pages) registerBulk(mux *http.ServeMux) {
	mux.HandleFunc("GET "+IssueBulkPath+"{$}", p.handle(p.bulkImport))
	mux.HandleFunc("GET "+bulkTemplatePath, p.handle(p.bulkTemplate))
	mux.HandleFunc("POST "+bulkUploadPath, p.handle(p.bulkUpload))
	mux.HandleFunc("GET "+bulkUploadsPath+"{id}", p.handle(p.bulkPreview))
	mux.HandleFunc("POST "+bulkUploadsPath+"{id}/issue", p.handle(p.bulkIssue))
	mux.HandleFunc("GET "+BulkFilesPath, p.handle(p.bulkFiles))
	mux.HandleFunc("GET "+BulkFilesPath+"/{id}", p.handle(p.bulkFile))
	mux.HandleFunc("POST "+BulkFilesPath+"/{id}/retry", p.handle(p.bulkRetry))
}

// stackBulk reports whether the stack of the pair runs a bulk import that
// mails each holder an offer, and the pages reach it.
func (p *Pages) stackBulk(caps *backendv1.GetCapabilitiesResponse) bool {
	return p.opts.BulkImport != nil && has(caps, backendv1.Feature_FEATURE_BULK_NATIVE) &&
		caps.GetBulkImport().GetChannel() == backendv1.Channel_CHANNEL_EMAIL
}

// configurationKeys maps a format onto the key of the configuration ids
// of a schema, as the schema registry names it.
var configurationKeys = map[commonv1.Format]string{
	commonv1.Format_FORMAT_ANONCREDS: "anoncreds",
	commonv1.Format_FORMAT_LDP_VC:    "ldp_vc",
}

// configurationOf returns the configuration id of the stack for one
// format of a schema: the id the adapter gave at the publication, such
// as a credential definition, or else the type of the schema.
func configurationOf(s *schemav1.Schema, f commonv1.Format) string {
	if key, ok := configurationKeys[f]; ok {
		return strings.TrimSpace(s.GetConfigurationIds()[key])
	}
	return s.GetType()
}

// bulkFormats returns the formats of a schema that the bulk import of
// the stack issues, each with a configuration id of the stack.
func bulkFormats(s *schemav1.Schema, caps *backendv1.GetCapabilitiesResponse) []commonv1.Format {
	imp := caps.GetBulkImport().GetFormats()
	var out []commonv1.Format
	for _, f := range formatsOn(s, caps) {
		if (len(imp) == 0 || slices.Contains(imp, f)) && configurationOf(s, f) != "" {
			out = append(out, f)
		}
	}
	return out
}

// bulkFormat reads the format of a form among the formats of the
// import. An unknown format gives the first one.
func bulkFormat(formats []commonv1.Format, value string) commonv1.Format {
	f := commonv1.Format(commonv1.Format_value[value])
	if slices.Contains(formats, f) {
		return f
	}
	return formats[0]
}

// topClaims returns the names of the top level claims of a schema, in
// the order of the schema.
func topClaims(w wizard) []string {
	var out []string
	for _, f := range w.claims.fields {
		if strings.Count(f.pointer, "/") == 1 && !slices.Contains(out, f.key) {
			out = append(out, f.key)
		}
	}
	return out
}

// bulkSetup is what every page of the import of one schema reads: the
// wizard of the schema and the formats of the import.
type bulkSetup struct {
	w       wizard
	formats []commonv1.Format
	format  commonv1.Format
}

// bulkWizard reads the schema of an import page and checks that the
// stack imports it. ok is false when the page answered already.
func (p *Pages) bulkWizard(pg page, q url.Values) (bulkSetup, bool, error) {
	if !canIssue(pg.r.Context()) {
		return bulkSetup{}, false, errForbidden
	}
	if q.Get("schema") == "" {
		http.Redirect(pg.w, pg.r, IssuePath, http.StatusSeeOther)
		return bulkSetup{}, false, nil
	}
	w, err := p.wizardFor(pg, q, stepSource)
	if err != nil {
		return bulkSetup{}, false, err
	}
	if !p.stackBulk(w.caps) {
		return bulkSetup{}, false, connect.NewError(connect.CodeNotFound, errors.New("the stack has no bulk import"))
	}
	s := bulkSetup{w: w, formats: bulkFormats(w.schema, w.caps)}
	if len(s.formats) == 0 {
		return bulkSetup{}, false, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the bulk import of the stack issues no format of the schema"))
	}
	s.format = bulkFormat(s.formats, q.Get("format"))
	return s, true, nil
}

// bulkQuery returns the query of the schema and the format of an import.
func bulkQuery(s bulkSetup) string {
	return url.Values{"schema": {s.w.ref}, "format": {s.format.String()}}.Encode()
}

// bulkImport draws the import page: the template and the upload.
func (p *Pages) bulkImport(pg page) error {
	s, ok, err := p.bulkWizard(pg, pg.r.URL.Query())
	if !ok {
		return err
	}
	return p.renderBulkImport(pg, s, "")
}

// renderBulkImport draws the import page, with a toast when the last
// upload failed.
func (p *Pages) renderBulkImport(pg page, s bulkSetup, toast string) error {
	b := p.blocks()
	name := stackName(s.w.caps)
	column := s.w.caps.GetBulkImport().GetEmailColumn()
	var formatField template.HTML
	if len(s.formats) > 1 {
		opts := make([]components.Option, 0, len(s.formats))
		for _, f := range s.formats {
			opts = append(opts, components.Option{Value: f.String(), Text: formatName(f), Selected: f == s.format})
		}
		formatField = b.add("field", components.Field{ID: "format", Label: msg.T("issuer.issue.format.label"), Type: "select",
			Options: opts, Hint: msg.T("issuer.bulk.format.hint")})
	} else {
		formatField = template.HTML(hiddenInput("format", s.format.String())) //nolint:gosec // the input is escaped
	}
	tpl := b.add("block", components.Block{ID: "template", Title: msg.T("issuer.bulk.template.title.label"),
		Lead: msg.T("issuer.bulk.template.lead", column),
		Body: b.add("button", components.Button{Text: msg.T("issuer.bulk.template.download.label"),
			Href: bulkTemplatePath + "?" + bulkQuery(s), Variant: "secondary"})})
	upload := b.add("block", components.Block{ID: "upload", Title: msg.T("issuer.bulk.upload.title.label"),
		Lead: msg.T("issuer.bulk.upload.lead", name),
		Body: uploadForm(pg, components.Join(
			template.HTML(hiddenInput("schema", s.w.ref)), //nolint:gosec // the input is escaped
			formatField,
			b.add("field", components.Field{ID: "file", Label: msg.T("issuer.bulk.file.label"), Type: "file", Required: true,
				Hint: msg.T("issuer.bulk.file.hint", strconv.Itoa(MaxBulkFileBytes>>20)), Attrs: map[string]string{"accept": ".csv,text/csv"}}),
			p.actions(b,
				components.Button{Text: msg.T("issuer.bulk.upload.submit.label"), Type: "submit", Variant: "primary"},
				components.Button{Text: msg.T("issuer.bulk.history.link.label"), Href: BulkFilesPath, Variant: "ghost"}),
		))})
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if toast != "" {
		toasts = []components.Toast{{Level: "bad", Text: toast}}
	}
	return p.renderBulk(pg, 1, toasts, p.chosen(b, s.w), tpl, upload)
}

// uploadForm wraps the parts of the upload in a multipart POST form
// with the synchronizer token of the session.
func uploadForm(pg page, parts template.HTML) template.HTML {
	open := template.HTML(`<form method="post" action="` + bulkUploadPath + `" enctype="multipart/form-data">`) //nolint:gosec // a constant action
	return open + staffsession.HiddenField(pg.r.Context()) + parts + template.HTML(`</form>`)
}

// renderBulk writes one page of the import inside the issuer frame, with
// the stepper of the import on top.
func (p *Pages) renderBulk(pg page, step int, toasts []components.Toast, parts ...template.HTML) error {
	b := p.blocks()
	stepper := b.add("stepper", components.Stepper{
		Label: msg.T("issuer.bulk.progress.label"), Current: step,
		Steps: []string{msg.T("issuer.bulk.step.upload.label"), msg.T("issuer.bulk.step.preview.label"), msg.T("issuer.bulk.step.history.label")},
	})
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.bulk.title.label", stackName(p.caps(pg))), Lead: msg.T("issuer.bulk.lead"),
		Content: components.Join(append([]template.HTML{stepper}, parts...)...), Toasts: toasts,
	})
}

// bulkTemplate sends the CSV template of the stack for the schema.
func (p *Pages) bulkTemplate(pg page) error {
	s, ok, err := p.bulkWizard(pg, pg.r.URL.Query())
	if !ok {
		return err
	}
	ctx := pg.r.Context()
	res, err := p.opts.BulkImport.GetBulkTemplate(ctx, staffshell.AsActor(ctx, &backendv1.GetBulkTemplateRequest{
		ConfigurationId: configurationOf(s.w.schema, s.format), Format: s.format, Claims: topClaims(s.w),
	}))
	if err != nil {
		return err
	}
	pg.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	pg.w.Header().Set("Content-Disposition", `attachment; filename="`+fileName(schemaName(s.w.schema))+`"`)
	pg.w.Header().Set("Cache-Control", "no-store")
	_, err = pg.w.Write(res.Msg.GetContent())
	return err
}

// fileName turns a schema name into a safe CSV file name.
func fileName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" {
		base = "credentials"
	}
	return base + ".csv"
}

// bulkUpload hands the file of the form to the stack and goes on to the
// preview. A refusal of the stack comes back as a toast on the import
// page.
func (p *Pages) bulkUpload(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	pg.r.Body = http.MaxBytesReader(pg.w, pg.r.Body, MaxBulkFileBytes+bulkFormSlack)
	if err := pg.r.ParseMultipartForm(MaxBulkFileBytes + bulkFormSlack); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	s, ok, err := p.bulkWizard(pg, pg.r.PostForm)
	if !ok {
		return err
	}
	content, name, ferr := readUpload(pg.r)
	if ferr != nil {
		return p.renderBulkImport(pg, s, ferr.Error())
	}
	ctx := pg.r.Context()
	res, err := p.opts.BulkImport.UploadBulkFile(ctx, staffshell.AsActor(ctx, &backendv1.UploadBulkFileRequest{
		ConfigurationId: configurationOf(s.w.schema, s.format), Format: s.format, FileName: name, Content: content,
	}))
	p.audit(ctx, ActionBulkUpload, s.w.schema.GetId(), err)
	if err != nil {
		return p.renderBulkImport(pg, s, msg.T("issuer.bulk.error.upload", refusalOf(err)))
	}
	http.Redirect(pg.w, pg.r, bulkUploadsPath+url.PathEscape(res.Msg.GetUploadId())+"?"+bulkQuery(s), http.StatusSeeOther)
	return nil
}

// readUpload reads the CSV file of an upload form and its base name.
func readUpload(r *http.Request) ([]byte, string, error) {
	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, "", errors.New(msg.T("issuer.bulk.error.file"))
	}
	defer func() { anyval.Discard(file.Close()) }()
	content, err := io.ReadAll(io.LimitReader(file, MaxBulkFileBytes+1))
	if err != nil || len(content) == 0 {
		return nil, "", errors.New(msg.T("issuer.bulk.error.file"))
	}
	if len(content) > MaxBulkFileBytes {
		return nil, "", errors.New(msg.T("issuer.bulk.error.size", strconv.Itoa(MaxBulkFileBytes>>20)))
	}
	return content, path.Base(strings.ReplaceAll(header.Filename, `\`, "/")), nil
}

// refusalOf returns the sentence of the stack in an error, or the
// message of the error.
func refusalOf(err error) string {
	text := connect.CodeOf(err).String()
	var ce *connect.Error
	if errors.As(err, &ce) {
		text = ce.Message()
	}
	if i := strings.LastIndex(text, "the platform refused: "); i >= 0 {
		return strings.TrimSuffix(strings.TrimSpace(text[i+len("the platform refused: "):]), ".")
	}
	return text
}

// pageNumber reads the page of a list from the query, from one.
func pageNumber(q url.Values) int {
	n, err := strconv.Atoi(q.Get("page"))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// pageToken is the page token of the adapter for a page number.
func pageToken(n int) string {
	if n <= 1 {
		return ""
	}
	return strconv.Itoa(n)
}

// pager draws the links to the page before and the page after.
func (p *Pages) pager(b *blocks, base string, q url.Values, page int, next bool) template.HTML {
	var buttons []components.Button
	if page > 1 {
		q.Set("page", strconv.Itoa(page-1))
		buttons = append(buttons, components.Button{Text: msg.T("issuer.bulk.page.previous.label"), Href: base + "?" + q.Encode(), Variant: "ghost"})
	}
	if next {
		q.Set("page", strconv.Itoa(page+1))
		buttons = append(buttons, components.Button{Text: msg.T("issuer.bulk.page.next.label"), Href: base + "?" + q.Encode(), Variant: "ghost"})
	}
	if len(buttons) == 0 {
		return ""
	}
	return p.actions(b, buttons...)
}

// bulkPreview draws the rows of an upload and the button that issues
// them.
func (p *Pages) bulkPreview(pg page) error {
	q := pg.r.URL.Query()
	s, ok, err := p.bulkWizard(pg, q)
	if !ok {
		return err
	}
	id := pg.r.PathValue("id")
	page := pageNumber(q)
	ctx := pg.r.Context()
	res, err := p.opts.BulkImport.PreviewBulkFile(ctx, staffshell.AsActor(ctx, &backendv1.PreviewBulkFileRequest{
		UploadId: id, Page: &commonv1.Pagination{PageSize: bulkPageSize, PageToken: pageToken(page)},
	}))
	if err != nil {
		return p.renderBulkImport(pg, s, msg.T("issuer.bulk.error.preview", refusalOf(err)))
	}
	b := p.blocks()
	claims := previewColumns(res.Msg.GetRows())
	columns := append([]string{msg.T("issuer.bulk.column.email.label")}, claims...)
	rows := make([]components.Row, 0, len(res.Msg.GetRows()))
	for _, r := range res.Msg.GetRows() {
		row := components.Row{{Text: r.GetEmail()}}
		for _, c := range claims {
			row = append(row, components.Cell{Text: r.GetClaims()[c]})
		}
		rows = append(rows, row)
	}
	total := strconv.FormatInt(res.Msg.GetPage().GetTotalSize(), 10)
	table := b.add("table", components.Table{ID: "preview-rows", Caption: msg.T("issuer.bulk.preview.caption.label", total),
		Columns: columns, Rows: rows, Empty: msg.T("issuer.bulk.preview.empty")})
	pager := p.pager(b, bulkUploadsPath+url.PathEscape(id), url.Values{"schema": {s.w.ref}, "format": {s.format.String()}},
		page, res.Msg.GetPage().GetNextPageToken() != "")
	issue := formHTML(bulkUploadsPath+url.PathEscape(id)+"/issue", staffsession.HiddenField(ctx), components.Join(
		template.HTML(hiddenInput("schema", s.w.ref)),           //nolint:gosec // the input is escaped
		template.HTML(hiddenInput("format", s.format.String())), //nolint:gosec // the input is escaped
		p.actions(b,
			components.Button{Text: msg.T("issuer.bulk.issue.submit.label", total), Type: "submit", Variant: "primary"},
			components.Button{Text: msg.T("issuer.bulk.upload.again.label"), Href: IssueBulkPath + "?" + bulkQuery(s), Variant: "ghost"}),
	))
	block := b.add("block", components.Block{ID: "preview", Title: msg.T("issuer.bulk.preview.title.label"),
		Lead: msg.T("issuer.bulk.preview.lead", stackName(s.w.caps)), Body: table + pager + issue})
	if b.err != nil {
		return b.err
	}
	return p.renderBulk(pg, 2, nil, p.chosen(b, s.w), block)
}

// previewColumns returns the claim names of the rows of a preview, in
// name order.
func previewColumns(rows []*backendv1.BulkPreviewRow) []string {
	var out []string
	for _, r := range rows {
		for name := range r.GetClaims() {
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// bulkIssue starts the issue of an upload and goes to the history.
func (p *Pages) bulkIssue(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	f, err := readForm(pg)
	if err != nil {
		return err
	}
	s, ok, err := p.bulkWizard(pg, f)
	if !ok {
		return err
	}
	id := pg.r.PathValue("id")
	ctx := pg.r.Context()
	_, err = p.opts.BulkImport.IssueBulkFile(ctx, staffshell.AsActor(ctx, &backendv1.IssueBulkFileRequest{
		UploadId: id, ConfigurationId: configurationOf(s.w.schema, s.format), Format: s.format,
	}))
	p.audit(ctx, ActionBulkIssue, s.w.schema.GetId(), err)
	if err != nil {
		return p.renderBulkImport(pg, s, msg.T("issuer.bulk.error.issue", refusalOf(err)))
	}
	http.Redirect(pg.w, pg.r, BulkFilesPath+"?started=1", http.StatusSeeOther)
	return nil
}

// fileStates maps the state of an issued file onto its badge.
var fileStates = map[backendv1.BulkFile_State]struct {
	status, key string
}{
	backendv1.BulkFile_STATE_STARTED:     {"info", "issuer.bulk.state.started.label"},
	backendv1.BulkFile_STATE_COMPLETED:   {"ok", "issuer.bulk.state.completed.label"},
	backendv1.BulkFile_STATE_PARTIAL:     {"warn", "issuer.bulk.state.partial.label"},
	backendv1.BulkFile_STATE_INTERRUPTED: {"bad", "issuer.bulk.state.interrupted.label"},
	backendv1.BulkFile_STATE_RETRIED:     {"info", "issuer.bulk.state.retried.label"},
}

// stateBadge draws the badge of the state of a file.
func stateBadge(b *blocks, st backendv1.BulkFile_State) template.HTML {
	s, ok := fileStates[st]
	if !ok {
		s = struct{ status, key string }{"info", "issuer.bulk.state.unknown.label"}
	}
	return b.add("badge", components.Badge{Status: s.status, Text: msg.T(s.key)})
}

// when names a time for the history.
func when(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format("2006-01-02 15:04 UTC")
}

// bulkFiles draws the history: the files the stack issued from.
func (p *Pages) bulkFiles(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	caps := p.caps(pg)
	if !p.stackBulk(caps) {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack has no bulk import"))
	}
	q := pg.r.URL.Query()
	page := pageNumber(q)
	ctx := pg.r.Context()
	res, err := p.opts.BulkImport.ListBulkFiles(ctx, staffshell.AsActor(ctx, &backendv1.ListBulkFilesRequest{
		Page: &commonv1.Pagination{PageSize: bulkPageSize, PageToken: pageToken(page)},
	}))
	b := p.blocks()
	var body template.HTML
	switch {
	case err != nil:
		body = b.add("note", components.Note{Text: msg.T("issuer.bulk.history.down", stackName(caps))})
	case len(res.Msg.GetFiles()) == 0 && page == 1:
		body = b.add("empty", components.Empty{Title: msg.T("issuer.bulk.history.empty.label"), Text: msg.T("issuer.bulk.history.empty.text"),
			Action: components.Button{Text: msg.T("issuer.bulk.history.issue.label"), Href: IssuePath}})
	default:
		rows := make([]components.Row, 0, len(res.Msg.GetFiles()))
		for _, f := range res.Msg.GetFiles() {
			name := f.GetName()
			if name == "" {
				name = f.GetId()
			}
			rows = append(rows, components.Row{
				{HTML: link(BulkFilesPath+"/"+url.PathEscape(f.GetId()), name)}, {Text: f.GetSchemaName()},
				{HTML: stateBadge(b, f.GetState())}, {Text: strconv.FormatInt(f.GetTotalRows(), 10)},
				{Text: strconv.FormatInt(f.GetFailedRows(), 10)}, {Text: when(f.GetCreatedAt())},
			})
		}
		body = b.add("table", components.Table{ID: "bulk-files", Caption: msg.T("issuer.bulk.history.caption.label"),
			Columns: []string{msg.T("issuer.bulk.column.file.label"), msg.T("issuer.issue.step.schema.label"), msg.T("issuer.bulk.column.state.label"),
				msg.T("issuer.bulk.column.rows.label"), msg.T("issuer.bulk.column.failed.label"), msg.T("issuer.bulk.column.started.label")},
			Rows: rows}) + p.pager(b, BulkFilesPath, url.Values{}, page, res.Msg.GetPage().GetNextPageToken() != "")
	}
	block := b.add("block", components.Block{ID: "history", Title: msg.T("issuer.bulk.history.title.label"),
		Lead: msg.T("issuer.bulk.history.lead", stackName(caps)), Body: body})
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if q.Get("started") != "" {
		toasts = []components.Toast{{Level: "ok", Text: msg.T("issuer.bulk.started")}}
	}
	return p.renderBulk(pg, 3, toasts, block)
}

// bulkFile draws the rows of one issued file and the retry of its
// failed rows.
func (p *Pages) bulkFile(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	caps := p.caps(pg)
	if !p.stackBulk(caps) {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack has no bulk import"))
	}
	id := pg.r.PathValue("id")
	q := pg.r.URL.Query()
	page := pageNumber(q)
	ctx := pg.r.Context()
	res, err := p.opts.BulkImport.ListBulkFileRows(ctx, staffshell.AsActor(ctx, &backendv1.ListBulkFileRowsRequest{
		FileId: id, Page: &commonv1.Pagination{PageSize: bulkPageSize, PageToken: pageToken(page)},
	}))
	if err != nil {
		return err
	}
	b := p.blocks()
	rows := make([]components.Row, 0, len(res.Msg.GetRows()))
	for _, r := range res.Msg.GetRows() {
		result := b.add("badge", components.Badge{Status: "ok", Text: msg.T("issuer.bulk.row.issued.label")})
		switch {
		case r.GetError() != "":
			result = b.add("badge", components.Badge{Status: "bad", Text: msg.T("issuer.bulk.row.failed.label")})
		case !r.GetIssued():
			result = b.add("badge", components.Badge{Status: "info", Text: msg.T("issuer.bulk.row.waiting.label")})
		}
		rows = append(rows, components.Row{{Text: r.GetEmail()}, {HTML: result}, {Text: r.GetError()}})
	}
	table := b.add("table", components.Table{ID: "file-rows", Caption: msg.T("issuer.bulk.rows.caption.label", strconv.FormatInt(res.Msg.GetPage().GetTotalSize(), 10)),
		Columns: []string{msg.T("issuer.bulk.column.email.label"), msg.T("issuer.bulk.column.result.label"), msg.T("issuer.bulk.column.reason.label")},
		Rows:    rows, Empty: msg.T("issuer.bulk.rows.empty")})
	pager := p.pager(b, BulkFilesPath+"/"+url.PathEscape(id), url.Values{}, page, res.Msg.GetPage().GetNextPageToken() != "")
	// The stack keeps the failed rows of every page, so the retry sits
	// under each page.
	retry := formHTML(BulkFilesPath+"/"+url.PathEscape(id)+"/retry", staffsession.HiddenField(ctx), p.actions(b,
		components.Button{Text: msg.T("issuer.bulk.retry.label"), Type: "submit", Variant: "primary"},
		components.Button{Text: msg.T("issuer.bulk.history.back.label"), Href: BulkFilesPath, Variant: "ghost"}))
	block := b.add("block", components.Block{ID: "file", Title: msg.T("issuer.bulk.rows.title.label"),
		Lead: msg.T("issuer.bulk.rows.lead"), Body: table + pager + retry})
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	switch q.Get("retry") {
	case "started":
		toasts = []components.Toast{{Level: "ok", Text: msg.T("issuer.bulk.retry.started")}}
	case "failed":
		toasts = []components.Toast{{Level: "bad", Text: msg.T("issuer.bulk.retry.failed")}}
	}
	return p.renderBulk(pg, 3, toasts, block)
}

// bulkRetry issues the failed rows of a file again.
func (p *Pages) bulkRetry(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if _, err := readForm(pg); err != nil {
		return err
	}
	if !p.stackBulk(p.caps(pg)) {
		return connect.NewError(connect.CodeNotFound, errors.New("the stack has no bulk import"))
	}
	id := pg.r.PathValue("id")
	ctx := pg.r.Context()
	_, err := p.opts.BulkImport.RetryBulkFile(ctx, staffshell.AsActor(ctx, &backendv1.RetryBulkFileRequest{FileId: id}))
	p.audit(ctx, ActionBulkRetry, id, err)
	outcome := "started"
	if err != nil {
		outcome = "failed"
	}
	http.Redirect(pg.w, pg.r, BulkFilesPath+"/"+url.PathEscape(id)+"?retry="+outcome, http.StatusSeeOther)
	return nil
}
