// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/csvsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The kinds of a new source, in the order of the tabs.
var kinds = []string{"csv", "sql", "http"}

// defaultAccess is the role rule of a source added on a page: every
// issuer role sees the field names, an operator previews the masked rows
// and issues from them, and an admin does everything (ADR-015 decision 3).
func defaultAccess() *datasourcev1.Source_Access {
	return &datasourcev1.Source_Access{
		ViewFields:  []string{authz.Viewer, authz.Operator},
		PreviewRows: []string{authz.Operator},
		Issue:       []string{authz.Operator},
	}
}

// delimiters maps the choice of the CSV form onto the separator.
var delimiters = map[string]string{"comma": ",", "semicolon": ";", "tab": "\t"}

// sourceForm is a form of a new source with its values and the error of
// each field.
type sourceForm struct {
	kind   string
	ref    string
	values url.Values
	errs   map[string]string
	toast  string
}

// newSource draws the form of one kind of source.
func (p *Pages) newSource(pg page) error {
	q := pg.r.URL.Query()
	kind := q.Get("kind")
	if !validKind(kind) {
		kind = kinds[0]
	}
	return p.renderNew(pg, sourceForm{kind: kind, ref: q.Get("schema"), values: url.Values{}, errs: map[string]string{}})
}

// validKind reports whether kind names a form.
func validKind(kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// renderNew draws the tabs of the three kinds and the form of one.
func (p *Pages) renderNew(pg page, f sourceForm) error {
	b := p.blocks()
	var parts []template.HTML
	schema, withSchema, err := p.schemaOf(pg.ctx(), f.ref)
	if err != nil {
		return err
	}
	if withSchema {
		parts = append(parts, p.stepper(b, stepSource), p.chosen(b, schema))
	} else {
		f.ref = ""
	}
	tabs := make([]components.Link, 0, len(kinds))
	for _, k := range kinds {
		tabs = append(tabs, components.Link{Href: newPath(k, f.ref), Text: msg.T("issuer.sources.kind." + k + ".label"), Current: k == f.kind})
	}
	parts = append(parts, b.add("tabs", components.Tabs{Label: msg.T("issuer.sources.kinds.label"), Links: tabs}))
	var fields []template.HTML
	switch f.kind {
	case "csv":
		fields = p.csvFields(b, f)
	case "sql":
		fields = p.sqlFields(b, f)
	default:
		fields = p.httpFields(b, f)
	}
	fields = append([]template.HTML{
		hiddenInput("schema", f.ref),
		b.add("field", components.Field{ID: "name", Label: msg.T("issuer.sources.name.label"), Hint: msg.T("issuer.sources.name.hint"),
			Value: f.values.Get("name"), Error: f.errs["name"], Required: true, Attrs: map[string]string{"maxlength": "80"}}),
	}, fields...)
	fields = append(fields, actionRow(
		b.add("button", components.Button{Text: msg.T("issuer.sources.add.label"), Type: "submit", Variant: "primary"}),
		b.add("button", components.Button{Text: msg.T("common.cancel.label"), Href: listPath(f.ref), Variant: "ghost"}),
	))
	parts = append(parts, b.add("block", components.Block{
		ID: "new-source", Title: msg.T("issuer.sources.kind." + f.kind + ".title.label"), Lead: msg.T("issuer.sources.kind." + f.kind + ".lead"),
		Body: form(pg, NewPath+"/"+f.kind, f.kind == "csv", fields...),
	}))
	if b.err != nil {
		return b.err
	}
	var toasts []components.Toast
	if f.toast != "" {
		toasts = []components.Toast{{Level: "bad", Text: f.toast}}
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.sources.new.title.label"), Lead: msg.T("issuer.sources.new.lead"),
		Content: components.Join(parts...), Toasts: toasts,
	})
}

// listPath returns the list, with the schema of a bulk run.
func listPath(ref string) string {
	if ref == "" {
		return Prefix
	}
	return Prefix + "?" + url.Values{"schema": {ref}}.Encode()
}

// megabytes names a size cap in whole megabytes.
func megabytes(n int64) string { return strconv.FormatInt((n+(1<<20)-1)>>20, 10) }

// csvFields are the fields of a CSV upload.
func (p *Pages) csvFields(b *blocks, f sourceForm) []template.HTML {
	delimiter := f.values.Get("delimiter")
	header := f.values.Get("header")
	return []template.HTML{
		b.add("field", components.Field{ID: "file", Label: msg.T("issuer.sources.file.label"), Type: "file", Required: true,
			Hint: msg.T("issuer.sources.file.hint", megabytes(p.opts.UploadMaxBytes)), Error: f.errs["file"],
			Attrs: map[string]string{"accept": ".csv,text/csv"}}),
		b.add("field", components.Field{ID: "delimiter", Label: msg.T("issuer.sources.delimiter.label"), Type: "select", Options: []components.Option{
			{Value: "comma", Text: msg.T("issuer.sources.delimiter.comma.label"), Selected: delimiter == "comma"},
			{Value: "semicolon", Text: msg.T("issuer.sources.delimiter.semicolon.label"), Selected: delimiter == "semicolon"},
			{Value: "tab", Text: msg.T("issuer.sources.delimiter.tab.label"), Selected: delimiter == "tab"},
		}}),
		b.add("field", components.Field{ID: "header", Label: msg.T("issuer.sources.header.label"), Type: "select", Options: []components.Option{
			{Value: "yes", Text: msg.T("issuer.sources.header.yes.label"), Selected: header != "no"},
			{Value: "no", Text: msg.T("issuer.sources.header.no.label"), Selected: header == "no"},
		}}),
	}
}

// secretFields are the fields of a secret reference: the store and the
// name. The page never asks for a secret value (ADR-015 decision 2).
func secretFields(b *blocks, f sourceForm, hint string) []template.HTML {
	store := f.values.Get("secret-store")
	return []template.HTML{
		b.add("field", components.Field{ID: "secret-store", Label: msg.T("issuer.sources.secret.store.label"), Type: "select", Options: []components.Option{
			{Value: string(secrets.Env), Text: msg.T("issuer.sources.secret.env.label"), Selected: store != string(secrets.File)},
			{Value: string(secrets.File), Text: msg.T("issuer.sources.secret.file.label"), Selected: store == string(secrets.File)},
		}}),
		b.add("field", components.Field{ID: "secret-name", Label: msg.T("issuer.sources.secret.name.label"), Hint: hint,
			Value: f.values.Get("secret-name"), Error: f.errs["secret-name"], Attrs: map[string]string{"spellcheck": "false"}}),
	}
}

// sqlFields are the fields of a database query.
func (p *Pages) sqlFields(b *blocks, f sourceForm) []template.HTML {
	var out []template.HTML
	driver := components.Field{ID: "driver", Label: msg.T("issuer.sources.driver.label"), Required: true,
		Value: f.values.Get("driver"), Error: f.errs["driver"]}
	if len(p.opts.Drivers) == 0 {
		out = append(out, b.add("note", components.Note{Label: msg.T("issuer.sources.driver.none.label"), Text: msg.T("issuer.sources.driver.none")}))
		driver.Hint = msg.T("issuer.sources.driver.hint")
	} else {
		driver.Type = "select"
		for _, d := range p.opts.Drivers {
			driver.Options = append(driver.Options, components.Option{Value: d, Text: d, Selected: d == driver.Value})
		}
	}
	out = append(out, b.add("field", driver))
	out = append(out, secretFields(b, f, msg.T("issuer.sources.secret.dsn.hint"))...)
	return append(out,
		b.add("field", components.Field{ID: "query", Label: msg.T("issuer.sources.query.label"), Type: "textarea", Required: true,
			Hint: msg.T("issuer.sources.query.hint"), Value: f.values.Get("query"), Error: f.errs["query"],
			Attrs: map[string]string{"rows": "5", "spellcheck": "false"}}),
	)
}

// httpFields are the fields of an HTTP API.
func (p *Pages) httpFields(b *blocks, f sourceForm) []template.HTML {
	hosts := msg.T("issuer.sources.url.none")
	if len(p.opts.AllowHosts) > 0 {
		hosts = msg.T("issuer.sources.url.hint", strings.Join(p.opts.AllowHosts, ", "))
	}
	method := f.values.Get("method")
	auth := f.values.Get("auth")
	out := []template.HTML{
		b.add("field", components.Field{ID: "url", Label: msg.T("issuer.sources.url.label"), Type: "url", Required: true,
			Hint: hosts, Value: f.values.Get("url"), Error: f.errs["url"], Attrs: map[string]string{"spellcheck": "false"}}),
		b.add("field", components.Field{ID: "method", Label: msg.T("issuer.sources.method.label"), Type: "select", Options: []components.Option{
			{Value: "GET", Text: "GET", Selected: method != "POST"}, {Value: "POST", Text: "POST", Selected: method == "POST"},
		}}),
		b.add("field", components.Field{ID: "rows-path", Label: msg.T("issuer.sources.rows_path.label"), Hint: msg.T("issuer.sources.rows_path.hint"),
			Value: f.values.Get("rows-path"), Error: f.errs["rows-path"], Attrs: map[string]string{"spellcheck": "false"}}),
		b.add("field", components.Field{ID: "auth", Label: msg.T("issuer.sources.auth.label"), Type: "select", Options: []components.Option{
			{Value: "none", Text: msg.T("issuer.sources.auth.none.label"), Selected: auth != "bearer"},
			{Value: "bearer", Text: msg.T("issuer.sources.auth.bearer.label"), Selected: auth == "bearer"},
		}}),
	}
	return append(out, secretFields(b, f, msg.T("issuer.sources.secret.token.hint"))...)
}

// postedForm reads the fields of a posted source form.
func postedForm(pg page, kind string) sourceForm {
	return sourceForm{kind: kind, ref: pg.r.PostFormValue("schema"), values: pg.r.PostForm, errs: map[string]string{}}
}

// checkName checks the display name of a posted form.
func (f *sourceForm) checkName() string {
	name := strings.TrimSpace(f.values.Get("name"))
	if name == "" {
		f.errs["name"] = msg.T("issuer.sources.error.name")
	}
	return name
}

// createCSV adds a CSV source from an upload. The upload has a size cap,
// and the page reads the file once, so a bad file never becomes a source.
func (p *Pages) createCSV(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	pg.r.Body = http.MaxBytesReader(pg.w, pg.r.Body, p.opts.UploadMaxBytes+(1<<20))
	if err := pg.r.ParseMultipartForm(p.opts.UploadMaxBytes); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			f := sourceForm{kind: "csv", values: url.Values{}, errs: map[string]string{"file": msg.T("issuer.sources.error.file_size", megabytes(p.opts.UploadMaxBytes))}}
			return p.renderNew(pg, f)
		}
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f := postedForm(pg, "csv")
	f.values = url.Values(pg.r.MultipartForm.Value)
	f.ref = f.values.Get("schema")
	name := f.checkName()
	data := p.readUpload(pg, &f)
	if len(f.errs) > 0 {
		return p.renderNew(pg, f)
	}
	ref, err := p.keepCSV(data)
	if err != nil {
		return err
	}
	return p.create(pg, f, &datasourcev1.Source{DisplayName: name, Access: defaultAccess(), Kind: &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{
		FileRef: ref, Delimiter: delimiters[f.values.Get("delimiter")], HasHeader: f.values.Get("header") != "no",
	}}})
}

// readUpload reads the uploaded file and checks that it is a CSV file
// under the cap. It sets the error of the file field.
func (p *Pages) readUpload(pg page, f *sourceForm) []byte {
	file, header, err := pg.r.FormFile("file")
	if err != nil {
		f.errs["file"] = msg.T("issuer.sources.error.file")
		return nil
	}
	defer file.Close() //nolint:errcheck // a read only upload
	if header.Size > p.opts.UploadMaxBytes {
		f.errs["file"] = msg.T("issuer.sources.error.file_size", megabytes(p.opts.UploadMaxBytes))
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(file, p.opts.UploadMaxBytes+1))
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		f.errs["file"] = msg.T("issuer.sources.error.file")
		return nil
	}
	if int64(len(data)) > p.opts.UploadMaxBytes {
		f.errs["file"] = msg.T("issuer.sources.error.file_size", megabytes(p.opts.UploadMaxBytes))
		return nil
	}
	tb, err := csvsrc.Parse(bytes.NewReader(data), csvsrc.Options{
		Delimiter: delimiters[f.values.Get("delimiter")], HasHeader: f.values.Get("header") != "no", MaxBytes: p.opts.UploadMaxBytes,
	})
	if err != nil || len(tb.Fields) == 0 {
		f.errs["file"] = msg.T("issuer.sources.error.csv")
		return nil
	}
	return data
}

// keepCSV stores the bytes of an upload and returns the file reference.
func (p *Pages) keepCSV(data []byte) (string, error) {
	if p.opts.SaveCSV != nil {
		return p.opts.SaveCSV(data)
	}
	return reader.DataPrefix + base64.StdEncoding.EncodeToString(data), nil
}

// createSQL adds a database query. The DSN stays in a secret store; the
// source keeps its reference only.
func (p *Pages) createSQL(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if err := pg.r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f := postedForm(pg, "sql")
	name := f.checkName()
	driver := strings.TrimSpace(f.values.Get("driver"))
	if driver == "" {
		f.errs["driver"] = msg.T("issuer.sources.error.driver")
	}
	dsn := f.secret(true)
	query := strings.TrimSpace(f.values.Get("query"))
	if err := sqlsrc.CheckQuery(query); err != nil {
		f.errs["query"] = msg.T("issuer.sources.error.query")
	}
	if len(f.errs) > 0 {
		return p.renderNew(pg, f)
	}
	return p.create(pg, f, &datasourcev1.Source{DisplayName: name, Access: defaultAccess(), Kind: &datasourcev1.Source_Sql{Sql: &datasourcev1.SqlSource{
		Driver: driver, Dsn: dsn, Query: query,
	}}})
}

// secret reads the secret reference of a form. need makes a missing
// reference an error.
func (f *sourceForm) secret(need bool) *commonv1.SecretRef {
	name := strings.TrimSpace(f.values.Get("secret-name"))
	if name == "" && !need {
		return nil
	}
	ref := secrets.Ref{Store: secrets.Env, Name: name}
	out := &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_ENV, Name: name}
	if f.values.Get("secret-store") == string(secrets.File) {
		ref.Store, out.Store = secrets.File, commonv1.SecretRef_STORE_FILE
	}
	if err := ref.Validate(); err != nil {
		f.errs["secret-name"] = msg.T("issuer.sources.error.secret." + string(ref.Store))
	}
	return out
}

// createHTTP adds an HTTP API. The page checks the scheme and the host
// allowlist before it keeps the source; the service checks the address
// again on every read.
func (p *Pages) createHTTP(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if err := pg.r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f := postedForm(pg, "http")
	name := f.checkName()
	raw := strings.TrimSpace(f.values.Get("url"))
	guard := httpsrc.Guard{AllowHosts: p.opts.AllowHosts, AllowHTTP: p.opts.AllowHTTP}
	if _, err := guard.CheckURL(raw); err != nil {
		f.errs["url"] = urlError(err)
	}
	rowsPath := strings.TrimSpace(f.values.Get("rows-path"))
	if rowsPath != "" && !strings.HasPrefix(rowsPath, "/") {
		f.errs["rows-path"] = msg.T("issuer.sources.error.rows_path")
	}
	src := &datasourcev1.HttpSource{Url: raw, Method: f.values.Get("method"), RowsPath: rowsPath}
	if f.values.Get("auth") == "bearer" {
		src.Auth = &datasourcev1.HttpSource_BearerToken{BearerToken: f.secret(true)}
	}
	if len(f.errs) > 0 {
		return p.renderNew(pg, f)
	}
	return p.create(pg, f, &datasourcev1.Source{DisplayName: name, Access: defaultAccess(), Kind: &datasourcev1.Source_Http{Http: src}})
}

// urlError names the problem of the address of an HTTP source.
func urlError(err error) string {
	switch {
	case errors.Is(err, httpsrc.ErrNoAllowlist):
		return msg.T("issuer.sources.error.url.no_hosts")
	case errors.Is(err, httpsrc.ErrHost):
		return msg.T("issuer.sources.error.url.host")
	case errors.Is(err, httpsrc.ErrScheme):
		return msg.T("issuer.sources.error.url.scheme")
	}
	return msg.T("issuer.sources.error.url")
}

// create keeps the source through the service and opens it. A source
// the service refuses goes back to the form with a toast.
func (p *Pages) create(pg page, f sourceForm, src *datasourcev1.Source) error {
	res, err := p.opts.Sources.Create(pg.ctx(), connect.NewRequest(&datasourcev1.CreateRequest{Source: src}))
	switch {
	case connect.CodeOf(err) == connect.CodeInvalidArgument:
		f.toast = msg.T("issuer.sources.error.refused")
		return p.renderNew(pg, f)
	case err != nil:
		return err
	}
	schema, withSchema, err := p.schemaOf(pg.ctx(), f.ref)
	if err != nil {
		return err
	}
	ref := ""
	if withSchema {
		ref = schemaRef(schema)
	}
	http.Redirect(pg.w, pg.r, sourcePath(res.Msg.GetSource().GetId(), "", ref), http.StatusSeeOther)
	return nil
}
