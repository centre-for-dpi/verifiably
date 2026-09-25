// SPDX-License-Identifier: Apache-2.0

// Package pages renders the data source pages of the issuer inside the
// issuer shell of services/internal/staffshell (P3-08, ADR-043 decision
// 4, ADR-044 decision 1). Every page calls the DataSourceService of the
// service in process, as the staff member of the session, so the pages
// and the API follow the same role rules.
//
// Paths:
//
//	GET  /sources/                     the sources; ?schema= starts a bulk run
//	GET  /sources/new?kind=            the form of a CSV file, a database, or an HTTP API
//	POST /sources/new/csv              add a CSV file from an upload, under a size cap
//	POST /sources/new/sql              add a database query with a secret reference
//	POST /sources/new/http             add an HTTP API on the host allowlist
//	GET  /sources/{id}                 the fields and a masked preview
//	POST /sources/{id}/delete          delete a source
//	GET  /sources/{id}/map?schema=     the field map onto the claims of a schema
//	POST /sources/{id}/map             save the field map
//	GET  /sources/{id}/run?schema=     the delivery and the start of a bulk run
//	POST /sources/{id}/run             start the run through IssueBatch
//	GET  /sources/{id}/runs/{job}      the progress and the result of each row
//	GET  /sources/{id}/runs/{job}/progress   the progress block, for htmx
//	GET  /sources/{id}/runs/{job}/offers.csv the offers of the run as CSV
//	POST /sources/signout              end the session at issuer-auth
//
// The guard of the service checks the session and the synchronizer
// token before a request reaches a page.
package pages

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The paths of the pages.
const (
	Prefix      = "/sources/"
	NewPath     = "/sources/new"
	SignOutPath = "/sources/signout"
	// IssuePath and OffersPath are pages of the issuance service on the
	// same host: the issue wizard and the result of one offer.
	IssuePath  = "/issue/"
	OffersPath = "/issue/offers/"
)

// Sources is the DataSourceService of this service, called in process.
type Sources interface {
	List(context.Context, *connect.Request[datasourcev1.ListRequest]) (*connect.Response[datasourcev1.ListResponse], error)
	Get(context.Context, *connect.Request[datasourcev1.GetRequest]) (*connect.Response[datasourcev1.GetResponse], error)
	Create(context.Context, *connect.Request[datasourcev1.CreateRequest]) (*connect.Response[datasourcev1.CreateResponse], error)
	Delete(context.Context, *connect.Request[datasourcev1.DeleteRequest]) (*connect.Response[datasourcev1.DeleteResponse], error)
	PreviewFields(context.Context, *connect.Request[datasourcev1.PreviewFieldsRequest]) (*connect.Response[datasourcev1.PreviewFieldsResponse], error)
	PreviewRows(context.Context, *connect.Request[datasourcev1.PreviewRowsRequest]) (*connect.Response[datasourcev1.PreviewRowsResponse], error)
	SetFieldMap(context.Context, *connect.Request[datasourcev1.SetFieldMapRequest]) (*connect.Response[datasourcev1.SetFieldMapResponse], error)
	GetFieldMap(context.Context, *connect.Request[datasourcev1.GetFieldMapRequest]) (*connect.Response[datasourcev1.GetFieldMapResponse], error)
	// IssueRows returns every row of a source with its values. It checks
	// the issue rule of the source.
	IssueRows(ctx context.Context, id string) (table.Table, error)
}

// Schemas lists and reads the schemas of the schema registry of the pair.
type Schemas interface {
	List(context.Context, *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error)
	Get(context.Context, *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error)
}

// Issuance runs and reads batches at the issuance service of the pair.
// The generated Connect client fits it.
type Issuance interface {
	IssueBatch(context.Context, *connect.Request[issuancev1.IssueBatchRequest]) (*connect.ServerStreamForClient[issuancev1.IssueBatchResponse], error)
	GetBatch(context.Context, *connect.Request[issuancev1.GetBatchRequest]) (*connect.Response[issuancev1.GetBatchResponse], error)
}

// Options configure the pages.
type Options struct {
	// Kit renders the components. Required.
	Kit *components.Kit
	// Shell draws the issuer frame. Required.
	Shell *staffshell.Shell
	// Sources is the service of the pages. Required.
	Sources Sources
	// Schemas reads the schema registry. Nil shows no schema.
	Schemas Schemas
	// Issuance runs the batches. Nil shows the run page without a start.
	Issuance Issuance
	// AllowHosts are the hosts an HTTP source can reach, from the
	// allowlist of the service (ADR-015 decision 6).
	AllowHosts []string
	// AllowHTTP permits the plain http scheme for an HTTP source.
	AllowHTTP bool
	// Drivers are the database drivers of this build.
	Drivers []string
	// UploadMaxBytes caps one CSV upload. Zero means 32 MiB.
	UploadMaxBytes int64
	// SaveCSV keeps the bytes of an upload and returns the file
	// reference of the source. Nil keeps the bytes in the source as a
	// data URL.
	SaveCSV func(data []byte) (string, error)
	// RunTimeout bounds one bulk run. Zero means two hours.
	RunTimeout time.Duration
	// SignOut ends the session. Nil answers the sign out form with 404.
	SignOut http.Handler
	// Log receives the end of a run that stopped early. Nil means
	// slog.Default.
	Log *slog.Logger
}

// Pages serves the data source pages.
type Pages struct {
	opts Options
}

// New checks the options and returns the pages.
func New(opts Options) (*Pages, error) {
	switch {
	case opts.Kit == nil:
		return nil, errors.New("pages: a kit is required")
	case opts.Shell == nil:
		return nil, errors.New("pages: a shell is required")
	case opts.Sources == nil:
		return nil, errors.New("pages: the data source service is required")
	}
	if opts.UploadMaxBytes <= 0 {
		opts.UploadMaxBytes = 32 << 20
	}
	if opts.RunTimeout <= 0 {
		opts.RunTimeout = 2 * time.Hour
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Pages{opts: opts}, nil
}

// Register adds the pages to mux.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+Prefix+"{$}", p.handle(p.list))
	mux.HandleFunc("GET "+NewPath, p.handle(p.newSource))
	mux.HandleFunc("POST "+NewPath+"/csv", p.handle(p.createCSV))
	mux.HandleFunc("POST "+NewPath+"/sql", p.handle(p.createSQL))
	mux.HandleFunc("POST "+NewPath+"/http", p.handle(p.createHTTP))
	mux.HandleFunc("GET "+Prefix+"{id}", p.handle(p.detail))
	mux.HandleFunc("POST "+Prefix+"{id}/delete", p.handle(p.remove))
	mux.HandleFunc("GET "+Prefix+"{id}/map", p.handle(p.fieldMap))
	mux.HandleFunc("POST "+Prefix+"{id}/map", p.handle(p.saveFieldMap))
	mux.HandleFunc("GET "+Prefix+"{id}/run", p.handle(p.runForm))
	mux.HandleFunc("POST "+Prefix+"{id}/run", p.handle(p.startRun))
	mux.HandleFunc("GET "+Prefix+"{id}/runs/{job}", p.handle(p.progress))
	mux.HandleFunc("GET "+Prefix+"{id}/runs/{job}/progress", p.handle(p.progressFragment))
	mux.HandleFunc("GET "+Prefix+"{id}/runs/{job}/offers.csv", p.handle(p.exportOffers))
	if p.opts.SignOut != nil {
		mux.Handle("POST "+SignOutPath, p.opts.SignOut)
	}
}

// page is one request of a page: the frame of the shell, read once.
type page struct {
	w http.ResponseWriter
	r *http.Request
	f staffshell.Frame
}

// ctx returns the context of the request with the principal of the
// session, so the service in process checks the role rules of the staff
// member.
func (pg page) ctx() context.Context {
	ctx := pg.r.Context()
	if s, ok := staffsession.User(ctx); ok {
		return authz.WithPrincipal(ctx, authz.FromSession(s))
	}
	return ctx
}

// handle reads the frame and answers a short sentence when the page fails.
func (p *Pages) handle(fn func(pg page) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pg := page{w: w, r: r, f: p.opts.Shell.Frame(r.Context())}
		err := fn(pg)
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			err = p.forbidden(pg)
		}
		if err != nil {
			http.Error(w, msg.T("common.render_failed"), statusOf(err))
		}
	}
}

// statusOf maps a Connect code to an HTTP status.
func statusOf(err error) int {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		return http.StatusNotFound
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
		return http.StatusBadRequest
	case connect.CodePermissionDenied:
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

// render writes a page inside the issuer frame.
func (p *Pages) render(pg page, cp components.Page) error {
	if cp.Label == "" {
		cp.Label = msg.T("issuer.sources.label")
	}
	if cp.Description == "" {
		cp.Description = msg.T("issuer.sources.lead")
	}
	return p.opts.Shell.Render(p.opts.Kit, pg.w, pg.r, pg.f, cp)
}

// forbidden answers an action the role of the staff member does not
// allow with 403 and a page that says why.
func (p *Pages) forbidden(pg page) error {
	b := p.blocks()
	note := b.add("block", components.Block{ID: "role", Title: msg.T("issuer.sources.role.label"), Lead: msg.T("issuer.sources.role.text"),
		Body: b.add("button", components.Button{Text: msg.T("issuer.sources.back.label"), Href: Prefix})})
	if b.err != nil {
		return b.err
	}
	pg.w = &statusWriter{ResponseWriter: pg.w, status: http.StatusForbidden}
	return p.render(pg, components.Page{Title: msg.T("issuer.nav.sources.label"), Lead: msg.T("issuer.sources.lead"), Content: note})
}

// statusWriter writes a fixed status with the first header or body.
type statusWriter struct {
	http.ResponseWriter
	status int
	sent   bool
}

func (s *statusWriter) WriteHeader(int) {
	if !s.sent {
		s.sent = true
		s.ResponseWriter.WriteHeader(s.status)
	}
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.WriteHeader(s.status)
	return s.ResponseWriter.Write(b)
}

// caps returns the capability answer of the adapter of the own pair,
// from the probe. A pair the probe does not see gives an empty answer.
func caps(f staffshell.Frame) *backendv1.GetCapabilitiesResponse {
	if own, ok := f.Own(); ok && own.Capabilities != nil {
		return own.Capabilities
	}
	return &backendv1.GetCapabilitiesResponse{}
}

// stackName is the name of the stack of the pair as its adapter reports
// it (ADR-001 decision 4).
func stackName(c *backendv1.GetCapabilitiesResponse) string {
	if name := c.GetDpgInfo().GetDisplayName(); name != "" {
		return name
	}
	return msg.T("issuer.stack.this.label")
}

// blocks renders components and keeps the first error.
type blocks struct {
	kit *components.Kit
	err error
}

func (b *blocks) add(name string, data any) template.HTML {
	if b.err != nil {
		return ""
	}
	h, err := b.kit.HTML(name, data)
	if err != nil {
		b.err = err
	}
	return h
}

func (p *Pages) blocks() *blocks { return &blocks{kit: p.opts.Kit} }

// link returns an anchor with escaped parts.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
}

// hiddenInput returns one escaped hidden input.
func hiddenInput(name, value string) template.HTML {
	return template.HTML(`<input type="hidden" name="` + template.HTMLEscapeString(name) + `" value="` + template.HTMLEscapeString(value) + `">`) //nolint:gosec // both parts are escaped
}

// form wraps parts in a POST form with the synchronizer token of the
// session. multipart sets the encoding of a file upload.
func form(pg page, action string, multipart bool, parts ...template.HTML) template.HTML {
	enc := ""
	if multipart {
		enc = ` enctype="multipart/form-data"`
	}
	open := template.HTML(`<form method="post" action="` + template.HTMLEscapeString(action) + `"` + enc + `>`) //nolint:gosec // the action is escaped
	return open + staffsession.HiddenField(pg.r.Context()) + components.Join(parts...) + template.HTML(`</form>`)
}

// actionRow puts buttons from the kit in one row.
func actionRow(parts ...template.HTML) template.HTML {
	return template.HTML(`<div class="form-actions">`) + components.Join(parts...) + template.HTML(`</div>`)
}

// sourcePath returns the path of one source page, with the schema of a
// bulk run in the query when there is one.
func sourcePath(id, suffix, ref string) string {
	path := Prefix + url.PathEscape(id) + suffix
	if ref != "" {
		path += "?" + url.Values{"schema": {ref}}.Encode()
	}
	return path
}

// schemaRef names one schema version: the id and the version.
func schemaRef(s *schemav1.Schema) string { return s.GetId() + "@" + strconv.Itoa(int(s.GetVersion())) }

// parseRef reads a schema reference. A reference without a version
// selects the latest published version.
func parseRef(ref string) (string, int32, bool) {
	ref = strings.TrimSpace(ref)
	id, version := ref, int32(0)
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		n, err := strconv.ParseInt(ref[i+1:], 10, 32)
		if err != nil || n < 1 {
			return "", 0, false
		}
		id, version = ref[:i], int32(n)
	}
	return id, version, id != ""
}

// schemaOf reads the schema of a reference. ok is false when the
// reference is empty or names no schema.
func (p *Pages) schemaOf(ctx context.Context, ref string) (*schemav1.Schema, bool, error) {
	id, version, ok := parseRef(ref)
	if !ok || p.opts.Schemas == nil {
		return nil, false, nil
	}
	res, err := p.opts.Schemas.Get(ctx, staffshell.AsActor(ctx, &schemav1.GetRequest{Id: id, Version: version}))
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return res.Msg.GetSchema(), res.Msg.GetSchema() != nil, nil
}

// schemaName is the display name of a schema in English, or its type.
func schemaName(s *schemav1.Schema) string {
	for _, d := range s.GetDisplay() {
		if d.GetName() != "" && (d.GetLocale() == "" || strings.HasPrefix(d.GetLocale(), "en")) {
			return d.GetName()
		}
	}
	if s.GetType() != "" {
		return s.GetType()
	}
	return s.GetId()
}

// stepper returns the progress of a bulk run for a page, or nothing when
// the page shows no run.
func (p *Pages) stepper(b *blocks, current int) template.HTML {
	return b.add("stepper", components.Stepper{
		Label: msg.T("issuer.sources.progress.label"), Current: current,
		Steps: []string{msg.T("issuer.issue.step.schema.label"), msg.T("issuer.sources.step.source.label"),
			msg.T("issuer.sources.step.map.label"), msg.T("issuer.sources.step.run.label")},
	})
}

// The steps of a bulk run, counted from 1.
const (
	stepSource = 2
	stepMap    = 3
	stepRun    = 4
)

// chosen names the schema of a bulk run in one table row, with a link to
// pick another one in the issue wizard.
func (p *Pages) chosen(b *blocks, s *schemav1.Schema) template.HTML {
	return b.add("table", components.Table{
		ID: "chosen", Caption: msg.T("issuer.issue.chosen.caption.label"),
		Columns: []string{msg.T("issuer.issue.step.schema.label"), msg.T("common.version.label"), msg.T("issuer.issue.column.action.label")},
		Rows: []components.Row{{
			{Text: schemaName(s)}, {Text: strconv.Itoa(int(s.GetVersion()))}, {HTML: link(IssuePath, msg.T("common.change.label"))},
		}},
	})
}

// kindLabel names the kind of a source.
func kindLabel(s *datasourcev1.Source) string {
	switch s.GetKind().(type) {
	case *datasourcev1.Source_Csv:
		return msg.T("issuer.sources.kind.csv.label")
	case *datasourcev1.Source_Sql:
		return msg.T("issuer.sources.kind.sql.label")
	}
	return msg.T("issuer.sources.kind.http.label")
}

// canIssue reports whether the staff member may start a run: an issuer
// operator or an issuer admin (ADR-012 decision 3).
func canIssue(ctx context.Context) bool {
	s, ok := staffsession.User(ctx)
	return ok && (s.HasRole(staffsession.IssuerOperatorRole) || s.HasRole(staffsession.IssuerAdminRole))
}

// roleDenied reports whether err is the refusal of a role rule of the
// service (VCA-302). The address guard of an HTTP source refuses with
// the same code but without that detail, and a page reports it as a
// source it cannot read.
func roleDenied(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodePermissionDenied {
		return false
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if e, ok := v.(*commonv1.Error); ok && e.GetCode() == "VCA-302" {
				return true
			}
		}
	}
	return false
}

// errForbidden answers an action the role of the staff member does not
// allow.
var errForbidden = connect.NewError(connect.CodePermissionDenied, errors.New("the role cannot do this"))
