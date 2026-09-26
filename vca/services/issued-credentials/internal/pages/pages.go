// SPDX-License-Identifier: Apache-2.0

// Package pages renders the issued credentials pages of the issuer
// inside the issuer shell of services/internal/staffshell (P3-10,
// ADR-017 decision 3, ADR-044 decision 2). Every page calls the
// IssuedService of the service in process and names the staff member
// of the session in X-Vca-Actor, so the audit log of the service holds
// each change and each export.
//
// Paths:
//
//	GET  /issued/                     the list: search, filters, table
//	GET  /issued/export.csv           the rows of the filters as CSV
//	GET  /issued/export.json          the rows of the filters as JSON lines
//	GET  /issued/sync                 the ledger search, with FEATURE_ISSUED_LEDGER
//	POST /issued/sync                 add the ledger entries the log lacks
//	GET  /issued/{id}                 the stored fields, the record, the history
//	GET  /issued/{id}?action=         the same page with the reason dialog open
//	POST /issued/{id}/suspend         suspend with a reason
//	POST /issued/{id}/revoke          revoke with a reason
//	POST /issued/{id}/reinstate       end a suspension with a reason
//	POST /issued/signout              end the session at issuer-auth
//
// The guard of the service checks the session and the synchronizer
// token before a request reaches a page. The public chain head
// endpoints of the service stay outside the guard.
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

	"github.com/centre-for-dpi/vc-adapters/core/vc"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The paths of the pages.
const (
	Prefix         = "/issued/"
	SignOutPath    = "/issued/signout"
	ExportCSVPath  = "/issued/export.csv"
	ExportJSONPath = "/issued/export.json"
	// IssuePath is the issue wizard of the issuance service on the same
	// host.
	IssuePath = "/issue/"
)

// DefaultPageSize is the number of rows of one list page.
const DefaultPageSize = 25

// Records is the IssuedService of this service, called in process.
type Records interface {
	Search(context.Context, *connect.Request[issuedv1.SearchRequest]) (*connect.Response[issuedv1.SearchResponse], error)
	Get(context.Context, *connect.Request[issuedv1.GetRequest]) (*connect.Response[issuedv1.GetResponse], error)
	Revoke(context.Context, *connect.Request[issuedv1.RevokeRequest]) (*connect.Response[issuedv1.RevokeResponse], error)
	Reinstate(context.Context, *connect.Request[issuedv1.ReinstateRequest]) (*connect.Response[issuedv1.ReinstateResponse], error)
	// ExportTo writes the export and its audit event with the actor of
	// the context.
	ExportTo(ctx context.Context, m *issuedv1.ExportRequest, out service.Sender) error
	// History returns the audit events of one record, oldest first.
	History(ctx context.Context, id string) ([]auditlog.Record, error)
	// SchemaIDs returns the schema of every record, once each.
	SchemaIDs() []string
	// Sync adds the entries of the stack ledger that the log lacks.
	Sync(ctx context.Context, q service.SyncQuery) ([]service.SyncRow, error)
}

// Stack is the DPG adapter of the pair as the pages see it.
type Stack interface {
	// Has reports whether the adapter lists a feature now.
	Has(ctx context.Context, feature backendv1.Feature) bool
	// Name is the name of the stack as the adapter reports it.
	Name(ctx context.Context) string
	// Pending reports an offer that no wallet claimed yet.
	Pending(ctx context.Context, offerID string) bool
}

// Options configure the pages.
type Options struct {
	// Kit renders the components. Required.
	Kit *components.Kit
	// Shell draws the issuer frame. Required.
	Shell *staffshell.Shell
	// Records is the service of the pages. Required.
	Records Records
	// Stack is the adapter of the pair. Nil lists no feature, so a
	// revoke goes to the status services of VCA and no offer state shows.
	Stack Stack
	// SignOut ends the session. Nil answers the sign out form with 404.
	SignOut http.Handler
	// PageSize is the number of rows of one list page. Zero means
	// DefaultPageSize.
	PageSize int
}

// Pages serves the issued credentials pages.
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
	case opts.Records == nil:
		return nil, errors.New("pages: the issued credentials service is required")
	}
	if opts.PageSize <= 0 {
		opts.PageSize = DefaultPageSize
	}
	return &Pages{opts: opts}, nil
}

// Register adds the pages to mux.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+Prefix+"{$}", p.handle(p.list))
	mux.HandleFunc("GET "+ExportCSVPath, p.handle(p.exportAs(issuedv1.ExportRequest_ENCODING_CSV)))
	mux.HandleFunc("GET "+ExportJSONPath, p.handle(p.exportAs(issuedv1.ExportRequest_ENCODING_JSON)))
	mux.HandleFunc("GET "+SyncPath, p.handle(p.syncPage))
	mux.HandleFunc("POST "+SyncPath, p.handle(p.sync))
	mux.HandleFunc("GET "+Prefix+"{id}", p.handle(p.detail))
	mux.HandleFunc("POST "+Prefix+"{id}/{action}", p.handle(p.change))
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

// ctx returns the context of the request with the staff member as the
// actor of the audit log.
func (pg page) ctx() context.Context {
	ctx := pg.r.Context()
	return auditlog.WithActor(ctx, staffshell.Actor(ctx))
}

// handle reads the frame and answers a short sentence when the page
// fails.
func (p *Pages) handle(fn func(pg page) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pg := page{w: w, r: r, f: p.opts.Shell.Frame(r.Context())}
		err := fn(pg)
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			err = p.forbidden(pg)
		}
		switch {
		case err == nil:
		case connect.CodeOf(err) == connect.CodeNotFound:
			http.Error(w, msg.T("common.not_found"), http.StatusNotFound)
		default:
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
	case connect.CodeUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// render writes a page inside the issuer frame.
func (p *Pages) render(pg page, cp components.Page) error {
	if cp.Label == "" {
		cp.Label = msg.T("issuer.issued.label")
	}
	if cp.Description == "" {
		cp.Description = msg.T("issuer.issued.lead")
	}
	return p.opts.Shell.Render(p.opts.Kit, pg.w, pg.r, pg.f, cp)
}

// forbidden answers an action the role of the staff member does not
// allow with 403 and a page that says why.
func (p *Pages) forbidden(pg page) error {
	b := p.blocks()
	note := b.add("block", components.Block{ID: "role", Title: msg.T("issuer.issued.role.label"), Lead: msg.T("issuer.issued.role.text"),
		Body: b.add("button", components.Button{Text: msg.T("issuer.nav.issued.label"), Href: Prefix})})
	if b.err != nil {
		return b.err
	}
	pg.w = &statusWriter{ResponseWriter: pg.w, status: http.StatusForbidden}
	return p.render(pg, components.Page{Title: msg.T("issuer.nav.issued.label"), Lead: msg.T("issuer.issued.lead"), Content: note})
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

// has reports whether the adapter of the pair lists a feature.
func (p *Pages) has(ctx context.Context, feature backendv1.Feature) bool {
	return p.opts.Stack != nil && p.opts.Stack.Has(ctx, feature)
}

// stackName is the name of the stack of the pair as its adapter reports
// it (ADR-001 decision 4).
func (p *Pages) stackName(ctx context.Context) string {
	if p.opts.Stack != nil {
		if name := p.opts.Stack.Name(ctx); name != "" {
			return name
		}
	}
	return msg.T("issuer.stack.this.label")
}

// canAct reports whether the staff member may change a status: an
// issuer operator or an issuer admin (ADR-012 decision 3).
func canAct(ctx context.Context) bool {
	s, ok := staffsession.User(ctx)
	return ok && (s.HasRole(staffsession.IssuerOperatorRole) || s.HasRole(staffsession.IssuerAdminRole))
}

// errForbidden answers an action the role of the staff member does not
// allow.
var errForbidden = connect.NewError(connect.CodePermissionDenied, errors.New("the role cannot change a status"))

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

// code returns text in a code element.
func code(text string) template.HTML {
	return template.HTML(`<code>` + template.HTMLEscapeString(text) + `</code>`) //nolint:gosec // the text is escaped
}

// recordPath returns the path of the page of one record, with a query
// when q has values.
func recordPath(id string, q url.Values) string {
	path := Prefix + url.PathEscape(id)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return path
}

// shortID is the first part of a record id, for a heading or a link.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// schemaText names a schema version, for example "farmer v2".
func schemaText(id string, version int32) string {
	return msg.T("issuer.issued.schema.value.label", vc.TypeTitle(id), strconv.Itoa(int(version)))
}

// subjectText is the searchable claim values of a record: a claim whose
// name holds "name" first, then the rest in the order of their names. A
// record without one shows the start of its subject reference.
func subjectText(r *issuedv1.IssuedRecord) string {
	claims := r.GetSearchableClaims()
	if len(claims) == 0 {
		return shortID(r.GetSubject().GetRef())
	}
	var names, rest []string
	for _, key := range sortedKeys(claims) {
		if strings.Contains(strings.ToLower(key), "name") {
			names = append(names, claims[key])
		} else {
			rest = append(rest, claims[key])
		}
	}
	return strings.Join(append(names, rest...), ", ")
}
