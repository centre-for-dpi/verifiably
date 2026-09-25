// SPDX-License-Identifier: Apache-2.0

// Package pages renders the issuer home and the issuer pages that the
// issuance service owns (ADR-044 decision 1), inside the issuer shell of
// services/internal/staffshell. Every page is a thin client of the RPCs
// of the issuer pair, so the pages and the API cannot diverge.
//
// Paths:
//
//	GET  /issuer/          the overview: the steps, the counts, the activity
//	POST /issuer/signout   end the session at issuer-auth
//	GET  /identity/        the issuer identity
//	POST /identity/provision  ask the stack for a new identity
//	POST /identity/import     check or import a DID or an X.509 chain
//	GET  /issue/           step 1 of the issue wizard: the schema
//	GET  /issue/source     step 2: the source, then the claim form
//	POST /issue/source     step 2 again, with the claims posted so far
//	POST /issue/delivery   step 3: the delivery channels of the pair
//	POST /issue/review     step 4: what the stack will issue
//	POST /issue/offers     issue, then go to the result
//	GET  /issue/offers/{id} the result: QR code, code, link, document
//	GET  /notifications/   the delivery channels of the issuer
//	GET  /help/            every issuer RPC with its help text
//
// The guard of the service checks the session and the synchronizer
// token before a request reaches a page.
package pages

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The paths of the pages.
const (
	HomePath          = "/issuer/"
	IdentityPath      = "/identity/"
	IssuePath         = "/issue/"
	NotificationsPath = "/notifications/"
	HelpPath          = "/help/"
	SignOutPath       = "/issuer/signout"
	// SchemasPath and BuilderPath are the pages of the schema registry and
	// the schema builder on the same host.
	SchemasPath = "/portal/"
	BuilderPath = "/builder/"
)

// Prefixes lists the path prefixes the pages take. The service puts the
// guard in front of each one.
func Prefixes() []string {
	return []string{HomePath, IdentityPath, IssuePath, NotificationsPath, HelpPath}
}

// Capability reads the capability answer of the adapter of the pair.
type Capability interface {
	GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (
		*connect.Response[backendv1.GetCapabilitiesResponse], error)
}

// Schemas lists and reads the schemas of the schema registry of the pair.
type Schemas interface {
	List(context.Context, *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error)
	Get(context.Context, *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error)
}

// Issued lists the records of the issued credentials service of the pair.
type Issued interface {
	List(context.Context, *connect.Request[issuedv1.ListRequest]) (*connect.Response[issuedv1.ListResponse], error)
}

// Options configure the pages.
type Options struct {
	// Kit renders the components. Required.
	Kit *components.Kit
	// Shell draws the issuer frame. Required.
	Shell *staffshell.Shell
	// Capability reads the adapter of the pair. Required.
	Capability Capability
	// Schemas reads the schema registry. Nil shows no schema count.
	Schemas Schemas
	// Issued reads the issued credentials. Nil shows no issued count.
	Issued Issued
	// Issuance issues and reads offers, in process. Nil answers the
	// issue step and the result with 404.
	Issuance Issuance
	// Identity reads and changes the issuer identity of the adapter. Nil
	// shows the identity as kept by the stack.
	Identity Identity
	// Trust returns the client of the trust registry at a URL. Nil asks
	// no registry for an entry.
	Trust func(url string) Trust
	// Audit keeps the events of the pages (ADR-039 decision 1). Nil
	// writes none.
	Audit *auditlog.Log
	// SignOut ends the session. Nil answers the sign out form with 404.
	SignOut http.Handler
	// PublicURL is the public URL of the pair.
	PublicURL string
	// DocsURL is the base of the documents the help page links, for
	// example the docs folder of the repository. Empty means DefaultDocsURL.
	DocsURL string
}

// Pages serves the issuer pages of the issuance service.
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
	case opts.Capability == nil:
		return nil, errors.New("pages: an adapter capability client is required")
	}
	opts.PublicURL = strings.TrimRight(opts.PublicURL, "/")
	return &Pages{opts: opts}, nil
}

// Register adds the pages to mux.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+HomePath+"{$}", p.handle(p.overview))
	mux.HandleFunc("GET "+IdentityPath+"{$}", p.handle(p.identity))
	mux.HandleFunc("POST "+IdentityPath+"provision", p.handle(p.provision))
	mux.HandleFunc("POST "+IdentityPath+"import", p.handle(p.importIdentity))
	mux.HandleFunc("GET "+IssuePath+"{$}", p.handle(p.issue))
	mux.HandleFunc("GET "+IssueSourcePath, p.handle(p.source))
	mux.HandleFunc("POST "+IssueSourcePath, p.handle(p.source))
	mux.HandleFunc("POST "+IssueDeliveryPath, p.handle(p.delivery))
	mux.HandleFunc("POST "+IssueReviewPath, p.handle(p.review))
	mux.HandleFunc("POST "+IssueOffersPath, p.handle(p.create))
	mux.HandleFunc("GET "+IssueOffersPath+"/{id}", p.handle(p.result))
	mux.HandleFunc("GET "+NotificationsPath+"{$}", p.handle(p.notifications))
	mux.HandleFunc("GET "+HelpPath+"{$}", p.handle(p.help))
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
	return p.opts.Shell.Render(p.opts.Kit, pg.w, pg.r, pg.f, cp)
}

// forbidden answers a step the role of the staff member does not allow
// with 403 and a page that says why.
func (p *Pages) forbidden(pg page) error {
	b := p.blocks()
	note := b.add("block", components.Block{ID: "role", Title: msg.T("issuer.issue.role.label"), Lead: msg.T("issuer.issue.role.text"),
		Body: b.add("button", components.Button{Text: msg.T("issuer.identity.back.label"), Href: HomePath})})
	if b.err != nil {
		return b.err
	}
	pg.w = &statusWriter{ResponseWriter: pg.w, status: http.StatusForbidden}
	return p.render(pg, components.Page{Title: msg.T("issuer.nav.issue.label"), Lead: msg.T("issuer.issue.lead"), Content: note})
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

// caps returns the capability answer of the own adapter: from the probe
// when the own pair is live, else from the adapter itself. A failed call
// gives an empty answer, so a page still draws.
func (p *Pages) caps(pg page) *backendv1.GetCapabilitiesResponse {
	if own, ok := pg.f.Own(); ok && own.Capabilities != nil {
		return own.Capabilities
	}
	res, err := p.opts.Capability.GetCapabilities(pg.r.Context(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		return &backendv1.GetCapabilitiesResponse{}
	}
	return res.Msg
}

// has reports whether the own adapter lists a feature.
func has(caps *backendv1.GetCapabilitiesResponse, feature backendv1.Feature) bool {
	for _, f := range caps.GetFeatures() {
		if f == feature {
			return true
		}
	}
	return false
}

// stackName is the name of the stack of the pair as its adapter reports
// it (ADR-001 decision 4).
func stackName(caps *backendv1.GetCapabilitiesResponse) string {
	if name := caps.GetDpgInfo().GetDisplayName(); name != "" {
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

// escape returns text as HTML.
func escape(text string) template.HTML {
	return template.HTML(template.HTMLEscapeString(text)) //nolint:gosec // the text is escaped
}

// link returns an anchor with escaped parts.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
}
