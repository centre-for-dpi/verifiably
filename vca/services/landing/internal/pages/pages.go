// SPDX-License-Identifier: Apache-2.0

// Package pages renders the landing, the stacks fragment, the deployment
// descriptor, the role picker, and the role intro pages (ADR-033). Every
// page is composed from kit components, and every sentence comes from
// the message catalogue.
package pages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/descriptor"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Source gives the pages the state of every peer. A topology.Prober is
// one; a test passes a fixed snapshot.
type Source interface {
	Snapshot(ctx context.Context) topology.Snapshot
}

// External links of the primer tiles.
const (
	dpgStandardURL = "https://digitalpublicgoods.net/standard/"
	vcDataModelURL = "https://www.w3.org/TR/vc-data-model-2.0/"
	ecosystemURL   = vcDataModelURL + "#ecosystem-overview"
)

// refreshEvery is the htmx trigger of the stacks block.
const refreshEvery = "every 30s"

// listingTimeout bounds the read of the sign in listing of a pair. The
// intro page renders without it.
const listingTimeout = time.Second

// ProviderSource reads the sign in listing of an auth service at base
// (P1-08). signin.Fetch is one; a test passes a fixed table.
type ProviderSource func(ctx context.Context, base string) (signin.Listing, error)

// Renderer renders the components and the pages. A components.Kit is
// one; a test passes one that fails on purpose.
type Renderer interface {
	HTML(name string, data any) (template.HTML, error)
	RenderPage(w http.ResponseWriter, r *http.Request, page components.Page) error
}

// Options configure New.
type Options struct {
	// Kit renders the components. Required.
	Kit Renderer
	// Source gives the peer states. Required.
	Source Source
	// Version is the image version the page and the descriptor show.
	Version string
	// PublicURL is the address of the landing. The descriptor carries it.
	PublicURL string
	// RepositoryURL is the source repository the header links to.
	RepositoryURL string
	// DocsURL is the documentation the header links to.
	DocsURL string
	// Now returns the current time for the "updated" line. Nil means
	// time.Now.
	Now func() time.Time
	// Providers reads the sign in listing of a pair, so the intro page
	// names the realm of the role. Nil selects signin.Fetch with a one
	// second client.
	Providers ProviderSource
}

// Pages serves the landing routes.
type Pages struct {
	opts Options
}

// New checks the options.
func New(opts Options) (*Pages, error) {
	if opts.Kit == nil {
		return nil, errors.New("pages: a kit is required")
	}
	if opts.Source == nil {
		return nil, errors.New("pages: a peer source is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Providers == nil {
		client := &http.Client{Timeout: listingTimeout}
		opts.Providers = func(ctx context.Context, base string) (signin.Listing, error) {
			return signin.Fetch(ctx, client, base)
		}
	}
	return &Pages{opts: opts}, nil
}

// Register mounts the routes on mux. Every other path gets the not
// found page.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", p.landing)
	mux.HandleFunc("GET /stacks", p.stacks)
	mux.HandleFunc("GET /.well-known/vca.json", p.descriptor)
	mux.HandleFunc("GET /roles/{$}", p.roles)
	mux.HandleFunc("GET /roles/{role}/{$}", p.intro)
	mux.HandleFunc("/", p.notFound)
}

// overview probes the peers and reads the result.
func (p *Pages) overview(r *http.Request) (Overview, topology.Snapshot) {
	snap := p.opts.Source.Snapshot(r.Context())
	return NewOverview(snap), snap
}

// nav is the header of every landing page.
func (p *Pages) nav(current string) components.Nav {
	links := []components.Link{
		{Href: "/#how", Text: msg.T("landing.nav.how.label")},
		{Href: "/#stacks", Text: msg.T("landing.nav.stacks.label")},
	}
	if current == "/" {
		links[0].Href, links[1].Href = "#how", "#stacks"
	}
	if p.opts.DocsURL != "" {
		links = append(links, components.Link{Href: p.opts.DocsURL, Text: msg.T("landing.nav.docs.label")})
	}
	if p.opts.RepositoryURL != "" {
		links = append(links, components.Link{Href: p.opts.RepositoryURL, Text: msg.T("common.github.label")})
	}
	links = append(links, components.Link{Href: "/roles/", Text: msg.T("landing.nav.start.label"), Current: current == "/roles/"})
	return components.Nav{Label: msg.T("shell.main_nav.label"), Brand: components.Link{Href: "/"}, Links: links}
}

// page fills the parts every landing page shares.
func (p *Pages) page(current, title string, content template.HTML) components.Page {
	return components.Page{
		Title:   title,
		Nav:     p.nav(current),
		Content: content,
		Footer:  msg.T("landing.footer"),
		Text:    layoutText(),
	}
}

// layoutText takes the layout words from the catalogue.
func layoutText() components.Text {
	return components.Text{
		SkipLink: msg.T("layout.skip.label"), ThemeToggle: msg.T("layout.theme.label"), ThemeSystem: msg.T("layout.theme.system.label"),
		ThemeLight: msg.T("layout.theme.light.label"), ThemeDark: msg.T("layout.theme.dark.label"),
	}
}

// render writes a page with the status, or the render failed message.
// The page renders into a buffer first, so a failure never leaves half a
// page behind a 200 or a 404.
func (p *Pages) render(w http.ResponseWriter, r *http.Request, status int, page components.Page) {
	buf := &bufferedResponse{header: http.Header{}}
	if err := p.opts.Kit.RenderPage(buf, r, page); err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	for name, values := range buf.header {
		w.Header()[name] = values
	}
	w.WriteHeader(status)
	anyval.DiscardWrite(w.Write(buf.body.Bytes()))
}

// bufferedResponse collects a rendered page before anything reaches the
// client.
type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) WriteHeader(int)             {}

// html renders one component, or fails the page.
func (p *Pages) html(name string, data any) (template.HTML, error) {
	return p.opts.Kit.HTML(name, data)
}

// notFound is the page of every unknown path.
func (p *Pages) notFound(w http.ResponseWriter, r *http.Request) {
	empty, err := p.html("empty", components.Empty{
		Title:  msg.T("common.not_found"),
		Action: components.Button{Text: msg.T("common.back.label"), Href: "/", Variant: "primary"},
	})
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	page := p.page(r.URL.Path, msg.T("landing.title.label"), empty)
	page.Heading = msg.T("common.not_found")
	p.render(w, r, http.StatusNotFound, page)
}

// descriptor serves /.well-known/vca.json.
func (p *Pages) descriptor(w http.ResponseWriter, r *http.Request) {
	_, snap := p.overview(r)
	doc := descriptor.Build(p.opts.Version, p.opts.PublicURL, snap)
	data, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	anyval.DiscardWrite(w.Write(data))
}
