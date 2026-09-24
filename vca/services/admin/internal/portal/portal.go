// SPDX-License-Identifier: Apache-2.0

// Package portal renders the super admin portal with the vca UI kit
// (ADR-009 decision 1). Every page is a thin client of one
// vca.admin.v1.AdminService RPC, so the portal and the CLI cannot
// diverge.
//
// Paths, under the configured prefix:
//
//	GET  /                       the dashboard with the service health
//	GET  /login                  the OpenID Connect login page
//	GET  /tenants                the tenant list with the create form
//	POST /tenants                create one tenant
//	POST /tenants/{id}/delete    remove one tenant
//	GET  /trust                  the trust entry list with the add form
//	POST /trust                  create or replace one trust entry
//	POST /trust/delete           remove one trust entry
//	GET  /providers              the login provider table (board Admin-Providers)
//	GET  /providers/new          the provider form with the kind presets
//	POST /providers              save a new provider and push it to the live pairs
//	POST /providers/test         read the metadata of the typed issuer (htmx fragment)
//	GET  /providers/{id}         the edit form of one provider
//	POST /providers/{id}         save the changes and push them
//	POST /providers/{id}/enable  turn one provider on or off
//	POST /providers/{id}/delete  remove one provider
//	GET  /keys                   the API key list with the create form
//	POST /keys                   create one API key
//	POST /keys/{id}/revoke       revoke one API key
//	GET  /audit                  the audit log with filters
//	GET  /help                   every RPC with its help text
//
// Every browser POST carries a synchronizer token and the session
// cookie is SameSite=Lax (ADR-010 decision 7). A page without a super
// admin session redirects to the login page.
package portal

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the portal pages.
const DefaultPrefix = "/admin"

// MaxFormBytes caps a posted form.
const MaxFormBytes = 1 << 20

// TimeFormat is how every page prints a time.
const TimeFormat = "2006-01-02 15:04 UTC"

// Options configure the portal.
type Options struct {
	// Client calls the AdminService. The service satisfies it in process.
	Client adminv1connect.AdminServiceClient
	// Login checks the session and the synchronizer token.
	Login *login.Service
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Prefix is the URL prefix of the pages. Empty means DefaultPrefix.
	Prefix string
	// LoginPath is where the login page sends the browser. Empty means
	// /auth/login.
	LoginPath string
	// RegisterPath is where the register action sends the browser. Empty
	// means /auth/register.
	RegisterPath string
	// LandingURL is the public URL of the landing. The login page links
	// back to its role picker. Empty hides the link.
	LandingURL string
	// PublicURL is the public URL of this admin pair. The stack switcher
	// of the shell marks the pair whose public URL matches it current.
	PublicURL string
	// Snapshot returns the state of every peer of the deployment. The
	// shell draws the stack switcher and the feature gates from it. Nil
	// means the deployment names no peers: no switcher, no gate.
	Snapshot func(ctx context.Context) topology.Snapshot
	// Fetcher reads the metadata document of the "Test discovery" action
	// through the guard against server side request forgery. Nil builds
	// a fetcher that reaches public https hosts only.
	Fetcher *fetchguard.Fetcher
}

// Portal serves the admin pages.
type Portal struct {
	opts    Options
	chooser *signin.Chooser
}

// New builds the portal.
func New(opts Options) (*Portal, error) {
	if opts.Client == nil {
		return nil, errors.New("portal: an AdminService client is required")
	}
	if opts.Login == nil {
		return nil, errors.New("portal: a login service is required")
	}
	if opts.Prefix == "" {
		opts.Prefix = DefaultPrefix
	}
	opts.Prefix = "/" + strings.Trim(opts.Prefix, "/")
	opts.PublicURL = strings.TrimRight(opts.PublicURL, "/")
	if opts.LoginPath == "" {
		opts.LoginPath = signin.DefaultLoginPath
	}
	if opts.RegisterPath == "" {
		opts.RegisterPath = signin.DefaultRegisterPath
	}
	if opts.Kit == nil {
		kit, err := components.New()
		if err != nil {
			return nil, err
		}
		opts.Kit = kit
	}
	if opts.Fetcher == nil {
		opts.Fetcher = fetchguard.New(fetchguard.Options{})
	}
	p := &Portal{opts: opts}
	chooser, err := signin.New(signin.Options{
		Kit: opts.Kit, Role: commonv1.Role_ROLE_ADMIN, Providers: opts.Login.Providers(), Metadata: opts.Login.Flow(),
		LoginPath: opts.LoginPath, RegisterPath: opts.RegisterPath, LandingURL: opts.LandingURL,
		Home: opts.Prefix + "/", Callout: true, Extra: p.bootstrapCard, Empty: msg.T("signin.admin.none"),
		Toasts: func(r *http.Request) []components.Toast { return notice(r.URL.Query().Get("notice")) },
	})
	if err != nil {
		return nil, err
	}
	p.chooser = chooser
	return p, nil
}

// Prefix returns the URL prefix of the pages.
func (p *Portal) Prefix() string { return p.opts.Prefix }

// Register adds the pages to mux.
func (p *Portal) Register(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/{$}", p.guarded(p.overview))
	mux.HandleFunc("GET "+at+"/login", p.chooser.Page)
	mux.HandleFunc("GET "+at+"/help", p.open(p.help))
	mux.HandleFunc("GET "+at+"/tenants", p.guarded(p.tenants))
	mux.HandleFunc("POST "+at+"/tenants", p.posted(p.createTenant))
	mux.HandleFunc("POST "+at+"/tenants/{id}/delete", p.posted(p.deleteTenant))
	mux.HandleFunc("GET "+at+"/trust", p.guarded(p.trust))
	mux.HandleFunc("POST "+at+"/trust", p.posted(p.addTrust))
	mux.HandleFunc("POST "+at+"/trust/delete", p.posted(p.deleteTrust))
	p.registerProviders(mux)
	mux.HandleFunc("GET "+at+"/keys", p.guarded(p.keys))
	mux.HandleFunc("POST "+at+"/keys", p.posted(p.createKey))
	mux.HandleFunc("POST "+at+"/keys/{id}/revoke", p.posted(p.revokeKey))
	mux.HandleFunc("GET "+at+"/audit", p.guarded(p.auditLog))
}

// session is the caller of one page.
type session struct {
	// Token is the raw session JWT. Every RPC call carries it.
	Token string
	// Claims are the session claims.
	Claims oidcflow.Claims
	// CSRF is a fresh synchronizer token for the next POST.
	CSRF string
}

// open serves a page that needs no session, for example the login page.
func (p *Portal) open(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, "the page could not render", statusOf(err))
		}
	}
}

// guarded serves a page that needs a super admin session.
func (p *Portal) guarded(fn func(http.ResponseWriter, *http.Request, session) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := p.session(r)
		if !ok {
			p.toLogin(w, r)
			return
		}
		if err := fn(w, r, s); err != nil {
			http.Error(w, "the page could not render", statusOf(err))
		}
	}
}

// posted serves a POST that needs a session and a synchronizer token.
func (p *Portal) posted(fn func(http.ResponseWriter, *http.Request, session) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "the form could not be read", http.StatusBadRequest)
			return
		}
		s, ok := p.session(r)
		if !ok {
			p.toLogin(w, r)
			return
		}
		if _, err := p.opts.Login.CheckCSRF(r.Context(), r); err != nil {
			http.Error(w, "the request needs a valid form token", http.StatusForbidden)
			return
		}
		if err := fn(w, r, s); err != nil {
			http.Error(w, "the action failed", statusOf(err))
		}
	}
}

// session reads the session of a request.
func (p *Portal) session(r *http.Request) (session, bool) {
	id, err := p.opts.Login.Authenticate(r.Context(), r.Header)
	if err != nil || !id.IsSuperAdmin() {
		return session{}, false
	}
	token := oidcflow.TokenFromRequest(r, p.opts.Login.Cookie().Name)
	return session{Token: token, Claims: id.Session, CSRF: p.opts.Login.CSRFToken(id.Session.SID)}, true
}

// toLogin sends the browser to the login page.
func (p *Portal) toLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.opts.Prefix+"/login", http.StatusSeeOther)
}

// call returns a Connect request that carries the session token.
func call[T any](s session, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if s.Token != "" {
		req.Header().Set("Authorization", "Bearer "+s.Token)
	}
	return req
}

// statusOf maps a Connect code to an HTTP status.
func statusOf(err error) int {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		switch cerr.Code() {
		case connect.CodeNotFound:
			return http.StatusNotFound
		case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeAlreadyExists:
			return http.StatusBadRequest
		case connect.CodeUnauthenticated:
			return http.StatusUnauthorized
		case connect.CodePermissionDenied:
			return http.StatusForbidden
		}
	}
	return http.StatusInternalServerError
}

// blocks renders components and keeps the first error. A component fails
// only when its data is wrong, which is a programming fault, so one
// check for each page is enough.
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

func (p *Portal) blocks() *blocks { return &blocks{kit: p.opts.Kit} }

// form wraps content in a POST form with the synchronizer token.
func form(action, csrf string, content ...template.HTML) template.HTML {
	open := `<form class="filters" action="` + template.HTMLEscapeString(action) + `" method="post">` +
		`<input type="hidden" name="` + oidcflow.CSRFField + `" value="` + template.HTMLEscapeString(csrf) + `">`
	parts := append([]template.HTML{template.HTML(open)}, content...) //nolint:gosec // both parts are escaped
	return components.Join(append(parts, template.HTML(`</form>`))...)
}

// getForm wraps content in a GET form, for filters and the login page.
func getForm(action string, content ...template.HTML) template.HTML {
	open := `<form class="filters" action="` + template.HTMLEscapeString(action) + `" method="get">`
	parts := append([]template.HTML{template.HTML(open)}, content...) //nolint:gosec // both parts are escaped
	return components.Join(append(parts, template.HTML(`</form>`))...)
}

// Notices maps a notice code to the sentence the page shows.
var Notices = map[string]components.Toast{
	"tenant-created":    {Level: "ok", Text: "The tenant is created."},
	"tenant-deleted":    {Level: "warn", Text: "The tenant is removed with every record it owns."},
	"trust-saved":       {Level: "ok", Text: "The trust entry is saved. The registry publishes it again."},
	"trust-deleted":     {Level: "warn", Text: "The trust entry is removed from the lists."},
	"provider-added":    {Level: "ok", Text: "The login provider is ready. Its roles can sign in with it."},
	"provider-saved":    {Level: "ok", Text: "The login provider is saved."},
	"provider-enabled":  {Level: "ok", Text: "The login provider is on. Its roles can sign in with it."},
	"provider-disabled": {Level: "warn", Text: "The login provider is off. New sign ins with it fail."},
	"provider-removed":  {Level: "warn", Text: "The login provider is removed. Its sessions end."},
	"key-revoked":       {Level: "warn", Text: "The API key is revoked. Calls with it fail now."},
	"signed-out":        {Level: "info", Text: "You are signed out."},
}

// notice returns the toast of a notice query value.
func notice(value string) []components.Toast {
	if t, ok := Notices[value]; ok {
		return []components.Toast{t}
	}
	return nil
}

// Chooser returns the sign in chooser of the admin role (ADR-035, board
// Signin-Admin). The app mounts its page and listing under /auth too.
func (p *Portal) Chooser() *signin.Chooser { return p.chooser }

// bootstrapCard is the extra block of the admin chooser (ADR-010
// decision 4, ADR-035 decision 6): the bootstrap token with a sign in
// and a register action, both of which bind the first super admin. The
// page has no password field at all.
func (p *Portal) bootstrapCard(returnTo string) (template.HTML, error) {
	b := p.blocks()
	// With one provider the form names it in a hidden field. Otherwise
	// the admin types the id.
	provider := b.add("field", components.Field{
		ID: "provider", Label: msg.T("signin.admin.provider.label"), Hint: msg.T("signin.admin.provider.hint"),
	})
	if enabled := p.opts.Login.Providers().Enabled(); len(enabled) == 1 {
		provider = template.HTML(`<input type="hidden" name="provider" value="` + template.HTMLEscapeString(enabled[0].ID) + `">`) //nolint:gosec // the value is escaped
	}
	card := b.add("card", components.Card{
		ID: "bootstrap", Title: msg.T("signin.admin.bootstrap.label"),
		Text: msg.T("signin.admin.bootstrap.text"),
		Body: getForm(p.opts.LoginPath,
			provider,
			b.add("field", components.Field{
				ID: login.BootstrapField, Label: msg.T("signin.admin.token.label"), Type: "password",
			}),
			template.HTML(`<input type="hidden" name="return_to" value="`+template.HTMLEscapeString(returnTo)+`">`), //nolint:gosec // the value is escaped
			b.add("button", components.Button{Text: msg.T("signin.admin.bind.label"), Type: "submit", Variant: "primary"}),
			b.add("button", components.Button{Text: msg.T("signin.admin.register_bind.label"), Type: "submit", Attrs: map[string]string{"formaction": p.opts.RegisterPath}}),
		),
	})
	return card, b.err
}

// checkedText returns the reader facing probe result of one service.
func checkedText(svc *adminv1.GetServiceHealthResponse_ServiceHealth) string {
	if svc.GetError() != "" {
		return svc.GetError()
	}
	if svc.GetCheckedAt() == nil {
		return "Never"
	}
	return svc.GetCheckedAt().AsTime().UTC().Format(TimeFormat)
}

// displayName returns the name of the signed in admin.
func displayName(c oidcflow.Claims) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Subject
}

// tenants renders the tenant list with the create form.
func (p *Portal) tenants(w http.ResponseWriter, r *http.Request, s session) error {
	res, err := p.opts.Client.ListTenants(r.Context(), call(s, &adminv1.ListTenantsRequest{
		Page: &commonv1.Pagination{PageToken: r.URL.Query().Get("page_token")},
	}))
	if err != nil {
		return err
	}
	b := p.blocks()
	rows := make([]components.Row, 0, len(res.Msg.GetTenants()))
	for _, t := range res.Msg.GetTenants() {
		status, text := "warn", "Suspended"
		if t.GetState() == adminv1.Tenant_STATE_ACTIVE {
			status, text = "ok", "Active"
		}
		rows = append(rows, components.Row{
			{Text: t.GetDisplayName()},
			{Text: t.GetId()},
			{HTML: b.add("badge", components.Badge{Status: status, Text: text})},
			{Text: t.GetCreatedAt().AsTime().UTC().Format(TimeFormat)},
			{HTML: form(p.opts.Prefix+"/tenants/"+t.GetId()+"/delete", s.CSRF,
				b.add("button", components.Button{Text: "Delete", Type: "submit", Variant: "danger"}))},
		})
	}
	table := b.add("table", components.Table{
		ID: "tenants", Caption: fmt.Sprintf("Tenants, %d found", res.Msg.GetPage().GetTotalSize()),
		Columns: []string{"Name", "Id", "State", "Created", "Action"}, Rows: rows,
		Empty: "No tenant exists. Create the first tenant below.",
	})
	create := b.add("card", components.Card{
		ID: "create-tenant", Title: "New tenant",
		Body: form(p.opts.Prefix+"/tenants", s.CSRF,
			b.add("field", components.Field{ID: "display_name", Label: "Display name", Required: true}),
			b.add("button", components.Button{Text: "Create tenant", Type: "submit", Variant: "primary"}),
		),
	})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       "Tenants",
		Description: "A tenant is one operator organisation of the deployment.",
		Content:     components.Join(table, create),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// createTenant creates one tenant and returns to the list.
func (p *Portal) createTenant(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.CreateTenant(r.Context(), call(s, &adminv1.CreateTenantRequest{
		DisplayName: r.PostFormValue("display_name"),
	}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/tenants", "tenant-created")
	return nil
}

// deleteTenant removes one tenant.
func (p *Portal) deleteTenant(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.DeleteTenant(r.Context(), call(s, &adminv1.DeleteTenantRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/tenants", "tenant-deleted")
	return nil
}

// trust renders the trust entry list with the add form.
func (p *Portal) trust(w http.ResponseWriter, r *http.Request, s session) error {
	b := p.blocks()
	role := service.RoleValue(r.URL.Query().Get("role"))
	res, err := p.opts.Client.ListTrustEntries(r.Context(), call(s, &adminv1.ListTrustEntriesRequest{Role: role}))
	var table template.HTML
	switch {
	case err != nil && connect.CodeOf(err) == connect.CodeFailedPrecondition:
		table = b.add("card", components.Card{
			ID: "no-registry", Title: "No trust registry",
			Text: "Set VCA_ADMIN_TRUST_URL to the trust registry service. The portal edits the trust list through that service.",
		})
	case err != nil:
		return err
	default:
		rows := make([]components.Row, 0, len(res.Msg.GetEntries()))
		for _, e := range res.Msg.GetEntries() {
			rows = append(rows, components.Row{
				{Text: e.GetDisplayName()},
				{Text: identifierText(e.GetIdentifier())},
				{Text: service.RoleName(e.GetRole())},
				{HTML: b.add("badge", components.Badge{Status: statusBadge(e.GetStatus()), Text: statusText(e.GetStatus())})},
				{HTML: form(p.opts.Prefix+"/trust/delete", s.CSRF,
					template.HTML(`<input type="hidden" name="identifier" value="`+template.HTMLEscapeString(identifierText(e.GetIdentifier()))+`">`), //nolint:gosec // the value is escaped
					b.add("button", components.Button{Text: "Remove", Type: "submit", Variant: "danger"}))},
			})
		}
		table = b.add("table", components.Table{
			ID: "entries", Caption: fmt.Sprintf("Trust entries, %d found", len(rows)),
			Columns: []string{"Entity", "Identifier", "Role", "Status", "Action"}, Rows: rows,
			Empty: "The trust list is empty. Add the first entity below.",
		})
	}
	add := b.add("card", components.Card{
		ID: "add-entry", Title: "New trust entry",
		Text: "The registry publishes every enabled method again after the change.",
		Body: form(p.opts.Prefix+"/trust", s.CSRF,
			b.add("field", components.Field{ID: "identifier", Label: "DID or x509 subject", Required: true,
				Hint: "A value that starts with did: is a DID. Any other value is an x509 subject."}),
			b.add("field", components.Field{ID: "display_name", Label: "Display name", Required: true}),
			b.add("field", components.Field{ID: "role", Label: "Role", Type: "select", Options: []components.Option{
				{Value: "issuer", Text: "Issuer", Selected: true},
				{Value: "verifier", Text: "Verifier"},
				{Value: "holder", Text: "Holder"},
			}}),
			b.add("field", components.Field{ID: "status", Label: "Status", Type: "select", Options: []components.Option{
				{Value: "active", Text: "Active", Selected: true},
				{Value: "suspended", Text: "Suspended"},
				{Value: "revoked", Text: "Revoked"},
			}}),
			b.add("field", components.Field{ID: "service_endpoint", Label: "Service endpoint"}),
			b.add("button", components.Button{Text: "Save entry", Type: "submit", Variant: "primary"}),
		),
	})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       "Trust list",
		Description: "Edit the entities the deployment trusts. The trust registry signs and publishes the lists.",
		Content:     components.Join(table, add),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// addTrust creates or replaces one trust entry.
func (p *Portal) addTrust(w http.ResponseWriter, r *http.Request, s session) error {
	entry := &trustv1.TrustEntry{
		Identifier:      identifierOf(r.PostFormValue("identifier")),
		DisplayName:     r.PostFormValue("display_name"),
		Role:            service.RoleValue(r.PostFormValue("role")),
		Status:          statusValue(r.PostFormValue("status")),
		ServiceEndpoint: r.PostFormValue("service_endpoint"),
	}
	if _, err := p.opts.Client.UpsertTrustEntry(r.Context(), call(s, &adminv1.UpsertTrustEntryRequest{Entry: entry})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-saved")
	return nil
}

// deleteTrust removes one trust entry.
func (p *Portal) deleteTrust(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.DeleteTrustEntry(r.Context(), call(s, &adminv1.DeleteTrustEntryRequest{
		Identifier: identifierOf(r.PostFormValue("identifier")),
	}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/trust", "trust-deleted")
	return nil
}

// keys renders the API key list with the create form.
func (p *Portal) keys(w http.ResponseWriter, r *http.Request, s session) error {
	return p.keysPage(w, r, s, "", nil)
}

// keysPage renders the key list. A new secret is shown once, in a card.
func (p *Portal) keysPage(w http.ResponseWriter, r *http.Request, s session, secret string, toasts []components.Toast) error {
	tenantID := r.FormValue("tenant_id")
	res, err := p.opts.Client.ListApiKeys(r.Context(), call(s, &adminv1.ListApiKeysRequest{TenantId: tenantID}))
	if err != nil {
		return err
	}
	tenants, err := p.opts.Client.ListTenants(r.Context(), call(s, &adminv1.ListTenantsRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	rows := make([]components.Row, 0, len(res.Msg.GetKeys()))
	for _, k := range res.Msg.GetKeys() {
		status, text := "ok", "Active"
		if k.GetRevokedAt() != nil {
			status, text = "bad", "Revoked"
		}
		rows = append(rows, components.Row{
			{Text: k.GetDisplayName()},
			{Text: k.GetPrefix() + "..."},
			{Text: k.GetTenantId()},
			{Text: roleText(k.GetRoles())},
			{HTML: b.add("badge", components.Badge{Status: status, Text: text})},
			{HTML: form(p.opts.Prefix+"/keys/"+k.GetId()+"/revoke", s.CSRF,
				b.add("button", components.Button{Text: "Revoke", Type: "submit", Variant: "danger"}))},
		})
	}
	var shown template.HTML
	if secret != "" {
		shown = b.add("card", components.Card{
			ID: "new-secret", Title: "The new key secret",
			Text:   "Copy the value now. The service shows it once and stores only its hash.",
			Body:   template.HTML(`<p><code>` + template.HTMLEscapeString(secret) + `</code></p>`), //nolint:gosec // the value is escaped
			Footer: "Store the value in a secret manager.",
		})
	}
	table := b.add("table", components.Table{
		ID: "keys", Caption: fmt.Sprintf("API keys, %d found", len(rows)),
		Columns: []string{"Name", "Prefix", "Tenant", "Roles", "State", "Action"}, Rows: rows,
		Empty: "No API key exists. Create one below.",
	})
	options := make([]components.Option, 0, len(tenants.Msg.GetTenants()))
	for _, t := range tenants.Msg.GetTenants() {
		options = append(options, components.Option{Value: t.GetId(), Text: t.GetDisplayName()})
	}
	create := b.add("card", components.Card{
		ID: "create-key", Title: "New API key",
		Body: form(p.opts.Prefix+"/keys", s.CSRF,
			b.add("field", components.Field{ID: "display_name", Label: "Display name", Required: true}),
			b.add("field", components.Field{ID: "tenant_id", Label: "Tenant", Type: "select", Options: options}),
			b.add("field", components.Field{ID: "role", Label: "Role", Type: "select", Options: []components.Option{
				{Value: "admin", Text: "Admin", Selected: true},
				{Value: "issuer", Text: "Issuer"},
				{Value: "verifier", Text: "Verifier"},
				{Value: "holder", Text: "Holder"},
			}}),
			b.add("field", components.Field{ID: "expires_days", Label: "Days until expiry",
				Hint: "Leave the field empty for a key with no end."}),
			b.add("button", components.Button{Text: "Create key", Type: "submit", Variant: "primary"}),
		),
	})
	if b.err != nil {
		return b.err
	}
	if toasts == nil {
		toasts = notice(r.URL.Query().Get("notice"))
	}
	return p.render(w, r, s, components.Page{
		Title:       "API keys",
		Description: "A machine client calls the services with an API key.",
		Content:     components.Join(shown, table, create),
		Toasts:      toasts,
	})
}

// createKey creates one key and shows its secret once.
func (p *Portal) createKey(w http.ResponseWriter, r *http.Request, s session) error {
	req := &adminv1.CreateApiKeyRequest{
		DisplayName: r.PostFormValue("display_name"),
		TenantId:    r.PostFormValue("tenant_id"),
		Roles:       []commonv1.Role{service.RoleValue(r.PostFormValue("role"))},
	}
	if days := strings.TrimSpace(r.PostFormValue("expires_days")); days != "" {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("portal: the days value must be a positive number"))
		}
		req.ExpiresAt = timestamp(time.Now().AddDate(0, 0, n))
	}
	res, err := p.opts.Client.CreateApiKey(r.Context(), call(s, req))
	if err != nil {
		return err
	}
	return p.keysPage(w, r, s, res.Msg.GetSecret(), []components.Toast{{Level: "ok", Text: "The API key is created."}})
}

// revokeKey revokes one key.
func (p *Portal) revokeKey(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.RevokeApiKey(r.Context(), call(s, &adminv1.RevokeApiKeyRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/keys", "key-revoked")
	return nil
}

// auditLog renders the audit log with its filters (ADR-009 decision 6).
func (p *Portal) auditLog(w http.ResponseWriter, r *http.Request, s session) error {
	q := r.URL.Query()
	res, err := p.opts.Client.QueryAuditLog(r.Context(), call(s, &adminv1.QueryAuditLogRequest{
		Actor: strings.TrimSpace(q.Get("actor")), Action: strings.TrimSpace(q.Get("action")),
		Page: &commonv1.Pagination{PageToken: q.Get("page_token")},
	}))
	if err != nil {
		return err
	}
	b := p.blocks()
	rows := make([]components.Row, 0, len(res.Msg.GetRecords()))
	for _, rec := range res.Msg.GetRecords() {
		status, text := "bad", "Failed"
		if rec.GetOk() {
			status, text = "ok", "Done"
		}
		rows = append(rows, components.Row{
			{Text: rec.GetAt().AsTime().UTC().Format(TimeFormat)},
			{Text: rec.GetActor()},
			{Text: rec.GetAction()},
			{Text: rec.GetTarget()},
			{Text: rec.GetRequestId()},
			{HTML: b.add("badge", components.Badge{Status: status, Text: text})},
		})
	}
	filters := getForm(p.opts.Prefix+"/audit",
		b.add("field", components.Field{ID: "actor", Label: "Actor", Value: q.Get("actor")}),
		b.add("field", components.Field{ID: "action", Label: "Action", Value: q.Get("action")}),
		b.add("button", components.Button{Text: "Apply filters", Type: "submit"}),
	)
	table := b.add("table", components.Table{
		ID: "audit", Caption: fmt.Sprintf("Audit records, %d match", res.Msg.GetPage().GetTotalSize()),
		Columns: []string{"Time", "Actor", "Action", "Target", "Request id", "Result"}, Rows: rows,
		Empty: "No record matches the filters.",
	})
	var more template.HTML
	if token := res.Msg.GetPage().GetNextPageToken(); token != "" {
		more = b.add("button", components.Button{
			Text: "Next page",
			Href: p.opts.Prefix + "/audit?page_token=" + queryEscape(token) +
				"&actor=" + queryEscape(q.Get("actor")) + "&action=" + queryEscape(q.Get("action")),
		})
	}
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       "Audit log",
		Description: "Every admin action with its actor, its action, and its request id.",
		Content:     components.Join(filters, table, more),
	})
}

// help renders the help text of every RPC and every command from the
// proto descriptors (ADR-009 decisions 3 and 4). The CLI shows the same
// sentences. The page needs no session; with one, the shell shows the
// user menu.
func (p *Portal) help(w http.ResponseWriter, r *http.Request) error {
	s, _ := p.session(r)
	res, err := p.opts.Client.ListCommands(r.Context(), connect.NewRequest(&adminv1.ListCommandsRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	commandRows := make([]components.Row, 0, len(res.Msg.GetCommands()))
	for _, c := range res.Msg.GetCommands() {
		commandRows = append(commandRows, components.Row{
			{Text: c.GetPath()}, {Text: c.GetSummary()}, {Text: c.GetRpc()}, {Text: flagText(c.GetFlags())},
		})
	}
	commandTable := b.add("table", components.Table{
		ID: "commands", Caption: fmt.Sprintf("Commands, %d found", len(commandRows)),
		Columns: []string{"Command", "What it does", "RPC", "Flags"}, Rows: commandRows,
		Empty: "No command is registered.",
	})
	entries := helptext.Service(service.ServiceName)
	rpcRows := make([]components.Row, 0, len(entries))
	for _, e := range entries {
		rpcRows = append(rpcRows, components.Row{{Text: e.Method}, {Text: e.Description}})
	}
	rpcTable := b.add("table", components.Table{
		ID: "rpcs", Caption: fmt.Sprintf("RPCs, %d found", len(rpcRows)),
		Columns: []string{"RPC", "What it does"}, Rows: rpcRows,
		Empty: "No RPC description is available.",
	})
	intro := b.add("card", components.Card{
		ID: "intro", Title: "One sentence, four places",
		Text: "Each sentence below comes from the description option of the RPC in the proto file. " +
			"The CLI help, the man pages, this page, and the OpenAPI document read the same source.",
	})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       "Admin help",
		Description: "Every vca admin command and every admin RPC with its help text.",
		Content:     components.Join(intro, commandTable, rpcTable),
	})
}

// flagText returns the flags of one command as one sentence.
func flagText(flags []*adminv1.ListCommandsResponse_Flag) string {
	if len(flags) == 0 {
		return "None"
	}
	names := make([]string, 0, len(flags))
	for _, f := range flags {
		name := "--" + f.GetName()
		if f.GetMandatory() {
			name += " (required)"
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// roleText returns the roles of a key as one string.
func roleText(roles []commonv1.Role) string {
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		if name := service.RoleName(r); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// redirect sends the browser back to one page with a notice.
func (p *Portal) redirect(w http.ResponseWriter, r *http.Request, path, code string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.opts.Prefix+path+"?notice="+code, http.StatusSeeOther)
}

// queryEscape escapes one query value.
func queryEscape(value string) string { return url.QueryEscape(value) }

// timestamp returns the protobuf time of t.
func timestamp(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// identifierOf returns the trust identifier of a form value. A value
// that starts with did: is a DID.
func identifierOf(value string) *trustv1.TrustEntry_Identifier {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "did:") {
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: value}}
	}
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: value}}
}

// identifierText returns the reader facing identifier of an entry.
func identifierText(id *trustv1.TrustEntry_Identifier) string {
	if id.GetDid() != "" {
		return id.GetDid()
	}
	return id.GetX509Subject()
}

// statusValue returns the trust status of a form value.
func statusValue(value string) trustv1.Status {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active":
		return trustv1.Status_STATUS_ACTIVE
	case "suspended":
		return trustv1.Status_STATUS_SUSPENDED
	case "revoked":
		return trustv1.Status_STATUS_REVOKED
	}
	return trustv1.Status_STATUS_UNSPECIFIED
}

// statusText returns the reader facing words of a trust status.
func statusText(s trustv1.Status) string {
	switch s {
	case trustv1.Status_STATUS_ACTIVE:
		return "Active"
	case trustv1.Status_STATUS_SUSPENDED:
		return "Suspended"
	case trustv1.Status_STATUS_REVOKED:
		return "Revoked"
	}
	return "Unknown"
}

// statusBadge returns the badge status of a trust status.
func statusBadge(s trustv1.Status) string {
	switch s {
	case trustv1.Status_STATUS_ACTIVE:
		return "ok"
	case trustv1.Status_STATUS_SUSPENDED:
		return "warn"
	case trustv1.Status_STATUS_REVOKED:
		return "bad"
	}
	return "info"
}
