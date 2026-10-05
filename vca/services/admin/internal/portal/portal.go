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
//	POST /tenants                create one tenant, on the chosen stacks too
//	GET  /tenants/{id}           one tenant with its stack tenants
//	POST /tenants/{id}/delete    remove one tenant and its stack tenants
//	POST /tenants/{id}/bind      create the tenant on one more stack
//	POST /tenants/{id}/unbind    remove the tenant from one stack
//	GET  /trust                  the trust entry list with the add form
//	POST /trust                  create or replace one trust entry
//	POST /trust/delete           remove one trust entry
//	POST /trust/approve          set one pending trust entry active
//	POST /trust/reject           remove one pending trust entry
//	GET  /trust/registries       the local registry and the external registries
//	POST /trust/registries       add one external registry
//	POST /trust/registries/{id}/sync    read one external registry now
//	POST /trust/registries/{id}/delete  remove one external registry
//	GET  /providers              the login provider table (board Admin-Providers)
//	GET  /providers/new          the provider form with the kind presets
//	POST /providers              save a new provider and push it to the live pairs
//	POST /providers/test         read the metadata of the typed issuer (htmx fragment)
//	GET  /providers/{id}         the edit form of one provider
//	POST /providers/{id}         save the changes and push them
//	POST /providers/{id}/enable  turn one provider on or off
//	POST /providers/{id}/delete  remove one provider
//	POST /providers/{id}/default make one provider the default
//	GET  /providers/{id}/console the management console of one provider
//	GET  /providers/pairs/{pair}/{id}/console the console of a provider of a pair
//	GET  /keys                   the API key list with the create form
//	POST /keys                   create one API key
//	POST /keys/{id}/revoke       revoke one API key
//	POST /keys/stack             create one client credential on a stack tenant
//	POST /keys/stack/delete      remove one client credential of a stack tenant
//	GET  /notifications          the delivery channels and the stack webhooks
//	POST /notifications/webhook  set or clear the webhook of a stack tenant
//	GET  /audit                  the audit log of every live service, with filters
//	GET  /audit/export.csv       the events that match the filters as CSV
//	POST /audit/retention        set the retention days of every audit store
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
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/auditfed"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helpdoc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/reason"
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
	// Audit merges the audit store of this service with the stores of
	// every live peer (ADR-039 decision 2). Nil turns the audit pages off.
	Audit *auditfed.Federation
	// Retention returns the retention days of the audit store of this
	// service. Nil shows no current value.
	Retention func(ctx context.Context) (int, error)
	// PeerClient calls the provider RPCs of the holder authorization
	// server of an issuer pair on the compose network. Nil means a client
	// with a ten second timeout.
	PeerClient *http.Client
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
	mux.HandleFunc("GET "+at+"/help/doc/{name}", p.open(p.helpDoc))
	p.registerTenants(mux)
	p.registerEcosystems(mux)
	p.registerTrust(mux)
	p.registerProviders(mux)
	p.registerKeys(mux)
	p.registerNotifications(mux)
	p.registerAudit(mux)
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
			p.failed(w, r, s, err)
		}
	}
}

// failed renders the page of an action that did not finish. A refusal
// the admin can act on shows the sentence of the service. A fault inside
// the service shows a plain sentence and no detail (ADR-027 decision 7).
func (p *Portal) failed(w http.ResponseWriter, r *http.Request, s session, err error) {
	status := statusOf(err)
	b := p.blocks()
	card := b.add("card", components.Card{ID: "failed", Title: msg.T("admin.action.failed.title"), Text: safeMessage(err)})
	if b.err != nil {
		http.Error(w, msg.T("admin.action.failed.text"), status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	page := components.Page{Title: msg.T("admin.action.failed.title"), Description: msg.T("admin.action.failed.text"), Content: card}
	if rerr := p.render(&statusWriter{ResponseWriter: w, status: status}, r, s, page); rerr != nil {
		http.Error(w, msg.T("admin.action.failed.text"), status)
	}
}

// safeMessage returns the sentence a page may show for an error. The
// Connect message of a refusal reads as a sentence once the package
// prefixes go. Any other error gives the plain sentence of the catalogue.
func safeMessage(err error) string {
	if text := reason.Of(err, connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeNotFound,
		connect.CodeAlreadyExists, connect.CodePermissionDenied, connect.CodeOutOfRange); text != "" {
		return text
	}
	return msg.T("admin.action.failed.text")
}

// statusWriter writes a status before the first byte of the body.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader sends the status of the writer once, whatever the caller
// names.
func (s *statusWriter) WriteHeader(int) {
	if !s.wrote {
		s.wrote = true
		s.ResponseWriter.WriteHeader(s.status)
	}
}

// Write sends the status once, then the bytes.
func (s *statusWriter) Write(b []byte) (int, error) {
	s.WriteHeader(s.status)
	return s.ResponseWriter.Write(b)
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

// form wraps content in a POST form with the synchronizer token, in the
// one row layout of the class filters. It suits a form with buttons only,
// such as the actions of a table row. A form with a field uses
// stackedForm, and a test fails on a one row POST form with a field.
func form(action, csrf string, content ...template.HTML) template.HTML {
	open := `<form class="filters" action="` + template.HTMLEscapeString(action) + `" method="post">` +
		`<input type="hidden" name="` + oidcflow.CSRFField + `" value="` + template.HTMLEscapeString(csrf) + `">`
	parts := append([]template.HTML{template.HTML(open)}, content...) //nolint:gosec // both parts are escaped
	return components.Join(append(parts, template.HTML(`</form>`))...)
}

// stackedForm wraps the fields in a POST form that puts one field under
// the other, since the fields carry hints of different lengths.
func stackedForm(action, csrf string, fields template.HTML) template.HTML {
	open := `<form action="` + template.HTMLEscapeString(action) + `" method="post">` +
		`<input type="hidden" name="` + oidcflow.CSRFField + `" value="` + template.HTMLEscapeString(csrf) + `">`
	return components.Join(template.HTML(open), fields, template.HTML(`</form>`)) //nolint:gosec // both parts are escaped
}

// getForm wraps content in a GET form, for filters and the login page.
func getForm(action string, content ...template.HTML) template.HTML {
	open := `<form class="filters" action="` + template.HTMLEscapeString(action) + `" method="get">`
	parts := append([]template.HTML{template.HTML(open)}, content...) //nolint:gosec // both parts are escaped
	return components.Join(append(parts, template.HTML(`</form>`))...)
}

// Notices maps a notice code to the sentence the page shows.
var Notices = map[string]components.Toast{
	"tenant-created":           {Level: "ok", Text: msg.T("admin.tenants.created")},
	"tenant-deleted":           {Level: "warn", Text: msg.T("admin.tenants.deleted")},
	"tenant-bound":             {Level: "ok", Text: msg.T("admin.tenants.bound")},
	"tenant-unbound":           {Level: "warn", Text: msg.T("admin.tenants.unbound")},
	"tenant-primary-did":       {Level: "ok", Text: msg.T("admin.tenants.primary_did.set")},
	"trust-saved":              {Level: "ok", Text: msg.T("admin.trust.saved")},
	"trust-deleted":            {Level: "warn", Text: msg.T("admin.trust.deleted")},
	"trust-approved":           {Level: "ok", Text: msg.T("admin.trust.approved")},
	"trust-rejected":           {Level: "warn", Text: msg.T("admin.trust.rejected")},
	"registry-added":           {Level: "ok", Text: msg.T("admin.registries.added")},
	"registry-synced":          {Level: "ok", Text: msg.T("admin.registries.synced")},
	"registry-sync-failed":     {Level: "warn", Text: msg.T("admin.registries.sync_failed")},
	"registry-removed":         {Level: "warn", Text: msg.T("admin.registries.removed")},
	"provider-added":           {Level: "ok", Text: "The login provider is ready. Its roles can sign in with it."},
	"provider-saved":           {Level: "ok", Text: "The login provider is saved."},
	"provider-enabled":         {Level: "ok", Text: "The login provider is on. Its roles can sign in with it."},
	"provider-disabled":        {Level: "warn", Text: "The login provider is off. New sign ins with it fail."},
	"provider-removed":         {Level: "warn", Text: "The login provider is removed. Its sessions end."},
	"provider-default":         {Level: "ok", Text: "The provider is the default now."},
	"holder-provider-added":    {Level: "ok", Text: msg.T("admin.holders.added")},
	"holder-provider-saved":    {Level: "ok", Text: msg.T("admin.holders.saved")},
	"holder-provider-enabled":  {Level: "ok", Text: msg.T("admin.holders.enabled")},
	"holder-provider-disabled": {Level: "warn", Text: msg.T("admin.holders.disabled")},
	"holder-provider-removed":  {Level: "warn", Text: msg.T("admin.holders.removed")},
	"key-revoked":              {Level: "warn", Text: msg.T("admin.keys.revoked")},
	"stack-credential-deleted": {Level: "warn", Text: msg.T("admin.keys.stack.deleted")},
	"webhook-saved":            {Level: "ok", Text: msg.T("admin.notifications.webhook.saved")},
	"webhook-cleared":          {Level: "warn", Text: msg.T("admin.notifications.webhook.cleared")},
	"notification-saved":       {Level: "ok", Text: msg.T("admin.notifications.holder.saved")},
	"ecosystems-on":            {Level: "ok", Text: msg.T("admin.ecosystems.turned_on")},
	"ecosystems-off":           {Level: "warn", Text: msg.T("admin.ecosystems.turned_off")},
	"ecosystem-created":        {Level: "ok", Text: msg.T("admin.ecosystems.created")},
	"ecosystem-member-added":   {Level: "ok", Text: msg.T("admin.ecosystems.member_added")},
	"ecosystem-member-invited": {Level: "info", Text: msg.T("admin.ecosystems.member_invited")},
	"ecosystem-member-removed": {Level: "warn", Text: msg.T("admin.ecosystems.member_removed")},
	"signed-out":               {Level: "info", Text: "You are signed out."},
	"retention-saved":          {Level: "ok", Text: msg.T("admin.audit.retention.saved")},
	"retention-partial":        {Level: "warn", Text: msg.T("admin.audit.retention.partial")},
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
	list, err := helpdoc.Links("admin", p.docPath)
	if err != nil {
		return err
	}
	documents := b.add("card", components.Card{
		ID: "documents", Title: msg.T("common.help.docs.label"), Text: msg.T("common.help.docs.text"), Body: list,
	})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       "Admin help",
		Description: "Every vca admin command and every admin RPC with its help text.",
		Content:     components.Join(documents, intro, commandTable, rpcTable),
	})
}

// docPath is the page of one document of the admin help.
func (p *Portal) docPath(name string) string { return p.opts.Prefix + "/help/doc/" + name }

// helpDoc renders one document of the admin role. The page needs no
// session, as the help page does.
func (p *Portal) helpDoc(w http.ResponseWriter, r *http.Request) error {
	s, _ := p.session(r)
	doc, err := helpdoc.Render("admin", r.PathValue("name"), p.docPath)
	if errors.Is(err, helpdoc.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return err
	}
	b := p.blocks()
	back := b.add("button", components.Button{Text: msg.T("common.help.back.label"), Href: p.opts.Prefix + "/help"})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title: doc.Title, Lead: msg.T("common.help.doc.lead"), Description: msg.T("common.help.doc.lead"),
		Actions: back, Content: helpdoc.Article(doc),
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

// timestamp returns the protobuf time of t.
func timestamp(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
