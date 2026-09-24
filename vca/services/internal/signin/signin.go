// SPDX-License-Identifier: Apache-2.0

// Package signin renders the sign in chooser of a role (ADR-035, boards
// Signin and Signin-Admin) for every auth service: issuer-auth,
// wallet-auth, verifier-auth, and the admin service. One renderer draws
// the page, so the four look the same and a provider the admin adds
// appears on each.
//
// A Chooser serves three routes under a prefix:
//
//	GET <prefix>/                the page with one button per provider
//	GET <prefix>/providers.json  id, display name, realm, register flag
//	GET <prefix>/register        302 to the register URL of a provider
//
// The listing never carries a secret, a client id, or a discovery URL.
// The landing reads it to name the realm of a role on the intro page.
package signin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Default paths of the login start and the register start under the
// public URL of a pair.
const (
	DefaultLoginPath    = "/auth/login"
	DefaultRegisterPath = "/auth/register"
	// ListingPath is the path of the listing under the auth prefix.
	ListingPath = "/auth/providers.json"
)

// Entry is one provider of the listing.
type Entry struct {
	// ID is the provider id.
	ID string `json:"id"`
	// DisplayName is the name the page shows.
	DisplayName string `json:"display_name"`
	// Realm is the realm or tenant label of the provider, when any.
	Realm string `json:"realm"`
	// Register says whether the provider offers a register action.
	Register bool `json:"register"`
}

// Listing is the body of GET /auth/providers.json.
type Listing struct {
	// Role is the short name of the role, for example issuer.
	Role string `json:"role"`
	// Providers lists the enabled providers, the default first.
	Providers []Entry `json:"providers"`
}

// Providers lists the enabled providers of a service. An
// *oidcflow.Registry is one.
type Providers interface {
	Enabled() []oidcflow.Provider
}

// Registrar starts a registration at a provider (ADR-035 decision 3) and
// returns the URL the browser opens. It returns
// oidcflow.ErrRegisterUnsupported when the provider offers none.
type Registrar interface {
	Register(ctx context.Context, providerID, returnTo string) (string, error)
}

// Metadata reads the metadata of a provider, so the register flag
// follows the discovery document. An *oidcflow.Flow is one.
type Metadata interface {
	Metadata(ctx context.Context, p oidcflow.Provider) (oidcflow.Metadata, error)
}

// Options configure a Chooser.
type Options struct {
	// Kit renders the page. Required.
	Kit *components.Kit
	// Role is the role of the service. Required.
	Role commonv1.Role
	// Providers lists the providers. Required.
	Providers Providers
	// Registrar starts a registration. Nil leaves the register route out;
	// the page still links the register path, which the service mounts
	// itself.
	Registrar Registrar
	// Metadata reads provider metadata for the register flag. Nil lets
	// the record alone decide.
	Metadata Metadata
	// LoginPath is the login start. Empty selects DefaultLoginPath.
	LoginPath string
	// RegisterPath is the register start. Empty selects DefaultRegisterPath.
	RegisterPath string
	// LandingURL is the public URL of the landing. It gives the back
	// link and the header links. Empty leaves them out.
	LandingURL string
	// Home is the path the browser returns to when the request names no
	// valid return_to. Empty selects the home path of the role.
	Home string
	// Callout shows the first admin callout above the register action.
	Callout bool
	// Extra renders a block between the callout and the rule, for
	// example the bootstrap card of the admin. It gets the return path.
	Extra func(returnTo string) (template.HTML, error)
	// Empty replaces the sentence shown without a provider.
	Empty string
	// Toasts returns the notices of a request, for example after a sign
	// out. Nil shows none.
	Toasts func(r *http.Request) []components.Toast
}

// Chooser serves the sign in pages of one role.
type Chooser struct {
	opts Options
	id   string
}

// New checks the options and fills the defaults.
func New(opts Options) (*Chooser, error) {
	if opts.Kit == nil {
		return nil, errors.New("signin: a kit is required")
	}
	if opts.Role == commonv1.Role_ROLE_UNSPECIFIED {
		return nil, errors.New("signin: a role is required")
	}
	if opts.Providers == nil {
		return nil, errors.New("signin: a provider source is required")
	}
	if opts.LoginPath == "" {
		opts.LoginPath = DefaultLoginPath
	}
	if opts.RegisterPath == "" {
		opts.RegisterPath = DefaultRegisterPath
	}
	if opts.Home == "" {
		opts.Home = topology.HomePath(opts.Role)
	}
	opts.LandingURL = strings.TrimRight(opts.LandingURL, "/")
	return &Chooser{opts: opts, id: RoleID(opts.Role)}, nil
}

// RoleID returns the short name of a role, for example issuer.
func RoleID(role commonv1.Role) string {
	return strings.ToLower(strings.TrimPrefix(role.String(), "ROLE_"))
}

// Mount registers the routes under prefix, for example "/auth" gives
// /auth/, /auth/providers.json, and /auth/register. An empty prefix
// mounts them at the root.
func (c *Chooser) Mount(mux *http.ServeMux, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	mux.Handle("GET "+prefix+"/{$}", oidcflow.RejectQueryTokens(http.HandlerFunc(c.Page)))
	mux.Handle("GET "+prefix+"/providers.json", http.HandlerFunc(c.ProvidersJSON))
	if c.opts.Registrar != nil {
		mux.Handle("GET "+prefix+"/register", oidcflow.RejectQueryTokens(http.HandlerFunc(c.Register)))
	}
}

// Listing returns the providers of the role for the JSON route.
func (c *Chooser) Listing(ctx context.Context) Listing {
	out := Listing{Role: c.id, Providers: []Entry{}}
	for _, p := range c.enabled() {
		out.Providers = append(out.Providers, Entry{
			ID: p.ID, DisplayName: displayName(p), Realm: p.Realm, Register: c.registers(ctx, p),
		})
	}
	return out
}

// ProvidersJSON serves the listing.
func (c *Chooser) ProvidersJSON(w http.ResponseWriter, r *http.Request) {
	oidcflow.WriteJSON(w, http.StatusOK, c.Listing(r.Context()))
}

// Register sends the browser to the register URL of the provider named
// by the query. A provider with no register action gives 404.
func (c *Chooser) Register(w http.ResponseWriter, r *http.Request) {
	RegisterHandler(c.opts.Registrar, c.opts.Home).ServeHTTP(w, r)
}

// RegisterHandler returns the register start of a Registrar: GET
// ?provider=<id>&return_to=<path> answers 302 to the register URL, or
// 404 when the provider offers none. Mount wires it; a service that
// wraps it, for example in a rate limit, mounts it itself. A return
// path that is not a relative path falls back to home.
func RegisterHandler(reg Registrar, home string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		u, err := reg.Register(r.Context(), q.Get("provider"), ReturnTo(r, home))
		if err != nil {
			status := oidcflow.HTTPStatus(err)
			code := "invalid_request"
			if status == http.StatusNotFound {
				code = "not_found"
			}
			oidcflow.WriteError(w, status, code, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, u, http.StatusFound)
	})
}

// Page serves the chooser.
func (c *Chooser) Page(w http.ResponseWriter, r *http.Request) {
	page, err := c.page(r)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := c.opts.Kit.RenderPage(w, r, page); err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
	}
}

// page composes the chooser page of a request.
func (c *Chooser) page(r *http.Request) (components.Page, error) {
	returnTo := c.returnTo(r)
	block := &components.SignIn{
		Role:  msg.T("role." + c.id + ".label"),
		Title: msg.T("signin." + c.id + ".title"),
		Lead:  msg.T("signin."+c.id+".return") + " " + msg.T("signin.providers.text"),
		Label: msg.T("signin.continue.label"),
		Empty: c.opts.Empty,
		Or:    msg.T("signin.or.label"),
		Note:  msg.T("signin.note"),
	}
	if block.Empty == "" {
		block.Empty = msg.T("signin.none")
	}
	if c.opts.LandingURL != "" {
		block.Back = components.Link{Href: c.opts.LandingURL + "/roles/", Text: msg.T("signin.back.label")}
	}
	if c.opts.Callout {
		block.CalloutLabel = msg.T("signin.admin.callout.label")
		block.Callout = msg.T("signin.admin.callout")
	}
	if c.opts.Extra != nil {
		extra, err := c.opts.Extra(returnTo)
		if err != nil {
			return components.Page{}, err
		}
		block.Extra = extra
	}
	var registers []oidcflow.Provider
	for _, p := range c.enabled() {
		block.Providers = append(block.Providers, components.SignInProvider{
			Text: displayName(p), Href: withProvider(c.opts.LoginPath, p.ID, returnTo), Meta: p.Realm,
		})
		if c.registers(r.Context(), p) {
			registers = append(registers, p)
		}
	}
	for _, p := range registers {
		text := msg.T("signin.register.label")
		if len(registers) > 1 {
			text = msg.T("signin.register.with.label", displayName(p))
		}
		block.Register = append(block.Register, components.Button{
			Text: text, Href: withProvider(c.opts.RegisterPath, p.ID, returnTo), Variant: "ghost",
		})
	}
	page := components.Page{
		Title:       msg.T("signin.title.label"),
		Description: msg.T("signin.description"),
		Nav:         c.nav(),
		SignIn:      block,
		Footer:      msg.T("landing.footer"),
		Text:        LayoutText(),
	}
	if c.opts.Toasts != nil {
		page.Toasts = c.opts.Toasts(r)
	}
	return page, nil
}

// nav is the header of the chooser: the wordmark and the landing links
// when the service knows the landing.
func (c *Chooser) nav() components.Nav {
	nav := components.Nav{Label: msg.T("shell.main_nav.label"), Brand: components.Link{Href: "/"}}
	if c.opts.LandingURL == "" {
		return nav
	}
	nav.Brand.Href = c.opts.LandingURL
	nav.Links = []components.Link{
		{Href: c.opts.LandingURL + "/#how", Text: msg.T("landing.nav.how.label")},
		{Href: c.opts.LandingURL + "/#stacks", Text: msg.T("landing.nav.stacks.label")},
		{Href: c.opts.LandingURL + "/roles/", Text: msg.T("landing.nav.start.label")},
	}
	return nav
}

// LayoutText takes the layout words from the catalogue.
func LayoutText() components.Text {
	return components.Text{
		SkipLink: msg.T("layout.skip.label"), ThemeToggle: msg.T("layout.theme.label"), ThemeSystem: msg.T("layout.theme.system.label"),
		ThemeLight: msg.T("layout.theme.light.label"), ThemeDark: msg.T("layout.theme.dark.label"),
	}
}

// returnTo reads the return path of a request, or the home of the role.
func (c *Chooser) returnTo(r *http.Request) string { return ReturnTo(r, c.opts.Home) }

// ReturnTo reads the return_to query value of a request when it is a
// relative path, else home.
func ReturnTo(r *http.Request, home string) string {
	if v := r.URL.Query().Get("return_to"); oidcflow.ValidReturnTo(v) {
		return v
	}
	return home
}

// enabled lists the enabled providers, the default first, then by id.
func (c *Chooser) enabled() []oidcflow.Provider {
	list := c.opts.Providers.Enabled()
	sort.SliceStable(list, func(i, j int) bool { return list[i].IsDefault && !list[j].IsDefault })
	return list
}

// registers reports whether a provider offers a register action, from
// its metadata when the chooser can read it, else from the record.
func (c *Chooser) registers(ctx context.Context, p oidcflow.Provider) bool {
	var m oidcflow.Metadata
	if c.opts.Metadata != nil {
		// A provider that does not answer keeps the action of its
		// record, so an outage never hides a Keycloak realm.
		m = anyval.OrZero(c.opts.Metadata.Metadata(ctx, p))
	}
	return p.EffectiveRegistration(m) != oidcflow.RegistrationNone
}

// displayName returns the name the page shows for a provider.
func displayName(p oidcflow.Provider) string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.ID
}

// withProvider adds the provider and the return path to a start path.
func withProvider(path, id, returnTo string) string {
	q := url.Values{"provider": {id}, "return_to": {returnTo}}
	return path + "?" + q.Encode()
}

// maxListing bounds the body of a listing.
const maxListing = 1 << 20

// Fetch reads the listing of an auth service at base, for example the
// internal URL of issuer-auth. A nil client selects a client with a two
// second timeout.
func Fetch(ctx context.Context, client *http.Client, base string) (Listing, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+ListingPath, nil)
	if err != nil {
		return Listing{}, fmt.Errorf("signin: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return Listing{}, fmt.Errorf("signin: %w", err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	if res.StatusCode != http.StatusOK {
		return Listing{}, fmt.Errorf("signin: %s returned %d", req.URL, res.StatusCode)
	}
	var out Listing
	if err := json.NewDecoder(io.LimitReader(res.Body, maxListing)).Decode(&out); err != nil {
		return Listing{}, fmt.Errorf("signin: %s: %w", req.URL, err)
	}
	return out, nil
}
