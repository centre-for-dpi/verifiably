// SPDX-License-Identifier: Apache-2.0

// Package staffshell builds the portal frame of the staff pages of a role
// that signs in through its own auth service: the issuer and the
// verifier. Every service that draws pages for the role uses it, so the
// role chip, the stack switcher, the user menu, and the side navigation
// look the same on every page of the role (ADR-044 decision 5).
//
// The stack switcher lists the pairs of the role that are not absent,
// from the peer probe (ADR-034 decision 3). The user menu shows the staff
// member of the session the guard found. The side navigation comes from
// the rolenav table, with the pages the own adapter lacks a feature for
// hidden.
package staffshell

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// JWKSPath is the path of the key set of an auth service.
const JWKSPath = "/.well-known/jwks.json"

// Options configure a Shell.
type Options struct {
	// Role is the staff role of the pages.
	Role commonv1.Role
	// Peers are the candidate pairs of the deployment, from VCA_PEERS.
	// The shell finds its own pair among them.
	Peers []topology.Peer
	// Snapshot returns the probe of every peer. Nil means no stack
	// switcher and no gated page.
	Snapshot func(ctx context.Context) topology.Snapshot
	// JWKSURL is the key set of the auth service the guard checks. The
	// pair whose auth service serves it is the own pair.
	JWKSURL string
	// Home is the target of the wordmark. Empty means the home of the role.
	Home string
	// SignOut is the action of the sign out form of the user menu.
	SignOut string
}

// Shell draws the frame of the staff pages of one pair.
type Shell struct {
	opts Options
	own  topology.Peer
}

// New returns a shell. It finds the own pair: the peer of the role whose
// auth service serves the key set of the guard.
func New(opts Options) *Shell {
	if opts.Home == "" {
		opts.Home = topology.HomePath(opts.Role)
	}
	s := &Shell{opts: opts}
	for _, p := range opts.Peers {
		auth := p.Auth()
		if p.Role == opts.Role && auth != "" && strings.TrimRight(auth, "/")+JWKSPath == opts.JWKSURL {
			s.own = p
			break
		}
	}
	return s
}

// Pair returns the name of the own pair, or "" when no peer matches.
func (s *Shell) Pair() string { return s.own.Pair }

// AuthURL returns the internal URL of the auth service of the own pair,
// or "" when no peer matches.
func (s *Shell) AuthURL() string { return s.own.Auth() }

// Frame is the probe a page reads once per request.
type Frame struct {
	snap topology.Snapshot
	pair string
}

// Frame reads the snapshot for one page.
func (s *Shell) Frame(ctx context.Context) Frame {
	f := Frame{pair: s.own.Pair}
	if s.opts.Snapshot != nil {
		f.snap = s.opts.Snapshot(ctx)
	}
	return f
}

// Snapshot returns the probe the frame read.
func (f Frame) Snapshot() topology.Snapshot { return f.snap }

// Own returns the status of the own pair.
func (f Frame) Own() (topology.Status, bool) {
	if f.pair == "" {
		return topology.Status{}, false
	}
	for _, st := range f.snap.Peers {
		if st.Peer.Pair == f.pair {
			return st, true
		}
	}
	return topology.Status{}, false
}

// Has reports whether the adapter of the own pair lists a feature. A
// page of one pair gates on its own stack (ADR-034 decision 5).
func (f Frame) Has(feature backendv1.Feature) bool {
	own, ok := f.Own()
	return ok && own.State == topology.Live && own.Has(feature)
}

// Live returns the live pairs of a role, in stack order.
func (f Frame) Live(role commonv1.Role) []topology.Status {
	var out []topology.Status
	for _, st := range f.snap.Live() {
		if st.Peer.Role == role {
			out = append(out, st)
		}
	}
	return out
}

// Build returns the portal frame of one page: the role chip, the stack
// switcher, the user menu of the session, and the side navigation with
// the page of the request marked.
func (s *Shell) Build(r *http.Request, f Frame) *components.Shell {
	role := strings.ToLower(strings.TrimPrefix(s.opts.Role.String(), "ROLE_"))
	sh := &components.Shell{
		Role:      role,
		RoleLabel: msg.T("role." + role + ".label"),
		Stacks:    s.stacks(f),
		Sections:  rolenav.Nav(s.opts.Role, f.Has, r.URL.Path),
	}
	if sess, ok := staffsession.User(r.Context()); ok && sess.Subject != "" {
		name := sess.Name
		if name == "" {
			name = sess.Subject
		}
		sh.User = components.User{Name: name, SignOut: s.opts.SignOut, CSRF: sess.CSRF, CSRFField: staffsession.Field}
	}
	return sh
}

// stacks lists the pairs of the role that are not absent, in stack
// order: a live pair links to its home, the own pair is current, and a
// starting pair is text (ADR-034 decision 3).
func (s *Shell) stacks(f Frame) []components.StackLink {
	var out []components.StackLink
	for _, st := range f.snap.ForRole(s.opts.Role) {
		link := components.StackLink{
			Name:    f.snap.StackName(st.Peer.Dpg),
			Href:    strings.TrimRight(st.Peer.PublicURL, "/") + topology.HomePath(s.opts.Role),
			Current: st.Peer.Pair != "" && st.Peer.Pair == f.pair,
		}
		if st.State != topology.Live {
			link.State, link.Href = "starting", ""
		}
		out = append(out, link)
	}
	return out
}

// Render writes a page inside the frame. The wordmark leads to the home
// of the role.
func (s *Shell) Render(kit *components.Kit, w http.ResponseWriter, r *http.Request, f Frame, page components.Page) error {
	page.Shell = s.Build(r, f)
	page.Nav = components.Nav{Label: msg.T("shell.main_nav.label"), Brand: components.Link{Href: s.opts.Home}}
	return kit.RenderPage(w, r, page)
}

// Actor returns the actor of the session of ctx: the pairwise subject of
// the staff member, or "" without a session.
func Actor(ctx context.Context) string {
	s, ok := staffsession.User(ctx)
	if !ok {
		return ""
	}
	return s.Subject
}

// AsActor returns a request that names the staff member of ctx in the
// actor header, so the audit log of the called service names the staff
// member (ADR-039 decision 1).
func AsActor[T any](ctx context.Context, m *T) *connect.Request[T] {
	req := connect.NewRequest(m)
	if actor := Actor(ctx); actor != "" {
		req.Header().Set(auditlog.ActorHeader, actor)
	}
	return req
}

// SignOutOptions configure the sign out handler.
type SignOutOptions struct {
	// Cookie is the name of the session cookie of the role.
	Cookie string
	// Secure sets the Secure attribute of the cookie that clears it.
	Secure bool
	// Logout ends the session at the auth service and returns the logout
	// URL of the provider, or "". Nil only clears the cookie.
	Logout func(ctx context.Context, token string) (string, error)
	// After is where the browser goes when the provider has no logout
	// URL. Empty means the root.
	After string
}

// SignOut returns the handler of the sign out form. The guard checks the
// session and the synchronizer token first. The handler ends the session
// at the auth service, clears the cookie, and sends the browser to the
// logout URL of the provider or to After. A failed call to the auth
// service still clears the cookie.
func SignOut(o SignOutOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := o.After
		if target == "" {
			target = "/"
		}
		if token := oidcflow.TokenFromRequest(r, o.Cookie); token != "" && o.Logout != nil {
			if u, err := o.Logout(r.Context(), token); err == nil && u != "" {
				target = u
			}
		}
		oidcflow.Cookie{Name: o.Cookie, Secure: o.Secure}.Clear(w)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}
