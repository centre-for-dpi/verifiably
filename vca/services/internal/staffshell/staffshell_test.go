// SPDX-License-Identifier: Apache-2.0

package staffshell_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// peer returns one issuer or verifier pair with its auth service.
func peer(role commonv1.Role, dpg configv1.Dpg) topology.Peer {
	pair := topology.PairName(role, dpg)
	return topology.Peer{
		Pair: pair, Role: role, Dpg: dpg, PublicURL: "https://" + pair + ".labs.example",
		Services: map[string]string{topology.AuthService(role): "http://" + pair + "-auth:8081"},
	}
}

// caps is the capability answer of an adapter that names its stack.
func caps(name string, features ...backendv1.Feature) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: name}, Features: features}
}

// deployment is three issuer pairs and one verifier pair: the first two
// issuer pairs live, the third starting.
func deployment() ([]topology.Peer, topology.Snapshot) {
	waltid := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	inji := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_INJI)
	credebl := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL)
	verifier := peer(commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_WALTID)
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: waltid, State: topology.Live, Capabilities: caps("First stack", backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION)},
		{Peer: inji, State: topology.Live, Capabilities: caps("Second stack")},
		{Peer: credebl, State: topology.Starting},
		{Peer: verifier, State: topology.Live, Capabilities: caps("First stack")},
	}}
	return []topology.Peer{waltid, inji, credebl, verifier}, snap
}

// shell returns the issuer shell of the first pair.
func shell(t *testing.T) *staffshell.Shell {
	t.Helper()
	peers, snap := deployment()
	return staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: peers,
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  peers[0].Auth() + "/.well-known/jwks.json", SignOut: "/issuer/signout",
	})
}

// session returns a request with a signed in staff member.
func session(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	s := staffsession.Session{Subject: "kc|alice", Name: "Alice Wanjiru", ID: "sid-1", CSRF: "token-1"}
	return r.WithContext(staffsession.With(r.Context(), s))
}

func TestOwnPairFromTheKeySet(t *testing.T) {
	sh := shell(t)
	if sh.Pair() != "issuer-waltid" {
		t.Fatalf("pair = %q", sh.Pair())
	}
	if sh.AuthURL() != "http://issuer-waltid-auth:8081" {
		t.Fatalf("auth URL = %q", sh.AuthURL())
	}
	// A key set of no peer names no pair, and the shell still works.
	none := staffshell.New(staffshell.Options{Role: commonv1.Role_ROLE_ISSUER, JWKSURL: "http://elsewhere/jwks"})
	if none.Pair() != "" || none.AuthURL() != "" {
		t.Fatalf("pair = %q auth = %q", none.Pair(), none.AuthURL())
	}
}

func TestStackSwitcherListsLiveIssuerPairs(t *testing.T) {
	sh := shell(t)
	r := session("/issuer/")
	got := sh.Build(r, sh.Frame(r.Context()))
	if got.Role != "issuer" || got.RoleLabel != "Issuer" {
		t.Fatalf("role = %q %q", got.Role, got.RoleLabel)
	}
	if len(got.Stacks) != 3 {
		t.Fatalf("stacks = %+v", got.Stacks)
	}
	want := []components.StackLink{
		{Name: "First stack", Href: "https://issuer-waltid.labs.example/issuer/", Current: true},
		{Name: "Second stack", Href: "https://issuer-inji.labs.example/issuer/"},
		{Name: "credebl", State: "starting"},
	}
	for i, w := range want {
		if got.Stacks[i] != w {
			t.Errorf("stack %d = %+v, want %+v", i, got.Stacks[i], w)
		}
	}
}

func TestShellUserComesFromTheSession(t *testing.T) {
	sh := shell(t)
	r := session("/identity/")
	got := sh.Build(r, sh.Frame(r.Context()))
	if got.User.Name != "Alice Wanjiru" || got.User.SignOut != "/issuer/signout" ||
		got.User.CSRF != "token-1" || got.User.CSRFField != staffsession.Field {
		t.Fatalf("user = %+v", got.User)
	}
	// Without a session the menu hides.
	anon := httptest.NewRequest(http.MethodGet, "/identity/", nil)
	if u := sh.Build(anon, sh.Frame(anon.Context())).User; u.Name != "" {
		t.Fatalf("anonymous user = %+v", u)
	}
	// A session without a name shows the subject.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(staffsession.With(r.Context(), staffsession.Session{Subject: "kc|bob", CSRF: "x"}))
	if u := sh.Build(r, sh.Frame(r.Context())).User; u.Name != "kc|bob" {
		t.Fatalf("user = %+v", u)
	}
}

func TestSideNavComesFromRolenav(t *testing.T) {
	sh := shell(t)
	r := session("/identity/")
	got := sh.Build(r, sh.Frame(r.Context()))
	var hrefs, current []string
	for _, s := range got.Sections {
		for _, l := range s.Links {
			hrefs = append(hrefs, l.Href)
			if l.Current {
				current = append(current, l.Href)
			}
		}
	}
	if strings.Join(hrefs, " ") != "/issuer/ /identity/ /portal/ /builder/ /issue/ /sources/ /issued/ /notifications/ /help/" {
		t.Errorf("links = %v", hrefs)
	}
	if len(current) != 1 || current[0] != "/identity/" {
		t.Errorf("current = %v", current)
	}
}

func TestFrameReadsTheOwnPair(t *testing.T) {
	sh := shell(t)
	f := sh.Frame(context.Background())
	own, ok := f.Own()
	if !ok || own.Peer.Pair != "issuer-waltid" {
		t.Fatalf("own = %+v %v", own.Peer, ok)
	}
	if !f.Has(backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) || f.Has(backendv1.Feature_FEATURE_WEBHOOKS) {
		t.Fatal("the gate must read the adapter of the own pair")
	}
	if len(f.Live(commonv1.Role_ROLE_ADMIN)) != 0 || len(f.Live(commonv1.Role_ROLE_ISSUER)) != 2 {
		t.Fatal("live pairs per role are wrong")
	}
	// A shell without peers has no frame and no gate.
	bare := staffshell.New(staffshell.Options{Role: commonv1.Role_ROLE_ISSUER})
	bf := bare.Frame(context.Background())
	if _, ok := bf.Own(); ok || bf.Has(backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) {
		t.Fatal("a bare shell found a pair")
	}
	r := session("/issuer/")
	if got := bare.Build(r, bf); len(got.Stacks) != 0 || len(got.Sections) == 0 {
		t.Fatalf("bare shell = %+v", got)
	}
}

func TestRenderDrawsAnAccessibleShellPage(t *testing.T) {
	sh := shell(t)
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	r := session("/issuer/")
	rec := httptest.NewRecorder()
	if err := sh.Render(kit, rec, r, sh.Frame(r.Context()), components.Page{Title: "Overview"}); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`data-role="issuer"`, `<span class="role-chip">Issuer</span>`, `aria-label="Stack"`,
		`href="https://issuer-inji.labs.example/issuer/"`, `action="/issuer/signout"`, `class="wordmark" href="/issuer/"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestAsActorNamesTheStaffMember(t *testing.T) {
	r := session("/")
	req := staffshell.AsActor(r.Context(), &backendv1.GetCapabilitiesRequest{})
	if got := auditlog.ActorFrom(req.Header()); got != "kc|alice" {
		t.Fatalf("actor = %q", got)
	}
	if staffshell.Actor(r.Context()) != "kc|alice" {
		t.Fatal("Actor lost the subject")
	}
	bare := staffshell.AsActor(context.Background(), &backendv1.GetCapabilitiesRequest{})
	if bare.Header().Get(auditlog.ActorHeader) != "" {
		t.Fatal("a call without a session named an actor")
	}
}

func TestSignOutEndsTheSession(t *testing.T) {
	var got string
	h := staffshell.SignOut(staffshell.SignOutOptions{
		Cookie: staffsession.IssuerCookie, Secure: true, After: "https://issuer.example/auth/",
		Logout: func(_ context.Context, token string) (string, error) {
			got = token
			return "https://idp.example/logout", nil
		},
	})
	r := httptest.NewRequest(http.MethodPost, "/issuer/signout", nil)
	r.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: "session-jwt"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if got != "session-jwt" {
		t.Fatalf("logout got %q", got)
	}
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://idp.example/logout" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != staffsession.IssuerCookie || cookie[0].MaxAge >= 0 || !cookie[0].Secure {
		t.Fatalf("cookie = %+v", cookie)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the answer may be cached")
	}
}

func TestSignOutFallsBackToTheChooser(t *testing.T) {
	h := staffshell.SignOut(staffshell.SignOutOptions{
		Cookie: staffsession.IssuerCookie, After: "https://issuer.example/auth/",
		Logout: func(context.Context, string) (string, error) { return "", errors.New("down") },
	})
	r := httptest.NewRequest(http.MethodPost, "/issuer/signout", nil)
	r.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: "session-jwt"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	// The auth service is down: the cookie still goes, and the browser
	// lands on the chooser.
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://issuer.example/auth/" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	// Without a logout function and a target, the root is the target.
	bare := staffshell.SignOut(staffshell.SignOutOptions{Cookie: staffsession.IssuerCookie})
	rec = httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/issuer/signout", nil))
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("location %q", rec.Header().Get("Location"))
	}
}

// TestUserHookDrawsAnotherSession checks the frame of a role that signs
// in through its own session, such as the holder: the hook names the
// user menu, and a staff session on the request does not leak into it.
// Without the hook the staff session still names the menu.
func TestUserHookDrawsAnotherSession(t *testing.T) {
	wallet := topology.Peer{
		Pair: "holder-waltid", Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID,
		PublicURL: "https://holder-waltid.labs.example",
		Services:  map[string]string{"wallet-auth": "http://holder-waltid-auth:8083"},
	}
	snap := topology.Snapshot{Peers: []topology.Status{{Peer: wallet, State: topology.Live, Capabilities: caps("First stack")}}}
	calls := 0
	sh := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_HOLDER, Peers: []topology.Peer{wallet},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  "http://holder-waltid-auth:8083/.well-known/jwks.json",
		User: func(*http.Request) components.User {
			calls++
			return components.User{Name: "Wanjiku Njeri", SignOut: "/wallet/signout", CSRF: "w-1"}
		},
	})
	if sh.Pair() != "holder-waltid" {
		t.Fatalf("pair = %q", sh.Pair())
	}
	r := session("/wallet/")
	got := sh.Build(r, sh.Frame(r.Context()))
	if calls != 1 || got.User.Name != "Wanjiku Njeri" || got.User.SignOut != "/wallet/signout" || got.User.CSRF != "w-1" {
		t.Fatalf("user = %+v, calls = %d", got.User, calls)
	}
	if got.Role != "holder" || len(got.Sections) == 0 {
		t.Fatalf("shell = %+v", got)
	}
}
