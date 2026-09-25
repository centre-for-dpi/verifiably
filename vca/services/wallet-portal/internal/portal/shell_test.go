// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// holderPeer returns one holder pair with its wallet-auth service.
func holderPeer(dpg configv1.Dpg) topology.Peer {
	pair := topology.PairName(commonv1.Role_ROLE_HOLDER, dpg)
	return topology.Peer{
		Pair: pair, Role: commonv1.Role_ROLE_HOLDER, Dpg: dpg, PublicURL: "https://" + pair + ".labs.example",
		Services: map[string]string{
			"wallet-auth": "http://" + pair + "-wallet-auth:8083", "wallet-portal": "http://" + pair + "-wallet-portal:8092",
		},
	}
}

// stackCaps is the capability answer of an adapter that names its stack.
func stackCaps(name string, features ...backendv1.Feature) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: name}, Features: features}
}

// holderDeployment is three holder pairs and one issuer pair: the first
// two holder pairs live, the third starting. The own pair lists the
// features of own.
func holderDeployment(own ...backendv1.Feature) portal.Topology {
	first := holderPeer(configv1.Dpg_DPG_WALTID)
	second := holderPeer(configv1.Dpg_DPG_INJI)
	third := holderPeer(configv1.Dpg_DPG_CREDEBL)
	issuer := topology.Peer{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID,
		PublicURL: "https://issuer-waltid.labs.example", Services: map[string]string{"issuer-auth": "http://issuer-auth:8081"}}
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: first, State: topology.Live, Capabilities: stackCaps("First stack", own...)},
		{Peer: second, State: topology.Live, Capabilities: stackCaps("Second stack")},
		{Peer: third, State: topology.Starting},
		{Peer: issuer, State: topology.Live, Capabilities: stackCaps("First stack")},
	}}
	return portal.Topology{
		Peers:    []topology.Peer{first, second, third, issuer},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  first.Auth() + "/.well-known/jwks.json",
	}
}

// TestWalletUsesShell checks the frame of every wallet page: the holder
// role chip, the side navigation of board Holder-Portal, and the user
// menu of the wallet session with its sign out form. The keys page shows
// only when the wallet of the own stack manages keys.
func TestWalletUsesShell(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	for _, path := range []string{"/wallet/", "/wallet/discover", "/wallet/claim", "/wallet/present", "/wallet/help"} {
		rec := h.get(t, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			`data-role="holder"`, `class="role-chip"`, ">Holder<",
			`<a href="/wallet/"`, `>My credentials</a>`, `<a href="/wallet/discover"`, `>Discover</a>`,
			`<a href="/wallet/claim"`, `>Claim</a>`, `<a href="/wallet/present"`, `>Present</a>`,
			`<a href="/wallet/help"`, `>Help</a>`,
			"Wanjiku Njeri", `action="/wallet/signout"`, `name="csrf_token"`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s misses %s", path, want)
			}
		}
		if strings.Contains(body, "Keys and identifiers") {
			t.Fatalf("%s shows the keys page without the feature", path)
		}
	}
	if rec := h.get(t, "/wallet/keys"); rec.Code != http.StatusNotFound {
		t.Fatalf("keys without the feature: status = %d", rec.Code)
	}
	keys := setupShell(t, nil, holderDeployment(backendv1.Feature_FEATURE_WALLET_KEYS))
	rec := keys.get(t, "/wallet/keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("keys: status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`<a href="/wallet/keys" aria-current="page"`, `>Keys and identifiers</a>`, "did:jwk:holder-1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("keys page misses %s\n%s", want, body)
		}
	}
}

// TestStackSwitcherListsLiveHolderPairs checks the stack switcher: the
// holder pairs that run, named by their adapters, the own pair marked,
// a starting pair as text, and no pair of another role.
func TestStackSwitcherListsLiveHolderPairs(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	body := h.get(t, "/wallet/").Body.String()
	for _, want := range []string{
		`href="https://holder-waltid.labs.example/wallet/" aria-current="true">First stack</a>`,
		`href="https://holder-inji.labs.example/wallet/">Second stack</a>`,
		`credebl`, "Starting",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the switcher misses %s\n%s", want, body)
		}
	}
	if strings.Contains(body, "issuer-waltid.labs.example") {
		t.Fatal("the switcher lists an issuer pair")
	}
}

// TestHomeFollowsTheBoard checks the home page of board Holder-Portal:
// the actions, one card per credential with the issuer, the type, the
// status word and the stripe, and the tile to discovery.
func TestHomeFollowsTheBoard(t *testing.T) {
	h := setupShell(t, func(o *serviceOptions) { o.Holder = &fakeHolder{credential: dated(t)} }, holderDeployment())
	body := h.get(t, "/wallet/").Body.String()
	for _, want := range []string{
		"Credentials you hold in the First stack wallet on this deployment.",
		`href="/wallet/present"`, `href="/wallet/claim"`,
		`class="credential credential-ok"`, `<span class="badge badge-ok">Valid</span>`,
		"Expires 1 Jan 2027", `class="credential-add" href="/wallet/discover"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("home misses %s\n%s", want, body)
		}
	}
}

// TestHelpListsTheWalletPages checks the help page: one row per page the
// deployment shows.
func TestHelpListsTheWalletPages(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	body := h.get(t, "/wallet/help").Body.String()
	for _, want := range []string{"Find the credentials that issuers on this deployment offer.", "Discover"} {
		if !strings.Contains(body, want) {
			t.Fatalf("help misses %s", want)
		}
	}
}

// TestSignOutEndsTheSession checks the sign out form: the wallet token
// guards it, the auth service of the own pair ends the session, the
// cookie goes, and the browser follows the logout URL.
func TestSignOutEndsTheSession(t *testing.T) {
	topo := holderDeployment()
	var gotAuth, gotToken string
	topo.Logout = func(_ context.Context, auth, token string) (string, error) {
		gotAuth, gotToken = auth, token
		return "https://idp.example/logout", nil
	}
	h := setupShell(t, nil, topo)
	form := url.Values{session.Field: {h.guard.Token(citizen())}}
	req := httptest.NewRequest(http.MethodPost, "/wallet/signout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "jwt-1"})
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://idp.example/logout" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	if gotAuth != "http://holder-waltid-wallet-auth:8083" || gotToken != "jwt-1" {
		t.Fatalf("logout called with %q %q", gotAuth, gotToken)
	}
	if c := rec.Header().Get("Set-Cookie"); !strings.Contains(c, session.CookieName+"=;") {
		t.Fatalf("cookie = %q", c)
	}
	// A failed call still clears the cookie and goes to the login page.
	topo.Logout = func(context.Context, string, string) (string, error) { return "", errors.New("down") }
	down := setupShell(t, nil, topo)
	form = url.Values{session.Field: {down.guard.Token(citizen())}}
	req = httptest.NewRequest(http.MethodPost, "/wallet/signout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	down.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("down: status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	// A form without the token stays.
	req = httptest.NewRequest(http.MethodPost, "/wallet/signout", nil)
	rec = httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no token: status = %d", rec.Code)
	}
}

// TestShellPagesPassTheChecks renders every wallet page inside the frame
// through htmx too, where the page part must pass the fragment checks.
func TestShellPagesPassTheChecks(t *testing.T) {
	h := setupShell(t, nil, holderDeployment(backendv1.Feature_FEATURE_WALLET_KEYS))
	for _, path := range []string{"/wallet/", "/wallet/discover", "/wallet/claim", "/wallet/present", "/wallet/keys", "/wallet/help"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
		a11ytest.AssertFragment(t, rec.Body.String())
	}
}
