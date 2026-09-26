// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
)

// esignetShape makes the holder provider answer as eSignet 1.5.1 does:
// an ID token with the pairwise sub only, and the claims of the person
// in a userinfo JWT without iss and aud.
func (h *harness) esignetShape(claims map[string]any) {
	h.idp.Claims = map[string]any{}
	h.idp.UserinfoSigned, h.idp.UserinfoBare = true, true
	h.idp.Userinfo = claims
}

// TestABindingMatchesAVouchedUserinfoClaim: eSignet returns the claims
// of a person only in its signed userinfo answer. The server reads it
// when the ID token does not vouch for the claim of the binding rule,
// and the claim counts when the provider record lists it.
func TestABindingMatchesAVouchedUserinfoClaim(t *testing.T) {
	h := newHarnessVouching(t, "individual_id")
	h.esignetShape(map[string]any{"individual_id": "5174920386"})
	h.bindOffer("offer-1", "individual_id", "5174920386")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	if back.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", back)
	}
	if len(h.issuer.staged) != 1 || h.idp.Requests["/userinfo"] != 1 {
		t.Fatalf("staged = %v, userinfo calls = %d", h.issuer.staged, h.idp.Requests["/userinfo"])
	}
}

// TestAUserinfoClaimFollowsTheVouchedRule: a claim of the userinfo
// answer that the record does not list, and an email without its
// verified flag, match no offer. An answer the key set of the provider
// did not sign ends the sign in, and nothing is staged.
func TestAUserinfoClaimFollowsTheVouchedRule(t *testing.T) {
	cases := []struct {
		name     string
		verified []string
		claim    string
		userinfo map[string]any
		want     string
	}{
		{"an unlisted claim", nil, "individual_id", map[string]any{"individual_id": "5174920386"}, authz.DeniedAnotherPerson},
		{"an email without a flag", []string{"email"}, "email", map[string]any{"email": "5174920386"}, authz.DeniedAnotherPerson},
		{"an email verified false", nil, "email", map[string]any{"email": "5174920386", "email_verified": false}, authz.DeniedAnotherPerson},
		{"another value", []string{"individual_id"}, "individual_id", map[string]any{"individual_id": "5174920387"}, authz.DeniedAnotherPerson},
		{"another person", []string{"individual_id"}, "individual_id", map[string]any{"individual_id": "5174920386", "sub": "someone-else"}, authz.DeniedSignIn},
	}
	for _, c := range cases {
		h := newHarnessVouching(t, c.verified...)
		h.esignetShape(c.userinfo)
		h.bindOffer("offer-1", c.claim, "5174920386")
		r := newRequest(publicClient, walletCallback)
		r.issuerState = "offer-1"
		back := h.signIn(r)
		wantError(t, back, "access_denied", r.state)
		if got := back.Query().Get("error_description"); got != c.want {
			t.Errorf("%s: description = %q, want %q", c.name, got, c.want)
		}
		if len(h.issuer.staged) != 0 {
			t.Errorf("%s: staged = %v", c.name, h.issuer.staged)
		}
	}
	// A verified email of the userinfo answer matches.
	h := newHarness(t)
	h.esignetShape(map[string]any{"email": "amina@example.org", "email_verified": true})
	h.addOffer("offer-2", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-2"
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Fatalf("a verified email: %s", back)
	}
	// A key outside the key set of the provider ends the sign in.
	h = newHarnessVouching(t, "individual_id")
	h.esignetShape(map[string]any{"individual_id": "5174920386"})
	h.idp.UserinfoKey = anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	h.bindOffer("offer-1", "individual_id", "5174920386")
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	wantError(t, back, "access_denied", r.state)
	if got := back.Query().Get("error_description"); got != authz.DeniedSignIn || len(h.issuer.staged) != 0 {
		t.Fatalf("a foreign key: %q %v", got, h.issuer.staged)
	}
	if !strings.Contains(h.logs.String(), "userinfo") {
		t.Errorf("the log does not name the userinfo answer:\n%s", h.logs.String())
	}
}

// TestTheIDTokenSparesTheUserinfoCall: a provider whose ID token already
// vouches for the claim of the rule gets no userinfo call.
func TestTheIDTokenSparesTheUserinfoCall(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", back)
	}
	if h.idp.Requests["/userinfo"] != 0 {
		t.Fatalf("userinfo calls = %d", h.idp.Requests["/userinfo"])
	}
}

// TestASignInSourceFindsTheHolderByAUserinfoClaim: a claim without an
// offer looks the holder up by a vouched claim of the userinfo answer.
func TestASignInSourceFindsTheHolderByAUserinfoClaim(t *testing.T) {
	h := newHarnessVouching(t, "individual_id")
	h.esignetShape(map[string]any{"individual_id": "5174920386"})
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{
		ConfigID: "ResidencePermit", SourceID: "registry", Field: "national_id", TokenClaim: "individual_id",
	}); err != nil {
		t.Fatal(err)
	}
	h.lookup.rows["5174920386"] = `{"fullName":"Wanjiru Kamau"}`
	r := newRequest(publicClient, walletCallback)
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", back)
	}
	if strings.Join(h.lookup.calls, ",") != "registry/national_id=5174920386" {
		t.Fatalf("lookups = %v", h.lookup.calls)
	}
}
