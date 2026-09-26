// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
)

// userinfoLogin runs a login at a provider whose userinfo answer holds
// the claims, and returns the flow, the record and the result.
func userinfoLogin(t *testing.T, idp *oidctest.Provider, claims map[string]any) (*oidcflow.Flow, oidcflow.Provider, oidcflow.Result) {
	t.Helper()
	idp.Userinfo = claims
	f := newFlow(t)
	p := testProvider(idp)
	res, err := runLogin(t, f, idp, p)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return f, p, res
}

// TestUserinfoVerifiesTheSignedAnswer: a provider such as eSignet sends
// the claims of a person only in a signed userinfo JWT. The flow reads it
// with the access token, checks the signature against the key set of the
// provider, its iss, its aud and its sub, and returns the claims.
func TestUserinfoVerifiesTheSignedAnswer(t *testing.T) {
	idp := oidctest.NewRS256()
	defer idp.Close()
	idp.UserinfoSigned = true
	f, p, res := userinfoLogin(t, idp, map[string]any{"individual_id": "5174920386"})
	got, err := f.Userinfo(context.Background(), p, res)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if got["individual_id"] != "5174920386" || got["sub"] != "user-1" || got["iss"] != idp.Issuer() {
		t.Fatalf("claims = %v", got)
	}
	if idp.Requests["/userinfo"] != 1 {
		t.Fatalf("userinfo calls = %d", idp.Requests["/userinfo"])
	}
}

// TestUserinfoTakesPlainJSON: most providers answer userinfo with plain
// JSON over the TLS channel of the call. The flow takes it when its sub
// is the sub of the ID token.
func TestUserinfoTakesPlainJSON(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	f, p, res := userinfoLogin(t, idp, map[string]any{"member_no": "M-2291"})
	got, err := f.Userinfo(context.Background(), p, res)
	if err != nil || got["member_no"] != "M-2291" {
		t.Fatalf("userinfo = %v %v", got, err)
	}
}

// TestUserinfoWithoutIssAndAud: the authenticator plugins of eSignet
// 1.5.1 sign the userinfo claims and sub with no iss and no aud
// (IdaAuthenticatorImpl of the MOSIP identity plugin and
// SunbirdRCAuthenticationService.doKycExchange of esignet-plugins
// v1.3.1). The key set of eSignet publishes the key. The flow takes such
// an answer from its own call, and it still checks iss and aud whenever
// the answer names them.
func TestUserinfoWithoutIssAndAud(t *testing.T) {
	idp := oidctest.NewRS256()
	defer idp.Close()
	idp.UserinfoSigned, idp.UserinfoBare = true, true
	f, p, res := userinfoLogin(t, idp, map[string]any{"name": "Wanjiru Kamau"})
	got, err := f.Userinfo(context.Background(), p, res)
	if err != nil || got["name"] != "Wanjiru Kamau" {
		t.Fatalf("userinfo = %v %v", got, err)
	}
}

// TestUserinfoRefusesWhatItCannotTrust: a wrong key, issuer, audience,
// subject or expiry, an encrypted or unknown answer, an error of the
// endpoint, and a login without an access token all fail. No claim of
// such an answer reaches the caller.
func TestUserinfoRefusesWhatItCannotTrust(t *testing.T) {
	other := anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	cases := []struct {
		name  string
		setup func(idp *oidctest.Provider)
		res   func(res *oidcflow.Result)
		want  error
	}{
		{"a key the key set does not hold", func(idp *oidctest.Provider) { idp.UserinfoKey = other }, nil, oidcflow.ErrSessionInvalid},
		{"another issuer", func(idp *oidctest.Provider) { idp.Userinfo["iss"] = "https://idp.other.example" }, nil, oidcflow.ErrSessionInvalid},
		{"another audience", func(idp *oidctest.Provider) { idp.Userinfo["aud"] = []any{"another-client"} }, nil, oidcflow.ErrSessionInvalid},
		{"another person", func(idp *oidctest.Provider) { idp.Userinfo["sub"] = "user-2" }, nil, oidcflow.ErrSessionInvalid},
		{"no subject", func(idp *oidctest.Provider) { idp.Userinfo["sub"] = "" }, nil, oidcflow.ErrSessionInvalid},
		{"an expired answer", func(idp *oidctest.Provider) { idp.Userinfo["exp"] = time.Now().Add(-time.Hour).Unix() }, nil, oidcflow.ErrSessionInvalid},
		{"an encrypted answer", func(idp *oidctest.Provider) {
			idp.UserinfoBody, idp.UserinfoType = "eyJhbGciOiJSU0EtT0FFUC0yNTYifQ.a.b.c.d", "application/jwt"
		}, nil, oidcflow.ErrSessionInvalid},
		{"a broken JWT", func(idp *oidctest.Provider) {
			idp.UserinfoBody, idp.UserinfoType = "not-a-jwt", "application/jwt; charset=utf-8"
		}, nil, oidcflow.ErrSessionInvalid},
		{"JSON that is no object", func(idp *oidctest.Provider) {
			idp.UserinfoBody, idp.UserinfoType = `["a"]`, "application/json"
		}, nil, oidcflow.ErrProviderError},
		{"an unknown media type", func(idp *oidctest.Provider) {
			idp.UserinfoBody, idp.UserinfoType = "sub=user-1", "text/plain"
		}, nil, oidcflow.ErrProviderError},
		{"a refused token", nil, func(res *oidcflow.Result) { res.AccessToken = "at-unknown" }, oidcflow.ErrProviderError},
		{"no access token", nil, func(res *oidcflow.Result) { res.AccessToken = "" }, oidcflow.ErrProviderError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idp := oidctest.New()
			defer idp.Close()
			idp.UserinfoSigned = true
			f, p, res := userinfoLogin(t, idp, map[string]any{"individual_id": "5174920386"})
			if c.setup != nil {
				c.setup(idp)
			}
			if c.res != nil {
				c.res(&res)
			}
			got, err := f.Userinfo(context.Background(), p, res)
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("userinfo = %v %v, want %v", got, err, c.want)
			}
		})
	}
}

// TestUserinfoNeedsAnEndpoint: a provider that publishes no userinfo
// endpoint gives ErrNoUserinfo, and an unreachable one ErrUpstream.
func TestUserinfoNeedsAnEndpoint(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	f, p, res := userinfoLogin(t, idp, nil)
	p.InternalAuthority = "http://127.0.0.1:1"
	if _, err := f.Userinfo(context.Background(), p, res); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("unreachable = %v", err)
	}
	cache := oidcflow.NewCache(nil, 0)
	bare := &oidcflow.Flow{Cache: cache}
	p = testProvider(idp)
	p.DiscoveryURL = idp.Issuer() + "/bare"
	if _, err := bare.Userinfo(context.Background(), p, res); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("no metadata = %v", err)
	}
}

// TestMergeVouchedTakesOnlyWhatTheProviderVouchesFor: the userinfo
// answer adds a claim the ID token does not vouch for, only when the
// record lists it or its verified flag says true (ADR-056 decision 2).
// sub and the claims of the token itself never change.
func TestMergeVouchedTakesOnlyWhatTheProviderVouchesFor(t *testing.T) {
	id := map[string]any{"iss": "https://idp.example", "sub": "psut-1", "email": "a@x.example", "email_verified": false}
	info := map[string]any{
		"sub": "psut-2", "iss": "https://evil.example", "individual_id": "5174920386", "name": "Wanjiru Kamau",
		"email": "b@x.example", "email_verified": true, "phone_number": "+254700000001",
		"preferred_username": "wkamau", "email_verified_note": "x",
	}
	got := oidcflow.MergeVouched(id, info, []string{"individual_id", "sub", "iss", "email_verified"})
	want := map[string]any{
		"iss": "https://idp.example", "sub": "psut-1", "email": "b@x.example", "email_verified": true,
		"individual_id": "5174920386",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v\nwant %v", got, want)
	}
	if id["email"] != "a@x.example" {
		t.Fatal("the merge changed the claims of the ID token")
	}
	// A claim the ID token vouches for stays as the token says.
	id = map[string]any{"sub": "psut-1", "email": "a@x.example", "email_verified": true, "individual_id": "111"}
	got = oidcflow.MergeVouched(id, info, []string{"individual_id"})
	if got["email"] != "a@x.example" || got["individual_id"] != "111" {
		t.Fatalf("merged = %v", got)
	}
	// A flagged claim without a true flag in the answer stays out.
	got = oidcflow.MergeVouched(map[string]any{"sub": "psut-1"}, map[string]any{"phone_number": "+254700000001", "phone_number_verified": "false"}, nil)
	if _, ok := got["phone_number"]; ok {
		t.Fatalf("merged = %v", got)
	}
}

// TestVouchedValue is the rule of ADR-056 decision 2 in one place: sub
// always, email and phone_number with their flag true, any other claim
// only when the record lists it.
func TestVouchedValue(t *testing.T) {
	claims := map[string]any{
		"sub": "psut-1", "email": " a@x.example ", "email_verified": "TRUE", "phone_number": "+254700000001",
		"phone_number_verified": 1, "individual_id": "5174920386", "empty": "  ", "number": 7.0,
	}
	for _, c := range []struct {
		name string
		want string
		ok   bool
	}{
		{"sub", "psut-1", true}, {"email", "a@x.example", true}, {"phone_number", "+254700000001", false},
		{"individual_id", "5174920386", true}, {"name", "", false}, {"empty", "", false}, {"number", "", false},
	} {
		got, ok := oidcflow.VouchedValue(claims, c.name, []string{"individual_id", "empty", "number"})
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s = %q %v, want %q %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if _, ok := oidcflow.VouchedValue(claims, "individual_id", nil); ok {
		t.Error("an unlisted claim counted")
	}
}

// TestVouchedAsksUserinfoOnlyWhenTheIDTokenFallsShort: the flow reads
// userinfo only for a claim the ID token does not vouch for and the
// provider could vouch for. A provider without a userinfo endpoint
// leaves the ID token claims as they are.
func TestVouchedAsksUserinfoOnlyWhenTheIDTokenFallsShort(t *testing.T) {
	idp := oidctest.NewRS256()
	defer idp.Close()
	idp.UserinfoSigned = true
	idp.Claims = map[string]any{"email": "wanjiru@x.example", "email_verified": true}
	f, p, res := userinfoLogin(t, idp, map[string]any{"individual_id": "5174920386"})
	p.VerifiedClaims = []string{"individual_id"}
	ctx := context.Background()
	for _, name := range []string{"email", "sub", "preferred_username"} {
		got, err := f.Vouched(ctx, p, res, name)
		if err != nil || !reflect.DeepEqual(got, res.Claims) {
			t.Fatalf("%s: %v %v", name, got, err)
		}
	}
	if idp.Requests["/userinfo"] != 0 {
		t.Fatalf("userinfo calls = %d, want none", idp.Requests["/userinfo"])
	}
	got, err := f.Vouched(ctx, p, res, "individual_id")
	if err != nil || got["individual_id"] != "5174920386" || got["email"] != "wanjiru@x.example" {
		t.Fatalf("individual_id: %v %v", got, err)
	}
	idp.UserinfoKey = anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	if _, err = f.Vouched(ctx, p, res, "individual_id"); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("a bad answer = %v", err)
	}
	// Without an endpoint the claims stay those of the ID token.
	bare := oidctest.New()
	defer bare.Close()
	bare.NoUserinfo = true
	f, p, res = userinfoLogin(t, bare, map[string]any{"individual_id": "5174920386"})
	p.VerifiedClaims = []string{"individual_id"}
	got, err = f.Vouched(ctx, p, res, "individual_id")
	if err != nil || !reflect.DeepEqual(got, res.Claims) {
		t.Fatalf("no endpoint: %v %v", got, err)
	}
	if _, err := f.Userinfo(ctx, p, res); !errors.Is(err, oidcflow.ErrNoUserinfo) {
		t.Fatalf("no endpoint = %v", err)
	}
}
