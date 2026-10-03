// SPDX-License-Identifier: Apache-2.0

package peerauth_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// trustGet is a procedure of an internal service.
const trustGet = "/vca.trust.v1.TrustService/GetEntry"

// newAuthority makes the authority of one deployment.
func newAuthority(t *testing.T) peerauth.Authority {
	t.Helper()
	a, err := peerauth.NewAuthority(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// issue gives a service of the deployment its identity.
func issue(t *testing.T, a peerauth.Authority, service string) peerauth.Settings {
	t.Helper()
	s, err := a.Issue(peerauth.ID{Service: service, Pair: "issuer-waltid"}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// serve mounts one procedure behind the interceptor of callee and
// returns its server and the caller the handler saw.
func serve(t *testing.T, callee peerauth.Settings, procedure string) (*httptest.Server, *peerauth.ID) {
	t.Helper()
	seen := &peerauth.ID{}
	h := connect.NewUnaryHandler(procedure,
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			if id, ok := peerauth.CallerFrom(ctx); ok {
				*seen = id
			}
			return connect.NewResponse(&emptypb.Empty{}), nil
		}, peerauth.Require(callee))
	mux := http.NewServeMux()
	mux.Handle(procedure, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, seen
}

// call calls procedure on srv with client and returns the Connect code.
func call(t *testing.T, client *http.Client, srv *httptest.Server, procedure string) connect.Code {
	t.Helper()
	c := connect.NewClient[emptypb.Empty, emptypb.Empty](client, srv.URL+procedure)
	_, err := c.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	if err == nil {
		return 0
	}
	return connect.CodeOf(err)
}

func TestAListedCallerPasses(t *testing.T) {
	a := newAuthority(t)
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"admin", "issuance"}}
	srv, seen := serve(t, callee, trustGet)
	caller := issue(t, a, "issuance")
	if code := call(t, caller.Client(srv.Client()), srv, trustGet); code != 0 {
		t.Fatalf("a listed caller got %v", code)
	}
	if seen.Service != "issuance" || seen.Pair != "issuer-waltid" {
		t.Errorf("the handler saw %+v", *seen)
	}
}

func TestAnUnlistedCallerIsRefused(t *testing.T) {
	a := newAuthority(t)
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"admin"}}
	srv, _ := serve(t, callee, trustGet)
	caller := issue(t, a, "wallet-portal")
	if code := call(t, caller.Client(srv.Client()), srv, trustGet); code != connect.CodePermissionDenied {
		t.Fatalf("an unlisted caller got %v, want permission_denied", code)
	}
	// A Connect service that the list does not name has no caller.
	other := "/vca.audit.v1.AuditService/ListEvents"
	srv2, _ := serve(t, callee, other)
	admin := issue(t, a, "admin")
	if code := call(t, admin.Client(srv2.Client()), srv2, other); code != connect.CodePermissionDenied {
		t.Fatalf("a caller of an unlisted service got %v, want permission_denied", code)
	}
}

func TestACallWithoutIdentityIsUnauthenticated(t *testing.T) {
	a := newAuthority(t)
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	srv, _ := serve(t, callee, trustGet)
	if code := call(t, srv.Client(), srv, trustGet); code != connect.CodeUnauthenticated {
		t.Fatalf("a call with no identity got %v, want unauthenticated", code)
	}
	// A caller with no identity of its own sends nothing either.
	if code := call(t, (peerauth.Settings{}).Client(srv.Client()), srv, trustGet); code != connect.CodeUnauthenticated {
		t.Fatalf("a caller with no identity got %v, want unauthenticated", code)
	}
}

func TestACalleeWithoutAuthorityRefusesEveryone(t *testing.T) {
	a := newAuthority(t)
	srv, _ := serve(t, peerauth.Settings{Callers: peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}}, trustGet)
	caller := issue(t, a, "issuance")
	if code := call(t, caller.Client(srv.Client()), srv, trustGet); code != connect.CodeUnauthenticated {
		t.Fatalf("a callee with no authority answered %v, want unauthenticated", code)
	}
}

func TestAnIdentityOfAnotherAuthorityIsRefused(t *testing.T) {
	callee := issue(t, newAuthority(t), "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	srv, _ := serve(t, callee, trustGet)
	stranger := issue(t, newAuthority(t), "issuance")
	if code := call(t, stranger.Client(srv.Client()), srv, trustGet); code != connect.CodeUnauthenticated {
		t.Fatalf("a stranger got %v, want unauthenticated", code)
	}
}

// headerFor returns the identity headers of one call of s.
func headerFor(t *testing.T, s peerauth.Settings, procedure string) http.Header {
	t.Helper()
	h, err := s.Header(procedure)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCheck(t *testing.T) {
	a := newAuthority(t)
	now := time.Now()
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	callee.Now = func() time.Time { return now }
	caller := issue(t, a, "issuance")
	caller.Now = func() time.Time { return now }
	good := headerFor(t, caller, trustGet)
	if id, err := callee.Check(good, trustGet); err != nil || id.Service != "issuance" {
		t.Fatalf("Check = %+v, %v", id, err)
	}
	// Another identity's key cannot sign for the statement.
	other := issue(t, a, "issuance")
	mixed := headerFor(t, other, trustGet)
	mixed.Set(peerauth.IdentityHeader, good.Get(peerauth.IdentityHeader))
	// A statement whose subject differs from the token issuer.
	admin := issue(t, a, "admin")
	swapped := headerFor(t, caller, trustGet)
	swapped.Set(peerauth.IdentityHeader, admin.Statement)
	late := func() time.Time { return now.Add(peerauth.TokenTTL + time.Second) }
	early := func() time.Time { return now.Add(-time.Minute) }
	cases := []struct {
		name      string
		h         http.Header
		procedure string
		now       func() time.Time
		code      connect.Code
	}{
		{"another procedure", good, "/vca.trust.v1.TrustService/PutEntry", nil, connect.CodeUnauthenticated},
		{"expired", good, trustGet, late, connect.CodeUnauthenticated},
		{"from the future", good, trustGet, early, connect.CodeUnauthenticated},
		{"key of another identity", mixed, trustGet, nil, connect.CodeUnauthenticated},
		{"subject swapped", swapped, trustGet, nil, connect.CodeUnauthenticated},
		{"no token", http.Header{peerauth.IdentityHeader: good[peerauth.IdentityHeader]}, trustGet, nil, connect.CodeUnauthenticated},
		{"garbage", http.Header{peerauth.IdentityHeader: {"x"}, peerauth.TokenHeader: {"y"}}, trustGet, nil, connect.CodeUnauthenticated},
		{"a statement as token", http.Header{peerauth.IdentityHeader: {caller.Statement}, peerauth.TokenHeader: {caller.Statement}}, trustGet, nil, connect.CodeUnauthenticated},
		{"a token as statement", http.Header{peerauth.IdentityHeader: good[peerauth.TokenHeader], peerauth.TokenHeader: good[peerauth.TokenHeader]}, trustGet, nil, connect.CodeUnauthenticated},
		{"not a procedure", good, "/healthz", nil, connect.CodeUnauthenticated},
	}
	for _, tc := range cases {
		c := callee
		if tc.now != nil {
			c.Now = tc.now
		}
		_, err := c.Check(tc.h, tc.procedure)
		if connect.CodeOf(err) != tc.code {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.code)
		}
	}
}

func TestTheTransportSignsConnectCallsOnly(t *testing.T) {
	a := newAuthority(t)
	caller := issue(t, a, "issuance")
	var got []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Clone())
	}))
	defer srv.Close()
	client := caller.Client(&http.Client{Timeout: time.Second})
	send := func(path string, header map[string]string) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	connectJSON := map[string]string{"Content-Type": "application/json", "Connect-Protocol-Version": "1"}
	send("/readyz", connectJSON)
	send(trustGet, map[string]string{"Content-Type": "application/json"})
	send(trustGet, connectJSON)
	send(trustGet, map[string]string{"Content-Type": "application/grpc+proto"})
	send(trustGet, map[string]string{"Content-Type": "application/connect+json"})
	for i, h := range got[:2] {
		if h.Get(peerauth.TokenHeader) != "" || h.Get(peerauth.IdentityHeader) != "" {
			t.Errorf("request %d is no Connect call but carried the identity: %v", i, h)
		}
	}
	for i, h := range got[2:] {
		if h.Get(peerauth.TokenHeader) == "" || h.Get(peerauth.IdentityHeader) != caller.Statement {
			t.Errorf("Connect call %d carried no identity: %v", i, h)
		}
	}
	// The wrapped client keeps its timeout, and a nil client works.
	if client.Timeout != time.Second || caller.Client(nil) == nil {
		t.Error("the client lost its settings")
	}
}

func TestEnvRoundTrip(t *testing.T) {
	a := newAuthority(t)
	s := issue(t, a, "issuance")
	s.Callers = peerauth.Callers{"vca.issuance.v1.IssuanceService": {"data-source"}, "vca.audit.v1.AuditService": {"admin"}}
	env := s.Env()
	for _, name := range []string{peerauth.KeyEnv, peerauth.IdentityEnv, peerauth.AuthorityEnv, peerauth.CallersEnv} {
		if env[name] == "" {
			t.Errorf("Env lacks %s", name)
		}
	}
	got, err := peerauth.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured() || got.ID != s.ID || got.Statement != s.Statement {
		t.Errorf("Load = %+v", got.ID)
	}
	if got.Callers.String() != s.Callers.String() {
		t.Errorf("callers %q, want %q", got.Callers.String(), s.Callers.String())
	}
	// The loaded identity calls a service that trusts the authority.
	callee := issue(t, a, "issued-credentials")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	if _, cerr := callee.Check(headerFor(t, got, trustGet), trustGet); cerr != nil {
		t.Fatal(cerr)
	}
	// No variable at all is a service without an identity.
	none, err := peerauth.Load(func(string) string { return "" })
	if err != nil || none.Configured() {
		t.Fatalf("Load of nothing = %+v, %v", none, err)
	}
}

func TestLoadRefusesBadValues(t *testing.T) {
	a := newAuthority(t)
	env := issue(t, a, "issuance").Env()
	stranger := issue(t, newAuthority(t), "issuance").Env()
	cases := map[string]map[string]string{
		"bad key":                    {peerauth.KeyEnv: "%%%"},
		"key not JSON":               {peerauth.KeyEnv: "bm90IGpzb24"},
		"public key":                 {peerauth.KeyEnv: env[peerauth.AuthorityEnv]},
		"bad authority":              {peerauth.AuthorityEnv: "%%%"},
		"bad statement":              {peerauth.IdentityEnv: "x.y.z"},
		"statement of another one":   {peerauth.IdentityEnv: stranger[peerauth.IdentityEnv]},
		"key of another identity":    {peerauth.KeyEnv: stranger[peerauth.KeyEnv]},
		"bad callers":                {peerauth.CallersEnv: "vca.trust.v1.TrustService"},
		"key with no statement":      {peerauth.IdentityEnv: ""},
		"statement with no key":      {peerauth.KeyEnv: ""},
		"identity with no authority": {peerauth.AuthorityEnv: ""},
	}
	for name, change := range cases {
		getenv := func(k string) string {
			if v, ok := change[k]; ok {
				return v
			}
			return env[k]
		}
		if _, err := peerauth.Load(getenv); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
	// A callee may hold the authority and the list with no identity of
	// its own: it checks callers and calls nobody.
	only := map[string]string{peerauth.AuthorityEnv: env[peerauth.AuthorityEnv], peerauth.CallersEnv: "vca.trust.v1.TrustService=admin"}
	s, err := peerauth.Load(func(k string) string { return only[k] })
	if err != nil || s.Configured() || len(s.Authority.Keys) != 1 {
		t.Fatalf("Load of a callee only = %+v, %v", s.ID, err)
	}
}

func TestCallers(t *testing.T) {
	c, err := peerauth.ParseCallers(" vca.b.v1.B = y , x ; vca.a.v1.A= ;")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.String(); got != "vca.a.v1.A=;vca.b.v1.B=x,y" {
		t.Errorf("String = %q", got)
	}
	if !c.Allows("vca.b.v1.B", "x") || c.Allows("vca.a.v1.A", "x") || c.Allows("vca.c.v1.C", "x") {
		t.Error("Allows is wrong")
	}
	for _, bad := range []string{"novalue", "=x", "vca.a.v1.A=x;vca.a.v1.A=y", "vca.a.v1.A=x y"} {
		if _, err := peerauth.ParseCallers(bad); err == nil {
			t.Errorf("ParseCallers(%q) accepted it", bad)
		}
	}
	if c, err := peerauth.ParseCallers(""); err != nil || len(c) != 0 {
		t.Errorf("ParseCallers(\"\") = %v, %v", c, err)
	}
}

func TestAuthorityPEMRoundTrip(t *testing.T) {
	a := newAuthority(t)
	pemBytes, err := a.PEM()
	if err != nil {
		t.Fatal(err)
	}
	b, err := peerauth.ParseAuthority(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	// An identity of the parsed authority passes the first one.
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	if _, err := callee.Check(headerFor(t, issue(t, b, "issuance"), trustGet), trustGet); err != nil {
		t.Fatal(err)
	}
	if a.PublicSet() != b.PublicSet() {
		t.Error("the public set changed")
	}
	if _, err := peerauth.ParseAuthority([]byte("nope")); err == nil {
		t.Error("ParseAuthority accepted garbage")
	}
	if _, err := peerauth.NewAuthority(strings.NewReader("")); err == nil {
		t.Error("NewAuthority took no randomness")
	}
	if _, err := a.Issue(peerauth.ID{Service: "x"}, strings.NewReader(""), time.Now()); err == nil {
		t.Error("Issue took no randomness")
	}
	if _, err := a.Issue(peerauth.ID{}, rand.Reader, time.Now()); err == nil {
		t.Error("Issue took no service name")
	}
	if _, err := (peerauth.Settings{}).Header(trustGet); !errors.Is(err, peerauth.ErrNoIdentity) {
		t.Errorf("Header with no identity = %v", err)
	}
}

func TestAStreamChecksItsCaller(t *testing.T) {
	a := newAuthority(t)
	callee := issue(t, a, "verifier-results")
	callee.Callers = peerauth.Callers{"vca.results.v1.ResultsService": {"verifier-combined"}}
	const procedure = "/vca.results.v1.ResultsService/Watch"
	h := connect.NewServerStreamHandler(procedure,
		func(ctx context.Context, _ *connect.Request[emptypb.Empty], stream *connect.ServerStream[emptypb.Empty]) error {
			if id, ok := peerauth.CallerFrom(ctx); !ok || id.String() != "issuer-waltid/verifier-combined" {
				return connect.NewError(connect.CodeInternal, errors.New("no caller"))
			}
			return stream.Send(&emptypb.Empty{})
		}, peerauth.Require(callee))
	srv := httptest.NewServer(h)
	defer srv.Close()
	open := func(s peerauth.Settings) error {
		c := connect.NewClient[emptypb.Empty, emptypb.Empty](s.Client(srv.Client()), srv.URL+procedure)
		stream, err := c.CallServerStream(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		if err != nil {
			return err
		}
		defer func() {
			if err := stream.Close(); err != nil {
				t.Log(err)
			}
		}()
		for stream.Receive() {
		}
		return stream.Err()
	}
	if err := open(issue(t, a, "verifier-combined")); err != nil {
		t.Fatalf("a listed caller: %v", err)
	}
	if err := open(issue(t, a, "wallet-portal")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an unlisted caller: %v", err)
	}
	if (peerauth.ID{Service: "cli"}).String() != "cli" {
		t.Error("an ID with no pair names the service alone")
	}
}

// doFunc is a Connect client that is no *http.Client.
type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestSignWrapsEveryKindOfClient(t *testing.T) {
	a := newAuthority(t)
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	srv, _ := serve(t, callee, trustGet)
	caller := issue(t, a, "issuance")
	called := false
	custom := doFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return srv.Client().Do(r)
	})
	for name, c := range map[string]connect.HTTPClient{"nil": nil, "http": srv.Client(), "custom": custom} {
		client := connect.NewClient[emptypb.Empty, emptypb.Empty](caller.Sign(c), srv.URL+trustGet)
		if _, err := client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{})); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !called {
		t.Error("the custom client sent nothing")
	}
}
