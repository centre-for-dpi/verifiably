// SPDX-License-Identifier: Apache-2.0

package peerauth_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	// The test server listens on the loopback address, which is no
	// name of the callee in a deployment.
	callee.Hosts = append(callee.Hosts, "127.0.0.1")
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

// trustHost is the address of the callee "trust-registry" of the pair
// issuer-waltid on the compose network.
const trustHost = "issuer-waltid-trust-registry:8082"

// headerFor returns the identity headers of one call of s to the host.
func headerFor(t *testing.T, s peerauth.Settings, procedure string, host ...string) http.Header {
	t.Helper()
	to := trustHost
	if len(host) > 0 {
		to = host[0]
	}
	h, err := s.Header(procedure, to)
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
	late := func() time.Time { return now.Add(peerauth.TokenTTL + peerauth.ClockSkew + time.Second) }
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

// envWithKeyFile returns the variables of the identity file of s, with
// the key in a file of its own, as vca setup writes them.
func envWithKeyFile(t *testing.T, s peerauth.Settings) map[string]string {
	t.Helper()
	key, err := s.KeyJWK()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.jwk")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	env := s.Env()
	env[peerauth.KeyFileEnv] = path
	return env
}

func TestEnvRoundTrip(t *testing.T) {
	a := newAuthority(t)
	s := issue(t, a, "issuance")
	s.Callers = peerauth.Callers{"vca.issuance.v1.IssuanceService": {"data-source"}, "vca.audit.v1.AuditService": {"admin"}}
	env := s.Env()
	for _, name := range []string{peerauth.IdentityEnv, peerauth.AuthorityEnv, peerauth.CallersEnv} {
		if env[name] == "" {
			t.Errorf("Env lacks %s", name)
		}
	}
	// The private key never travels in the environment (finding 4 of the
	// review of ADR-075): it goes to a file of its own.
	if _, ok := env[peerauth.KeyEnv]; ok {
		t.Errorf("Env holds the private key in %s", peerauth.KeyEnv)
	}
	env = envWithKeyFile(t, s)
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
	if _, cerr := callee.Check(headerFor(t, got, trustGet, "issuer-waltid-issued-credentials:8084"), trustGet); cerr != nil {
		t.Fatal(cerr)
	}
	// The documented fallback: the key itself in VCA_PEER_KEY, as
	// base64url, where the platform cannot mount a file.
	key, err := s.KeyJWK()
	if err != nil {
		t.Fatal(err)
	}
	fallback := s.Env()
	fallback[peerauth.KeyEnv] = base64.RawURLEncoding.EncodeToString(key)
	if back, ferr := peerauth.Load(func(k string) string { return fallback[k] }); ferr != nil || !back.Configured() {
		t.Fatalf("Load of the fallback = %+v, %v", back.ID, ferr)
	}
	// No variable at all is a service without an identity.
	none, err := peerauth.Load(func(string) string { return "" })
	if err != nil || none.Configured() {
		t.Fatalf("Load of nothing = %+v, %v", none, err)
	}
	if _, err := (peerauth.Settings{}).KeyJWK(); !errors.Is(err, peerauth.ErrNoIdentity) {
		t.Errorf("KeyJWK with no identity = %v", err)
	}
}

func TestLoadRefusesBadValues(t *testing.T) {
	a := newAuthority(t)
	env := envWithKeyFile(t, issue(t, a, "issuance"))
	stranger := envWithKeyFile(t, issue(t, newAuthority(t), "issuance"))
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	public := write("public.jwk", `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`)
	cases := map[string]map[string]string{
		"missing key file":           {peerauth.KeyFileEnv: filepath.Join(dir, "none.jwk")},
		"key file not JSON":          {peerauth.KeyFileEnv: write("bad.jwk", "not json")},
		"public key file":            {peerauth.KeyFileEnv: public},
		"key file and key":           {peerauth.KeyEnv: "bm90IGpzb24"},
		"bad authority":              {peerauth.AuthorityEnv: "%%%"},
		"bad statement":              {peerauth.IdentityEnv: "x.y.z"},
		"statement of another one":   {peerauth.IdentityEnv: stranger[peerauth.IdentityEnv]},
		"key of another identity":    {peerauth.KeyFileEnv: stranger[peerauth.KeyFileEnv]},
		"bad callers":                {peerauth.CallersEnv: "vca.trust.v1.TrustService"},
		"key with no statement":      {peerauth.IdentityEnv: ""},
		"statement with no key":      {peerauth.KeyFileEnv: ""},
		"identity with no authority": {peerauth.AuthorityEnv: ""},
		"bad fallback key":           {peerauth.KeyFileEnv: "", peerauth.KeyEnv: "%%%"},
		"fallback key not JSON":      {peerauth.KeyFileEnv: "", peerauth.KeyEnv: "bm90IGpzb24"},
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
	if _, err := (peerauth.Settings{}).Header(trustGet, trustHost); !errors.Is(err, peerauth.ErrNoIdentity) {
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
		}, peerauth.Require(withLoopback(callee)))
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

// withLoopback returns s with the loopback address as a name of its own.
func withLoopback(s peerauth.Settings) peerauth.Settings {
	s.Hosts = append(s.Hosts, "127.0.0.1")
	return s
}

// statusAllocate is a procedure that two services of one pair serve.
const statusAllocate = "/vca.status.v1.StatusService/Allocate"

// TestATokenNamesItsCallee: the token names the procedure and the host
// of the callee. A callee takes a token for its own name only, so a
// token that a party reads on the network opens no other server: not
// the other status service of the pair, not the same service of
// another pair. A deployment scoped caller, such as the vca command on
// the machine of the operator, calls through a published port, so the
// callee takes its token only at a name of its own as well.
func TestATokenNamesItsCallee(t *testing.T) {
	a := newAuthority(t)
	list := peerauth.Callers{"vca.status.v1.StatusService": {"issuance", "cli"}}
	callee := func(service, pair string) peerauth.Settings {
		s, err := a.Issue(peerauth.ID{Service: service, Pair: pair}, rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		s.Callers = list
		return s
	}
	token, bitstring, inji := callee("status-token", "issuer-waltid"), callee("status-bitstring", "issuer-waltid"), callee("status-token", "issuer-inji")
	issuance := issue(t, a, "issuance")
	h := headerFor(t, issuance, statusAllocate, "issuer-waltid-status-token:8085")
	if _, err := token.Check(h, statusAllocate); err != nil {
		t.Fatalf("the callee the token names: %v", err)
	}
	for name, other := range map[string]peerauth.Settings{"the other status service": bitstring, "another pair": inji} {
		if _, err := other.Check(h, statusAllocate); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s took the token: %v", name, err)
		}
	}
	// The cluster name of a Helm release starts with the same label.
	if _, err := token.Check(headerFor(t, issuance, statusAllocate, "issuer-waltid-status-token.vca.svc.cluster.local:8085"), statusAllocate); err != nil {
		t.Errorf("a cluster name of the callee: %v", err)
	}
	if _, err := token.Check(headerFor(t, issuance, statusAllocate, ""), statusAllocate); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("a token that names no host: %v", err)
	}
	// More names of the callee come from VCA_PEER_HOSTS. A name with no
	// port stands for any port.
	named := token
	named.Hosts = []string{"127.0.0.1:9000", "status.internal"}
	for host, ok := range map[string]bool{
		"127.0.0.1:9000": true, "127.0.0.1:9001": false, "status.internal:8085": true,
		"issuer-waltid-status-token:8085": true, "issuer-waltid-status-bitstring:8084": false,
	} {
		_, err := named.Check(headerFor(t, issuance, statusAllocate, host), statusAllocate)
		if (err == nil) != ok {
			t.Errorf("host %s: %v, want accepted %v", host, err, ok)
		}
	}
	// A service with no pair, or a deployment scoped one that carries
	// its own name as the pair, has its name alone as the host.
	for _, id := range []peerauth.ID{{Service: "landing"}, {Service: "landing", Pair: "landing"}} {
		landing, err := a.Issue(id, rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		landing.Callers = list
		if _, err := landing.Check(headerFor(t, issuance, statusAllocate, "landing:8090"), statusAllocate); err != nil {
			t.Errorf("the host of %+v: %v", id, err)
		}
	}
	if _, err := (peerauth.Settings{Authority: token.Authority, Callers: list}).Check(h, statusAllocate); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("a callee with no name of its own took the token: %v", err)
	}
	cli, err := a.Issue(peerauth.ID{Service: "cli", Deployment: true}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A deployment scoped caller is bound to one callee too (amendment of
	// ADR-075 of 2026-10-04): the callee takes its token only at a name of
	// its own, such as the host port it publishes.
	published := token
	published.Hosts = []string{"127.0.0.1:18085", "localhost:18085"}
	cliToken := headerFor(t, cli, statusAllocate, "localhost:18085")
	if id, err := published.Check(cliToken, statusAllocate); err != nil || !id.Deployment {
		t.Errorf("the callee that publishes the port: %+v, %v", id, err)
	}
	for _, c := range []peerauth.Settings{token, bitstring, inji} {
		if _, err := c.Check(cliToken, statusAllocate); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s took a token of the deployment scoped caller for another host: %v", c.ID, err)
		}
	}
	if _, err := bitstring.Check(headerFor(t, cli, statusAllocate, "issuer-waltid-status-bitstring:8084"), statusAllocate); err != nil {
		t.Errorf("the deployment scoped caller at the default name of the callee: %v", err)
	}
}

// TestTheTimeWindowIsSymmetric: two clocks may differ by ClockSkew
// either way. A token counts from ClockSkew before its issue time to
// ClockSkew after its end, and a refusal names the difference.
func TestTheTimeWindowIsSymmetric(t *testing.T) {
	a := newAuthority(t)
	now := time.Now()
	callee := issue(t, a, "trust-registry")
	callee.Callers = peerauth.Callers{"vca.trust.v1.TrustService": {"issuance"}}
	caller := issue(t, a, "issuance")
	caller.Now = func() time.Time { return now }
	h := headerFor(t, caller, trustGet)
	half := peerauth.ClockSkew / 2
	for at, ok := range map[time.Duration]bool{
		-half: true, -peerauth.ClockSkew - time.Second: false,
		peerauth.TokenTTL + half: true, peerauth.TokenTTL + peerauth.ClockSkew + time.Second: false,
	} {
		callee.Now = func() time.Time { return now.Add(at) }
		_, err := callee.Check(h, trustGet)
		if (err == nil) != ok {
			t.Errorf("at %v: %v, want accepted %v", at, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "30s") {
			t.Errorf("at %v the refusal names no skew: %v", at, err)
		}
	}
}

// TestHostsAndScopeRoundTrip: VCA_PEER_HOSTS and the scope of a
// deployment scoped identity survive the identity file.
func TestHostsAndScopeRoundTrip(t *testing.T) {
	a := newAuthority(t)
	s, err := a.Issue(peerauth.ID{Service: "landing", Pair: "landing", Deployment: true}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.Hosts = []string{"landing.internal", "127.0.0.1:8090"}
	env := envWithKeyFile(t, s)
	if env[peerauth.HostsEnv] != "landing.internal,127.0.0.1:8090" {
		t.Errorf("%s = %q", peerauth.HostsEnv, env[peerauth.HostsEnv])
	}
	got, err := peerauth.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !got.ID.Deployment || len(got.Hosts) != 2 || got.Hosts[1] != "127.0.0.1:8090" {
		t.Errorf("Load = %+v, hosts %v", got.ID, got.Hosts)
	}
	if _, err := peerauth.Load(func(k string) string {
		if k == peerauth.HostsEnv {
			return "a b"
		}
		return env[k]
	}); err == nil {
		t.Error("Load took a host with a space")
	}
}
