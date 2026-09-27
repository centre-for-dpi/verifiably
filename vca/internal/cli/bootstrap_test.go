// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// fakeAdapter is the issuer side of the walt.id adapter: it keeps the
// identity it provisions or imports, as the adapter keeps it in its
// data volume (ADR-046 decision 4).
type fakeAdapter struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	identity   *backendv1.IssuerIdentity
	provisions []*backendv1.ProvisionIssuerIdentityRequest
	imports    []*backendv1.ImportIssuerIdentityRequest
	fail       error
}

func (f *fakeAdapter) GetIssuerIdentity(context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest]) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{Identity: f.identity}), nil
}

func (f *fakeAdapter) ProvisionIssuerIdentity(_ context.Context, req *connect.Request[backendv1.ProvisionIssuerIdentityRequest]) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	f.provisions = append(f.provisions, req.Msg)
	f.identity = &backendv1.IssuerIdentity{Identifiers: []string{"did:web:" + req.Msg.GetDomain()}}
	return connect.NewResponse(&backendv1.ProvisionIssuerIdentityResponse{Identity: f.identity}), nil
}

func (f *fakeAdapter) ImportIssuerIdentity(_ context.Context, req *connect.Request[backendv1.ImportIssuerIdentityRequest]) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	f.imports = append(f.imports, req.Msg)
	f.identity = &backendv1.IssuerIdentity{Identifiers: []string{req.Msg.GetDid()}}
	return connect.NewResponse(&backendv1.ImportIssuerIdentityResponse{Identity: f.identity}), nil
}

// serveAdapter serves the fake adapter as the pair routes it.
func serveAdapter(t *testing.T, h backendv1connect.IssuerBackendServiceHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewIssuerBackendServiceHandler(h))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func waltidOptions(t *testing.T, adapter string, out io.Writer) BootstrapOptions {
	t.Helper()
	return BootstrapOptions{
		Pair:   issuerPair(),
		Dir:    t.TempDir(),
		Values: map[string]string{"VCA_PUBLIC_URL": "https://issuer.example", EnvBootstrapAdapterURL: adapter},
		Client: &http.Client{},
		Out:    out,
	}
}

// TestBootstrapWaltidProvisionsThroughTheAdapter checks that the run asks
// the adapter to make a did:web of the host of the pair, so the stack
// keeps the key and the host keeps no key file (ADR-001 decision 3). A
// second run finds the identity and changes nothing.
func TestBootstrapWaltidProvisionsThroughTheAdapter(t *testing.T) {
	adapter := &fakeAdapter{}
	var out bytes.Buffer
	opts := waltidOptions(t, serveAdapter(t, adapter).URL, &out)
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(got.Steps) != 1 || !strings.Contains(got.Steps[0], "created") || !strings.Contains(got.Steps[0], "did:web:issuer.example") {
		t.Fatalf("steps = %v", got.Steps)
	}
	if len(adapter.provisions) != 1 {
		t.Fatalf("provisions = %d", len(adapter.provisions))
	}
	p := adapter.provisions[0]
	if p.GetMethod() != "did:web" || p.GetKeyType() != "secp256r1" || p.GetDomain() != "issuer.example" || p.GetKeyBackend() != "" {
		t.Errorf("provision = %v", p)
	}
	if _, serr := os.Stat(filepath.Join(opts.Dir, IssuerFile)); serr == nil {
		t.Errorf("the run wrote %s on the host", IssuerFile)
	}
	again, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if !strings.Contains(again.Steps[0], "present") || len(adapter.provisions) != 1 {
		t.Errorf("the second run said %v after %d provisions", again.Steps, len(adapter.provisions))
	}
}

// TestBootstrapWaltidImportsAnEarlierFile checks that the file an older
// run left on the host goes into the adapter, and that the run says the
// file can go.
func TestBootstrapWaltidImportsAnEarlierFile(t *testing.T) {
	adapter := &fakeAdapter{}
	var out bytes.Buffer
	opts := waltidOptions(t, serveAdapter(t, adapter).URL, &out)
	legacy := `{"issuerDid":"did:web:issuer.example:issuer","issuerKey":{"type":"jwk","jwk":{"kty":"EC","crv":"P-256"}}}`
	path := filepath.Join(opts.Dir, IssuerFile)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(adapter.imports) != 1 || len(adapter.provisions) != 0 {
		t.Fatalf("imports %d, provisions %d", len(adapter.imports), len(adapter.provisions))
	}
	in := adapter.imports[0]
	if in.GetDid() != "did:web:issuer.example:issuer" || !strings.Contains(in.GetKeyReference(), `"type":"jwk"`) {
		t.Errorf("import = %v", in)
	}
	if !strings.Contains(got.Steps[0], "imported") || !strings.Contains(got.Steps[0], path) {
		t.Errorf("steps = %v", got.Steps)
	}
	// A file with no DID or no key is not an earlier answer.
	for _, bad := range []string{`{`, `{"issuerDid":"did:web:x"}`, `{"issuerKey":{}}`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := readIssuerFile(path); ok {
			t.Errorf("%s reads as an earlier answer", bad)
		}
	}
}

// TestBootstrapWaltidReportsAdapterProblems checks that a run that cannot
// reach the adapter fails and writes no key on the host.
func TestBootstrapWaltidReportsAdapterProblems(t *testing.T) {
	var out bytes.Buffer
	down := &fakeAdapter{fail: connect.NewError(connect.CodeUnavailable, errors.New("down"))}
	opts := waltidOptions(t, serveAdapter(t, down).URL, &out)
	if _, err := BootstrapWaltid(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "issuer adapter") {
		t.Fatalf("a failing adapter passed: %v", err)
	}
	refused := &refusingAdapter{}
	opts = waltidOptions(t, serveAdapter(t, refused).URL, &out)
	if _, err := BootstrapWaltid(context.Background(), opts); err == nil {
		t.Fatal("a refused provision passed")
	}
	if err := os.WriteFile(filepath.Join(opts.Dir, IssuerFile), []byte(`{"issuerDid":"did:key:z","issuerKey":{"type":"jwk"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapWaltid(context.Background(), opts); err == nil {
		t.Fatal("a refused import passed")
	}
	if _, err := os.Stat(filepath.Join(opts.Dir, OnboardFile)); err == nil {
		t.Fatal("the run wrote a file")
	}
}

// refusingAdapter has no identity and refuses every change.
type refusingAdapter struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
}

func (refusingAdapter) GetIssuerIdentity(context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest]) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{}), nil
}

func TestBootstrapWaltidNeedsAPublicURL(t *testing.T) {
	for _, values := range []map[string]string{nil, {"VCA_PUBLIC_URL": "not a url"}, {"VCA_PUBLIC_URL": "ftp://h"},
		{"VCA_PUBLIC_URL": "https://issuer.example", EnvBootstrapAdapterURL: "nope"}} {
		opts := BootstrapOptions{Pair: issuerPair(), Dir: t.TempDir(), Values: values}
		if _, err := BootstrapWaltid(context.Background(), opts); err == nil {
			t.Errorf("values %v passed", values)
		}
	}
}

// TestBootstrapWaltidUsesTheHostPort is ADR-047 decision 3: the proxy
// publishes no adapter service, so without an override the run reaches
// the adapter on 127.0.0.1 and its host port from the .env of the pair,
// never on the public URL.
func TestBootstrapWaltidUsesTheHostPort(t *testing.T) {
	adapter := &fakeAdapter{identity: &backendv1.IssuerIdentity{Identifiers: []string{"did:web:issuer.example"}}}
	server := serveAdapter(t, adapter)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	public := serveAdapter(t, &fakeAdapter{fail: connect.NewError(connect.CodeNotFound, errors.New("the proxy publishes no adapter"))})
	var out bytes.Buffer
	opts := BootstrapOptions{Pair: issuerPair(), Dir: t.TempDir(), Out: &out, Values: map[string]string{
		"VCA_PUBLIC_URL": public.URL, "VCA_HOST_PORT_DPG_ADAPTER_WALTID": u.Port(),
	}}
	got, err := BootstrapWaltid(context.Background(), opts)
	if err != nil || !strings.Contains(got.Steps[0], "present: did:web:issuer.example") {
		t.Fatalf("steps %v: %v", got.Steps, err)
	}
	// With no override in the .env file the port plan names the port.
	base, err := BootstrapOptions{Pair: issuerPair(), Values: map[string]string{}}.adapterURL()
	want := ""
	for _, a := range AssignPorts(issuerPair(), nil) {
		if a.Service.Name == "dpg-adapter-waltid" {
			want = fmt.Sprintf("http://127.0.0.1:%d", a.Host)
		}
	}
	if err != nil || want == "" || base != want {
		t.Errorf("adapter URL %q, want %q: %v", base, want, err)
	}
	// The override still wins.
	base, err = BootstrapOptions{Pair: issuerPair(), Values: map[string]string{EnvBootstrapAdapterURL: "http://adapter.internal:8090/"}}.adapterURL()
	if err != nil || base != "http://adapter.internal:8090" {
		t.Errorf("override %q: %v", base, err)
	}
}

// TestBootstrapWaltidSkipsOtherRoles checks that a pair of another role
// needs no issuer identity.
func TestBootstrapWaltidSkipsOtherRoles(t *testing.T) {
	adapter := &fakeAdapter{}
	opts := waltidOptions(t, serveAdapter(t, adapter).URL, nil)
	opts.Pair.Role = commonv1.Role_ROLE_HOLDER
	got, err := BootstrapWaltid(context.Background(), opts)
	if err != nil || len(adapter.provisions) != 0 || !strings.Contains(got.Steps[0], "needs no issuer identity") {
		t.Fatalf("steps %v: %v", got.Steps, err)
	}
}

func TestBootstrapNeedsABaseURL(t *testing.T) {
	for _, values := range []map[string]string{nil, {"VCA_DPG_URL": "not a url"}, {"VCA_DPG_URL": "ftp://h"}} {
		opts := BootstrapOptions{Pair: Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}, Dir: t.TempDir(), Values: values}
		if _, err := Bootstrap(context.Background(), opts); err == nil {
			t.Errorf("values %v passed", values)
		}
	}
}

func TestBootstrapRejectsAnUnknownDpg(t *testing.T) {
	opts := BootstrapOptions{
		Pair:   Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_UNSPECIFIED},
		Values: map[string]string{"VCA_DPG_URL": "http://h"},
	}
	if _, err := Bootstrap(context.Background(), opts); err == nil {
		t.Fatal("an unspecified DPG passed")
	}
}

// keycloakState holds what the fake Keycloak server knows.
type keycloakState struct {
	// realm is the realm name the fake serves.
	realm string
	// password is the administrator password the fake accepts. Empty
	// accepts any.
	password    string
	realmExists bool
	created     int
	updated     int
	badToken    bool
	// createdRealm is the realm name of the last POST body.
	createdRealm string
	// putBody is the body of the last PUT.
	putBody []byte
	// clients maps the clientId of each client of the realm onto its id.
	clients map[string]string
	// clientPosts and clientPuts list the clientId of each client write.
	clientPosts, clientPuts []string
}

func fakeKeycloak(t *testing.T, state *keycloakState) *httptest.Server {
	t.Helper()
	if state.realm == "" {
		state.realm = RealmName(commonv1.Role_ROLE_ISSUER)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/master/protocol/openid-connect/token":
			if state.badToken {
				_, errAssign := io.WriteString(w, `{}`)
				if errAssign != nil {
					t.Fatalf("io.WriteString: %v", errAssign)
				}
				return
			}
			if state.password != "" && r.FormValue("password") != state.password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, errAssign2 := io.WriteString(w, `{"access_token":"a-token"}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
		case r.URL.Path == "/admin/realms/"+state.realm && r.Method == http.MethodGet:
			if !state.realmExists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, errAssign3 := io.WriteString(w, `{"realm":"`+state.realm+`"}`)
			if errAssign3 != nil {
				t.Fatalf("io.WriteString: %v", errAssign3)
			}
		case r.URL.Path == "/admin/realms/"+state.realm && r.Method == http.MethodPut:
			state.updated++
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("read the PUT body: %v", readErr)
			}
			state.putBody = body
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/admin/realms/"+state.realm+"/clients" && r.Method == http.MethodGet:
			var list []map[string]string
			if id, ok := state.clients[r.URL.Query().Get("clientId")]; ok {
				list = append(list, map[string]string{"id": id, "clientId": r.URL.Query().Get("clientId")})
			}
			if err := json.NewEncoder(w).Encode(list); err != nil {
				t.Errorf("encode the clients: %v", err)
			}
		case r.URL.Path == "/admin/realms/"+state.realm+"/clients" && r.Method == http.MethodPost:
			var body struct {
				ClientID string `json:"clientId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.clientPosts = append(state.clientPosts, body.ClientID)
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/"+state.realm+"/clients/") && r.Method == http.MethodPut:
			var body struct {
				ID       string `json:"id"`
				ClientID string `json:"clientId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || "/admin/realms/"+state.realm+"/clients/"+body.ID != r.URL.Path {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.clientPuts = append(state.clientPuts, body.ClientID)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/admin/realms" && r.Method == http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer a-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct {
				Realm string `json:"realm"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.createdRealm = body.Realm
			state.created++
			state.realmExists = true
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// injiOptions lays out a deploy root with the realm of one Inji pair in
// the stack directory, as vca setup writes it, and returns the options
// of a bootstrap run of that pair.
func injiOptions(t *testing.T, base string, out io.Writer) BootstrapOptions {
	return injiRoleOptions(t, commonv1.Role_ROLE_ISSUER, base, out)
}

func injiRoleOptions(t *testing.T, role commonv1.Role, base string, out io.Writer) BootstrapOptions {
	t.Helper()
	pair := Pair{Role: role, Dpg: configv1.Dpg_DPG_INJI}
	root := t.TempDir()
	dir := OutputDir(root, pair)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	body, err := KeycloakRealm(pair, map[string]string{"VCA_PUBLIC_URL": "https://issuer.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, KeycloakDir(pair.Dpg)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, RealmFileOf(pair)), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Every Inji run of an issuer or a holder pair registers the VCA
	// client in eSignet too.
	esignet := fakeEsignet(t, &esignetFake{})
	return BootstrapOptions{
		Pair: pair,
		Dir:  dir,
		Values: map[string]string{"VCA_DPG_URL": base, "VCA_PUBLIC_URL": "https://issuer.example", EnvBootstrapSecret: "s3cret",
			EnvBootstrapEsignetURL: esignet.URL, EsignetAuthenticatorEnv: "mosip-ida"},
		Out: out,
	}
}

// TestBootstrapCreatesTheRoleRealm is ADR-035 decision 1 at bootstrap
// time: the run reads the realm of the pair role from the stack
// directory, creates it when the server has none, and updates it when
// the server has it.
func TestBootstrapCreatesTheRoleRealm(t *testing.T) {
	state := &keycloakState{realm: RealmName(commonv1.Role_ROLE_HOLDER), password: "from-the-stack-env"}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := injiRoleOptions(t, commonv1.Role_ROLE_HOLDER, server.URL, &out)
	opts.Values[EnvBootstrapSecret] = "from-the-stack-env"
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if state.created != 1 || state.updated != 0 || state.createdRealm != "vca-holder-realm" {
		t.Fatalf("created %d (%q), updated %d", state.created, state.createdRealm, state.updated)
	}
	if !strings.Contains(strings.Join(got.Steps, " "), "vca-holder-realm created") {
		t.Errorf("steps = %v", got.Steps)
	}
	again, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if state.created != 1 || state.updated != 1 {
		t.Fatalf("created %d, updated %d", state.created, state.updated)
	}
	if !strings.Contains(strings.Join(again.Steps, " "), "vca-holder-realm present") {
		t.Errorf("steps = %v", again.Steps)
	}
	// No default password exists (ADR-035 consequence 3).
	delete(opts.Values, EnvBootstrapSecret)
	if _, err := Bootstrap(context.Background(), opts); err == nil || !strings.Contains(err.Error(), EnvBootstrapSecret) {
		t.Errorf("a run with no administrator password passed: %v", err)
	}
}

// TestBootstrapUpdatesTheClientsOfAnExistingRealm: Keycloak ignores the
// clients of a realm update, so a realm that an earlier run made would
// never get a new client, such as the client of the holder
// authorization server (ADR-052 decision 2). The run writes each client
// of the realm file through the client API: an update for a client the
// realm has, a create for one it lacks. A new realm gets its clients
// with the create.
func TestBootstrapUpdatesTheClientsOfAnExistingRealm(t *testing.T) {
	state := &keycloakState{realm: RealmName(commonv1.Role_ROLE_HOLDER), realmExists: true,
		clients: map[string]string{"vca-holder": "0b7e1c52-uuid"}}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := injiRoleOptions(t, commonv1.Role_ROLE_HOLDER, server.URL, &out)
	body, err := KeycloakRealm(opts.Pair, map[string]string{"VCA_PUBLIC_URL": "https://wallet.example",
		injiAuthzIssuerHolderEnv: "https://issuer.example/authz"})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(opts.realmPath(), body, 0o600); werr != nil {
		t.Fatal(werr)
	}
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if strings.Join(state.clientPuts, ",") != "vca-holder" || strings.Join(state.clientPosts, ",") != InjiAuthzClientID {
		t.Fatalf("puts %v, posts %v", state.clientPuts, state.clientPosts)
	}
	if !strings.Contains(strings.Join(got.Steps, "\n"), InjiAuthzClientID+" added") {
		t.Errorf("steps = %v", got.Steps)
	}
	// A new realm takes its clients with the create call.
	fresh := &keycloakState{realm: RealmName(commonv1.Role_ROLE_HOLDER)}
	server2 := fakeKeycloak(t, fresh)
	defer server2.Close()
	opts.Values["VCA_DPG_URL"] = server2.URL
	if _, err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(fresh.clientPosts)+len(fresh.clientPuts) != 0 || fresh.created != 1 {
		t.Fatalf("a new realm: posts %v, puts %v", fresh.clientPosts, fresh.clientPuts)
	}
}

func TestBootstrapInjiCreatesThenUpdates(t *testing.T) {
	state := &keycloakState{}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := injiOptions(t, server.URL, &out)
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if state.created != 1 || state.updated != 0 {
		t.Fatalf("created %d, updated %d", state.created, state.updated)
	}
	if !strings.Contains(strings.Join(got.Steps, " "), "created") {
		t.Errorf("steps = %v", got.Steps)
	}
	// A second run finds the realm and updates it, so the outcome is
	// the same either way.
	again, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if state.created != 1 || state.updated != 1 {
		t.Fatalf("created %d, updated %d", state.created, state.updated)
	}
	if !strings.Contains(strings.Join(again.Steps, " "), "present") {
		t.Errorf("steps = %v", again.Steps)
	}
}

func TestBootstrapInjiReportsABadToken(t *testing.T) {
	state := &keycloakState{badToken: true}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var out bytes.Buffer
	if _, err := BootstrapInji(context.Background(), injiOptions(t, server.URL, &out)); err == nil {
		t.Fatal("an answer with no token passed")
	}
}

func TestBootstrapInjiNeedsTheGeneratedRealm(t *testing.T) {
	state := &keycloakState{}
	server := fakeKeycloak(t, state)
	defer server.Close()
	opts := BootstrapOptions{
		Pair:   Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI},
		Dir:    t.TempDir(),
		Values: map[string]string{"VCA_DPG_URL": server.URL},
	}
	if _, err := BootstrapInji(context.Background(), opts); err == nil {
		t.Fatal("a run with no realm file passed")
	}
}

func TestBootstrapInjiReportsAnUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, errAssign := io.WriteString(w, `{"access_token":"a-token"}`)
			if errAssign != nil {
				t.Fatalf("io.WriteString: %v", errAssign)
			}
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	var out bytes.Buffer
	if _, err := BootstrapInji(context.Background(), injiOptions(t, server.URL, &out)); err == nil {
		t.Fatal("a 403 answer passed")
	}
}

// credeblState holds what the fake CREDEBL server knows.
type credeblState struct {
	orgs    []string
	created int
	// signin is the body of the last sign in.
	signin map[string]string
	// noPlatform leaves out the platform admin organisation that the
	// database initialisation of the release makes.
	noPlatform bool
	// configured holds the body of each agent configuration by
	// organisation. A second configuration of one organisation gets the
	// status conflict, as the platform answers.
	configured map[string]map[string]string
	// wallets holds the body of each shared agent wallet by
	// organisation, with the same conflict rule.
	wallets map[string]map[string]string
	// The Keycloak of the stack: the password of the last token call,
	// the body of the created platform realm, the number of creates, the
	// bodies of the client updates, and every path the run called.
	adminToken    string
	realm         []byte
	realmPosts    int
	clientPuts    [][]byte
	keycloakPaths []string
	// onRealm runs when the run creates the platform realm.
	onRealm func()
	// The user profile of the platform realm, the number of its
	// updates, and the protocol mappers of the profile client scope.
	profile     []byte
	profilePuts int
	mappers     [][]byte
	// broken makes one Keycloak path answer the status internal server
	// error or, for the client scopes, a list without the profile scope.
	broken string
}

// credeblKeycloakAdminPassword is the administrator password of the
// Keycloak .env of the tests.
const credeblKeycloakAdminPassword = "the-generated-keycloak-password"

// credeblPlatformOrgID is the id of the platform admin organisation of
// the fake.
const credeblPlatformOrgID = "platform-org"

func fakeCredebl(t *testing.T, state *credeblState) *httptest.Server {
	t.Helper()
	if state.configured == nil {
		state.configured = map[string]map[string]string{}
	}
	if state.wallets == nil {
		state.wallets = map[string]map[string]string{}
	}
	// record reads one agent call into the map of its organisation. A
	// second call for one organisation gets the status conflict.
	record := func(w http.ResponseWriter, r *http.Request, into map[string]map[string]string, org string) {
		if _, done := into[org]; done {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode %s: %v", r.URL.Path, err)
		}
		into[org] = body
		w.WriteHeader(http.StatusCreated)
		anyval.DiscardWrite(io.WriteString(w, `{"data":{}}`))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if strings.HasPrefix(r.URL.Path, "/realms/") || strings.HasPrefix(r.URL.Path, "/admin/") {
			state.keycloakPaths = append(state.keycloakPaths, r.URL.Path)
			fakePlatformRealm(t, state, w, r)
			return
		}
		switch {
		case r.URL.Path == "/v1/auth/signin":
			if err := json.NewDecoder(r.Body).Decode(&state.signin); err != nil {
				t.Errorf("decode the sign in: %v", err)
			}
			_, errAssign := io.WriteString(w, `{"data":{"access_token":"a-token"}}`)
			if errAssign != nil {
				t.Fatalf("io.WriteString: %v", errAssign)
			}
		case r.URL.Path == "/v1/orgs" && r.Method == http.MethodGet:
			out := struct {
				Data struct {
					Organizations []credeblOrg `json:"organizations"`
				} `json:"data"`
			}{}
			if !state.noPlatform {
				out.Data.Organizations = append(out.Data.Organizations, credeblOrg{ID: credeblPlatformOrgID, Name: PlatformOrgName})
			}
			for _, name := range state.orgs {
				out.Data.Organizations = append(out.Data.Organizations, credeblOrg{ID: "id-" + name, Name: name})
			}
			if err := json.NewEncoder(w).Encode(out); err != nil {
				t.Fatalf("json.NewEncoder: %v", err)
			}
		case r.URL.Path == "/v1/orgs" && r.Method == http.MethodPost:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("json.NewDecoder: %v", err)
			}
			state.orgs = append(state.orgs, body["name"])
			state.created++
			w.WriteHeader(http.StatusCreated)
			_, errAssign2 := io.WriteString(w, `{"data":{"id":"id-`+body["name"]+`"}}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
		case len(parts) == 5 && parts[1] == "orgs" && parts[3] == "agents" && parts[4] == "configure" && r.Method == http.MethodPost:
			record(w, r, state.configured, parts[2])
		case len(parts) == 5 && parts[1] == "orgs" && parts[3] == "agents" && parts[4] == "wallet" && r.Method == http.MethodPost:
			record(w, r, state.wallets, parts[2])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// fakePlatformRealm answers the calls of the bootstrap run at the
// Keycloak of the stack: the token of the master realm, the platform
// realm, and its clients.
func fakePlatformRealm(t *testing.T, state *credeblState, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	realmPath := "/admin/realms/" + CredeblPlatformRealm
	if state.broken != "" && r.URL.Path == realmPath+state.broken {
		if state.broken == "/client-scopes" {
			anyval.DiscardWrite(io.WriteString(w, `[{"id":"scope-email","name":"email"}]`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch {
	case r.URL.Path == "/realms/master/protocol/openid-connect/token":
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse the token form: %v", err)
		}
		state.adminToken = r.PostForm.Get("password")
		anyval.DiscardWrite(io.WriteString(w, `{"access_token":"an-admin-token"}`))
	case r.URL.Path == realmPath && r.Method == http.MethodGet:
		if state.realm == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		anyval.DiscardWrite(w.Write(state.realm))
	case r.URL.Path == "/admin/realms" && r.Method == http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the realm: %v", err)
		}
		state.realm = body
		state.realmPosts++
		if state.onRealm != nil {
			state.onRealm()
		}
		w.WriteHeader(http.StatusCreated)
	case r.URL.Path == realmPath+"/clients" && r.Method == http.MethodGet:
		id := r.URL.Query().Get("clientId")
		anyval.DiscardWrite(io.WriteString(w, `[{"id":"uuid-`+id+`"}]`))
	case r.URL.Path == realmPath+"/users/profile" && r.Method == http.MethodGet:
		if state.profile == nil {
			state.profile = []byte(`{"attributes":[{"name":"username"},{"name":"email"}],"groups":[]}`)
		}
		anyval.DiscardWrite(w.Write(state.profile))
	case r.URL.Path == realmPath+"/users/profile" && r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the user profile: %v", err)
		}
		state.profile = body
		state.profilePuts++
		anyval.DiscardWrite(w.Write(body))
	case r.URL.Path == realmPath+"/client-scopes" && r.Method == http.MethodGet:
		anyval.DiscardWrite(io.WriteString(w, `[{"id":"scope-email","name":"email"},{"id":"scope-profile","name":"profile"}]`))
	case r.URL.Path == realmPath+"/client-scopes/scope-profile/protocol-mappers/models" && r.Method == http.MethodGet:
		anyval.DiscardWrite(io.WriteString(w, "["+string(bytes.Join(state.mappers, []byte(",")))+"]"))
	case r.URL.Path == realmPath+"/client-scopes/scope-profile/protocol-mappers/models" && r.Method == http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the mapper: %v", err)
		}
		state.mappers = append(state.mappers, body)
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(r.URL.Path, realmPath+"/clients/uuid-") && r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the client: %v", err)
		}
		state.clientPuts = append(state.clientPuts, body)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// removeKeycloakEnv removes the Keycloak .env of the deploy root of a
// run.
func removeKeycloakEnv(opts BootstrapOptions) error {
	return os.Remove(filepath.Join(filepath.Dir(opts.Dir), KeycloakEnvFile(configv1.Dpg_DPG_CREDEBL)))
}

// credeblAdmin is the platform admin that the setup of the tests names.
const credeblAdmin = "platform.admin@registry.gov.test"

// credeblOptions returns a CREDEBL bootstrap run under a deploy root
// whose stack .env names the platform admin, with a runner that records
// every command.
func credeblOptions(t *testing.T, base string, out io.Writer) BootstrapOptions {
	t.Helper()
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	writeStackEnvAt(t, deploy, configv1.Dpg_DPG_CREDEBL, secretsTime, map[string]string{PlatformAdminEmailEnv: credeblAdmin})
	keycloak := filepath.Join(deploy, KeycloakEnvFile(configv1.Dpg_DPG_CREDEBL))
	if err := os.MkdirAll(filepath.Dir(keycloak), 0o750); err != nil {
		t.Fatal(err)
	}
	env := KeycloakAdminEnv + "=admin\n" + KeycloakAdminPasswordEnv + "=" + credeblKeycloakAdminPassword + "\n"
	if err := os.WriteFile(keycloak, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_CREDEBL}
	if err := os.MkdirAll(OutputDir(deploy, pair), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(OutputDir(deploy, pair), EnvFileName), []byte("VCA_DPG_URL="+base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return BootstrapOptions{
		Pair: pair,
		Dir:  OutputDir(deploy, pair),
		Values: map[string]string{
			"VCA_DPG_URL": base, "VCA_PUBLIC_URL": "https://issuer.example",
			CredeblKeycloakURLSetting: base,
		},
		Out: out,
		Run: func(context.Context, string, []string) error { return nil },
	}
}

// TestBootstrapCredeblNeedsThePlatformAdmin: the sign in names the
// platform admin of setup. No placeholder user exists (ADR-055
// decision 4).
func TestBootstrapCredeblNeedsThePlatformAdmin(t *testing.T) {
	var signedIn map[string]string
	realm := &credeblState{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/realms/") || strings.HasPrefix(r.URL.Path, "/admin/") {
			fakePlatformRealm(t, realm, w, r)
			return
		}
		if r.URL.Path == "/v1/auth/signin" {
			if err := json.NewDecoder(r.Body).Decode(&signedIn); err != nil {
				t.Errorf("decode the sign in: %v", err)
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	if _, err := BootstrapCredebl(context.Background(), opts); err == nil {
		t.Fatal("a refused sign in passed")
	}
	if signedIn["email"] != credeblAdmin {
		t.Errorf("the sign in named %q, want the platform admin of setup", signedIn["email"])
	}
	// A deployment whose setup named no platform admin stops before any
	// call, and the error names the setting.
	bare := opts
	bare.Dir = OutputDir(filepath.Join(t.TempDir(), "deploy"), opts.Pair)
	signedIn = nil
	_, err := BootstrapCredebl(context.Background(), bare)
	if err == nil || !strings.Contains(err.Error(), PlatformAdminEmailSetting) {
		t.Fatalf("err = %v, want the name of the setting", err)
	}
	if signedIn != nil || strings.Contains(err.Error(), "example.com") {
		t.Errorf("the run signed in as %v: %v", signedIn, err)
	}
	// The password of the platform admin has no default either: a
	// stack .env of an earlier release without it stops the run.
	noSecret := opts
	noSecret.Dir = OutputDir(filepath.Join(t.TempDir(), "deploy"), opts.Pair)
	writeStackEnvAt(t, filepath.Dir(noSecret.Dir), configv1.Dpg_DPG_CREDEBL, secretsTime, map[string]string{PlatformAdminEmailEnv: credeblAdmin})
	older := filepath.Join(filepath.Dir(noSecret.Dir), StackEnvFile(configv1.Dpg_DPG_CREDEBL))
	values, rerr := ReadStackEnv(filepath.Dir(noSecret.Dir), configv1.Dpg_DPG_CREDEBL)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var lines []string
	for name, value := range values {
		if name != PlatformAdminPasswordEnv {
			lines = append(lines, name+"="+value)
		}
	}
	if werr := os.WriteFile(older, []byte(strings.Join(lines, "\n")+"\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, berr := BootstrapCredebl(context.Background(), noSecret); berr == nil || !strings.Contains(berr.Error(), PlatformAdminPasswordEnv) {
		t.Errorf("err = %v, want the name of %s", berr, PlatformAdminPasswordEnv)
	}
	// The environment of the run still names another password.
	named := opts
	named.Values = map[string]string{"VCA_DPG_URL": server.URL, CredeblKeycloakURLSetting: server.URL, EnvBootstrapSecret: "an-operator-password"}
	signedIn = nil
	if _, berr := BootstrapCredebl(context.Background(), named); berr == nil {
		t.Error("a refused sign in passed")
	}
	stack, serr := ReadStackEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if serr != nil {
		t.Fatal(serr)
	}
	if plain, derr := decryptCryptoJS(signedIn["password"], stack["CRYPTO_PRIVATE_KEY"]); derr != nil || plain != `"an-operator-password"` {
		t.Errorf("the named password decrypts to %q, %v", plain, derr)
	}
}

// TestBootstrapCredeblRunsTheSeedOnce: the first run seeds the CREDEBL
// database through compose, and a later run finds the marker and skips
// the seed (plan section 3.8).
func TestBootstrapCredeblRunsTheSeedOnce(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	var runs [][]string
	opts.Run = func(_ context.Context, name string, args []string) error {
		// The restart after the webhook step is no seed.
		if !slices.Contains(args, "up") {
			runs = append(runs, append([]string{name}, args...))
		}
		return nil
	}
	if _, err := BootstrapCredebl(context.Background(), opts); err != nil {
		t.Fatalf("BootstrapCredebl: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %v, want one seed", runs)
	}
	cmd := strings.Join(runs[0], " ")
	for _, want := range []string{"docker compose", "--profile issuer-credebl", "--profile credebl-init run --rm credebl-seed"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the seed command %q lacks %q", cmd, want)
		}
	}
	deploy := filepath.Dir(opts.Dir)
	info, err := os.Stat(filepath.Join(deploy, PlatformInitMarker))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker: %v, %v", info, err)
	}
	if _, err := BootstrapCredebl(context.Background(), opts); err != nil {
		t.Fatalf("second BootstrapCredebl: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("the second run seeded again: %v", runs)
	}
	if !strings.Contains(out.String(), "initialisation present") {
		t.Errorf("out = %s", out.String())
	}
	// A failed seed writes no marker and stops the run.
	failing := credeblOptions(t, server.URL, &out)
	failing.Run = func(context.Context, string, []string) error { return errors.New("exit 1") }
	if _, err := BootstrapCredebl(context.Background(), failing); err == nil {
		t.Fatal("a failed seed passed")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(failing.Dir), PlatformInitMarker)); !os.IsNotExist(err) {
		t.Errorf("a failed seed wrote the marker: %v", err)
	}
	// A run without a command runner cannot seed.
	noRun := credeblOptions(t, server.URL, &out)
	noRun.Run = nil
	if _, err := BootstrapCredebl(context.Background(), noRun); err == nil {
		t.Error("a run without a runner passed")
	}
}

func TestBootstrapCredeblCreatesAndIsIdempotent(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if state.created != 1 {
		t.Fatalf("the server created %d organisations", state.created)
	}
	if !strings.Contains(strings.Join(got.Steps, " "), "created: vca-issuer") {
		t.Errorf("steps = %v", got.Steps)
	}
	again, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if state.created != 1 {
		t.Fatalf("the second run created %d organisations", state.created)
	}
	if !strings.Contains(strings.Join(again.Steps, " "), "present") {
		t.Errorf("steps = %v", again.Steps)
	}
}

func TestBootstrapCredeblUsesTheNamedOrganisation(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	opts.Values[EnvBootstrapOrg] = "ministry"
	if _, err := BootstrapCredebl(context.Background(), opts); err != nil {
		t.Fatalf("BootstrapCredebl: %v", err)
	}
	if len(state.orgs) != 1 || state.orgs[0] != "ministry" {
		t.Errorf("orgs = %v", state.orgs)
	}
}

func TestBootstrapCredeblReportsProblems(t *testing.T) {
	var out bytes.Buffer
	noToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, errAssign := io.WriteString(w, `{"data":{}}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer noToken.Close()
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(t, noToken.URL, &out)); err == nil {
		t.Error("an answer with no token passed")
	}

	badList := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			_, errAssign2 := io.WriteString(w, `{"data":{"access_token":"a-token"}}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
			return
		}
		_, errAssign3 := io.WriteString(w, `not json`)
		if errAssign3 != nil {
			t.Fatalf("io.WriteString: %v", errAssign3)
		}
	}))
	defer badList.Close()
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(t, badList.URL, &out)); err == nil {
		t.Error("an answer that is not JSON passed")
	}

	failCreate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/signin":
			_, errAssign4 := io.WriteString(w, `{"data":{"access_token":"a-token"}}`)
			if errAssign4 != nil {
				t.Fatalf("io.WriteString: %v", errAssign4)
			}
		case r.Method == http.MethodGet:
			_, errAssign5 := io.WriteString(w, `{"data":{"organizations":[]}}`)
			if errAssign5 != nil {
				t.Fatalf("io.WriteString: %v", errAssign5)
			}
		default:
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer failCreate.Close()
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(t, failCreate.URL, &out)); err == nil {
		t.Error("a 409 answer passed")
	}
}

func TestDoStatusReportsAnUnreachableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	if _, _, err := doStatus(context.Background(), http.DefaultClient, http.MethodGet, url, "", nil); err == nil {
		t.Fatal("a closed server passed")
	}
	if _, _, err := doStatus(context.Background(), http.DefaultClient, "bad method", "://", "", nil); err == nil {
		t.Fatal("a bad request passed")
	}
}

func TestReadIssuerFile(t *testing.T) {
	dir := t.TempDir()
	if _, _, ok := readIssuerFile(filepath.Join(dir, "missing.json")); ok {
		t.Error("a missing file reported a DID")
	}
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readIssuerFile(path); ok {
		t.Error("a file that is not JSON reported a DID")
	}
}

func TestBootstrapResultStepWithNoWriter(t *testing.T) {
	var r BootstrapResult
	r.step(nil, "hello %s", "world")
	if len(r.Steps) != 1 || r.Steps[0] != "hello world" {
		t.Errorf("steps = %v", r.Steps)
	}
}

// TestRealmRegistrationOff is P2-09: the realm helper sends the realm of
// the role with registrationAllowed false to the Keycloak of the stack
// and rewrites the generated realm file, so a later bootstrap keeps the
// setting (ADR-035 decision 6).
func TestRealmRegistrationOff(t *testing.T) {
	state := &keycloakState{realmExists: true}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := injiOptions(t, server.URL, &out)
	delete(opts.Values, "VCA_DPG_URL")
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	got, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts, Allowed: false})
	if err != nil {
		t.Fatalf("RealmRegistration: %v", err)
	}
	if state.updated != 1 || state.created != 0 {
		t.Fatalf("updated %d, created %d", state.updated, state.created)
	}
	var sent struct {
		Realm               string `json:"realm"`
		RegistrationAllowed *bool  `json:"registrationAllowed"`
	}
	if parseErr := json.Unmarshal(state.putBody, &sent); parseErr != nil {
		t.Fatalf("the PUT body is not JSON: %v", parseErr)
	}
	if sent.Realm != "vca-issuer-realm" || sent.RegistrationAllowed == nil || *sent.RegistrationAllowed {
		t.Errorf("PUT body = %s", state.putBody)
	}
	if !strings.Contains(strings.Join(got.Steps, " "), "self registration off") {
		t.Errorf("steps = %v", got.Steps)
	}
	// The generated file carries the new value, so vca dpg bootstrap does
	// not turn registration on again.
	data, err := os.ReadFile(opts.realmPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"registrationAllowed": false`) {
		t.Errorf("realm file = %s", data)
	}
	// On again.
	if _, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts, Allowed: true}); err != nil {
		t.Fatalf("RealmRegistration on: %v", err)
	}
	if !strings.Contains(string(state.putBody), `"registrationAllowed": true`) {
		t.Errorf("PUT body = %s", state.putBody)
	}
}

// TestRealmRegistrationNeedsTheRealm: a realm the Keycloak does not have
// is an error, because the helper never creates one. A run without a
// Keycloak URL names the variable.
func TestRealmRegistrationNeedsTheRealm(t *testing.T) {
	state := &keycloakState{}
	server := fakeKeycloak(t, state)
	defer server.Close()
	opts := injiOptions(t, server.URL, nil)
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	_, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts})
	if err == nil || !strings.Contains(err.Error(), "vca dpg bootstrap") {
		t.Errorf("a missing realm passed: %v", err)
	}
	delete(opts.Values, "VCA_OIDC_PUBLIC_URL")
	delete(opts.Values, "VCA_DPG_URL")
	_, err = RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts})
	if err == nil || !strings.Contains(err.Error(), "VCA_OIDC_PUBLIC_URL") {
		t.Errorf("a run with no URL passed: %v", err)
	}
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	opts.Dir = t.TempDir()
	if _, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts}); err == nil {
		t.Error("a run with no realm file passed")
	}
}

// TestRealmRegistrationRecordsTheProvider: with an admin client the
// helper sets the register action of every Keycloak provider of the realm
// to none, so the first run checklist marks the step done
// (ADR-035 decision 6).
func TestRealmRegistrationRecordsTheProvider(t *testing.T) {
	state := &keycloakState{realmExists: true}
	server := fakeKeycloak(t, state)
	defer server.Close()
	var updated []string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vca.admin.v1.AdminService/ListAuthProviders":
			_, errAssign := io.WriteString(w, `{"providers":[
				{"id":"kc-issuer","kind":"PROVIDER_KIND_KEYCLOAK","discoveryUrl":"`+server.URL+`/realms/vca-issuer-realm/.well-known/openid-configuration","roles":["ROLE_ISSUER"],"enabled":true},
				{"id":"kc-admin","kind":"PROVIDER_KIND_KEYCLOAK","discoveryUrl":"`+server.URL+`/realms/vca-admin-realm/.well-known/openid-configuration","roles":["ROLE_ADMIN"],"enabled":true},
				{"id":"wso2","kind":"PROVIDER_KIND_GENERIC","discoveryUrl":"https://idp.example/.well-known/openid-configuration","realm":"vca-issuer-realm","roles":["ROLE_ISSUER"],"enabled":true}
			]}`)
			if errAssign != nil {
				t.Fatalf("io.WriteString: %v", errAssign)
			}
		case "/vca.admin.v1.AdminService/UpdateAuthProvider":
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("read the body: %v", readErr)
			}
			updated = append(updated, string(body))
			_, errAssign := io.WriteString(w, `{}`)
			if errAssign != nil {
				t.Fatalf("io.WriteString: %v", errAssign)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer admin.Close()
	var out bytes.Buffer
	opts := injiOptions(t, server.URL, &out)
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	got, err := RealmRegistration(context.Background(), RealmOptions{
		BootstrapOptions: opts, Allowed: false, Admin: &AdminClient{BaseURL: admin.URL, Token: "t"},
	})
	if err != nil {
		t.Fatalf("RealmRegistration: %v", err)
	}
	if len(updated) != 1 || !strings.Contains(updated[0], `"kc-issuer"`) || !strings.Contains(updated[0], "REGISTRATION_NONE") {
		t.Errorf("updated = %v", updated)
	}
	if !strings.Contains(strings.Join(got.Steps, " "), "kc-issuer") {
		t.Errorf("steps = %v", got.Steps)
	}
	// On again clears the record, so the metadata decides.
	updated = nil
	if _, err := RealmRegistration(context.Background(), RealmOptions{
		BootstrapOptions: opts, Allowed: true, Admin: &AdminClient{BaseURL: admin.URL, Token: "t"},
	}); err != nil {
		t.Fatalf("RealmRegistration on: %v", err)
	}
	if len(updated) != 1 || !strings.Contains(updated[0], "REGISTRATION_UNSPECIFIED") {
		t.Errorf("updated = %v", updated)
	}
	// A failing admin service is an error after the realm change.
	admin.Close()
	if _, err := RealmRegistration(context.Background(), RealmOptions{
		BootstrapOptions: opts, Allowed: false, Admin: &AdminClient{BaseURL: admin.URL, Token: "t"},
	}); err == nil {
		t.Error("an unreachable admin service passed")
	}
}

// TestRealmRegistrationReportsProblems covers the failure paths: a realm
// file that is not JSON, a Keycloak that refuses the update, a token
// answer with no token, and a bad on or off word.
func TestRealmRegistrationReportsProblems(t *testing.T) {
	state := &keycloakState{realmExists: true}
	server := fakeKeycloak(t, state)
	defer server.Close()
	opts := injiOptions(t, server.URL, nil)
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	if err := os.WriteFile(opts.realmPath(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts}); err == nil {
		t.Error("a realm file that is not JSON passed")
	}
	if _, err := realmWithRegistration(filepath.Join(t.TempDir(), "none.json"), true); err == nil {
		t.Error("a missing realm file passed")
	}
	state.badToken = true
	opts = injiOptions(t, server.URL, nil)
	opts.Values["VCA_OIDC_PUBLIC_URL"] = server.URL
	if _, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts}); err == nil {
		t.Error("an answer with no token passed")
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			anyval.DiscardWrite(io.WriteString(w, `{"access_token":"a-token"}`))
		case r.Method == http.MethodGet:
			anyval.DiscardWrite(io.WriteString(w, `{}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer refusing.Close()
	opts = injiOptions(t, refusing.URL, nil)
	opts.Values["VCA_OIDC_PUBLIC_URL"] = refusing.URL
	if _, err := RealmRegistration(context.Background(), RealmOptions{BootstrapOptions: opts}); err == nil || !strings.Contains(err.Error(), "update the realm") {
		t.Errorf("a refused update passed: %v", err)
	}
	for _, word := range []string{"maybe", ""} {
		if _, err := ParseOnOff(word); err == nil {
			t.Errorf("%q passed", word)
		}
	}
	if on, err := ParseOnOff(" ON "); err != nil || !on {
		t.Errorf("ON = %v, %v", on, err)
	}
	if _, ok := realmOfDiscovery(&url.URL{Path: "/no/realm/here"}); ok {
		t.Error("a path with no realm passed")
	}
}
