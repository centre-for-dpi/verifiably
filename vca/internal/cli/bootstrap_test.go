// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// TestBootstrapWaltidUsesThePublicURL checks that without an override the
// run reaches the adapter through the public URL of the pair, where the
// reverse proxy routes the adapter services.
func TestBootstrapWaltidUsesThePublicURL(t *testing.T) {
	adapter := &fakeAdapter{identity: &backendv1.IssuerIdentity{Identifiers: []string{"did:web:127.0.0.1"}}}
	server := serveAdapter(t, adapter)
	var out bytes.Buffer
	opts := BootstrapOptions{Pair: issuerPair(), Dir: t.TempDir(), Values: map[string]string{"VCA_PUBLIC_URL": server.URL}, Out: &out}
	got, err := BootstrapWaltid(context.Background(), opts)
	if err != nil || !strings.Contains(got.Steps[0], "present: did:web:127.0.0.1") {
		t.Fatalf("steps %v: %v", got.Steps, err)
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
	return BootstrapOptions{
		Pair:   pair,
		Dir:    dir,
		Values: map[string]string{"VCA_DPG_URL": base, "VCA_PUBLIC_URL": "https://issuer.example", EnvBootstrapSecret: "s3cret"},
		Out:    out,
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
}

func fakeCredebl(t *testing.T, state *credeblState) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/signin":
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
			for _, name := range state.orgs {
				out.Data.Organizations = append(out.Data.Organizations, credeblOrg{ID: name, Name: name})
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
			_, errAssign2 := io.WriteString(w, `{"data":{"id":"1"}}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func credeblOptions(base string, out io.Writer) BootstrapOptions {
	return BootstrapOptions{
		Pair:   Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_CREDEBL},
		Values: map[string]string{"VCA_DPG_URL": base, "VCA_PUBLIC_URL": "https://issuer.example"},
		Out:    out,
	}
}

func TestBootstrapCredeblCreatesAndIsIdempotent(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(server.URL, &out)
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
	opts := credeblOptions(server.URL, &out)
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
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(noToken.URL, &out)); err == nil {
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
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(badList.URL, &out)); err == nil {
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
	if _, err := BootstrapCredebl(context.Background(), credeblOptions(failCreate.URL, &out)); err == nil {
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
