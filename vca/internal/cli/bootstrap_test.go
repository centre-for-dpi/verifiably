// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// fakeWaltid answers the walt.id onboarding call.
func fakeWaltid(t *testing.T, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/onboard/issuer" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		did := anyval.As[map[string]any](body["did"])
		cfg := anyval.As[map[string]any](did["config"])
		*calls++
		w.Header().Set("Content-Type", "application/json")
		_, errAssign := io.WriteString(w, `{"issuerDid":"did:web:`+anyval.As[string](cfg["domain"])+`:issuer","issuerKey":{"kty":"EC"}}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
}

func waltidOptions(t *testing.T, base string, out io.Writer) BootstrapOptions {
	t.Helper()
	return BootstrapOptions{
		Pair:   issuerPair(),
		Dir:    t.TempDir(),
		Values: map[string]string{"VCA_PUBLIC_URL": "https://issuer.example", "VCA_DPG_URL": base},
		Client: base2Client(),
		Out:    out,
	}
}

func base2Client() *http.Client { return &http.Client{} }

func TestBootstrapWaltidCreatesAndIsIdempotent(t *testing.T) {
	calls := 0
	server := fakeWaltid(t, &calls)
	defer server.Close()
	var out bytes.Buffer
	opts := waltidOptions(t, server.URL, &out)
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(got.Steps) != 1 || !strings.Contains(got.Steps[0], "created") {
		t.Fatalf("steps = %v", got.Steps)
	}
	if !strings.Contains(got.Steps[0], "did:web:issuer.example") {
		t.Errorf("the DID is missing: %v", got.Steps)
	}
	info, err := os.Stat(filepath.Join(opts.Dir, IssuerFile))
	if err != nil {
		t.Fatalf("stat %s: %v", IssuerFile, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %04o", IssuerFile, info.Mode().Perm())
	}
	// A second run changes nothing.
	again, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if !strings.Contains(again.Steps[0], "present") {
		t.Errorf("the second run said %v", again.Steps)
	}
	if calls != 1 {
		t.Errorf("the server saw %d onboarding calls, want 1", calls)
	}
}

func TestBootstrapWaltidReportsServerProblems(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	var out bytes.Buffer
	if _, err := BootstrapWaltid(context.Background(), waltidOptions(t, bad.URL, &out)); err == nil {
		t.Fatal("a 500 answer passed")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer empty.Close()
	if _, err := BootstrapWaltid(context.Background(), waltidOptions(t, empty.URL, &out)); err == nil {
		t.Fatal("an answer with no DID passed")
	}
}

func TestBootstrapWaltidNeedsAPublicURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	opts := BootstrapOptions{
		Pair:   issuerPair(),
		Dir:    t.TempDir(),
		Values: map[string]string{"VCA_DPG_URL": server.URL},
	}
	if _, err := BootstrapWaltid(context.Background(), opts); err == nil {
		t.Fatal("a run with no public URL passed")
	}
}

func TestBootstrapNeedsABaseURL(t *testing.T) {
	for _, values := range []map[string]string{nil, {"VCA_DPG_URL": "not a url"}, {"VCA_DPG_URL": "ftp://h"}} {
		opts := BootstrapOptions{Pair: issuerPair(), Dir: t.TempDir(), Values: values}
		if _, err := Bootstrap(context.Background(), opts); err == nil {
			t.Errorf("values %v passed", values)
		}
	}
}

func TestBootstrapUsesTheOverrideURL(t *testing.T) {
	calls := 0
	server := fakeWaltid(t, &calls)
	defer server.Close()
	opts := BootstrapOptions{
		Pair: issuerPair(),
		Dir:  t.TempDir(),
		Values: map[string]string{
			"VCA_PUBLIC_URL": "https://issuer.example",
			"VCA_DPG_URL":    "https://wrong.example",
			EnvBootstrapURL:  server.URL,
		},
	}
	if _, err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if calls != 1 {
		t.Errorf("the override URL was not used")
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
	realmExists bool
	created     int
	updated     int
	badToken    bool
}

func fakeKeycloak(t *testing.T, state *keycloakState) *httptest.Server {
	t.Helper()
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
			_, errAssign2 := io.WriteString(w, `{"access_token":"a-token"}`)
			if errAssign2 != nil {
				t.Fatalf("io.WriteString: %v", errAssign2)
			}
		case r.URL.Path == "/admin/realms/"+DefaultRealm && r.Method == http.MethodGet:
			if !state.realmExists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, errAssign3 := io.WriteString(w, `{"realm":"`+DefaultRealm+`"}`)
			if errAssign3 != nil {
				t.Fatalf("io.WriteString: %v", errAssign3)
			}
		case r.URL.Path == "/admin/realms/"+DefaultRealm && r.Method == http.MethodPut:
			state.updated++
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/admin/realms" && r.Method == http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer a-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			state.created++
			state.realmExists = true
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func injiOptions(t *testing.T, base string, out io.Writer) BootstrapOptions {
	t.Helper()
	pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}
	dir := t.TempDir()
	body, err := KeycloakRealm(pair, map[string]string{"VCA_PUBLIC_URL": "https://issuer.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RealmFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return BootstrapOptions{
		Pair:   pair,
		Dir:    dir,
		Values: map[string]string{"VCA_DPG_URL": base, "VCA_PUBLIC_URL": "https://issuer.example"},
		Out:    out,
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

func TestReadIssuerDid(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readIssuerDid(filepath.Join(dir, "missing.json")); ok {
		t.Error("a missing file reported a DID")
	}
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readIssuerDid(path); ok {
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
