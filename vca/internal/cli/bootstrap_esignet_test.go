// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// esignetFake is the client store of the fake eSignet.
type esignetFake struct {
	mu      sync.Mutex
	clients map[string]map[string]any
	creates []map[string]any
	updates []map[string]any
	auth    []string
	// status forces an answer of the client API.
	status int
}

// fakeEsignet answers the OAuth client API of eSignet 1.5.1: a create
// of a known id answers duplicate_client_id with the status 200.
func fakeEsignet(t *testing.T, state *esignetFake) *httptest.Server {
	t.Helper()
	state.clients = map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.auth = append(state.auth, r.Header.Get("Authorization"))
		if state.status != 0 {
			w.WriteHeader(state.status)
			return
		}
		var body struct {
			RequestTime string         `json:"requestTime"`
			Request     map[string]any `json:"request"`
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(raw, &body) != nil || body.RequestTime == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer := map[string]any{"response": nil, "errors": []any{}}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/esignet/client-mgmt/oauth-client":
			id := anyval.As[string](body.Request["clientId"])
			state.creates = append(state.creates, body.Request)
			if _, taken := state.clients[id]; taken {
				answer["errors"] = []any{map[string]string{"errorCode": "duplicate_client_id", "errorMessage": "the client exists"}}
			} else {
				state.clients[id] = body.Request
				answer["response"] = map[string]string{"clientId": id, "status": "ACTIVE"}
			}
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/esignet/client-mgmt/oauth-client/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/esignet/client-mgmt/oauth-client/")
			state.updates = append(state.updates, body.Request)
			answer["response"] = map[string]string{"clientId": id, "status": "ACTIVE"}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(answer); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBootstrapRegistersEsignetClient registers the VCA client in
// eSignet with an RSA public key and private_key_jwt. The private key
// stays in a file of mode 0600 beside the stack directories, which git
// ignores. A second run of another role keeps the key and adds its
// redirect URI, so the outcome is the same either way. A verifier pair
// runs no eSignet.
func TestBootstrapRegistersEsignetClient(t *testing.T) {
	kc := &keycloakState{}
	keycloak := fakeKeycloak(t, kc)
	defer keycloak.Close()
	es := &esignetFake{}
	esignet := fakeEsignet(t, es)
	var out bytes.Buffer
	opts := injiOptions(t, keycloak.URL, &out)
	opts.Values[EnvBootstrapEsignetURL] = esignet.URL
	got, err := Bootstrap(context.Background(), opts)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(es.creates) != 1 {
		t.Fatalf("creates = %d", len(es.creates))
	}
	req := es.creates[0]
	key := mustMap(t, req["publicKey"])
	if req["clientId"] != EsignetClientID || key["kty"] != "RSA" || key["n"] == nil || key["d"] != nil ||
		!sameList(req["clientAuthMethods"], "private_key_jwt") || !sameList(req["grantTypes"], "authorization_code") ||
		!sameList(req["redirectUris"], "https://issuer.example/auth/callback") {
		t.Fatalf("create = %v", req)
	}
	path := filepath.Join(filepath.Dir(opts.Dir), EsignetDir, EsignetKeyFile)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", info, err)
	}
	first, err := os.ReadFile(path) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(first)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil || rsaKey.N.BitLen() < 2048 {
		t.Fatalf("the key file holds no RSA key of 2048 bits: %v", err)
	}
	if ignore, gerr := os.ReadFile(filepath.Join(filepath.Dir(path), ".gitignore")); gerr != nil || strings.TrimSpace(string(ignore)) != "*" { // #nosec G304 -- a test path
		t.Fatalf("the key directory is not ignored: %q %v", ignore, gerr)
	}
	steps := strings.Join(got.Steps, "\n")
	if !strings.Contains(steps, "eSignet client "+EsignetClientID+" created") || !strings.Contains(steps, path) {
		t.Fatalf("steps = %s", steps)
	}

	holder := injiRoleOptions(t, commonv1.Role_ROLE_HOLDER, keycloak.URL, &out)
	holder.Dir = filepath.Join(filepath.Dir(opts.Dir), filepath.Base(holder.Dir))
	holder.Values[EnvBootstrapEsignetURL] = esignet.URL
	holder.Values["VCA_OIDC_REDIRECT_URI"] = "https://holder.example/auth/callback"
	if merr := os.MkdirAll(holder.Dir, 0o750); merr != nil {
		t.Fatal(merr)
	}
	copyRealm(t, holder)
	again, err := Bootstrap(context.Background(), holder)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if len(es.updates) != 1 || !sameList(es.updates[0]["redirectUris"], "https://issuer.example/auth/callback", "https://holder.example/auth/callback") {
		t.Fatalf("updates = %v", es.updates)
	}
	second, err := os.ReadFile(path) // #nosec G304 -- a test path
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("the second run replaced the key")
	}
	if !strings.Contains(strings.Join(again.Steps, "\n"), "eSignet client "+EsignetClientID+" present and updated") {
		t.Fatalf("steps = %v", again.Steps)
	}

	calls := len(es.auth)
	verifier := injiRoleOptions(t, commonv1.Role_ROLE_VERIFIER, keycloak.URL, &out)
	verifier.Values[EnvBootstrapEsignetURL] = esignet.URL
	if _, err := Bootstrap(context.Background(), verifier); err != nil {
		t.Fatal(err)
	}
	if len(es.auth) != calls {
		t.Fatal("a verifier pair called eSignet")
	}
}

// TestBootstrapEsignetNeedsTheClientScope reports a refused client API
// with the variable that carries a token, and sends the token.
func TestBootstrapEsignetNeedsTheClientScope(t *testing.T) {
	kc := &keycloakState{}
	keycloak := fakeKeycloak(t, kc)
	defer keycloak.Close()
	es := &esignetFake{status: http.StatusUnauthorized}
	esignet := fakeEsignet(t, es)
	var out bytes.Buffer
	opts := injiOptions(t, keycloak.URL, &out)
	opts.Values[EnvBootstrapEsignetURL] = esignet.URL
	if _, err := Bootstrap(context.Background(), opts); err == nil || !strings.Contains(err.Error(), EnvBootstrapEsignetToken) {
		t.Fatalf("a refused call = %v", err)
	}
	es.status = 0
	opts.Values[EnvBootstrapEsignetToken] = "tok-1"
	if _, err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if es.auth[len(es.auth)-1] != "Bearer tok-1" {
		t.Fatalf("authorization = %q", es.auth[len(es.auth)-1])
	}
	es.status = http.StatusInternalServerError
	if _, err := Bootstrap(context.Background(), opts); err == nil {
		t.Fatal("a failing eSignet passed")
	}
	// A key file that holds no RSA key stops the run.
	es.status = 0
	path := filepath.Join(filepath.Dir(opts.Dir), EsignetDir, EsignetKeyFile)
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(context.Background(), opts); err == nil {
		t.Fatal("a broken key file passed")
	}
}

// copyRealm writes the realm of the pair role beside the Keycloak of the
// stack.
func copyRealm(t *testing.T, opts BootstrapOptions) {
	t.Helper()
	body, err := KeycloakRealm(opts.Pair, map[string]string{"VCA_PUBLIC_URL": "https://holder.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.realmPath()), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.realmPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mustMap converts v to a JSON object.
func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("want an object, got %T", v)
	}
	return m
}

// sameList reports whether a JSON array holds the values in order.
func sameList(v any, want ...string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	got := make([]string, 0, len(list))
	for _, item := range list {
		got = append(got, anyval.As[string](item))
	}
	return slices.Equal(got, want)
}
