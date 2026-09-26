// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// adminKeycloak is the state of the fake Keycloak admin API.
type adminKeycloak struct {
	mu      sync.Mutex
	logins  []string
	users   map[string]string
	creates []map[string]any
	resets  []map[string]any
	calls   int
}

// seen is a copy of the state that the test reads after a run.
type seen struct {
	logins  []string
	creates []map[string]any
	resets  []map[string]any
	calls   int
}

// snapshot copies the state under the lock of the fake server.
func (s *adminKeycloak) snapshot() seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return seen{logins: append([]string(nil), s.logins...), creates: append([]map[string]any(nil), s.creates...),
		resets: append([]map[string]any(nil), s.resets...), calls: s.calls}
}

// fakeAdminKeycloak answers the token call of the master realm and the
// user calls of the admin API of Keycloak 25 for the holder realm.
func fakeAdminKeycloak(t *testing.T, state *adminKeycloak, password string) *httptest.Server {
	t.Helper()
	state.users = map[string]string{}
	const realm = "/admin/realms/vca-holder-realm/users"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.calls++
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != "admin-cli" ||
				r.PostForm.Get("grant_type") != "password" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.logins = append(state.logins, r.PostForm.Get("username"))
			if r.PostForm.Get("password") != password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"access_token":"admin-token","token_type":"Bearer"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == realm:
			name := r.URL.Query().Get("username")
			out := []map[string]string{}
			if id, ok := state.users[name]; ok && r.URL.Query().Get("exact") == "true" {
				out = append(out, map[string]string{"id": id, "username": name})
			}
			if err := json.NewEncoder(w).Encode(out); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodPost && r.URL.Path == realm:
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			name, ok := body["username"].(string)
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.creates = append(state.creates, body)
			state.users[name] = "user-1"
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == realm+"/user-1/reset-password":
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.resets = append(state.resets, body)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// contractScript is the script under test, relative to this package.
const contractScript = "../../hack/contract-tests.sh"

// contractScriptCommand runs hack/contract-tests.sh in its prepare only
// mode with a clean environment.
func contractScriptCommand(t *testing.T, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "bash", contractScript) // #nosec G204 -- fixed arguments
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		"VCA_CONTRACT_DPGS=inji", "VCA_CONTRACT_PREPARE_ONLY=1"}, env...)
	return cmd
}

// runContractScript runs the script and fails the test when it fails.
func runContractScript(t *testing.T, env ...string) string {
	t.Helper()
	out, err := contractScriptCommand(t, env...).CombinedOutput()
	if err != nil {
		t.Fatalf("contract-tests.sh: %v\n%s", err, out)
	}
	return string(out)
}

// TestContractScriptMakesTheTestHolder is P6-I7g. The nightly job signs
// a test holder in at the holder realm of the stack Keycloak. The
// contract script makes that holder through the Keycloak admin API with
// the administrator of deploy/keycloak-inji/.env, keeps its password and
// its wallet PIN in deploy/mimoto-inji/contract-holder.env with mode
// 0600, and sets the four holder variables. A second run finds the
// holder, sets the same password again, and keeps the PIN, so the
// Mimoto wallet of the holder still opens. Given values win.
func TestContractScriptMakesTheTestHolder(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("the contract script needs %s", tool)
		}
	}
	root := t.TempDir()
	adminPassword := "generated-admin-secret"
	for name, body := range map[string]string{
		filepath.Join(KeycloakDir(injiIssuer.Dpg), EnvFileName): "KEYCLOAK_ADMIN=admin\nKEYCLOAK_ADMIN_PASSWORD=" + adminPassword + "\n",
		filepath.Join("holder-inji", EnvFileName):               "VCA_OIDC_REDIRECT_URI=https://holder.example/auth/callback\n",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kc := &adminKeycloak{}
	srv := fakeAdminKeycloak(t, kc, adminPassword)
	env := []string{"VCA_CONTRACT_DEPLOY_DIR=" + root, "VCA_CONTRACT_KEYCLOAK_URL=" + srv.URL}

	out := runContractScript(t, env...)
	statePath := filepath.Join(root, MimotoDir, "contract-holder.env")
	info, err := os.Stat(statePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file %v %v\n%s", info, err, out)
	}
	first, err := os.ReadFile(statePath) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	state, err := ParseDotenv(strings.NewReader(string(first)))
	if err != nil {
		t.Fatal(err)
	}
	password := state["VCA_INJI_CONTRACT_HOLDER_PASSWORD"]
	pin := state["VCA_INJI_CONTRACT_HOLDER_PIN"]
	if state["VCA_INJI_CONTRACT_HOLDER_USER"] != "contract-holder" || len(password) < 16 ||
		state["VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI"] != "https://holder.example/auth/callback" ||
		len(pin) != 6 || strings.Trim(pin, "0123456789") != "" {
		t.Fatalf("state = %v", state)
	}
	if strings.Contains(out, password) || strings.Contains(out, adminPassword) {
		t.Errorf("the output shows a password:\n%s", out)
	}
	got := kc.snapshot()
	if len(got.creates) != 1 || len(got.logins) != 1 || got.logins[0] != "admin" {
		t.Fatalf("creates %v logins %v", got.creates, got.logins)
	}
	user := got.creates[0]
	creds, ok := user["credentials"].([]any)
	if !ok || len(creds) != 1 || mustMap(t, creds[0])["value"] != password || mustMap(t, creds[0])["temporary"] != false ||
		user["enabled"] != true || user["emailVerified"] != true || user["email"] == nil {
		t.Errorf("user = %v", user)
	}

	runContractScript(t, env...)
	second, err := os.ReadFile(statePath) // #nosec G304 -- a test path
	if err != nil || string(second) != string(first) {
		t.Fatalf("the second run changed the state: %v", err)
	}
	got = kc.snapshot()
	if len(got.creates) != 1 || len(got.resets) != 1 || got.resets[0]["value"] != password {
		t.Fatalf("second run: creates %d, resets %v", len(got.creates), got.resets)
	}

	calls := got.calls
	runContractScript(t, append(env, "VCA_INJI_CONTRACT_HOLDER_USER=given", "VCA_INJI_CONTRACT_HOLDER_PASSWORD=given")...)
	if kc.snapshot().calls != calls {
		t.Error("the script made a holder although the job gave one")
	}
}

// TestContractScriptStopsOnAWrongAdminPassword checks that the script
// fails when Keycloak refuses the administrator, writes no state, and
// shows no password.
func TestContractScriptStopsOnAWrongAdminPassword(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("the contract script needs %s", tool)
		}
	}
	root := t.TempDir()
	path := filepath.Join(root, KeycloakDir(injiIssuer.Dpg), EnvFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("KEYCLOAK_ADMIN=admin\nKEYCLOAK_ADMIN_PASSWORD=stale-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kc := &adminKeycloak{}
	srv := fakeAdminKeycloak(t, kc, "current-secret")
	out, err := contractScriptCommand(t, "VCA_CONTRACT_DEPLOY_DIR="+root, "VCA_CONTRACT_KEYCLOAK_URL="+srv.URL,
		"VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI=https://holder.example/auth/callback").CombinedOutput()
	if err == nil {
		t.Fatalf("the script passed with a wrong admin password:\n%s", out)
	}
	if strings.Contains(string(out), "stale-secret") {
		t.Errorf("the output shows the admin password:\n%s", out)
	}
	if _, serr := os.Stat(filepath.Join(root, MimotoDir, "contract-holder.env")); !os.IsNotExist(serr) {
		t.Errorf("the script wrote state after a failed login: %v", serr)
	}
	if got := kc.snapshot(); len(got.creates) != 0 {
		t.Errorf("creates = %v", got.creates)
	}
}
