// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAdminCommandsComeFromTheProto(t *testing.T) {
	cmds := AdminCommands()
	if len(cmds) < 18 {
		t.Fatalf("got %d commands", len(cmds))
	}
	byMethod := map[string]AdminCommand{}
	for _, c := range cmds {
		if c.Description == "" {
			t.Errorf("%s has no description", c.Method)
		}
		if !strings.HasSuffix(c.Description, ".") {
			t.Errorf("%s description is not a sentence: %q", c.Method, c.Description)
		}
		if c.Group == "" {
			t.Errorf("%s has no group", c.Method)
		}
		byMethod[c.Method] = c
	}
	want := map[string]string{
		"CreateTenant":          "tenant create",
		"ListTenants":           "tenant list",
		"DeleteTenant":          "tenant delete",
		"BindTenant":            "tenant bind",
		"UnbindTenant":          "tenant unbind",
		"UpsertTrustEntry":      "trust add",
		"ListTrustEntries":      "trust list",
		"DeleteTrustEntry":      "trust remove",
		"ApproveTrustEntry":     "trust approve",
		"RejectTrustEntry":      "trust reject",
		"AddTrustRegistry":      "registry add",
		"SyncTrustRegistry":     "registry sync",
		"CreateAuthProvider":    "onboard",
		"OnboardProvider":       "onboard-provider",
		"DeleteAuthProvider":    "provider remove",
		"RevokeApiKey":          "apikey revoke",
		"CreateStackCredential": "stack-credential create",
		"GetServiceHealth":      "health",
		"QueryAuditLog":         "audit",
		"OnboardAdmin":          "bind",
		"ListCommands":          "help",
	}
	for method, path := range want {
		got, ok := byMethod[method]
		if !ok {
			t.Errorf("%s is missing", method)
			continue
		}
		if got.Path() != path {
			t.Errorf("%s path = %q, want %q", method, got.Path(), path)
		}
	}
}

func TestAdminGroupNames(t *testing.T) {
	got := AdminGroupNames()
	want := []string{"tenant", "trust", "registry", "onboard", "onboard-provider", "provider", "apikey", "stack-credential", "webhook", "health", "audit", "bind", "help"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAdminCommandURL(t *testing.T) {
	cmd := AdminCommand{Method: "CreateTenant"}
	if got := cmd.URL("https://admin.example/"); got != "https://admin.example/vca.admin.v1.AdminService/CreateTenant" {
		t.Errorf("got %q", got)
	}
}

// TestAdminTreeMatchesTheAdminService keeps the CLI tree equal to the
// table the admin service renders on its help page (ADR-009 decision 3).
// The admin package is internal to services/, so the test reads the
// source instead of importing it.
func TestAdminTreeMatchesTheAdminService(t *testing.T) {
	path := filepath.Join("..", "..", "services", "admin", "internal", "service", "commands.go")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Skipf("the admin service is not in this tree: %v", err)
	}
	rx := regexp.MustCompile(`\{path: "admin ([a-z- ]+)", rpc: "(\w+)"`)
	var fromService []string
	for _, m := range rx.FindAllStringSubmatch(string(data), -1) {
		fromService = append(fromService, m[1]+" -> "+m[2])
	}
	if len(fromService) == 0 {
		t.Fatalf("no commands found in %s", path)
	}
	var fromCli []string
	for _, c := range AdminCommands() {
		fromCli = append(fromCli, c.Path()+" -> "+c.Method)
	}
	if strings.Join(fromCli, "\n") != strings.Join(fromService, "\n") {
		t.Errorf("the CLI tree and the admin service tree differ\nCLI:\n%s\nservice:\n%s",
			strings.Join(fromCli, "\n"), strings.Join(fromService, "\n"))
	}
}

func TestAdminCommandsCoverEveryRpc(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range AdminCommands() {
		if seen[c.Method] {
			t.Errorf("%s appears twice", c.Method)
		}
		seen[c.Method] = true
	}
	for method := range adminDescriptions() {
		if !seen[method] {
			t.Errorf("no command calls %s", method)
		}
	}
}

func TestAdminClientCall(t *testing.T) {
	var gotPath, gotAuth, gotBody, gotVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("Connect-Protocol-Version")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll: %v", err)
		}
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, errAssign := io.WriteString(w, `{"tenant":{"id":"t-1"}}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	client := AdminClient{BaseURL: server.URL, Token: "a-token"}
	cmd := AdminCommand{Group: "tenant", Verb: "create", Method: "CreateTenant"}
	answer, err := client.Call(context.Background(), cmd, []byte(`{"displayName":"City"}`))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotPath != "/vca.admin.v1.AdminService/CreateTenant" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer a-token" {
		t.Errorf("authorization = %q", gotAuth)
	}
	if gotVersion != "1" {
		t.Errorf("protocol version = %q", gotVersion)
	}
	if gotBody != `{"displayName":"City"}` {
		t.Errorf("body = %q", gotBody)
	}
	if !strings.Contains(PrettyJSON(answer), "\"id\": \"t-1\"") {
		t.Errorf("answer = %s", PrettyJSON(answer))
	}
}

func TestAdminClientSendsAnEmptyObject(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll: %v", err)
		}
		gotBody = string(body)
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	client := AdminClient{BaseURL: server.URL}
	if _, err := client.Call(context.Background(), AdminCommand{Method: "GetServiceHealth"}, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotBody != "{}" {
		t.Errorf("body = %q", gotBody)
	}
}

func TestAdminClientReportsAConnectError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, errAssign := io.WriteString(w, `{"code":"not_found","message":"no tenant t-9"}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	client := AdminClient{BaseURL: server.URL}
	_, err := client.Call(context.Background(), AdminCommand{Method: "GetTenant"}, []byte(`{"id":"t-9"}`))
	var fault *ConnectError
	if !errors.As(err, &fault) {
		t.Fatalf("got %T, want ConnectError", err)
	}
	if fault.Code != "not_found" || !strings.Contains(fault.Error(), "no tenant t-9") {
		t.Errorf("error = %v", fault)
	}
}

func TestAdminClientReportsAPlainStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	client := AdminClient{BaseURL: server.URL}
	_, err := client.Call(context.Background(), AdminCommand{Method: "GetTenant"}, nil)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("got %v", err)
	}
}

func TestAdminClientNeedsAURL(t *testing.T) {
	_, err := AdminClient{}.Call(context.Background(), AdminCommand{Method: "GetTenant"}, nil)
	if err == nil || !strings.Contains(err.Error(), "VCA_ADMIN_URL") {
		t.Fatalf("got %v", err)
	}
}

func TestAdminClientReportsAnUnreachableService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	client := AdminClient{BaseURL: url}
	if _, err := client.Call(context.Background(), AdminCommand{Method: "GetTenant"}, nil); err == nil {
		t.Fatal("a closed service passed")
	}
	bad := AdminClient{BaseURL: "://"}
	if _, err := bad.Call(context.Background(), AdminCommand{Method: "GetTenant"}, nil); err == nil {
		t.Fatal("a bad URL passed")
	}
}

func TestPrettyJSONKeepsPlainText(t *testing.T) {
	if got := PrettyJSON([]byte("not json")); got != "not json" {
		t.Errorf("got %q", got)
	}
}
