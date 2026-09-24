// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// run drives the whole CLI and returns the status, the output, and the
// error output.
func run(t *testing.T, env Environment, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if env.Out == nil {
		env.Out = &out
	}
	if env.ErrOut == nil {
		env.ErrOut = &errOut
	}
	if env.In == nil {
		env.In = strings.NewReader("")
	}
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Random == nil {
		env.Random = rand.Reader
	}
	if env.Run == nil {
		env.Run = func(context.Context, string, []string) error { return nil }
	}
	if env.NewProbe == nil {
		env.NewProbe = func(context.Context) Probe { return healthyProbe() }
	}
	env.Args = args
	status := Execute(env)
	return status, out.String(), errOut.String()
}

func TestRootHelp(t *testing.T) {
	status, out, _ := run(t, Environment{Root: t.TempDir()}, "--help")
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{"setup", "deploy", "status", "down", "dpg", "admin", "man"} {
		if !strings.Contains(out, want) {
			t.Errorf("the help text has no %q", want)
		}
	}
}

func TestHelpListsThemeCommands(t *testing.T) {
	status, out, _ := run(t, Environment{Root: t.TempDir()}, "--help")
	if status != 0 || !strings.Contains(out, "theme") {
		t.Fatalf("status %d, the root help has no theme command:\n%s", status, out)
	}
	status, out, _ = run(t, Environment{Root: t.TempDir()}, "theme", "--help")
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{"check", "apply", "print-default", "vca theme check", "helm upgrade"} {
		if !strings.Contains(out, want) {
			t.Errorf("the theme help has no %q:\n%s", want, out)
		}
	}
}

func TestUnknownCommandFails(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "fly")
	if status == 0 {
		t.Fatal("an unknown command passed")
	}
	if !strings.Contains(errOut, "vca:") {
		t.Errorf("error output = %q", errOut)
	}
}

func TestSetupNonInteractive(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--role", "issuer", "--dpg", "waltid", "--non-interactive",
		"--set", "VCA_PUBLIC_URL=https://issuer.example",
		"--set", "VCA_DATABASE_URL=postgres://vca@pg/vca",
		"--set", "VCA_DPG_URL=http://issuer-api:7002",
		"--set", "VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration",
	)
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "Setup plan for issuer-waltid") {
		t.Errorf("the summary is missing:\n%s", out)
	}
	for _, name := range []string{EnvFileName, SigningKeyFile, CaddyFile, OnboardFile} {
		path := filepath.Join(root, "deploy", "issuer-waltid", name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
	if !strings.Contains(out, "wrote ") {
		t.Errorf("the run printed no file names:\n%s", out)
	}
}

// TestSetupNonInteractiveNeedsNoValueOnALaptop is the laptop path of
// ADR-008 decision 7. Every value has a default.
func TestSetupNonInteractiveNeedsNoValueOnALaptop(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--role", "issuer", "--dpg", "waltid", "--non-interactive")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	for _, name := range []string{EnvFileName, OnboardFile} {
		if _, err := os.Stat(filepath.Join(root, "deploy", "issuer-waltid", name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
	for _, name := range []string{"keycloak-waltid/vca-issuer-realm.json", "keycloak-waltid/.env"} {
		if _, err := os.Stat(filepath.Join(root, "deploy", name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
}

// TestSetupNonInteractiveHolderNeedsNoValue proves the Redis URL no
// longer blocks a holder run (ADR-020 decision 6).
func TestSetupNonInteractiveHolderNeedsNoValue(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--role", "holder", "--dpg", "waltid", "--non-interactive")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if strings.Contains(out, "VCA_REDIS_URL") {
		t.Errorf("the plan holds a Redis URL:\n%s", out)
	}
}

func TestSetupReadsTheProcessEnvironment(t *testing.T) {
	root := t.TempDir()
	values := map[string]string{
		"VCA_PUBLIC_URL":         "https://from-env.example",
		"VCA_DATABASE_URL":       "postgres://vca@pg/vca",
		"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
	}
	status, out, errOut := run(t, Environment{Root: root, Getenv: func(k string) string { return values[k] }},
		"setup", "--role", "admin", "--dpg", "waltid", "--non-interactive")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "deploy", "admin-waltid", EnvFileName)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "https://from-env.example") {
		t.Errorf(".env = %s", data)
	}
	if !strings.Contains(out, "(environment)") {
		t.Errorf("the summary does not name the source:\n%s", out)
	}
}

func TestSetupUsesTheEnvFile(t *testing.T) {
	root := t.TempDir()
	prefill := filepath.Join(root, "base.env")
	body := strings.Join([]string{
		"VCA_PUBLIC_URL=https://from-file.example",
		"VCA_DATABASE_URL=postgres://vca@pg/vca",
		"VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration",
	}, "\n")
	if err := os.WriteFile(prefill, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--role", "admin", "--dpg", "inji", "--non-interactive", "--env-file", prefill)
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "(env file)") {
		t.Errorf("the summary does not name the env file:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "keycloak-inji", "vca-admin-realm.json")); err != nil {
		t.Errorf("the realm file is missing: %v", err)
	}
}

func TestSetupReportsABadEnvFile(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"setup", "--role", "admin", "--dpg", "inji", "--env-file", "/does/not/exist")
	if status == 0 {
		t.Fatal("a missing env file passed")
	}
	if !strings.Contains(errOut, "read /does/not/exist") {
		t.Errorf("error = %q", errOut)
	}
}

func TestSetupReportsABadSetFlag(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"setup", "--role", "admin", "--dpg", "inji", "--set", "NOTAPAIR")
	if status == 0 {
		t.Fatal("a bad --set flag passed")
	}
	if !strings.Contains(errOut, "NAME=value") {
		t.Errorf("error = %q", errOut)
	}
}

func TestSetupNeedsARoleAndADpg(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "setup")
	if status == 0 {
		t.Fatal("a run with no role passed")
	}
	if !strings.Contains(errOut, "--all") {
		t.Errorf("error = %q", errOut)
	}
	status, _, errOut = run(t, Environment{Root: t.TempDir()}, "setup", "--role", "mayor", "--dpg", "waltid")
	if status == 0 || !strings.Contains(errOut, "issuer") {
		t.Errorf("status %d, error %q", status, errOut)
	}
	status, _, errOut = run(t, Environment{Root: t.TempDir()}, "setup", "--role", "issuer", "--dpg", "nothing")
	if status == 0 || !strings.Contains(errOut, "waltid") {
		t.Errorf("status %d, error %q", status, errOut)
	}
	status, _, errOut = run(t, Environment{Root: t.TempDir()}, "deploy", "--all", "--dpg", "nothing")
	if status == 0 || !strings.Contains(errOut, "waltid") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestSetupAllComposesEveryRole(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--all", "--dpg", "waltid", "--non-interactive",
		"--set", "VCA_PUBLIC_URL=https://one.example",
		"--set", "VCA_DATABASE_URL=postgres://vca@pg/vca",
		"--set", "VCA_DPG_URL=http://issuer-api:7002",
		"--set", "VCA_REDIS_URL=redis://redis:6379/0",
		"--set", "VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration",
	)
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	for _, name := range []string{"issuer-waltid", "holder-waltid", "verifier-waltid", "admin-waltid"} {
		if _, err := os.Stat(filepath.Join(root, "deploy", name, EnvFileName)); err != nil {
			t.Errorf("%s has no .env file: %v", name, err)
		}
	}
}

func TestSetupInteractiveAsksThenWrites(t *testing.T) {
	root := t.TempDir()
	// Every value of the admin pair has a default, so the only
	// question is the last one.
	// The first line answers the public URL question with the default.
	answers := "\ny\n"
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader(answers)},
		"setup", "--role", "admin", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "Write these files?") {
		t.Errorf("the run asked nothing:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "admin-waltid", EnvFileName)); err != nil {
		t.Errorf("the .env file is missing: %v", err)
	}
}

func TestSetupInteractiveKeepsTheFilesOnNo(t *testing.T) {
	root := t.TempDir()
	// The first line answers the public URL question with the default.
	answers := "\nn\n"
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader(answers)},
		"setup", "--role", "admin", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "nothing written") {
		t.Errorf("out = %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "admin-waltid", EnvFileName)); err == nil {
		t.Error("the run wrote a file after a no")
	}
}

// TestSetupAllRepeatsThePublicHost is the --all path of ADR-007
// decision 2 with no base domain. The run asks the base domain once,
// then one public URL question per pair. The answer of the first pair
// pre-fills the next question, so enter repeats it.
func TestSetupAllRepeatsThePublicHost(t *testing.T) {
	root := t.TempDir()
	answers := strings.Join([]string{
		"\n",                           // no base domain
		"https://one.example\n", "y\n", // issuer
		"\n", "y\n", // holder
		"\n", "y\n", // verifier
		"\n", "y\n", // admin
	}, "")
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader(answers)},
		"setup", "--all", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if strings.Count(out, "Base domain [") != 1 {
		t.Errorf("the run asked %d base domain questions:\n%s", strings.Count(out, "Base domain ["), out)
	}
	if strings.Count(out, "Public URL [") != 4 {
		t.Errorf("the run asked %d public URL questions:\n%s", strings.Count(out, "Public URL ["), out)
	}
	if !strings.Contains(out, "Public URL [https://one.example]") {
		t.Errorf("the next pair got no offer:\n%s", out)
	}
	for _, name := range []string{"issuer-waltid", "holder-waltid", "verifier-waltid", "admin-waltid"} {
		data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "deploy", name, EnvFileName)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), "https://one.example") {
			t.Errorf("%s did not keep the public host:\n%s", name, data)
		}
	}
}

// TestSetupAllWithADomainAsksNoPublicURL gives every pair its own host
// name under the base domain, and the Keycloak of the stack its own.
func TestSetupAllWithADomainAsksNoPublicURL(t *testing.T) {
	root := t.TempDir()
	answers := strings.Join([]string{
		"*.Labs.Example\n", // the base domain, as a wildcard record reads
		"y\n", "y\n", "y\n", "y\n",
	}, "")
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader(answers)},
		"setup", "--all", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if strings.Contains(out, "Public URL [") {
		t.Errorf("the run asked a public URL question:\n%s", out)
	}
	if !strings.Contains(out, "VCA_PUBLIC_URL = https://issuer-waltid.labs.example  (domain)") {
		t.Errorf("the summary has no domain value:\n%s", out)
	}
	for _, name := range []string{"issuer-waltid", "holder-waltid", "verifier-waltid", "admin-waltid"} {
		data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "deploy", name, EnvFileName)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, want := range []string{
			"VCA_PUBLIC_URL=https://" + name + ".labs.example\n",
			"VCA_OIDC_REDIRECT_URI=https://" + name + ".labs.example/auth/callback\n",
			"VCA_OIDC_PUBLIC_URL=https://waltid-keycloak.labs.example\n",
		} {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s has no %q:\n%s", name, want, data)
			}
		}
	}
	caddy, err := os.ReadFile(filepath.Clean(filepath.Join(root, "deploy", "issuer-waltid", CaddyFile)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"issuer-waltid.labs.example {", "waltid-keycloak.labs.example {", "127.0.0.1:17010"} {
		if !strings.Contains(string(caddy), want) {
			t.Errorf("the Caddyfile has no %q:\n%s", want, caddy)
		}
	}
}

// TestSetupDomainFlagAndEnv take the base domain without a question.
func TestSetupDomainFlagAndEnv(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader("")},
		"setup", "--role", "issuer", "--dpg", "inji", "--domain", "labs.example", "--yes")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "VCA_PUBLIC_URL = https://issuer-inji.labs.example  (domain)") {
		t.Errorf("flag: %s", out)
	}
	getenv := func(name string) string {
		if name == DomainEnv {
			return "other.example"
		}
		return ""
	}
	status, out, errOut = run(t, Environment{Root: root, In: strings.NewReader(""), Getenv: getenv},
		"setup", "--role", "issuer", "--dpg", "inji", "--yes")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "VCA_PUBLIC_URL = https://issuer-inji.other.example  (domain)") {
		t.Errorf("env: %s", out)
	}
	status, _, errOut = run(t, Environment{Root: root, In: strings.NewReader("")},
		"setup", "--role", "issuer", "--dpg", "inji", "--domain", "https://x/y", "--yes")
	if status == 0 || !strings.Contains(errOut, "DNS name") {
		t.Errorf("a bad domain passed: %d %s", status, errOut)
	}
}

// TestSetupAllSkipsTheDomainQuestionWhenAPublicURLIsGiven keeps a
// scripted run scripted.
func TestSetupAllSkipsTheDomainQuestionWhenAPublicURLIsGiven(t *testing.T) {
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root, In: strings.NewReader("")},
		"setup", "--all", "--dpg", "waltid", "--set", "VCA_PUBLIC_URL=https://one.example", "--yes")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if strings.Contains(out, "Base domain [") {
		t.Errorf("the run asked the base domain:\n%s", out)
	}
}

func TestSetupWritesToTheNamedDirectory(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "elsewhere")
	status, _, errOut := run(t, Environment{Root: root},
		"setup", "--role", "admin", "--dpg", "waltid", "--non-interactive", "--out", out,
		"--set", "VCA_PUBLIC_URL=https://a.example",
		"--set", "VCA_DATABASE_URL=postgres://vca@pg/vca",
		"--set", "VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration",
	)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if _, err := os.Stat(filepath.Join(out, "admin-waltid", EnvFileName)); err != nil {
		t.Errorf("the .env file is missing: %v", err)
	}
}

func TestDeployDryRun(t *testing.T) {
	status, out, errOut := run(t, Environment{Root: t.TempDir()},
		"deploy", "--role", "issuer", "--dpg", "waltid", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if !strings.Contains(out, "profiles: [issuer-waltid]") {
		t.Errorf("the rendered compose file is missing:\n%s", out[:200])
	}
	if !strings.Contains(out, "docker compose --project-name vca") {
		t.Error("the command line is missing")
	}
}

func TestDeployStatusAndDownRunCompose(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "deploy", "issuer-waltid")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte("VCA_ROLE=issuer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ command, action string }{
		{"deploy", "up -d"}, {"status", "ps"}, {"down", "down --remove-orphans"},
	} {
		rec := &recorder{}
		status, _, errOut := run(t, Environment{Root: root, Run: rec.run},
			c.command, "--role", "issuer", "--dpg", "waltid")
		if status != 0 {
			t.Fatalf("%s: status = %d\n%s", c.command, status, errOut)
		}
		if len(rec.calls) != 1 {
			t.Fatalf("%s ran %d commands", c.command, len(rec.calls))
		}
		if !strings.Contains(strings.Join(rec.calls[0], " "), c.action) {
			t.Errorf("%s ran %v", c.command, rec.calls[0])
		}
	}
}

func TestDeployAllWithNoDpgTakesEveryPair(t *testing.T) {
	status, out, errOut := run(t, Environment{Root: t.TempDir()}, "deploy", "--all", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	for _, p := range AllPairs() {
		if !strings.Contains(out, "# "+p.Name()+"\n") {
			t.Errorf("the dry run has no command for %s", p.Name())
		}
	}
}

// TestSetupKeepsTheKeycloakPasswordAcrossRoles is ADR-035 decision 7 on
// the command: the second role of a stack finds the .env of the Keycloak
// and keeps its password, and both roles write their own realm there.
func TestSetupKeepsTheKeycloakPasswordAcrossRoles(t *testing.T) {
	root := t.TempDir()
	for _, role := range []string{"issuer", "holder"} {
		status, out, errOut := run(t, Environment{Root: root},
			"setup", "--role", role, "--dpg", "inji", "--non-interactive")
		if status != 0 {
			t.Fatalf("%s: status = %d\n%s\n%s", role, status, out, errOut)
		}
	}
	first, err := ReadKeycloakEnv(filepath.Join(root, "deploy"), configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatal(err)
	}
	password := first[KeycloakAdminPasswordEnv]
	if password == "" || password == "admin" {
		t.Fatalf("password = %q", password)
	}
	status, out, errOut := run(t, Environment{Root: root},
		"setup", "--role", "issuer", "--dpg", "inji", "--non-interactive")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	again, err := ReadKeycloakEnv(filepath.Join(root, "deploy"), configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatal(err)
	}
	if again[KeycloakAdminPasswordEnv] != password {
		t.Error("a later run replaced the password of the stack")
	}
	for _, name := range []string{"vca-issuer-realm.json", "vca-holder-realm.json", EnvFileName} {
		if _, err := os.Stat(filepath.Join(root, "deploy", "keycloak-inji", name)); err != nil {
			t.Errorf("%s is missing: %v", name, err)
		}
	}
	if strings.Contains(out, password) {
		t.Error("the output shows the password")
	}
}

// TestDpgBootstrapReadsTheKeycloakPassword proves the bootstrap run
// signs in with the generated password of the stack, with no default.
func TestDpgBootstrapReadsTheKeycloakPassword(t *testing.T) {
	root := t.TempDir()
	state := &keycloakState{realm: RealmName(commonv1.Role_ROLE_ISSUER), password: "generated-by-setup"}
	server := fakeKeycloak(t, state)
	defer server.Close()
	pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}
	dir := filepath.Join(root, "deploy", pair.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := "VCA_PUBLIC_URL=https://issuer.example\nVCA_DPG_URL=" + server.URL + "\n"
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stack := filepath.Join(root, "deploy", KeycloakDir(pair.Dpg))
	if err := os.MkdirAll(stack, 0o750); err != nil {
		t.Fatal(err)
	}
	realm, err := KeycloakRealm(pair, map[string]string{"VCA_PUBLIC_URL": "https://issuer.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stack, RealmName(pair.Role)+".json"), realm, 0o600); err != nil {
		t.Fatal(err)
	}
	// No password yet: the run names the variable and the file.
	status, _, errOut := run(t, Environment{Root: root}, "dpg", "bootstrap", "inji", "--role", "issuer")
	if status == 0 || !strings.Contains(errOut, EnvBootstrapSecret) || !strings.Contains(errOut, "keycloak-inji/.env") {
		t.Fatalf("status = %d, error = %q", status, errOut)
	}
	env := KeycloakAdminEnv + "=admin\n" + KeycloakAdminPasswordEnv + "=generated-by-setup\n"
	if err := os.WriteFile(filepath.Join(stack, EnvFileName), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	status, out, errOut := run(t, Environment{Root: root}, "dpg", "bootstrap", "inji", "--role", "issuer")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if state.created != 1 || state.createdRealm != "vca-issuer-realm" {
		t.Errorf("created %d realms (%q)", state.created, state.createdRealm)
	}
	// The environment beats the file.
	getenv := func(k string) string {
		if k == EnvBootstrapSecret {
			return "wrong"
		}
		return ""
	}
	if status, _, _ := run(t, Environment{Root: root, Getenv: getenv}, "dpg", "bootstrap", "inji", "--role", "issuer"); status == 0 {
		t.Error("a wrong password from the environment passed")
	}
}

func TestDpgBootstrapCommand(t *testing.T) {
	root := t.TempDir()
	calls := 0
	server := fakeWaltid(t, &calls)
	defer server.Close()
	dir := filepath.Join(root, "deploy", "issuer-waltid")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := "VCA_PUBLIC_URL=https://issuer.example\nVCA_DPG_URL=" + server.URL + "\n"
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	status, out, errOut := run(t, Environment{Root: root}, "dpg", "bootstrap", "waltid", "--role", "issuer")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "walt.id issuer created") {
		t.Errorf("out = %s", out)
	}
	if calls != 1 {
		t.Errorf("the server saw %d calls", calls)
	}
}

func TestDpgBootstrapUsesTheOverrideEnvironment(t *testing.T) {
	root := t.TempDir()
	calls := 0
	server := fakeWaltid(t, &calls)
	defer server.Close()
	dir := filepath.Join(root, "deploy", "issuer-waltid")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName),
		[]byte("VCA_PUBLIC_URL=https://issuer.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == EnvBootstrapURL {
			return server.URL
		}
		return ""
	}
	status, out, errOut := run(t, Environment{Root: root, Getenv: getenv},
		"dpg", "bootstrap", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if calls != 1 {
		t.Errorf("the override URL was not used")
	}
}

func TestDpgBootstrapRejectsBadNames(t *testing.T) {
	root := t.TempDir()
	status, _, errOut := run(t, Environment{Root: root}, "dpg", "bootstrap", "nothing")
	if status == 0 || !strings.Contains(errOut, "waltid") {
		t.Errorf("status %d, error %q", status, errOut)
	}
	status, _, errOut = run(t, Environment{Root: root}, "dpg", "bootstrap", "waltid", "--role", "mayor")
	if status == 0 || !strings.Contains(errOut, "issuer") {
		t.Errorf("status %d, error %q", status, errOut)
	}
	status, _, _ = run(t, Environment{Root: root}, "dpg", "bootstrap")
	if status == 0 {
		t.Error("a bootstrap with no DPG name passed")
	}
}

func TestAdminCommandCallsTheService(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, errAssign := io.WriteString(w, `{"tenants":[]}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"admin", "tenant", "list", "--url", server.URL, "--token", "a-token", "--json", `{"pageSize":10}`)
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if gotPath != "/vca.admin.v1.AdminService/ListTenants" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(out, "\"tenants\"") {
		t.Errorf("out = %s", out)
	}
}

func TestAdminCommandReadsTheURLFromTheEnvironment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	getenv := func(k string) string {
		if k == "VCA_ADMIN_URL" {
			return server.URL
		}
		return ""
	}
	status, _, errOut := run(t, Environment{Root: t.TempDir(), Getenv: getenv}, "admin", "health")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
}

func TestAdminCommandReadsTheSavedToken(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if _, err := SaveToken(state, "saved-token"); err != nil {
		t.Fatal(err)
	}
	status, _, errOut := run(t, Environment{Root: root, StateDir: state},
		"admin", "health", "--url", server.URL)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if gotAuth != "Bearer saved-token" {
		t.Errorf("authorization = %q", gotAuth)
	}
}

func TestAdminCommandReadsTheRequestFile(t *testing.T) {
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
	root := t.TempDir()
	path := filepath.Join(root, "request.json")
	if err := os.WriteFile(path, []byte(`{"id":"t-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, errOut := run(t, Environment{Root: root},
		"admin", "tenant", "get", "--url", server.URL, "--file", path)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if gotBody != `{"id":"t-1"}` {
		t.Errorf("body = %q", gotBody)
	}
	status, _, errOut = run(t, Environment{Root: root},
		"admin", "tenant", "get", "--url", server.URL, "--file", "/does/not/exist")
	if status == 0 || !strings.Contains(errOut, "read /does/not/exist") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestAdminCommandReportsAServiceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, errAssign := io.WriteString(w, `{"code":"not_found","message":"no tenant"}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"admin", "tenant", "get", "--url", server.URL, "--json", `{"id":"x"}`)
	if status == 0 || !strings.Contains(errOut, "not_found") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestAdminBindIsOneCommand(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"admin", "bind", "--url", server.URL, "--json", `{"bootstrapToken":"t"}`)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if gotPath != "/vca.admin.v1.AdminService/OnboardAdmin" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestAdminLoginDeviceFlow(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	root := t.TempDir()
	status, out, errOut := run(t, Environment{Root: root},
		"admin", "login", "--device", "--url", server.URL,
		"--bootstrap-token", "boot", "--provider", "p-1")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "login done") {
		t.Errorf("out = %s", out)
	}
	if state.bootstrap != "boot" {
		t.Errorf("the bootstrap token did not reach the service: %q", state.bootstrap)
	}
	token, err := LoadToken(filepath.Join(root, "deploy", ".vca"))
	if err != nil || token != "an-admin-session" {
		t.Errorf("token = %q, %v", token, err)
	}
}

func TestAdminLoginReadsTheEnvironment(t *testing.T) {
	state := &fakeAdmin{}
	server := newFakeAdmin(t, state)
	defer server.Close()
	getenv := func(k string) string {
		if k == "VCA_ADMIN_URL" {
			return server.URL
		}
		return ""
	}
	status, _, errOut := run(t, Environment{Root: t.TempDir(), Getenv: getenv}, "admin", "login", "--device")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
}

func TestAdminLoginNeedsTheAdminURL(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "admin", "login")
	if status == 0 || !strings.Contains(errOut, "VCA_ADMIN_URL") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestAdminLoginReportsAFailedFlow(t *testing.T) {
	state := &fakeAdmin{failStart: true}
	server := newFakeAdmin(t, state)
	defer server.Close()
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"admin", "login", "--device", "--url", server.URL)
	if status == 0 || !strings.Contains(errOut, "unsupported_grant_type") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestAdminHelpCallsListCommands(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, errAssign := io.WriteString(w, `{"commands":[{"path":"admin trust add"}]}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	status, out, errOut := run(t, Environment{Root: t.TempDir()},
		"admin", "help", "--url", server.URL)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if gotPath != "/vca.admin.v1.AdminService/ListCommands" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(out, "admin trust add") {
		t.Errorf("out = %s", out)
	}
}

func TestAdminTrustAddCallsUpsert(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, errAssign := io.WriteString(w, `{}`)
		if errAssign != nil {
			t.Fatalf("io.WriteString: %v", errAssign)
		}
	}))
	defer server.Close()
	status, _, errOut := run(t, Environment{Root: t.TempDir()},
		"admin", "trust", "add", "--url", server.URL, "--json", `{"entry":{}}`)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if gotPath != "/vca.admin.v1.AdminService/UpsertTrustEntry" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestManWritesOnePagePerCommand(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "man")
	status, out, errOut := run(t, Environment{Root: root}, "man", "--dir", dir)
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if !strings.Contains(out, "wrote the man pages") {
		t.Errorf("out = %s", out)
	}
	entries, entriesErr := os.ReadDir(dir)
	if entriesErr != nil {
		t.Fatal(entriesErr)
	}
	if len(entries) < 30 {
		t.Errorf("got %d man pages", len(entries))
	}
	for _, name := range []string{"vca.1", "vca-setup.1", "vca-deploy.1", "vca-admin-trust-add.1"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is missing: %v", name, err)
		}
	}
	page, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "vca-admin-trust-add.1")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "Creates or replaces one trust entry") {
		t.Errorf("the man page does not carry the proto description:\n%s", page)
	}
}

func TestManNeedsADirectory(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "man")
	if status == 0 || !strings.Contains(errOut, "--dir") {
		t.Errorf("status %d, error %q", status, errOut)
	}
}

func TestManReportsABadDirectory(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, _ := run(t, Environment{Root: root}, "man", "--dir", filepath.Join(file, "man"))
	if status == 0 {
		t.Fatal("a file in place of a directory passed")
	}
}

func TestEnvironmentDefaults(t *testing.T) {
	got := Environment{}.withDefaults()
	if got.Root != "." || got.In == nil || got.Out == nil || got.ErrOut == nil {
		t.Errorf("defaults = %+v", got)
	}
	if got.Getenv == nil || got.Random == nil || got.Run == nil || got.StateDir == "" {
		t.Errorf("defaults = %+v", got)
	}
}

func TestParseSets(t *testing.T) {
	got, err := parseSets([]string{"A=1", " B =two=three"})
	if err != nil {
		t.Fatalf("parseSets: %v", err)
	}
	if got["A"] != "1" || got["B"] != "two=three" {
		t.Errorf("got %v", got)
	}
	if _, err := parseSets([]string{"=1"}); err == nil {
		t.Error("an empty name passed")
	}
}

func TestSetupReportsAWriteFailure(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "blocked")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, errOut := run(t, Environment{Root: root},
		"setup", "--role", "admin", "--dpg", "waltid", "--non-interactive", "--out", file,
		"--set", "VCA_PUBLIC_URL=https://a.example",
		"--set", "VCA_DATABASE_URL=postgres://vca@pg/vca",
		"--set", "VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration",
	)
	if status == 0 {
		t.Fatalf("a bad output directory passed:\n%s", errOut)
	}
}

// smallHostMiB is the free memory of the small host: under one stack,
// over one issuer pair.
const smallHostMiB = 3600

// smallHostEnv answers every check with a pass, but with little memory.
func smallHostEnv(root string) Environment {
	return Environment{Root: root, NewProbe: func(context.Context) Probe {
		probe := healthyProbe()
		probe.memory = smallHostMiB
		return probe
	}}
}

func TestDoctorSuggestPrintsASelection(t *testing.T) {
	status, out, errOut := run(t, smallHostEnv(t.TempDir()), "doctor", "--suggest")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	best, ok := LargestFit(smallHostMiB)
	if !ok {
		t.Fatal("no selection fits 6 GB")
	}
	if !strings.Contains(out, best.Flags) {
		t.Errorf("the output does not name %s:\n%s", best.Flags, out)
	}
}

func TestDoctorAllPrintsTheMemoryHint(t *testing.T) {
	status, out, _ := run(t, smallHostEnv(t.TempDir()), "doctor", "--all")
	if status == 0 {
		t.Error("a host with 6 GB free passed --all")
	}
	if !strings.Contains(out, MemoryHint(smallHostMiB)) {
		t.Errorf("the report has no hint:\n%s", out)
	}
	if !strings.Contains(out, "Memory floor of this selection") {
		t.Errorf("the report has no floor table:\n%s", out)
	}
}

func TestSetupAllPrintsTheMemoryHint(t *testing.T) {
	root := t.TempDir()
	env := smallHostEnv(root)
	env.In = strings.NewReader("")
	status, out, errOut := run(t, env, "setup", "--all", "--dpg", "waltid",
		"--non-interactive", "--set", "VCA_REDIS_URL=redis://redis:6379")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, MemoryHint(smallHostMiB)) {
		t.Errorf("the run printed no hint:\n%s", out)
	}
}
