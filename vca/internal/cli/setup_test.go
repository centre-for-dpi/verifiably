// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

func roleHolder(t *testing.T) commonv1.Role {
	t.Helper()
	r, err := ParseRole("holder")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func dpgWaltid(t *testing.T) configv1.Dpg {
	t.Helper()
	d, err := ParseDpg("waltid")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// issuerFlags holds a complete non interactive answer set for the issuer.
func issuerFlags() map[string]string {
	return map[string]string{
		"VCA_PUBLIC_URL":         "https://issuer.example",
		"VCA_DATABASE_URL":       "postgres://vca:pass@postgres:5432/vca",
		"VCA_DPG_URL":            "http://issuer-api:7002",
		"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
		"VCA_OIDC_CLIENT_ID":     "vca-issuer",
	}
}

func issuerPair() Pair {
	return Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
}

func TestBuildPlanNonInteractive(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	values := Values(plan.Resolutions)
	if values["VCA_ROLE"] != "issuer" || values["VCA_DPG"] != "waltid" {
		t.Errorf("role and DPG = %q, %q", values["VCA_ROLE"], values["VCA_DPG"])
	}
	if values["VCA_INTERNAL_URL"] != "https://issuer.example" {
		t.Errorf("the internal URL did not follow the public URL: %q", values["VCA_INTERNAL_URL"])
	}
	if values["VCA_OIDC_REDIRECT_URI"] != "https://issuer.example/auth/callback" {
		t.Errorf("the redirect URI = %q", values["VCA_OIDC_REDIRECT_URI"])
	}
	if values["VCA_LOG_LEVEL"] != "info" {
		t.Errorf("the default log level is missing: %q", values["VCA_LOG_LEVEL"])
	}
	if values["VCA_SECRETS_SESSION_KEY"] == "" {
		t.Error("the session key was not generated")
	}
	if !strings.HasPrefix(values["VCA_SECRETS_SIGNING_KEY"], SigningKeyRefPrefix) {
		t.Errorf("the signing key = %q", values["VCA_SECRETS_SIGNING_KEY"])
	}
	names := fileNames(plan)
	for _, want := range []string{EnvFileName, SigningKeyFile, CaddyFile, OnboardFile} {
		if !names[want] {
			t.Errorf("the plan has no %s", want)
		}
	}
	if names["keycloak/vca-realm.json"] {
		t.Error("the pair holds the old realm file")
	}
	sharedFile(t, plan, RealmFileOf(issuerPair()))
}

func fileNames(p Plan) map[string]bool {
	out := map[string]bool{}
	for _, f := range p.Files {
		out[f.Name] = true
	}
	return out
}

func TestBuildPlanEnvFileModeIs0600(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, f := range plan.Files {
		if f.Name == EnvFileName || f.Name == SigningKeyFile {
			if f.Mode != 0o600 {
				t.Errorf("%s has mode %04o, want 0600", f.Name, f.Mode)
			}
		}
	}
}

// TestBuildPlanFailsAndListsEveryMissingValue uses a pair with no DPG.
// No stack backs it, so the discovery URL has no default. Every one of
// the twelve real pairs has a default for every required value.
func TestBuildPlanFailsAndListsEveryMissingValue(t *testing.T) {
	_, err := BuildPlan(SetupRequest{Pair: Pair{Role: commonv1.Role_ROLE_HOLDER}, Random: rand.Reader})
	if err == nil {
		t.Fatal("BuildPlan passed with no values")
	}
	var missing *MissingValuesError
	if !asMissing(err, &missing) {
		t.Fatalf("got %T, want MissingValuesError", err)
	}
	if len(missing.Settings) < 1 {
		t.Errorf("got %d missing settings", len(missing.Settings))
	}
	text := err.Error()
	for _, want := range []string{"VCA_OIDC_DISCOVERY_URL"} {
		if !strings.Contains(text, want) {
			t.Errorf("the error does not name %s:\n%s", want, text)
		}
	}
}

func asMissing(err error, target **MissingValuesError) bool {
	var m *MissingValuesError
	if !errors.As(err, &m) {
		return false
	}
	*target = m
	return true
}

func TestBuildPlanReportsBadValues(t *testing.T) {
	flags := issuerFlags()
	flags["VCA_LOG_LEVEL"] = "trace"
	flags["VCA_PUBLIC_URL"] = "https://issuer.example/path"
	_, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader})
	if err == nil {
		t.Fatal("BuildPlan passed a bad value")
	}
	if !strings.Contains(err.Error(), "VCA_LOG_LEVEL") || !strings.Contains(err.Error(), "VCA_PUBLIC_URL") {
		t.Errorf("the error does not list both problems:\n%v", err)
	}
}

// TestBuildPlanHolderRedisIsOptional is ADR-020 decision 6. An empty
// Redis URL selects the in-memory limiter, which serves one replica.
func TestBuildPlanHolderRedisIsOptional(t *testing.T) {
	pair := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	flags := issuerFlags()
	plan, err := BuildPlan(SetupRequest{Pair: pair, Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan with no Redis URL: %v", err)
	}
	if Values(plan.Resolutions)["VCA_REDIS_URL"] != "" {
		t.Error("the plan invented a Redis URL")
	}
	flags["VCA_REDIS_URL"] = "redis://redis:6379/0"
	plan, err = BuildPlan(SetupRequest{Pair: pair, Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if Values(plan.Resolutions)["VCA_REDIS_URL"] != "redis://redis:6379/0" {
		t.Error("the plan dropped the Redis URL")
	}
	sharedFile(t, plan, RealmFileOf(pair))
}

func TestBuildPlanAdminNeedsABootstrapToken(t *testing.T) {
	pair := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	flags := map[string]string{
		"VCA_PUBLIC_URL":         "https://admin.example",
		"VCA_DATABASE_URL":       "postgres://vca:pass@postgres:5432/vca",
		"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
	}
	plan, err := BuildPlan(SetupRequest{Pair: pair, Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if Values(plan.Resolutions)["VCA_SECRETS_BOOTSTRAP_TOKEN"] == "" {
		t.Error("the bootstrap token was not generated")
	}
}

func TestBuildPlanInteractive(t *testing.T) {
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	// An empty answer keeps the localhost default.
	var out strings.Builder
	plan, err := BuildPlan(SetupRequest{
		Pair:        holder,
		Interactive: true,
		Prompter:    NewPrompter(strings.NewReader("\n"), &out),
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v\n%s", err, out.String())
	}
	values := Values(plan.Resolutions)
	if values["VCA_PUBLIC_URL"] != LocalPublicURL(holder) {
		t.Errorf("the public URL = %q", values["VCA_PUBLIC_URL"])
	}
	if values["VCA_REDIS_URL"] != "" {
		t.Errorf("the CLI asked for the optional Redis URL: %q", values["VCA_REDIS_URL"])
	}
	if !strings.Contains(out.String(), "VCA_PUBLIC_URL") {
		t.Errorf("the CLI asked no question:\n%s", out.String())
	}
	// A public host answer wins over the default.
	out.Reset()
	plan, err = BuildPlan(SetupRequest{
		Pair:        holder,
		Interactive: true,
		Prompter:    NewPrompter(strings.NewReader("https://wallet.example\n"), &out),
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v\n%s", err, out.String())
	}
	if got := Values(plan.Resolutions)["VCA_PUBLIC_URL"]; got != "https://wallet.example" {
		t.Errorf("the public URL = %q", got)
	}
}

// TestBuildPlanEveryPairNeedsNoValue is ADR-007 decision 3. A run with
// no flag, no environment, and no env file must pass for each of the
// twelve pairs. Every required value has a default, a derived value, or
// a generated secret.
func TestBuildPlanEveryPairNeedsNoValue(t *testing.T) {
	for _, p := range AllPairs() {
		t.Run(p.Name(), func(t *testing.T) {
			plan, err := BuildPlan(SetupRequest{Pair: p, Random: rand.Reader})
			var missing *MissingValuesError
			if errors.As(err, &missing) {
				t.Fatalf("%s needs a value:\n%v", p.Name(), err)
			}
			if err != nil {
				t.Fatalf("BuildPlan %s: %v", p.Name(), err)
			}
			for _, r := range plan.Resolutions {
				if r.Setting.Required && r.Value == "" {
					t.Errorf("%s has no value for %s", p.Name(), r.Setting.Env)
				}
			}
		})
	}
}

// TestCarryOffersKeepsAPublicHostOnly proves a --all run repeats a
// public host on the next pair and never a localhost address.
func TestCarryOffersKeepsAPublicHostOnly(t *testing.T) {
	local, err := BuildPlan(SetupRequest{Pair: issuerPair(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(CarryOffers(local)) != 0 {
		t.Errorf("a localhost value carried over: %v", CarryOffers(local))
	}
	public, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if CarryOffers(public)["VCA_PUBLIC_URL"] != "https://issuer.example" {
		t.Errorf("the public host did not carry over: %v", CarryOffers(public))
	}
}

func TestBuildPlanInteractiveReportsAClosedInput(t *testing.T) {
	// A pair with no DPG has no default discovery URL, so the run asks.
	var out strings.Builder
	_, err := BuildPlan(SetupRequest{
		Pair:        Pair{Role: commonv1.Role_ROLE_HOLDER},
		Interactive: true,
		Prompter:    NewPrompter(strings.NewReader(""), &out),
		Random:      rand.Reader,
	})
	if err == nil {
		t.Fatal("BuildPlan passed with no input")
	}
}

func TestBuildPlanReportsARandomFailure(t *testing.T) {
	_, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: &shortReader{n: 1}})
	if err == nil {
		t.Fatal("BuildPlan passed with a failing random source")
	}
}

func TestPlanSummaryHidesSecrets(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	summary := plan.Summary()
	if strings.Contains(summary, "pass@postgres") {
		t.Errorf("the summary leaked the database password:\n%s", summary)
	}
	if !strings.Contains(summary, "VCA_PUBLIC_URL = https://issuer.example") {
		t.Errorf("the summary is missing a value:\n%s", summary)
	}
	if !strings.Contains(summary, "issuance  listens on 8080") {
		t.Errorf("the summary is missing the ports:\n%s", summary)
	}
	if !strings.Contains(summary, EnvFileName+"  mode 0600") {
		t.Errorf("the summary is missing the files:\n%s", summary)
	}
	if !strings.Contains(summary, "(flag)") {
		t.Errorf("the summary is missing the origin:\n%s", summary)
	}
}

func TestWritePlanAndReadExisting(t *testing.T) {
	root := t.TempDir()
	plan, planErr := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if planErr != nil {
		t.Fatalf("BuildPlan: %v", planErr)
	}
	written, writtenErr := WritePlan(root, plan)
	if writtenErr != nil {
		t.Fatalf("WritePlan: %v", writtenErr)
	}
	// The first run also writes the shared landing file and the default
	// theme file (ADR-032, ADR-033).
	if len(written) != len(plan.Files)+len(plan.Shared)+1 {
		t.Errorf("wrote %d files, want %d", len(written), len(plan.Files)+len(plan.Shared)+1)
	}
	dir := filepath.Join(root, "issuer-waltid")
	for _, name := range []string{EnvFileName, SigningKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", name, info.Mode().Perm())
		}
	}
	existing, err := ReadExisting(root, issuerPair())
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	if existing["VCA_SECRETS_SESSION_KEY"] == "" {
		t.Error("ReadExisting lost the session key")
	}
	// A second run keeps the secret (ADR-007 decision 5).
	again, err := BuildPlan(SetupRequest{
		Pair: issuerPair(), Flags: issuerFlags(), Existing: existing, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("BuildPlan again: %v", err)
	}
	if Values(again.Resolutions)["VCA_SECRETS_SESSION_KEY"] != existing["VCA_SECRETS_SESSION_KEY"] {
		t.Error("a second run replaced the session key")
	}
	if _, err := WritePlan(root, again); err != nil {
		t.Fatalf("WritePlan again: %v", err)
	}
}

func TestReadExistingMissingDirectory(t *testing.T) {
	got, err := ReadExisting(t.TempDir(), issuerPair())
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty map", got)
	}
}

func TestReadExistingReportsABadFile(t *testing.T) {
	root := t.TempDir()
	dir := OutputDir(root, issuerPair())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte("NOT A LINE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExisting(root, issuerPair()); err == nil {
		t.Fatal("ReadExisting passed a bad file")
	}
}

func TestWritePlanReportsABadRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePlan(root, Plan{Pair: issuerPair()}); err == nil {
		t.Fatal("WritePlan passed a file as the root")
	}
}

func TestWritePlanMakesASubdirectory(t *testing.T) {
	root := t.TempDir()
	plan := Plan{Pair: issuerPair(), Files: []File{{Name: "sub/dir/x", Data: []byte("x"), Mode: 0o644}}}
	written, err := WritePlan(root, plan)
	if err != nil {
		t.Fatalf("WritePlan: %v", err)
	}
	path := filepath.Join(OutputDir(root, issuerPair()), "sub", "dir", "x")
	if len(written) != 2 || written[0] != path || written[1] != filepath.Join(root, "vca", "theme.yaml") {
		t.Errorf("written = %v", written)
	}
	// Another user in a container reads the directory, so it is 0755.
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("subdirectory mode = %v, %v", info.Mode(), err)
	}
	// A second run keeps the directory and the file.
	if _, again := WritePlan(root, plan); again != nil {
		t.Fatalf("second WritePlan: %v", again)
	}
}

func TestWritePlanReportsABadSubdirectory(t *testing.T) {
	root := t.TempDir()
	// A file where the subdirectory must go is an error.
	if err := os.MkdirAll(OutputDir(root, issuerPair()), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(OutputDir(root, issuerPair()), "sub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Pair: issuerPair(), Files: []File{{Name: "sub/x", Data: []byte("x"), Mode: 0o600}}}
	if _, err := WritePlan(root, plan); err == nil {
		t.Fatal("WritePlan passed a file in place of the subdirectory")
	}
}

func TestGeneratedRealmIsValidJSON(t *testing.T) {
	pair := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_CREDEBL}
	body, err := KeycloakRealm(pair, map[string]string{"VCA_PUBLIC_URL": "https://verifier.example"})
	if err != nil {
		t.Fatalf("KeycloakRealm: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["realm"] != RealmName(commonv1.Role_ROLE_VERIFIER) || got["realm"] != "vca-verifier-realm" {
		t.Errorf("realm = %v", got["realm"])
	}
	clients := anyval.As[[]any](got["clients"])
	if len(clients) != 1 {
		t.Fatalf("got %d clients", len(clients))
	}
	client := anyval.As[map[string]any](clients[0])
	if client["clientId"] != "vca-verifier" {
		t.Errorf("client id = %v", client["clientId"])
	}
	if client["implicitFlowEnabled"] != false {
		t.Error("the implicit flow is on")
	}
	uris := anyval.As[[]any](client["redirectUris"])
	if len(uris) != 1 || uris[0] != "https://verifier.example/auth/callback" {
		t.Errorf("redirect URIs = %v", uris)
	}
}

func TestKeycloakRealmUsesTheSuppliedClientAndRedirect(t *testing.T) {
	body, err := KeycloakRealm(issuerPair(), map[string]string{
		"VCA_PUBLIC_URL":        "https://issuer.example",
		"VCA_OIDC_CLIENT_ID":    "given-id",
		"VCA_OIDC_REDIRECT_URI": "https://issuer.example/cb",
	})
	if err != nil {
		t.Fatalf("KeycloakRealm: %v", err)
	}
	if !strings.Contains(string(body), "given-id") || !strings.Contains(string(body), "/cb") {
		t.Errorf("realm = %s", body)
	}
}

func TestKeycloakRealmNeedsThePublicURL(t *testing.T) {
	if _, err := KeycloakRealm(issuerPair(), nil); err == nil {
		t.Fatal("KeycloakRealm passed with no public URL")
	}
}

func TestWaltidOnboard(t *testing.T) {
	body, err := WaltidOnboard(map[string]string{"VCA_PUBLIC_URL": "https://issuer.example:8443"})
	if err != nil {
		t.Fatalf("WaltidOnboard: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	did := anyval.As[map[string]any](got["did"])
	cfg := anyval.As[map[string]any](did["config"])
	if did["method"] != "web" || cfg["domain"] != "issuer.example" {
		t.Errorf("onboard body = %s", body)
	}
	if _, err := WaltidOnboard(map[string]string{"VCA_PUBLIC_URL": "not a url"}); err == nil {
		t.Fatal("WaltidOnboard passed a bad URL")
	}
}

func TestCaddyfile(t *testing.T) {
	values := map[string]string{"VCA_PUBLIC_URL": "https://issuer.example"}
	got := Caddyfile(issuerPair(), values)
	if !strings.Contains(got, "issuer.example {\n\tencode gzip\n") {
		t.Errorf("the host block is missing:\n%s", got)
	}
	// The proxy of the host reaches each service on its host port.
	for _, want := range []string{
		"\thandle /auth/* {\n\t\treverse_proxy 127.0.0.1:18004\n\t}\n",
		"\thandle /token {\n\t\treverse_proxy 127.0.0.1:18004\n\t}\n",
		"\thandle /.well-known/jwks.json {\n\t\treverse_proxy 127.0.0.1:18004\n\t}\n",
		"\thandle /portal/* {\n\t\treverse_proxy 127.0.0.1:18006\n\t}\n",
		"\thandle /static/* {\n\t\treverse_proxy 127.0.0.1:18002\n\t}\n",
		"\thandle /issuer/* {\n\t\treverse_proxy 127.0.0.1:18002\n\t}\n",
		"\thandle /builder/* {\n\t\treverse_proxy 127.0.0.1:18005\n\t}\n",
		"\thandle /issuance/pdf/* {\n\t\treverse_proxy 127.0.0.1:18002\n\t}\n",
		"\thandle /status-bitstring/status/* {\n\t\turi strip_prefix /status-bitstring\n\t\treverse_proxy 127.0.0.1:18007\n\t}\n",
		"\thandle /status-token/.well-known/jwks.json {\n\t\turi strip_prefix /status-token\n\t\treverse_proxy 127.0.0.1:18008\n\t}\n",
		"\thandle /vca.* {\n\t\trespond 404\n\t}\n",
		"\thandle / {\n\t\tredir * /issuer/ 302\n\t}\n",
		"\thandle {\n\t\treverse_proxy 127.0.0.1:18002\n\t}\n}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the Caddyfile has no %q:\n%s", want, got)
		}
	}
	// No route names a service prefix that the services do not know, and
	// no Connect service without a caller check (ADR-047).
	for _, wrong := range []string{
		"/schema-registry/", "strip_prefix /auth", "handle /status-bitstring/* ",
		"/vca.issuance.", "/vca.issued.", "/vca.schema.", "/vca.backend.", "/vca.datasource.",
	} {
		if strings.Contains(got, wrong) {
			t.Errorf("a wrong route %q:\n%s", wrong, got)
		}
	}
	// The root redirect and the fallback come last.
	if strings.LastIndex(got, "strip_prefix") > strings.Index(got, "handle / {") ||
		strings.Index(got, "respond 404") > strings.Index(got, "handle / {") ||
		strings.Index(got, "handle / {") > strings.Index(got, "\thandle {\n") {
		t.Error("the home routes are not last")
	}
	if strings.Contains(got, "keycloak") {
		t.Errorf("a local OIDC public URL got a Keycloak site:\n%s", got)
	}
	if !strings.Contains(got, "import <deploy dir>/*/Caddyfile") {
		t.Errorf("the import hint is missing:\n%s", got)
	}
	fallback := Caddyfile(issuerPair(), nil)
	if !strings.Contains(fallback, "localhost {") {
		t.Errorf("the fallback host is missing:\n%s", fallback)
	}
}

func TestCaddyfileHonoursAHostPortOverride(t *testing.T) {
	values := map[string]string{
		"VCA_PUBLIC_URL":                "https://issuer.example",
		"VCA_HOST_PORT_ISSUANCE":        "28002",
		"VCA_HOST_PORT_SCHEMA_REGISTRY": "28006",
	}
	got := Caddyfile(issuerPair(), values)
	if !strings.Contains(got, "handle /issuance/pdf/* {\n\t\treverse_proxy 127.0.0.1:28002") {
		t.Errorf("the override was lost:\n%s", got)
	}
	if !strings.Contains(got, "\thandle {\n\t\treverse_proxy 127.0.0.1:28002") {
		t.Errorf("the home override was lost:\n%s", got)
	}
}

func TestCaddyfileKeycloakSite(t *testing.T) {
	values := map[string]string{
		"VCA_PUBLIC_URL":      "https://issuer-waltid.labs.example",
		"VCA_OIDC_PUBLIC_URL": "https://waltid-keycloak.labs.example",
	}
	got := Caddyfile(issuerPair(), values)
	if !strings.Contains(got, "waltid-keycloak.labs.example {\n\treverse_proxy 127.0.0.1:17010\n}") {
		t.Errorf("the Keycloak site is missing:\n%s", got)
	}
	values["WALTID_KEYCLOAK_HOST_PORT"] = "27010"
	if got := Caddyfile(issuerPair(), values); !strings.Contains(got, "127.0.0.1:27010") {
		t.Errorf("the Keycloak port override was lost:\n%s", got)
	}
	// Only the issuer pair carries the site, so an import of every
	// Caddyfile declares the host once.
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	if got := Caddyfile(holder, values); strings.Contains(got, "keycloak") {
		t.Errorf("the holder pair got a Keycloak site:\n%s", got)
	}
	admin := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_UNSPECIFIED}
	if got := Caddyfile(admin, values); strings.Contains(got, "keycloak") {
		t.Errorf("a pair with no Keycloak got a site:\n%s", got)
	}
}

func TestDpgConfigFilesReportsABadPublicURL(t *testing.T) {
	plan := AssignPorts(issuerPair(), nil)
	if _, err := DpgConfigFiles(issuerPair(), map[string]string{}, plan); err == nil {
		t.Fatal("the walt.id pair passed with no public URL")
	}
	inji := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	if _, err := DpgConfigFiles(inji, map[string]string{}, AssignPorts(inji, nil)); err != nil {
		t.Fatalf("the Inji pair needs no public URL for its Caddyfile: %v", err)
	}
	admin := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_UNSPECIFIED}
	files, err := DpgConfigFiles(admin, map[string]string{"VCA_PUBLIC_URL": "https://a.example"}, AssignPorts(admin, nil))
	if err != nil {
		t.Fatalf("DpgConfigFiles: %v", err)
	}
	// The realm lives in the stack directory, so the pair holds the
	// Caddyfile alone (ADR-035 decision 1).
	if len(files) != 1 || files[0].Name != CaddyFile {
		t.Errorf("files = %d entries", len(files))
	}
	if _, realmErr := KeycloakFiles(inji, map[string]string{}, nil, rand.Reader); realmErr == nil {
		t.Fatal("the Inji realm passed with no public URL")
	}
	// A pair whose DPG ships no Keycloak gets no realm and no password.
	none, err := KeycloakFiles(admin, map[string]string{"VCA_PUBLIC_URL": "https://a.example"}, nil, rand.Reader)
	if err != nil || len(none) != 0 {
		t.Errorf("KeycloakFiles with no Keycloak = %v, %v", none, err)
	}
}

func TestFloorAndFloorTable(t *testing.T) {
	for _, p := range AllPairs() {
		f := Floor(p)
		if f.Services != len(ServicesFor(p)) {
			t.Errorf("%s: service count = %d", p.Name(), f.Services)
		}
		if f.TotalMemoryMiB() > 4096 {
			t.Errorf("%s needs %d MiB, over the 4 GB target", p.Name(), f.TotalMemoryMiB())
		}
		if f.Cpus <= 0 {
			t.Errorf("%s needs %v CPUs", p.Name(), f.Cpus)
		}
	}
	table := FloorTable()
	for _, p := range AllPairs() {
		if !strings.Contains(table, "`"+p.Name()+"`") {
			t.Errorf("the table has no row for %s", p.Name())
		}
	}
	if strings.Count(table, "\n") != len(AllPairs())+2 {
		t.Errorf("the table has the wrong row count:\n%s", table)
	}
}

// TestReadExistingUpgradesTheLegacyKeyReference repairs a pair that an
// earlier setup wrote with file:signing-key.pem.
func TestReadExistingUpgradesTheLegacyKeyReference(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	dir := OutputDir(root, p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	env := "VCA_SECRETS_SIGNING_KEY=file:signing-key.pem\nVCA_SECRETS_SESSION_KEY=s\n"
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExisting(root, p); err == nil {
		t.Error("a missing PEM passed")
	}
	if err := os.WriteFile(filepath.Join(dir, SigningKeyFile), []byte("PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := ReadExisting(root, p)
	if err != nil {
		t.Fatal(err)
	}
	if values["VCA_SECRETS_SIGNING_KEY"] != SigningKeyRef([]byte("PEM")) || values["VCA_SECRETS_SESSION_KEY"] != "s" {
		t.Errorf("values = %v", values)
	}
}

// TestPassthroughWritesUndeclaredVariables carries a service setting
// that the proto does not declare from --set or the env file.
func TestPassthroughWritesUndeclaredVariables(t *testing.T) {
	settings := Filter(Settings(), commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL)
	flags := map[string]string{"VCA_CREDEBL_EMAIL": "ops@example", "VCA_PUBLIC_URL": "https://x.example", "OTHER": "no"}
	file := map[string]string{"VCA_CREDEBL_EMAIL": "file@example", "VCA_CREDEBL_ORG_ID": "org", "VCA_EMPTY": " "}
	got := Passthrough(settings, flags, file)
	want := map[string]string{"VCA_CREDEBL_EMAIL": "ops@example", "VCA_CREDEBL_ORG_ID": "org"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_CREDEBL}
	plan, err := BuildPlan(SetupRequest{Pair: p, Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	var env string
	for _, f := range plan.Files {
		if f.Name == EnvFileName {
			env = string(f.Data)
		}
	}
	if !strings.Contains(env, "VCA_CREDEBL_EMAIL=ops@example\n") || strings.Contains(env, "OTHER=") {
		t.Errorf("env:\n%s", env)
	}
}

// envValue reads one variable of the rendered .env file of a plan.
func envValue(t *testing.T, plan Plan, name string) string {
	t.Helper()
	for _, f := range plan.Files {
		if f.Name != EnvFileName {
			continue
		}
		values, err := ParseDotenv(strings.NewReader(string(f.Data)))
		if err != nil {
			t.Fatalf("parse the .env: %v", err)
		}
		return values[name]
	}
	t.Fatal("the plan has no .env file")
	return ""
}

// TestBuildPlanWritesThePeersOfADomainSetup checks that the base domain
// of the run reaches the peer list, so a page links every pair on its
// own host name (ADR-034 decision 1).
func TestBuildPlanWritesThePeersOfADomainSetup(t *testing.T) {
	flags := issuerFlags()
	delete(flags, "VCA_PUBLIC_URL")
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader, Domain: "labs.example"})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	peers, err := topology.Parse(envValue(t, plan, topology.Env))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != len(AllPairs()) {
		t.Fatalf("got %d peers, want %d", len(peers), len(AllPairs()))
	}
	for _, peer := range peers {
		if peer.PublicURL != "https://"+peer.Pair+".labs.example" {
			t.Errorf("%s: public URL = %q", peer.Pair, peer.PublicURL)
		}
	}
	if envValue(t, plan, DomainEnv) != "" {
		t.Error("the domain itself must not leak into the .env file as a setting")
	}
}

// TestBuildPlanReadsThePeerDirectories checks that setup honours the
// port overrides and the public URL of every pair directory present.
func TestBuildPlanReadsThePeerDirectories(t *testing.T) {
	root := t.TempDir()
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	holderPlan, planErr := BuildPlan(SetupRequest{
		Pair: holder, Random: rand.Reader,
		Flags: map[string]string{"VCA_PUBLIC_URL": "https://wallet.example", "VCA_PORTS_PORTAL": "9090"},
	})
	if planErr != nil {
		t.Fatalf("BuildPlan holder: %v", planErr)
	}
	if _, werr := WritePlan(root, holderPlan); werr != nil {
		t.Fatalf("WritePlan holder: %v", werr)
	}
	overrides, err := ReadPeerOverrides(root)
	if err != nil {
		t.Fatalf("ReadPeerOverrides: %v", err)
	}
	if overrides["holder-inji"]["VCA_PORTS_PORTAL"] != "9090" {
		t.Fatalf("overrides = %v", overrides)
	}
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader, Peers: overrides})
	if err != nil {
		t.Fatalf("BuildPlan issuer: %v", err)
	}
	peers, err := topology.Parse(envValue(t, plan, topology.Env))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, peer := range peers {
		if peer.Pair != "holder-inji" {
			continue
		}
		if peer.Home() != "http://holder-inji-wallet-portal:9090" || peer.PublicURL != "https://wallet.example" {
			t.Errorf("holder-inji = %+v", peer)
		}
	}
	// A root with no pair directory gives no override, and a broken
	// .env file reports its path.
	empty, err := ReadPeerOverrides(t.TempDir())
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty root: %v, %v", empty, err)
	}
	bad := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bad, "admin-waltid"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "admin-waltid", EnvFileName), []byte("not a line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPeerOverrides(bad); err == nil || !strings.Contains(err.Error(), "admin-waltid") {
		t.Fatalf("a broken .env must name its pair: %v", err)
	}
}

// TestSetupWritesTheLandingEnv checks that a setup run writes
// deploy/landing/.env beside the pair directories, with every candidate
// pair and the overrides of every pair directory present, the pair of
// the run included (ADR-033 decision 2, ADR-034 decision 1).
func TestSetupWritesTheLandingEnv(t *testing.T) {
	root := t.TempDir()
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	holderPlan, err := BuildPlan(SetupRequest{
		Pair: holder, Random: rand.Reader,
		Flags: map[string]string{"VCA_PUBLIC_URL": "https://wallet.example", "VCA_PORTS_PORTAL": "9090"},
	})
	if err != nil {
		t.Fatalf("BuildPlan holder: %v", err)
	}
	written, err := WritePlan(root, holderPlan)
	if err != nil {
		t.Fatalf("WritePlan holder: %v", err)
	}
	landingPath := filepath.Join(root, LandingDir, EnvFileName)
	found := false
	for _, path := range written {
		if path == landingPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("WritePlan wrote %v, not the landing file %s", written, landingPath)
	}
	overrides, err := ReadPeerOverrides(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := overrides[LandingDir]; ok {
		t.Error("the landing directory is not a pair")
	}
	flags := issuerFlags()
	flags["VCA_PORTS_ADAPTER"] = "9500"
	plan, err := BuildPlan(SetupRequest{
		Pair: issuerPair(), Flags: flags, Random: rand.Reader, Peers: overrides,
		Existing: map[string]string{VersionEnv: "local"},
	})
	if err != nil {
		t.Fatalf("BuildPlan issuer: %v", err)
	}
	if len(plan.Shared) != 3 || plan.Shared[0].Name != filepath.Join(LandingDir, EnvFileName) || plan.Shared[0].Mode != 0o600 {
		t.Fatalf("shared files = %v", sharedNames(plan))
	}
	if !strings.Contains(plan.Summary(), filepath.Join(LandingDir, EnvFileName)) {
		t.Errorf("the summary does not list the landing file:\n%s", plan.Summary())
	}
	if _, writeErr := WritePlan(root, plan); writeErr != nil {
		t.Fatalf("WritePlan issuer: %v", writeErr)
	}
	f, err := os.Open(landingPath) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	values, err := ParseDotenv(f)
	anyval.Discard(f.Close())
	if err != nil {
		t.Fatal(err)
	}
	if values["VCA_LANDING_LISTEN"] != ":8080" || values["VCA_LANDING_PUBLIC_URL"] != "http://localhost:17900" || values[VersionEnv] != "local" {
		t.Errorf("landing values = %v", values)
	}
	peers, err := topology.Parse(values[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != len(AllPairs()) {
		t.Fatalf("got %d peers, want %d", len(peers), len(AllPairs()))
	}
	byName := map[string]topology.Peer{}
	for _, peer := range peers {
		byName[peer.Pair] = peer
	}
	// The holder directory and the issuer of this run both count.
	if byName["holder-inji"].Home() != "http://holder-inji-wallet-portal:9090" || byName["holder-inji"].PublicURL != "https://wallet.example" {
		t.Errorf("holder-inji = %+v", byName["holder-inji"])
	}
	if byName["issuer-waltid"].Adapter() != "http://issuer-waltid-dpg-adapter-waltid:9500" || byName["issuer-waltid"].PublicURL != "https://issuer.example" {
		t.Errorf("issuer-waltid = %+v", byName["issuer-waltid"])
	}
	info, err := os.Stat(landingPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("landing file mode = %v, %v", info.Mode(), err)
	}

	// A domain setup names the landing host.
	delete(flags, "VCA_PUBLIC_URL")
	plan, err = BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader, Domain: "labs.example"})
	if err != nil {
		t.Fatalf("BuildPlan domain: %v", err)
	}
	shared, err := ParseDotenv(strings.NewReader(string(plan.Shared[0].Data)))
	if err != nil {
		t.Fatal(err)
	}
	if shared["VCA_LANDING_PUBLIC_URL"] != "https://vca.labs.example" || shared[VersionEnv] != "latest" {
		t.Errorf("domain landing values = %v", shared)
	}
	// A shared file under a directory that cannot be made reports it.
	if err := os.WriteFile(filepath.Join(root, "blocked"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePlan(filepath.Join(root, "blocked"), plan); err == nil {
		t.Error("a root that is a file passed")
	}
}

// sharedFile returns one shared file of a plan by name.
func sharedFile(t *testing.T, plan Plan, name string) File {
	t.Helper()
	for _, f := range plan.Shared {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("the plan has no shared file %s; it has %v", name, sharedNames(plan))
	return File{}
}

func sharedNames(plan Plan) []string {
	out := make([]string, 0, len(plan.Shared))
	for _, f := range plan.Shared {
		out = append(out, f.Name)
	}
	return out
}

// TestEveryRoleGetsItsOwnRealm is ADR-035 decision 1: the four pairs of
// one stack give four realms, each with self registration on and one
// client with the exact redirect URI and PKCE S256.
func TestEveryRoleGetsItsOwnRealm(t *testing.T) {
	defaultRoles := map[commonv1.Role]string{
		commonv1.Role_ROLE_ISSUER:   "issuer-operator",
		commonv1.Role_ROLE_VERIFIER: "verifier-operator",
		commonv1.Role_ROLE_HOLDER:   "holder",
		commonv1.Role_ROLE_ADMIN:    "",
	}
	seen := map[string]bool{}
	for _, p := range PairsForDpg(configv1.Dpg_DPG_WALTID) {
		public := "https://" + p.Name() + ".example"
		plan, err := BuildPlan(SetupRequest{Pair: p, Random: rand.Reader,
			Flags: map[string]string{"VCA_PUBLIC_URL": public, "VCA_REDIS_URL": "redis://redis:6379"}})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		f := sharedFile(t, plan, RealmFileOf(p))
		if f.Mode != 0o644 {
			t.Errorf("%s: realm mode = %04o", p.Name(), f.Mode)
		}
		seen[f.Name] = true
		var got map[string]any
		if err := json.Unmarshal(f.Data, &got); err != nil {
			t.Fatalf("%s: the realm is not JSON: %v", p.Name(), err)
		}
		if got["realm"] != RealmName(p.Role) || got["realm"] != "vca-"+ShortName(p.Role.String())+"-realm" {
			t.Errorf("%s: realm = %v", p.Name(), got["realm"])
		}
		if got["registrationAllowed"] != true || got["resetPasswordAllowed"] != true {
			t.Errorf("%s: self registration is off: %v", p.Name(), got)
		}
		clients := anyval.As[[]any](got["clients"])
		if len(clients) != 1 {
			t.Fatalf("%s: got %d clients", p.Name(), len(clients))
		}
		client := anyval.As[map[string]any](clients[0])
		if client["clientId"] != DefaultClientID(p.Role) {
			t.Errorf("%s: client id = %v", p.Name(), client["clientId"])
		}
		uris := anyval.As[[]any](client["redirectUris"])
		if len(uris) != 1 || uris[0] != public+"/auth/callback" {
			t.Errorf("%s: redirect URIs = %v", p.Name(), uris)
		}
		attrs := anyval.As[map[string]any](client["attributes"])
		if attrs["pkce.code.challenge.method"] != "S256" {
			t.Errorf("%s: PKCE method = %v", p.Name(), attrs["pkce.code.challenge.method"])
		}
		if client["implicitFlowEnabled"] != false || client["standardFlowEnabled"] != true {
			t.Errorf("%s: flows = %v", p.Name(), client)
		}
		// The default role of a self registered user follows G.2.
		roles := anyval.As[map[string]any](got["roles"])
		var composites []any
		for _, item := range anyval.As[[]any](roles["realm"]) {
			role := anyval.As[map[string]any](item)
			if role["name"] == "default-roles-"+RealmName(p.Role) {
				composites = anyval.As[[]any](anyval.As[map[string]any](role["composites"])["realm"])
			}
		}
		defaultRole := anyval.As[map[string]any](got["defaultRole"])
		if defaultRole["name"] != "default-roles-"+RealmName(p.Role) {
			t.Errorf("%s: defaultRole = %v", p.Name(), got["defaultRole"])
		}
		want := defaultRoles[p.Role]
		switch {
		case want == "" && len(composites) != 0:
			t.Errorf("%s: a self registered user gets %v", p.Name(), composites)
		case want != "" && (len(composites) != 1 || composites[0] != want):
			t.Errorf("%s: default role composites = %v, want %s", p.Name(), composites, want)
		}
	}
	if len(seen) != 4 {
		t.Errorf("the four pairs wrote %d realm files: %v", len(seen), seen)
	}
}

// TestRealmFilesLiveInTheStackDirectory keeps every realm of one stack
// in deploy/keycloak-<dpg>, next to the .env of that Keycloak, so the
// stack file mounts one directory whatever the role.
func TestRealmFilesLiveInTheStackDirectory(t *testing.T) {
	root := t.TempDir()
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	for _, p := range []Pair{issuerPair(), holder} {
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: baseFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		if _, err := WritePlan(root, plan); err != nil {
			t.Fatalf("%s: WritePlan: %v", p.Name(), err)
		}
		if _, err := os.Stat(filepath.Join(OutputDir(root, p), "keycloak")); err == nil {
			t.Errorf("%s: the old realm directory of the pair was written", p.Name())
		}
	}
	dir := filepath.Join(root, KeycloakDir(configv1.Dpg_DPG_WALTID))
	if dir != filepath.Join(root, "keycloak-waltid") {
		t.Errorf("KeycloakDir = %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != ".env,vca-holder-realm.json,vca-issuer-realm.json" {
		t.Errorf("the stack directory holds %v", names)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("stack directory mode = %v, %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Join(dir, "vca-issuer-realm.json")); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("realm mode = %v, %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Join(dir, EnvFileName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("keycloak .env mode = %v, %v", info.Mode(), err)
	}
	// Keycloak parses every JSON file of the directory, so nothing but
	// realms may end in .json there.
	for _, name := range names {
		if strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, "-realm.json") {
			t.Errorf("%s is not a realm file", name)
		}
	}
}

// TestSetupUpgradesTheOldVcaRealmURL repairs a pair that an earlier
// setup pointed at the realm named vca. The role realm replaces it. A
// discovery URL of another provider stays as it is.
func TestSetupUpgradesTheOldVcaRealmURL(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	dir := OutputDir(root, p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	old := "VCA_OIDC_DISCOVERY_URL=http://waltid-keycloak:8080/realms/vca/.well-known/openid-configuration\n"
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := ReadExisting(root, p)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	if values["VCA_OIDC_DISCOVERY_URL"] != DefaultDiscoveryURL(p) {
		t.Errorf("the old realm URL was kept: %q", values["VCA_OIDC_DISCOVERY_URL"])
	}
	if !strings.Contains(DefaultDiscoveryURL(p), "/realms/vca-issuer-realm/") {
		t.Errorf("the default discovery URL names no role realm: %q", DefaultDiscoveryURL(p))
	}
	plan, err := BuildPlan(SetupRequest{Pair: p, Existing: values, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := Values(plan.Resolutions)["VCA_OIDC_DISCOVERY_URL"]; got != DefaultDiscoveryURL(p) {
		t.Errorf("the plan kept the old realm: %q", got)
	}
	custom := "VCA_OIDC_DISCOVERY_URL=https://idp.example/realms/vca/.well-known/openid-configuration\n"
	if writeErr := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(custom), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	values, err = ReadExisting(root, p)
	if err != nil {
		t.Fatalf("ReadExisting: %v", err)
	}
	if values["VCA_OIDC_DISCOVERY_URL"] != "https://idp.example/realms/vca/.well-known/openid-configuration" {
		t.Errorf("another provider was changed: %q", values["VCA_OIDC_DISCOVERY_URL"])
	}
}

// TestKeycloakAdminPasswordIsGenerated is ADR-035 decision 7: the CLI
// writes a generated administrator password per stack, with mode 0600,
// and keeps it on the next run.
func TestKeycloakAdminPasswordIsGenerated(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: baseFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	f := sharedFile(t, plan, KeycloakEnvFile(configv1.Dpg_DPG_WALTID))
	if f.Name != filepath.Join("keycloak-waltid", EnvFileName) || f.Mode != 0o600 {
		t.Errorf("keycloak env = %s mode %04o", f.Name, f.Mode)
	}
	values, err := ParseDotenv(strings.NewReader(string(f.Data)))
	if err != nil {
		t.Fatal(err)
	}
	password := values[KeycloakAdminPasswordEnv]
	if password == "" || password == "admin" || len(password) < 32 {
		t.Errorf("the password is weak: %q", password)
	}
	if values[KeycloakAdminEnv] != "admin" {
		t.Errorf("the administrator name = %q", values[KeycloakAdminEnv])
	}
	if strings.Contains(plan.Summary(), password) {
		t.Error("the summary shows the password")
	}
	if _, writeErr := WritePlan(root, plan); writeErr != nil {
		t.Fatalf("WritePlan: %v", writeErr)
	}
	existing, err := ReadKeycloakEnv(root, configv1.Dpg_DPG_WALTID)
	if err != nil {
		t.Fatalf("ReadKeycloakEnv: %v", err)
	}
	if existing[KeycloakAdminPasswordEnv] != password {
		t.Errorf("the written password differs: %q", existing[KeycloakAdminPasswordEnv])
	}
	// The holder pair of the same stack keeps the password of the stack.
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	again, err := BuildPlan(SetupRequest{Pair: holder, Flags: baseFlags(), Random: rand.Reader, Keycloak: existing})
	if err != nil {
		t.Fatalf("BuildPlan holder: %v", err)
	}
	kept, err := ParseDotenv(strings.NewReader(string(sharedFile(t, again, KeycloakEnvFile(holder.Dpg)).Data)))
	if err != nil {
		t.Fatal(err)
	}
	if kept[KeycloakAdminPasswordEnv] != password {
		t.Errorf("the second run replaced the password")
	}
	// A missing file is not an error, so the first run works.
	none, err := ReadKeycloakEnv(t.TempDir(), configv1.Dpg_DPG_INJI)
	if err != nil || len(none) != 0 {
		t.Errorf("ReadKeycloakEnv of a fresh root = %v, %v", none, err)
	}
}
