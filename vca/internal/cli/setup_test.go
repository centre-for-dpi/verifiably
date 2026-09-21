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
	if values["VCA_SECRETS_SIGNING_KEY"] != "file:"+SigningKeyFile {
		t.Errorf("the signing key = %q", values["VCA_SECRETS_SIGNING_KEY"])
	}
	names := fileNames(plan)
	for _, want := range []string{EnvFileName, SigningKeyFile, CaddyFile, OnboardFile} {
		if !names[want] {
			t.Errorf("the plan has no %s", want)
		}
	}
	if !names[RealmFile] {
		t.Error("a walt.id pair got no Keycloak realm")
	}
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
	if !fileNames(plan)[RealmFile] {
		t.Error("an Inji pair got no Keycloak realm")
	}
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
	if len(written) != len(plan.Files) {
		t.Errorf("wrote %d files, want %d", len(written), len(plan.Files))
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

func TestWritePlanReportsABadFileName(t *testing.T) {
	root := t.TempDir()
	plan := Plan{Pair: issuerPair(), Files: []File{{Name: "sub/dir/x", Data: []byte("x"), Mode: 0o600}}}
	if _, err := WritePlan(root, plan); err == nil {
		t.Fatal("WritePlan passed a missing subdirectory")
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
	if got["realm"] != DefaultRealm {
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
	if !strings.Contains(got, "issuer.example {") {
		t.Errorf("the host block is missing:\n%s", got)
	}
	// The proxy of the host reaches a service on its host port.
	if !strings.Contains(got, "reverse_proxy 127.0.0.1:18002") {
		t.Errorf("the portal route is missing:\n%s", got)
	}
	if !strings.Contains(got, "handle /schema-registry/* {\n\t\treverse_proxy 127.0.0.1:18006") {
		t.Errorf("a service route is missing:\n%s", got)
	}
	// The portal route comes last, so it catches everything else.
	if strings.LastIndex(got, "handle /") > strings.Index(got, "reverse_proxy 127.0.0.1:18002") {
		t.Error("the portal route is not last")
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
		"VCA_PUBLIC_URL":         "https://issuer.example",
		"VCA_HOST_PORT_ISSUANCE": "28002",
	}
	got := Caddyfile(issuerPair(), values)
	if !strings.Contains(got, "reverse_proxy 127.0.0.1:28002") {
		t.Errorf("the override was lost:\n%s", got)
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
	if _, err := DpgConfigFiles(inji, map[string]string{}, AssignPorts(inji, nil)); err == nil {
		t.Fatal("the Inji pair passed with no public URL")
	}
	admin := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_UNSPECIFIED}
	files, err := DpgConfigFiles(admin, map[string]string{"VCA_PUBLIC_URL": "https://a.example"}, AssignPorts(admin, nil))
	if err != nil {
		t.Fatalf("DpgConfigFiles: %v", err)
	}
	if len(files) != 2 || files[0].Name != CaddyFile || files[1].Name != RealmFile {
		t.Errorf("files = %d entries", len(files))
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
