// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// ADR-054: setup writes the catalogue of the walt.id issuer API and the
// configuration of the walt.id wallet API. No demo type, no demo issuer
// and no key of the release reach a deployment.

func waltidPair(role commonv1.Role) Pair { return Pair{Role: role, Dpg: configv1.Dpg_DPG_WALTID} }

// waltidPlan builds the plan of one walt.id pair with the stack values
// of an earlier run, or none.
func waltidPlan(t *testing.T, role commonv1.Role, stacks map[configv1.Dpg]map[string]string) Plan {
	t.Helper()
	plan, err := BuildPlan(SetupRequest{Pair: waltidPair(role), Flags: baseFlags(), Random: rand.Reader, Stacks: stacks})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return plan
}

// pairFile returns one file of the pair directory with its mode.
func pairFile(t *testing.T, plan Plan, name string) File {
	t.Helper()
	for _, f := range plan.Files {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("%s: the plan writes no %s", plan.Pair.Name(), name)
	return File{}
}

// confValue returns the quoted value of one key of a HOCON file.
func confValue(t *testing.T, text, key string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*"([^"]*)"`).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no %s in:\n%s", key, text)
	}
	return m[1]
}

func TestIssuerCatalogueHasOneEntryPerFormatAndNoDemoType(t *testing.T) {
	plan := waltidPlan(t, commonv1.Role_ROLE_ISSUER, nil)
	f := pairFile(t, plan, WaltidIssuerCatalogueFile)
	text := string(f.Data)
	entry := regexp.MustCompile(`(?m)^\s*"?([A-Za-z0-9_.:+-]+)"?\s*=\s*\{`)
	var ids []string
	for _, m := range entry.FindAllStringSubmatch(text, -1) {
		ids = append(ids, m[1])
	}
	want := []string{"supportedCredentialTypes", "vca_jwt_vc_json", "credential_definition", "vca_ldp_vc",
		"credential_definition", "vca_vc_sd_jwt", "vca_dc_sd_jwt", "vca_mso_mdoc", "proof_types_supported", "cwt"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("catalogue blocks = %v, want %v", ids, want)
	}
	for _, format := range []string{"jwt_vc_json", "ldp_vc", `"vc+sd-jwt"`, `"dc+sd-jwt"`, "mso_mdoc"} {
		if strings.Count(text, "format = "+format+"\n") != 1 {
			t.Errorf("the catalogue has not one entry of the format %s:\n%s", format, text)
		}
	}
	for _, tok := range append([]string{"display", "UniversityDegree", "KiwiAccess", "org.iso.18013.5.1.mDL"}, mockTokens...) {
		if strings.Contains(text, tok) {
			t.Errorf("the catalogue names %q", tok)
		}
	}
	for _, id := range WaltidCatalogueIDs() {
		if !strings.HasPrefix(id, WaltidCataloguePrefix) {
			t.Errorf("the id %s lacks the prefix %s", id, WaltidCataloguePrefix)
		}
	}
	if f.Mode != 0o644 {
		t.Errorf("the catalogue has mode %04o; it holds no key", f.Mode)
	}
	// The other roles of the stack write no walt.id file.
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN} {
		for _, file := range waltidPlan(t, role, nil).Files {
			if strings.HasPrefix(file.Name, WaltidConfigDir+"/") {
				t.Errorf("%s writes %s", role, file.Name)
			}
		}
	}
}

func TestWalletAuthKeysAreGeneratedAndKept(t *testing.T) {
	first := waltidPlan(t, commonv1.Role_ROLE_HOLDER, nil)
	auth := pairFile(t, first, WaltidWalletFile("auth.conf"))
	if auth.Mode != 0o600 {
		t.Errorf("auth.conf has mode %04o", auth.Mode)
	}
	text := string(auth.Data)
	for key, length := range map[string]int{"encryptionKey": 16, "signKey": 16, "tokenKey": 48} {
		if v := confValue(t, text, key); len(v) != length || strings.Contains(v, "<") {
			t.Errorf("%s = %q, want %d generated characters", key, v, length)
		}
	}
	if iss := confValue(t, text, "issTokenClaim"); iss != "http://waltid-wallet-api:7001" {
		t.Errorf("issTokenClaim = %q", iss)
	}
	if life := confValue(t, text, "tokenLifetime"); life != "1" {
		t.Errorf("tokenLifetime = %q, want one day", life)
	}
	// A second run reads the stack .env and writes the same keys.
	root := t.TempDir()
	if _, err := WritePlan(root, first); err != nil {
		t.Fatal(err)
	}
	stacks, err := ReadStackEnvs(root)
	if err != nil {
		t.Fatal(err)
	}
	again := waltidPlan(t, commonv1.Role_ROLE_HOLDER, stacks)
	for _, name := range []string{"auth.conf", "ktor-authnz.conf", "db.conf"} {
		a := pairFile(t, first, WaltidWalletFile(name))
		b := pairFile(t, again, WaltidWalletFile(name))
		if string(a.Data) != string(b.Data) {
			t.Errorf("a second run changed %s", name)
		}
	}
	// Another deployment gets other keys.
	other := waltidPlan(t, commonv1.Role_ROLE_HOLDER, nil)
	if confValue(t, string(pairFile(t, other, WaltidWalletFile("auth.conf")).Data), "tokenKey") == confValue(t, text, "tokenKey") {
		t.Error("two deployments share a wallet token key")
	}
	written, err := os.Stat(filepath.Join(root, first.Pair.Name(), WaltidWalletFile("auth.conf")))
	if err != nil || written.Mode().Perm() != 0o600 {
		t.Errorf("auth.conf on disk: %v, %v", written, err)
	}
}

func TestWalletDefaultsHaveNoDefaultIssuer(t *testing.T) {
	plan := waltidPlan(t, commonv1.Role_ROLE_HOLDER, nil)
	defaults := string(pairFile(t, plan, WaltidWalletFile("registration-defaults.conf")).Data)
	for _, bad := range []string{"defaultIssuerConfig", "walt.id", "portal", "did:web"} {
		if strings.Contains(defaults, bad) {
			t.Errorf("registration-defaults.conf names %q:\n%s", bad, defaults)
		}
	}
	for _, good := range []string{"defaultKeyConfig", "defaultDidConfig"} {
		if !strings.Contains(defaults, good) {
			t.Errorf("registration-defaults.conf lacks %s", good)
		}
	}
	stack := string(sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_WALTID)).Data)
	db := pairFile(t, plan, WaltidWalletFile("db.conf"))
	if db.Mode != 0o600 {
		t.Errorf("db.conf has mode %04o", db.Mode)
	}
	password := confValue(t, string(db.Data), "password")
	if len(password) != stackSecretLength || !strings.Contains(stack, "WALTID_DB_PASSWORD="+password) {
		t.Errorf("db.conf password %q is not the password of the stack .env", password)
	}
	for _, want := range []string{"jdbc:postgresql://waltid-postgres:5432/waltid", "org.postgresql.Driver", "recreateDatabaseOnStart = false"} {
		if !strings.Contains(string(db.Data), want) {
			t.Errorf("db.conf lacks %s", want)
		}
	}
	authnz := pairFile(t, plan, WaltidWalletFile("ktor-authnz.conf"))
	if authnz.Mode != 0o600 {
		t.Errorf("ktor-authnz.conf has mode %04o", authnz.Mode)
	}
	if pepper := confValue(t, string(authnz.Data), "pepper"); len(pepper) != stackSecretLength || pepper == "waltid" {
		t.Errorf("pepper = %q", pepper)
	}
	for _, name := range []string{"auth.conf", "ktor-authnz.conf", "registration-defaults.conf", "db.conf", "_features.conf"} {
		text := string(pairFile(t, plan, WaltidWalletFile(name)).Data)
		for _, tok := range mockTokens {
			if strings.Contains(text, tok) {
				t.Errorf("%s names %q", name, tok)
			}
		}
	}
}

func TestWalletFeaturesDisableDevMode(t *testing.T) {
	plan := waltidPlan(t, commonv1.Role_ROLE_HOLDER, nil)
	text := string(pairFile(t, plan, WaltidWalletFile("_features.conf")).Data)
	enabled := regexp.MustCompile(`(?s)enabledFeatures = \[(.*?)\]`).FindStringSubmatch(text)
	disabled := regexp.MustCompile(`(?s)disabledFeatures = \[(.*?)\]`).FindStringSubmatch(text)
	if enabled == nil || disabled == nil {
		t.Fatalf("_features.conf lacks a list:\n%s", text)
	}
	if strings.Contains(enabled[1], "dev-mode") {
		t.Errorf("dev-mode is enabled:\n%s", text)
	}
	if !strings.Contains(disabled[1], "dev-mode") {
		t.Errorf("dev-mode is not disabled:\n%s", text)
	}
}

func TestWaltidStackMountsTheConfigDirectories(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "waltid.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc composeDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"waltid-issuer-api": "../issuer-waltid/config:/waltid-issuer-api/config:ro",
		"waltid-wallet-api": "../holder-waltid/config:/waltid-wallet-api/config:ro",
	}
	for service, mount := range want {
		s, ok := doc.Services[service]
		if !ok {
			t.Fatalf("no service %s", service)
		}
		if len(s.Volumes) != 1 || s.Volumes[0] != mount {
			t.Errorf("%s mounts %v, want %s", service, s.Volumes, mount)
		}
	}
	if env := doc.Services["waltid-wallet-api"].Environment; len(env) != 0 {
		t.Errorf("the wallet API takes %v from compose; db.conf holds the database", env)
	}
	// The mounted directories are the ones setup writes.
	if want["waltid-issuer-api"] != "../"+waltidPair(commonv1.Role_ROLE_ISSUER).Name()+"/"+WaltidConfigDir+":/waltid-issuer-api/config:ro" {
		t.Error("the issuer mount is not the directory of the issuer pair")
	}
}

// TestUpgradeSecretsRewritesTheWalletDatabaseFile: vca dpg
// upgrade-secrets puts the old password in the walt.id stack .env, and
// the db.conf of the holder pair follows it. A deployment without the
// holder pair gets no such file.
func TestUpgradeSecretsRewritesTheWalletDatabaseFile(t *testing.T) {
	deploy := t.TempDir()
	stack := writeStackEnvAt(t, deploy, configv1.Dpg_DPG_WALTID, secretsTime, nil)
	files, err := WaltidFiles(waltidPair(commonv1.Role_ROLE_HOLDER), stack)
	if err != nil {
		t.Fatal(err)
	}
	holder := filepath.Join(deploy, waltidPair(commonv1.Role_ROLE_HOLDER).Name())
	for _, f := range files {
		path := filepath.Join(holder, f.Name)
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(path, f.Data, f.Mode); wErr != nil {
			t.Fatal(wErr)
		}
	}
	probe := healthyProbe()
	probe.volumes = map[string]time.Time{"vca_waltid-db": secretsTime.Add(-time.Hour)}
	var out strings.Builder
	if _, upErr := UpgradeSecrets(UpgradeOptions{Deploy: deploy, Probe: probe, Random: rand.Reader, Out: &out,
		Dpgs: []configv1.Dpg{configv1.Dpg_DPG_WALTID}}); upErr != nil {
		t.Fatal(upErr)
	}
	db, err := os.ReadFile(filepath.Join(holder, WaltidWalletFile("db.conf"))) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	if got := confValue(t, string(db), "password"); got != "waltid" {
		t.Errorf("db.conf password = %q, want the old password of the volume", got)
	}
	info, err := os.Stat(filepath.Join(holder, WaltidWalletFile("db.conf")))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("db.conf: %v, %v", info, err)
	}
	// Without a holder pair the upgrade writes no wallet file.
	bare := t.TempDir()
	writeStackEnvAt(t, bare, configv1.Dpg_DPG_WALTID, secretsTime, nil)
	if _, err := UpgradeSecrets(UpgradeOptions{Deploy: bare, Probe: probe, Random: rand.Reader, Out: &out,
		Dpgs: []configv1.Dpg{configv1.Dpg_DPG_WALTID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bare, waltidPair(commonv1.Role_ROLE_HOLDER).Name())); !os.IsNotExist(err) {
		t.Errorf("the upgrade made the holder directory: %v", err)
	}
}
