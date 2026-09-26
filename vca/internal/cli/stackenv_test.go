// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// stackSecretRe is the form of a generated stack secret: 32 letters and
// digits, so a database URL and a properties file take it as it is.
var stackSecretRe = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)

// TestSetupGeneratesStackSecrets: a setup run of an Inji pair writes
// deploy/inji/.env with every password of the stack file, generated,
// with mode 0600, and a second run of any role of the stack keeps them
// (ADR-055 decision 1).
func TestSetupGeneratesStackSecrets(t *testing.T) {
	root := t.TempDir()
	issuer := injiPair(commonv1.Role_ROLE_ISSUER)
	plan, err := BuildPlan(SetupRequest{Pair: issuer, Flags: baseFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	f := sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_INJI))
	if f.Name != filepath.Join("inji", EnvFileName) || f.Mode != 0o600 {
		t.Errorf("stack env = %s mode %04o", f.Name, f.Mode)
	}
	if ignore := sharedFile(t, plan, filepath.Join("inji", ".gitignore")); string(ignore.Data) != "*\n" {
		t.Errorf("the stack directory is not ignored: %q", ignore.Data)
	}
	values, err := ParseDotenv(strings.NewReader(string(f.Data)))
	if err != nil {
		t.Fatal(err)
	}
	names := stackSecretNames(configv1.Dpg_DPG_INJI)
	want := []string{"INJI_DB_PASSWORD", "INJI_CERTIFY_KEYSTORE_PASSWORD", "INJI_ESIGNET_DB_PASSWORD",
		"INJI_MIMOTO_DB_PASSWORD", "INJI_MIMOTO_KEYSTORE_PASSWORD", "INJI_VERIFY_DB_PASSWORD"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("stack secrets of inji = %v, want %v", names, want)
	}
	seen := map[string]bool{}
	for _, name := range names {
		v := values[name]
		if !stackSecretRe.MatchString(v) {
			t.Errorf("%s = %q, want 32 letters and digits", name, v)
		}
		if seen[v] {
			t.Errorf("%s repeats another secret", name)
		}
		seen[v] = true
		if strings.Contains(plan.Summary(), v) {
			t.Errorf("the summary shows %s", name)
		}
	}
	if len(values) != len(names) {
		t.Errorf("the file holds %d values, want %d", len(values), len(names))
	}
	if !strings.Contains(plan.Summary(), f.Name) {
		t.Errorf("the summary does not list %s:\n%s", f.Name, plan.Summary())
	}
	if _, werr := WritePlan(root, plan); werr != nil {
		t.Fatalf("WritePlan: %v", werr)
	}
	path := filepath.Join(root, f.Name)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("written stack env %v %v", info, err)
	}
	existing, err := ReadStackEnv(root, configv1.Dpg_DPG_INJI)
	if err != nil {
		t.Fatalf("ReadStackEnv: %v", err)
	}
	holder := injiPair(commonv1.Role_ROLE_HOLDER)
	again, err := BuildPlan(SetupRequest{Pair: holder, Flags: baseFlags(), Random: rand.Reader,
		Stacks: map[configv1.Dpg]map[string]string{configv1.Dpg_DPG_INJI: existing}})
	if err != nil {
		t.Fatalf("BuildPlan holder: %v", err)
	}
	kept, err := ParseDotenv(strings.NewReader(string(sharedFile(t, again, StackEnvFile(holder.Dpg)).Data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if kept[name] != values[name] {
			t.Errorf("the second run replaced %s", name)
		}
	}
	// A value the operator put in the file stays too.
	custom := map[string]string{"INJI_DB_PASSWORD": "operator-chosen-value"}
	third, err := BuildPlan(SetupRequest{Pair: holder, Flags: baseFlags(), Random: rand.Reader,
		Stacks: map[configv1.Dpg]map[string]string{configv1.Dpg_DPG_INJI: custom}})
	if err != nil {
		t.Fatalf("BuildPlan custom: %v", err)
	}
	got, err := ParseDotenv(strings.NewReader(string(sharedFile(t, third, StackEnvFile(holder.Dpg)).Data)))
	if err != nil || got["INJI_DB_PASSWORD"] != "operator-chosen-value" || !stackSecretRe.MatchString(got["INJI_VERIFY_DB_PASSWORD"]) {
		t.Errorf("custom values = %v, %v", got, err)
	}
	// A missing file is not an error, so the first run works.
	none, err := ReadStackEnv(t.TempDir(), configv1.Dpg_DPG_WALTID)
	if err != nil || len(none) != 0 {
		t.Errorf("ReadStackEnv of a fresh root = %v, %v", none, err)
	}
}

// TestEveryStackHasItsSecrets: the walt.id and CREDEBL stacks get their
// database password the same way. Every setup run writes the file of
// every stack, because the main compose file includes all three stack
// files and compose checks every required variable of each. The order
// of the setup runs does not matter.
func TestEveryStackHasItsSecrets(t *testing.T) {
	for _, p := range AllPairs() {
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: baseFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		for _, d := range StackDpgs() {
			names := stackSecretNames(d)
			if len(names) == 0 {
				t.Errorf("%s: the stack has no secret", d)
				continue
			}
			f := sharedFile(t, plan, StackEnvFile(d))
			if f.Mode != 0o600 {
				t.Errorf("%s: %s has mode %04o", p.Name(), f.Name, f.Mode)
			}
			for _, name := range names {
				if !strings.Contains(string(f.Data), name+"=") {
					t.Errorf("%s: %s lacks %s", p.Name(), f.Name, name)
				}
			}
		}
	}
	// The run keeps the values of every stack that it finds.
	waltid := map[string]string{"WALTID_DB_PASSWORD": "kept"}
	plan, err := BuildPlan(SetupRequest{Pair: injiPair(commonv1.Role_ROLE_ISSUER), Flags: baseFlags(), Random: rand.Reader,
		Stacks: map[configv1.Dpg]map[string]string{configv1.Dpg_DPG_WALTID: waltid}})
	if err != nil {
		t.Fatal(err)
	}
	if got := sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_WALTID)); !strings.Contains(string(got.Data), "WALTID_DB_PASSWORD=kept") {
		t.Errorf("the walt.id stack lost its password:\n%s", got.Data)
	}
	root := t.TempDir()
	if _, werr := WritePlan(root, plan); werr != nil {
		t.Fatal(werr)
	}
	all, err := ReadStackEnvs(root)
	if err != nil || len(all) != len(StackDpgs()) || all[configv1.Dpg_DPG_WALTID]["WALTID_DB_PASSWORD"] != "kept" {
		t.Errorf("ReadStackEnvs = %v, %v", all, err)
	}
	// A broken file is an error, not a silent new password.
	if err := os.WriteFile(filepath.Join(root, StackEnvFile(configv1.Dpg_DPG_CREDEBL)), []byte("not a line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStackEnvs(root); err == nil {
		t.Error("ReadStackEnvs read a broken file")
	}
	if StackEnvFile(configv1.Dpg_DPG_UNSPECIFIED) != "" || stackSecretNames(configv1.Dpg_DPG_UNSPECIFIED) != nil {
		t.Error("an unknown DPG has a stack file")
	}
	if got := stackSecretNames(configv1.Dpg_DPG_WALTID); len(got) != 1 || got[0] != "WALTID_DB_PASSWORD" {
		t.Errorf("walt.id secrets = %v", got)
	}
	if got := stackSecretNames(configv1.Dpg_DPG_CREDEBL); len(got) != 1 || got[0] != "CREDEBL_DB_PASSWORD" {
		t.Errorf("CREDEBL secrets = %v", got)
	}
}

// TestSetupWritesCertificateSubject: the .env of an Inji issuer or
// holder pair carries the subject of the key manager certificates: the
// public host as the common name, the organisation and the unit the
// operator answered (ADR-055 decision 3).
func TestSetupWritesCertificateSubject(t *testing.T) {
	flags := withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")
	flags["VCA_ORGANISATION_NAME"] = "Ministry of the Interior"
	flags["VCA_ORGANISATION_UNIT"] = "Registry office"
	values := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_ISSUER), Flags: flags})
	if values[KeyCertCNEnv] != "issue.gov.example" || values[KeyCertOEnv] != "Ministry of the Interior" || values[KeyCertOUEnv] != "Registry office" {
		t.Errorf("subject = %q %q %q", values[KeyCertCNEnv], values[KeyCertOEnv], values[KeyCertOUEnv])
	}
	// Without an answer, the organisation is the public host and the
	// unit is the role.
	defaults := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_HOLDER), Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://wallet.gov.example")})
	if defaults[KeyCertCNEnv] != "wallet.gov.example" || defaults[KeyCertOEnv] != "wallet.gov.example" || defaults[KeyCertOUEnv] != "Holder" {
		t.Errorf("default subject = %q %q %q", defaults[KeyCertCNEnv], defaults[KeyCertOEnv], defaults[KeyCertOUEnv])
	}
	local := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_ISSUER)})
	if local[KeyCertCNEnv] != "localhost" || local[KeyCertOEnv] != "localhost" {
		t.Errorf("local subject = %q %q", local[KeyCertCNEnv], local[KeyCertOEnv])
	}
	// A verifier pair runs no key manager, and another stack neither.
	for _, p := range []Pair{injiPair(commonv1.Role_ROLE_VERIFIER), issuerPair()} {
		if v := planEnv(t, SetupRequest{Pair: p, Flags: issuerFlags()}); v[KeyCertCNEnv] != "" {
			t.Errorf("%s writes a certificate subject %q", p.Name(), v[KeyCertCNEnv])
		}
	}
}

// TestOrganisationSettingsArePrompted: an interactive run asks for the
// organisation and the unit of an Inji issuer or holder pair, with the
// public host and the role as defaults.
func TestOrganisationSettingsArePrompted(t *testing.T) {
	inji := Filter(Settings(), commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_INJI)
	for _, path := range []string{"organisation.name", "organisation.unit"} {
		s := find(t, inji, path)
		if !s.Prompt || s.Secret || s.Required {
			t.Errorf("%s: prompt %v secret %v required %v", path, s.Prompt, s.Secret, s.Required)
		}
	}
	waltid := Filter(Settings(), commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	for _, s := range waltid {
		if strings.HasPrefix(s.Path, "organisation.") {
			t.Errorf("a walt.id pair sees %s", s.Path)
		}
	}
	list := resolveWithDefaults(inji, Sources{Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")}, injiPair(commonv1.Role_ROLE_ISSUER), "")
	got := Values(list)
	if got["VCA_ORGANISATION_NAME"] != "issue.gov.example" || got["VCA_ORGANISATION_UNIT"] != "Issuer" {
		t.Errorf("defaults = %q %q", got["VCA_ORGANISATION_NAME"], got["VCA_ORGANISATION_UNIT"])
	}
}
