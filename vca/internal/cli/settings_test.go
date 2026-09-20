// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func find(t *testing.T, list []Setting, path string) Setting {
	t.Helper()
	for _, s := range list {
		if s.Path == path {
			return s
		}
	}
	t.Fatalf("setting %q not found", path)
	return Setting{}
}

func TestSettingsWalksEveryLeaf(t *testing.T) {
	all := Settings()
	if len(all) < 20 {
		t.Fatalf("got %d settings, want at least 20", len(all))
	}
	for _, path := range []string{
		"role", "dpg", "public_url", "database_url",
		"oidc.discovery_url", "oidc.client_secret", "oidc.roles_claim_path",
		"secrets.signing_key", "secrets.session_key", "secrets.bootstrap_token",
		"ports.portal", "ports.auth", "ports.adapter", "ports.services",
		"trust_methods", "dpg_url", "redis_url", "log_level",
	} {
		s := find(t, all, path)
		if s.Env == "" {
			t.Errorf("%s has no env name", path)
		}
		if s.Description == "" {
			t.Errorf("%s has no description", path)
		}
	}
}

// TestDatabaseURLIsOptional keeps the PostgreSQL URL out of the required
// list. No service reads it yet (ADR-002 decision 3).
func TestDatabaseURLIsOptional(t *testing.T) {
	db := find(t, Settings(), "database_url")
	if db.Required {
		t.Error("the database URL is still required")
	}
	if !strings.Contains(db.Description, "No service reads it yet") {
		t.Errorf("description = %q", db.Description)
	}
	if err := Validate(db, ""); err != nil {
		t.Errorf("an empty database URL failed: %v", err)
	}
}

func TestSettingsKinds(t *testing.T) {
	all := Settings()
	cases := map[string]Kind{
		"role":                KindEnum,
		"dpg":                 KindEnum,
		"public_url":          KindString,
		"trust_methods":       KindList,
		"ports.portal":        KindInt,
		"ports.services":      KindPortMap,
		"secrets.session_key": KindSecretRef,
	}
	for path, want := range cases {
		if got := find(t, all, path).Kind; got != want {
			t.Errorf("%s kind = %v, want %v", path, got, want)
		}
	}
}

func TestSettingsEnumChoices(t *testing.T) {
	all := Settings()
	role := find(t, all, "role")
	want := []string{"issuer", "holder", "verifier", "admin"}
	if strings.Join(role.Choices, ",") != strings.Join(want, ",") {
		t.Errorf("role choices = %v, want %v", role.Choices, want)
	}
	dpg := find(t, all, "dpg")
	if strings.Join(dpg.Choices, ",") != "waltid,inji,credebl" {
		t.Errorf("dpg choices = %v", dpg.Choices)
	}
	if find(t, all, "public_url").Choices != nil {
		t.Error("a string setting has choices")
	}
}

func TestSettingsSecretFlag(t *testing.T) {
	all := Settings()
	if !find(t, all, "secrets.session_key").Secret {
		t.Error("session key is not marked secret")
	}
	if find(t, all, "public_url").Secret {
		t.Error("public url is marked secret")
	}
}

func TestSettingsInheritRoles(t *testing.T) {
	all := Settings()
	// secrets.bootstrap_token declares the admin role itself.
	token := find(t, all, "secrets.bootstrap_token")
	if len(token.Roles) != 1 || token.Roles[0] != commonv1.Role_ROLE_ADMIN {
		t.Errorf("bootstrap token roles = %v", token.Roles)
	}
	// secrets.session_key declares none, so every role needs it.
	if len(find(t, all, "secrets.session_key").Roles) != 0 {
		t.Error("session key must apply to every role")
	}
}

func TestAsks(t *testing.T) {
	all := Settings()
	if find(t, all, "role").Asks() {
		t.Error("the CLI must not ask for the role")
	}
	if find(t, all, "dpg").Asks() {
		t.Error("the CLI must not ask for the DPG")
	}
	if find(t, all, "ports.services").Asks() {
		t.Error("the CLI must not ask for the service port map")
	}
	if !find(t, all, "public_url").Asks() {
		t.Error("the CLI must ask for the public URL")
	}
}

func TestFilterHidesOtherRoles(t *testing.T) {
	all := Settings()
	verifier := Filter(all, commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_WALTID)
	for _, s := range verifier {
		if s.Path == "redis_url" || s.Path == "secrets.bootstrap_token" {
			t.Errorf("verifier must not see %s", s.Path)
		}
	}
	admin := Filter(all, commonv1.Role_ROLE_ADMIN, configv1.Dpg_DPG_INJI)
	got := false
	for _, s := range admin {
		if s.Path == "secrets.bootstrap_token" {
			got = true
		}
		if s.Path == "dpg_url" {
			t.Error("admin must not see the DPG URL")
		}
	}
	if !got {
		t.Error("admin must see the bootstrap token")
	}
	holder := Filter(all, commonv1.Role_ROLE_HOLDER, configv1.Dpg_DPG_CREDEBL)
	found := false
	for _, s := range holder {
		if s.Path == "redis_url" {
			found = true
		}
	}
	if !found {
		t.Error("holder must see the Redis URL")
	}
	if len(verifier) >= len(all) {
		t.Error("the filter dropped nothing")
	}
}

func TestFilterKeepsOrder(t *testing.T) {
	all := Settings()
	got := Filter(all, commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	last := -1
	for _, s := range got {
		for i, a := range all {
			if a.Path == s.Path {
				if i <= last {
					t.Fatalf("order broken at %s", s.Path)
				}
				last = i
			}
		}
	}
}

func TestShortName(t *testing.T) {
	cases := map[string]string{
		"ROLE_ISSUER": "issuer", "DPG_WALTID": "waltid", "plain": "plain",
		"DPG_UNSPECIFIED": "unspecified",
	}
	for in, want := range cases {
		if got := ShortName(in); got != want {
			t.Errorf("ShortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, name := range RoleNames() {
		r, err := ParseRole(name)
		if err != nil {
			t.Fatalf("ParseRole(%q): %v", name, err)
		}
		if ShortName(r.String()) != name {
			t.Errorf("round trip broken for %q", name)
		}
	}
	_, err := ParseRole("mayor")
	if err == nil {
		t.Fatal("ParseRole accepted an unknown role")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error does not list the choices: %v", err)
	}
}

func TestParseDpg(t *testing.T) {
	for _, name := range DpgNames() {
		d, err := ParseDpg(name)
		if err != nil {
			t.Fatalf("ParseDpg(%q): %v", name, err)
		}
		if ShortName(d.String()) != name {
			t.Errorf("round trip broken for %q", name)
		}
	}
	if _, err := ParseDpg("nothing"); err == nil {
		t.Fatal("ParseDpg accepted an unknown DPG")
	}
}

func TestPairNameAndAllPairs(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	if p.Name() != "issuer-waltid" {
		t.Errorf("Name = %q", p.Name())
	}
	pairs := AllPairs()
	if len(pairs) != 12 {
		t.Fatalf("got %d pairs, want 12", len(pairs))
	}
	if pairs[0].Name() != "issuer-waltid" || pairs[11].Name() != "admin-credebl" {
		t.Errorf("pair order = %q .. %q", pairs[0].Name(), pairs[11].Name())
	}
	seen := map[string]bool{}
	for _, q := range pairs {
		if seen[q.Name()] {
			t.Fatalf("duplicate pair %s", q.Name())
		}
		seen[q.Name()] = true
	}
}
