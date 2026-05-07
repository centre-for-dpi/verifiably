package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/internal/auth"
)

// TestApplyEnvOverrides_PerField checks the per-provider scalar override
// path: an operator only needs to set what changed (typically issuer URL +
// client secret) without re-typing the whole provider config.
func TestApplyEnvOverrides_PerField(t *testing.T) {
	t.Setenv("VERIFIABLY_OIDC_KEYCLOAK_ISSUER_URL", "https://idp.example.com/realms/foo")
	t.Setenv("VERIFIABLY_OIDC_KEYCLOAK_CLIENT_SECRET", "hunter2")
	t.Setenv("VERIFIABLY_OIDC_KEYCLOAK_SCOPES", "openid, profile, email, custom_scope")

	in := []auth.ProviderConfig{
		{
			ID:        "keycloak",
			Type:      "oidc",
			IssuerURL: "http://localhost:8180/realms/old",
			ClientID:  "vcplatform",
			Scopes:    []string{"openid"},
		},
	}
	out := applyEnvOverrides(in)
	if out[0].IssuerURL != "https://idp.example.com/realms/foo" {
		t.Errorf("IssuerURL not overridden: %s", out[0].IssuerURL)
	}
	if out[0].ClientSecret != "hunter2" {
		t.Errorf("ClientSecret not overridden: %s", out[0].ClientSecret)
	}
	if !reflect.DeepEqual(out[0].Scopes, []string{"openid", "profile", "email", "custom_scope"}) {
		t.Errorf("Scopes CSV not parsed: %v", out[0].Scopes)
	}
	if out[0].ClientID != "vcplatform" {
		t.Errorf("ClientID should be untouched, got %s", out[0].ClientID)
	}
}

// TestApplyEnvOverrides_HyphenatedID covers the env-name normalisation:
// dashes/dots in the provider ID become underscores in the env var so
// "my-idp" reads VERIFIABLY_OIDC_MY_IDP_ISSUER_URL. Without this, an
// operator would have to know the exact transform up-front.
func TestApplyEnvOverrides_HyphenatedID(t *testing.T) {
	t.Setenv("VERIFIABLY_OIDC_MY_IDP_ISSUER_URL", "https://my-idp.test")
	in := []auth.ProviderConfig{{ID: "my-idp", Type: "oidc"}}
	out := applyEnvOverrides(in)
	if out[0].IssuerURL != "https://my-idp.test" {
		t.Errorf("hyphen→underscore env name not honoured: %s", out[0].IssuerURL)
	}
}

// TestApplyEnvOverrides_NoEnvLeavesConfigsUnchanged guards against an
// empty env clobbering values.
func TestApplyEnvOverrides_NoEnvLeavesConfigsUnchanged(t *testing.T) {
	in := []auth.ProviderConfig{
		{ID: "x", IssuerURL: "https://kept", ClientID: "kept", ClientSecret: "kept"},
	}
	out := applyEnvOverrides(in)
	if !reflect.DeepEqual(out, in) {
		t.Errorf("empty env mutated config: %+v vs %+v", out, in)
	}
}

// TestLoadProviderConfigs_EnvJSONOverridesFile verifies precedence: when
// VERIFIABLY_OIDC_PROVIDERS is set, it wins regardless of what the JSON
// file would have contained. This is the "single-line update to swap the
// whole IdP stack" knob.
func TestLoadProviderConfigs_EnvJSONOverridesFile(t *testing.T) {
	t.Setenv("VERIFIABLY_OIDC_PROVIDERS", `[{"id":"my_custom","type":"oidc","displayName":"My Custom","issuerUrl":"https://custom.example.com","clientId":"foo","clientSecret":"bar"}]`)
	// Point the file lookup at /dev/null so we'd notice if it leaked through.
	t.Setenv("VERIFIABLY_AUTH_PROVIDERS_FILE", "/dev/null")
	cfgs, source := loadProviderConfigs()
	if len(cfgs) != 1 || cfgs[0].ID != "my_custom" {
		t.Fatalf("env JSON did not win, got %+v (source=%s)", cfgs, source)
	}
	if source != "VERIFIABLY_OIDC_PROVIDERS env" {
		t.Errorf("source label should mention env, got %q", source)
	}
}

// TestLoadProviderConfigs_EnvJSONLayersWithFieldOverrides confirms the
// two env-var paths compose: VERIFIABLY_OIDC_PROVIDERS sets the base,
// then per-field overrides patch specific fields without re-declaring
// the whole entry.
func TestLoadProviderConfigs_EnvJSONLayersWithFieldOverrides(t *testing.T) {
	t.Setenv("VERIFIABLY_OIDC_PROVIDERS", `[{"id":"my_idp","type":"oidc","issuerUrl":"https://base","clientId":"base","clientSecret":"base"}]`)
	t.Setenv("VERIFIABLY_OIDC_MY_IDP_CLIENT_SECRET", "rotated")
	cfgs, _ := loadProviderConfigs()
	if cfgs[0].ClientSecret != "rotated" {
		t.Errorf("per-field override should layer on env JSON: %+v", cfgs[0])
	}
	if cfgs[0].IssuerURL != "https://base" {
		t.Errorf("untouched fields should keep env-JSON value: %+v", cfgs[0])
	}
}

// TestMergeProviders_UserWinsOnIDCollision pins the layered-merge
// precedence rule for the system+user file split. A user entry with the
// same id as a system entry replaces the system row in place; user-only
// rows are appended; system row order is preserved across overrides.
func TestMergeProviders_UserWinsOnIDCollision(t *testing.T) {
	system := []auth.ProviderConfig{
		{ID: "keycloak", DisplayName: "Keycloak (system)", Source: auth.SourceSystem},
		{ID: "wso2is", DisplayName: "WSO2IS", Source: auth.SourceSystem},
	}
	user := []auth.ProviderConfig{
		{ID: "keycloak", DisplayName: "Keycloak (user override)", Source: auth.SourceUser},
		{ID: "custom", DisplayName: "Custom IdP", Source: auth.SourceUser},
	}
	merged := mergeProviders(system, user)
	if len(merged) != 3 {
		t.Fatalf("expected 3 entries, got %d (%+v)", len(merged), merged)
	}
	if merged[0].DisplayName != "Keycloak (user override)" || merged[0].Source != auth.SourceUser {
		t.Errorf("user override on keycloak failed: %+v", merged[0])
	}
	if merged[1].ID != "wso2is" || merged[1].Source != auth.SourceSystem {
		t.Errorf("system row order shifted: %+v", merged[1])
	}
	if merged[2].ID != "custom" || merged[2].Source != auth.SourceUser {
		t.Errorf("user-only row missing: %+v", merged[2])
	}
}

// TestReadProvidersFile_StampsSource pins the contract that whatever the
// file contains, the loader stamps Source verbatim from the call site —
// preventing a hand-edited user.json from masquerading as a system entry.
func TestReadProvidersFile_StampsSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "providers.json")
	body := `[{"id":"a","displayName":"A"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readProvidersFile(path, auth.SourceUser)
	if len(got) != 1 || got[0].Source != auth.SourceUser {
		t.Errorf("readProvidersFile didn't stamp source: %+v", got)
	}
}

// TestReadProvidersFile_EmptyAndMissing accepts both as "no providers"
// — empty file is what deploy.sh writes for VERIFIABLY_NO_DEFAULT_IDPS,
// missing file is the natural state before the admin UI has saved
// anything.
func TestReadProvidersFile_EmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-file.json")
	if got := readProvidersFile(missing, auth.SourceSystem); len(got) != 0 {
		t.Errorf("missing file should be empty, got %+v", got)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readProvidersFile(empty, auth.SourceSystem); len(got) != 0 {
		t.Errorf("empty file should be empty, got %+v", got)
	}
}

// TestAuthAdminMode_normalises pins the env-flag parse — operators expect
// uppercase / unset / unknown to all behave sensibly.
func TestAuthAdminMode_normalises(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "rw"}, {"rw", "rw"}, {"RW", "rw"},
		{"ro", "ro"}, {"RO", "ro"},
		{"off", "off"}, {"OFF", "off"},
		{"weird", "rw"}, // unknown values fall back to rw with a log line
	}
	for _, tc := range cases {
		t.Setenv("VERIFIABLY_AUTH_ADMIN", tc.in)
		if got := authAdminMode(); got != tc.want {
			t.Errorf("authAdminMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
