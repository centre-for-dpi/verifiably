package federation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func writeFederationJSON(t *testing.T, c Config) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal federation config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "federation.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write federation.json: %v", err)
	}
	return path
}

func sampleConfig() Config {
	return Config{
		Ecosystem: EcosystemInfo{
			Name:             "Test Ecosystem",
			TrustRegistryURL: "https://hub.test/trust-registry",
			HubURL:           "https://hub.test",
		},
		Members: []Member{
			{
				ID:                  "issuer-a",
				Name:                "Issuer A",
				DeploymentURL:       "https://a.test",
				DID:                 "did:web:a.test",
				Roles:               []string{"issuer"},
				VerifierBackendType: "waltid",
				VerifierConfig:      json.RawMessage(`{"baseURL":"https://a.test"}`),
			},
			{
				ID:    "issuer-b",
				Name:  "Issuer B",
				DID:   "did:web:b.test",
				Roles: []string{"issuer"},
				// No VerifierBackendType → should be skipped in ToBackendEntries
			},
		},
	}
}

// ── LoadConfig ────────────────────────────────────────────────────────────────

func TestLoadConfig_Valid(t *testing.T) {
	path := writeFederationJSON(t, sampleConfig())

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Ecosystem.Name != "Test Ecosystem" {
		t.Errorf("Ecosystem.Name = %q", cfg.Ecosystem.Name)
	}
	if len(cfg.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(cfg.Members))
	}
	if cfg.Members[0].ID != "issuer-a" {
		t.Errorf("Member[0].ID = %q", cfg.Members[0].ID)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/federation.json")
	if err == nil {
		t.Fatal("LoadConfig on missing file should return error")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(path, []byte(`{not valid json`), 0o644)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig on invalid JSON should return error")
	}
}

func TestLoadConfig_EmptyMembers(t *testing.T) {
	path := writeFederationJSON(t, Config{
		Ecosystem: EcosystemInfo{Name: "Empty"},
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Members) != 0 {
		t.Errorf("expected 0 members, got %d", len(cfg.Members))
	}
}

// ── ToBackendEntries ──────────────────────────────────────────────────────────

func TestToBackendEntries_SkipsNoVerifierType(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()

	// issuer-a has VerifierBackendType; issuer-b does not → only 1 entry.
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (issuer-b skipped), got %d", len(entries))
	}
	if entries[0].Vendor != "issuer-a" {
		t.Errorf("Vendor = %q, want issuer-a", entries[0].Vendor)
	}
}

func TestToBackendEntries_VendorIsID(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()
	if entries[0].Vendor != "issuer-a" {
		t.Errorf("Vendor should equal Member.ID, got %q", entries[0].Vendor)
	}
}

func TestToBackendEntries_TypeFromMember(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()
	if entries[0].Type != "waltid" {
		t.Errorf("Type = %q, want waltid", entries[0].Type)
	}
}

func TestToBackendEntries_RolesVerifierOnly(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()
	if len(entries[0].Roles) != 1 || entries[0].Roles[0] != "verifier" {
		t.Errorf("Roles = %v, want [verifier]", entries[0].Roles)
	}
}

func TestToBackendEntries_DPGPopulated(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()
	dpg := entries[0].DPG
	if dpg.Vendor != "Issuer A" {
		t.Errorf("DPG.Vendor = %q, want Issuer A", dpg.Vendor)
	}
	if dpg.Tag != "issuer-a" {
		t.Errorf("DPG.Tag = %q, want issuer-a", dpg.Tag)
	}
	if dpg.Tagline != "https://a.test" {
		t.Errorf("DPG.Tagline = %q, want https://a.test", dpg.Tagline)
	}
}

func TestToBackendEntries_ConfigPreserved(t *testing.T) {
	cfg := sampleConfig()
	entries := cfg.ToBackendEntries()
	if string(entries[0].Config) != `{"baseURL":"https://a.test"}` {
		t.Errorf("Config = %s", entries[0].Config)
	}
}

func TestToBackendEntries_AllSkipped(t *testing.T) {
	cfg := Config{
		Members: []Member{
			{ID: "no-verifier-a", DID: "did:web:a.test"},
			{ID: "no-verifier-b", DID: "did:web:b.test"},
		},
	}
	entries := cfg.ToBackendEntries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when all members lack VerifierBackendType, got %d", len(entries))
	}
}
