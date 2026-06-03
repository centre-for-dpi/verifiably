package federation

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/verifiably/verifiably-go/internal/adapters/registry"
	"github.com/verifiably/verifiably-go/vctypes"
)

// LoadConfig reads and parses a federation.json file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("federation: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("federation: parse %s: %w", path, err)
	}
	return &c, nil
}

// ToBackendEntries converts federation members into BackendEntry slices for
// registering verifier adapters with the Registry. Members without a
// VerifierBackendType are skipped — they participate only as issuers and don't
// need an in-process verifier adapter on the Hub.
func (c *Config) ToBackendEntries() []registry.BackendEntry {
	entries := make([]registry.BackendEntry, 0, len(c.Members))
	for _, m := range c.Members {
		if m.VerifierBackendType == "" {
			continue
		}
		entries = append(entries, registry.BackendEntry{
			Vendor: m.ID,
			Type:   m.VerifierBackendType,
			Roles:  []string{"verifier"},
			DPG: vctypes.DPG{
				Vendor:  m.Name,
				Version: "federation-member",
				Tag:     m.ID,
				Tagline: m.DeploymentURL,
			},
			Config: m.VerifierConfig,
		})
	}
	return entries
}
