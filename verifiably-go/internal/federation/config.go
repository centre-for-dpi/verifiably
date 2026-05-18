package federation

import "encoding/json"

// Config is the shape of federation.json — the Hub's ecosystem descriptor.
// DB is master at runtime; this file is the seed on first boot and the export
// format for backup / migration.
type Config struct {
	Ecosystem EcosystemInfo `json:"ecosystem"`
	Members   []Member      `json:"members"`
}

// EcosystemInfo describes the Hub itself.
type EcosystemInfo struct {
	Name              string `json:"name"`
	TrustRegistryURL  string `json:"trustRegistryURL"`
	SchemaRegistryURL string `json:"schemaRegistryURL"`
	HubURL            string `json:"hubURL"`
}

// Member describes one federation participant.
type Member struct {
	// ID is the stable machine identifier used as the vendor key in the Registry.
	// It becomes the OID4VP state prefix ("dpg:<id>:<inner-state>").
	ID            string `json:"id"`
	Name          string `json:"name"`
	DeploymentURL string `json:"deploymentURL"`
	DID           string `json:"did"`
	Roles         []string `json:"roles"`

	// VerifierBackendType selects the adapter used to route OID4VP to this
	// member's verifier endpoint (e.g. "walt_community", "credebl").
	VerifierBackendType string          `json:"verifierBackendType"`
	VerifierConfig      json.RawMessage `json:"verifierConfig"`

	StatusListEndpoints []string `json:"statusListEndpoints"`
	// StatusListPolicy governs what happens when the status list is unavailable.
	// "fail-closed" (default): treat credential as invalid.
	// "fail-open": treat as valid with a visible warning.
	StatusListPolicy string `json:"statusListPolicy"`
}
