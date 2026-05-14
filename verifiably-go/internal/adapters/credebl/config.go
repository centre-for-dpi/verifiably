// Package credebl implements backend.Adapter against CREDEBL.
// It covers the issuer role (OID4VCI pre-authorized code flow) and the
// verifier role (OID4VP via DCQL). The holder role is not supported —
// CREDEBL has no wallet component; pair with Inji Web or walt.id wallet.
//
// Setup prerequisites (handled by init-credebl.sh in cdpi-poc):
//   - An organisation exists (orgId)
//   - A shared wallet is provisioned with a did:key
//   - An OID4VCI issuer is registered (issuerId)
//   - At least one credential template is defined on that issuer
//
// See cdpi-poc/credebl/docs/api-test-oid4vc.sh for the exact provisioning flow.
package credebl

import (
	"encoding/json"
	"fmt"
)

// Config is the per-backend config blob the registry passes in via backends.json.
type Config struct {
	// BaseURL is how verifiably-go reaches the CREDEBL API gateway.
	// e.g. "http://localhost:5000" or "https://credebl.bootcamp.cdpi.dev"
	BaseURL string `json:"baseUrl"`

	// Email and Password are the CREDEBL platform-admin credentials.
	// Password is stored as plaintext and AES-encrypted on the fly at sign-in
	// to match CREDEBL's CryptoJS-compatible wire format.
	Email    string `json:"email"`
	Password string `json:"password"`

	// CryptoPrivateKey is the CRYPTO_PRIVATE_KEY value from credebl/.env.
	// Used for CryptoJS-compatible AES password encryption.
	CryptoPrivateKey string `json:"cryptoPrivateKey"`

	// OrgID is the pre-provisioned organisation ID.
	OrgID string `json:"orgId"`

	// IssuerID is the OID4VCI issuer DB ID returned by
	// POST /v1/orgs/{orgId}/oid4vc/issuers during setup.
	IssuerID string `json:"issuerId"`

	// VerifierID is the OID4VP verifier DB ID. When empty the adapter
	// auto-provisions a verifier named "verifiably-go" on first use.
	VerifierID string `json:"verifierId"`

	// DefaultPIN is the pre-authorized code flow PIN shown to the holder.
	// Defaults to "1234" when empty.
	DefaultPIN string `json:"defaultPin"`

	// InternalBaseURL / PublicBaseURL handle offer URI rewriting.
	// CREDEBL's Credo controller may embed its internal Docker hostname
	// inside offer URIs; verifiably-go rewrites those to PublicBaseURL so
	// the holder's wallet can dereference them. Leave empty to skip.
	InternalBaseURL string `json:"internalBaseUrl"`
	PublicBaseURL   string `json:"publicBaseUrl"`
}

// UnmarshalConfig extracts and validates a Config from a raw JSON blob.
func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) == 0 {
		return c, fmt.Errorf("credebl: empty config")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.BaseURL == "" {
		return c, fmt.Errorf("credebl: baseUrl is required")
	}
	if c.Email == "" {
		return c, fmt.Errorf("credebl: email is required")
	}
	if c.Password == "" {
		return c, fmt.Errorf("credebl: password is required")
	}
	if c.CryptoPrivateKey == "" {
		return c, fmt.Errorf("credebl: cryptoPrivateKey is required")
	}
	if c.OrgID == "" {
		return c, fmt.Errorf("credebl: orgId is required")
	}
	if c.IssuerID == "" {
		return c, fmt.Errorf("credebl: issuerId is required")
	}
	if c.DefaultPIN == "" {
		c.DefaultPIN = "1234"
	}
	if c.PublicBaseURL == "" {
		c.PublicBaseURL = c.BaseURL
	}
	return c, nil
}
