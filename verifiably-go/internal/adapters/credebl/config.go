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
	"os"
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

	// PollTimeout is how long FetchPresentationResult waits for the holder
	// to submit a presentation before returning Pending. Parsed from the
	// JSON field "pollTimeoutSeconds" (integer). Defaults to 120 s.
	PollTimeoutSeconds int `json:"pollTimeoutSeconds"`

	// InternalBaseURL / PublicBaseURL handle offer URI rewriting.
	// CREDEBL's Credo controller may embed its internal Docker hostname
	// inside offer URIs; verifiably-go rewrites those to PublicBaseURL so
	// the holder's wallet can dereference them. Leave empty to skip.
	InternalBaseURL string `json:"internalBaseUrl"`
	PublicBaseURL   string `json:"publicBaseUrl"`
}

// UnmarshalConfig extracts and validates a Config from a raw JSON blob.
// Sensitive fields (email, password, cryptoPrivateKey, orgId, issuerId,
// verifierId) are overridden by their CREDEBL_* environment variables when
// set, so backends.json can omit secrets entirely.
//
// Env var mapping:
//
//	CREDEBL_EMAIL            → Email
//	CREDEBL_PASSWORD         → Password
//	CREDEBL_CRYPTO_PRIVATE_KEY → CryptoPrivateKey
//	CREDEBL_ORG_ID           → OrgID
//	CREDEBL_ISSUER_ID        → IssuerID
//	CREDEBL_VERIFIER_ID      → VerifierID
//	CREDEBL_API_URL          → BaseURL   (when non-empty, takes priority)
func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) == 0 {
		return c, fmt.Errorf("credebl: empty config")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	// Env vars take priority over JSON so secrets stay out of backends.json.
	if v := os.Getenv("CREDEBL_API_URL"); v != "" {
		c.BaseURL = v
	}
	if v := os.Getenv("CREDEBL_EMAIL"); v != "" {
		c.Email = v
	}
	if v := os.Getenv("CREDEBL_PASSWORD"); v != "" {
		c.Password = v
	}
	if v := os.Getenv("CREDEBL_CRYPTO_PRIVATE_KEY"); v != "" {
		c.CryptoPrivateKey = v
	}
	if v := os.Getenv("CREDEBL_ORG_ID"); v != "" {
		c.OrgID = v
	}
	if v := os.Getenv("CREDEBL_ISSUER_ID"); v != "" {
		c.IssuerID = v
	}
	if v := os.Getenv("CREDEBL_VERIFIER_ID"); v != "" {
		c.VerifierID = v
	}

	if c.BaseURL == "" {
		return c, fmt.Errorf("credebl: baseUrl is required (set baseUrl in backends.json or CREDEBL_API_URL env var)")
	}
	if c.Email == "" {
		return c, fmt.Errorf("credebl: email is required (set email in backends.json or CREDEBL_EMAIL env var)")
	}
	if c.Password == "" {
		return c, fmt.Errorf("credebl: password is required (set password in backends.json or CREDEBL_PASSWORD env var)")
	}
	if c.CryptoPrivateKey == "" {
		return c, fmt.Errorf("credebl: cryptoPrivateKey is required (set cryptoPrivateKey in backends.json or CREDEBL_CRYPTO_PRIVATE_KEY env var)")
	}
	// orgId and issuerId are populated by the deploy-time provisioning flow.
	// They may be empty right after a fresh deploy if provisioning is still
	// running; the adapter will return a clear error at operation time.
	if c.DefaultPIN == "" {
		c.DefaultPIN = "1234"
	}
	if c.PollTimeoutSeconds <= 0 {
		c.PollTimeoutSeconds = 120
	}
	if c.PublicBaseURL == "" {
		c.PublicBaseURL = c.BaseURL
	}
	return c, nil
}
