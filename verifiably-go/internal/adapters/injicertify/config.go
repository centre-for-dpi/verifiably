// Package injicertify implements backend.Adapter against Inji Certify v0.14.0.
// The package is parameterised by Mode so the same code serves the two cards:
//
//   - ModeAuthCode ("inji_authcode"): uses the primary instance whose /oauth/token
//     is validated against an external identity provider's JWKS. The card
//     generates a credential_offer carrying `authorization_code` grants so the
//     holder's wallet performs the full login flow at the provider before
//     redeeming. No operator-driven token exchange happens from verifiably-go.
//
//   - ModePreAuth ("inji_preauth"): uses an isolated instance whose /oauth/token
//     is signed by its own JWKS — self-contained flow. Verifiably-go calls
//     /v1/certify/pre-authorized-data, gets back an offer URI, and rewrites
//     the internal Docker hostname to the publicly-reachable one the operator
//     actually sees on their host.
package injicertify

import (
	"encoding/json"
	"fmt"
)

// Mode chooses which flow this adapter instance exposes.
type Mode string

const (
	ModeAuthCode Mode = "auth_code"
	ModePreAuth  Mode = "pre_auth"
)

// Config is the per-backend config blob the registry passes in via backends.json.
type Config struct {
	// Mode selects auth_code vs pre_auth (required).
	Mode Mode `json:"mode"`

	// BaseURL is how verifiably-go reaches the instance from its own process.
	// For host-local development: http://localhost:8091 (primary) or
	// http://localhost:8094 (pre-auth).
	BaseURL string `json:"baseUrl"`

	// InternalBaseURL is the hostname the instance advertises in offer URIs —
	// it's usually the Docker service name (http://inji-certify-preauth:8090)
	// because the instance reads domain.url from config at startup. Verifiably-go
	// rewrites this to PublicBaseURL when surfacing offers to the operator.
	// If empty, no rewrite is performed.
	InternalBaseURL string `json:"internalBaseUrl"`

	// PublicBaseURL is the host-reachable URL the operator pastes into their
	// wallet. For host-local dev this matches BaseURL; in a compose-only
	// deployment it can be a LAN IP or a reverse-proxied path.
	PublicBaseURL string `json:"publicBaseUrl"`

	// AuthorizationServer is only used by ModeAuthCode — it's the issuer URL of
	// the external identity provider (e.g. http://172.24.0.1:3005/v1/esignet)
	// that handles the interactive login before the wallet redeems a code.
	AuthorizationServer string `json:"authorizationServer"`

	// OfferIssuerURL is what the adapter writes into `credential_issuer` on the
	// offers it constructs. For ModePreAuth the adapter just echoes what the
	// backend returned; for ModeAuthCode it must match what the wallet will
	// discover via /.well-known/openid-credential-issuer.
	OfferIssuerURL string `json:"offerIssuerUrl"`

	// DB holds optional PostgreSQL connection details used by SaveCustomSchema
	// and DeleteCustomSchema to keep inji-certify's credential_config table in
	// sync with schemas created in verifiably-go. Only meaningful for
	// ModePreAuth; leave empty for ModeAuthCode.
	DB DBConfig `json:"db,omitempty"`
}

// DBConfig holds the optional PostgreSQL connection used to register custom
// credential configurations directly in inji-certify's database.
type DBConfig struct {
	// DSN is a libpq / pgx connection string, e.g.
	// "postgres://postgres:postgres@certify-preauth-postgres:5432/inji_certify?sslmode=disable"
	// When empty, SaveCustomSchema / DeleteCustomSchema are no-ops.
	DSN string `json:"dsn"`

	// DIDUrl is written into credential_config.did_url for newly-registered
	// credential configurations, e.g. "did:web:certify-preauth-nginx".
	DIDUrl string `json:"didUrl"`

	// Scope is the OAuth scope inserted into credential_config.scope.
	// Defaults to "mock_identity_vc_ldp" when empty.
	Scope string `json:"scope,omitempty"`

	// LogoURL is the credential-display logo written into each custom
	// credential_config's display[].logo.url. Inji Certify's display model
	// always serialises a `logo` key (null when unset), and some wallet UIs
	// crash ("undefined is not a function") rendering a credential whose
	// logo is null. Setting a real URL keeps the display logo a non-null
	// object. When empty, db.go falls back to a built-in default.
	LogoURL string `json:"logoUrl,omitempty"`
}

// UnmarshalConfig extracts a Config from a raw json.RawMessage and fills sensible defaults.
func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) == 0 {
		return c, fmt.Errorf("injicertify: empty config")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.Mode != ModeAuthCode && c.Mode != ModePreAuth {
		return c, fmt.Errorf("injicertify: invalid mode %q (want auth_code or pre_auth)", c.Mode)
	}
	if c.BaseURL == "" {
		return c, fmt.Errorf("injicertify: baseUrl is required")
	}
	if c.PublicBaseURL == "" {
		c.PublicBaseURL = c.BaseURL
	}
	return c, nil
}
