// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the Inji DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"time"

	shared "github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix starts every variable name of this service.
const Prefix = "VCA_INJI_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8080"`
	// CertifyURL is the base URL of the Inji Certify issuer.
	CertifyURL string `env:"CERTIFY_URL"`
	// VerifyURL is the base URL of the Inji Verify service.
	VerifyURL string `env:"VERIFY_URL"`
	// PublicURL is the address a wallet reaches this adapter on. The
	// authorization code offer lives under it.
	PublicURL string `env:"PUBLIC_URL"`
	// AuthorizationServer is the issuer URL of the identity provider of
	// the authorization code flow.
	AuthorizationServer string `env:"AUTHORIZATION_SERVER"`
	// OfferIssuer is the credential_issuer value of an authorization
	// code offer. Empty uses CertifyURL.
	OfferIssuer string `env:"OFFER_ISSUER"`
	// MetadataPath is the path of the OID4VCI issuer metadata on Certify.
	MetadataPath string `env:"METADATA_PATH" default:"/v1/certify/issuance/.well-known/openid-credential-issuer"`
	// VerifyClientID is the DID the Inji Verify service presents to a
	// wallet as the client identifier.
	VerifyClientID string `env:"VERIFY_CLIENT_ID"`
	// DpgVersion names the Inji Certify release for the capability
	// answer.
	DpgVersion string `env:"DPG_VERSION" default:"0.14.0"`
	// VerifyVersion names the Inji Verify release of the stack.
	VerifyVersion string `env:"VERIFY_VERSION" default:"0.16.0"`
	// EsignetVersion names the eSignet release of the stack.
	EsignetVersion string `env:"ESIGNET_VERSION" default:"1.5.1"`
	// MockIdentityVersion names the mock identity system release of the
	// stack.
	MockIdentityVersion string `env:"MOCK_IDENTITY_VERSION" default:"0.10.1"`
	// KeycloakVersion names the Keycloak release of the stack.
	KeycloakVersion string `env:"KEYCLOAK_VERSION" default:"25.0"`
	// Timeout bounds one call to Inji.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// Retries is the number of extra attempts after a failed call.
	Retries int `env:"RETRIES" default:"2"`
	// MaxBytes bounds a response body from Inji.
	MaxBytes int64 `env:"MAX_BYTES" default:"8388608"`
	// StoreFile keeps the hosted offers between restarts. Empty keeps
	// them in memory.
	StoreFile string `env:"STORE_FILE"`
	// OfferTTL is the life of a hosted authorization code offer.
	OfferTTL time.Duration `env:"OFFER_TTL" default:"15m"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := shared.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if c.CertifyURL == "" && c.VerifyURL == "" {
		return Config{}, fmt.Errorf("config: set %sCERTIFY_URL or %sVERIFY_URL", Prefix, Prefix)
	}
	if c.Timeout <= 0 {
		return Config{}, fmt.Errorf("config: %sTIMEOUT must be a positive duration", Prefix)
	}
	if c.OfferTTL <= 0 {
		return Config{}, fmt.Errorf("config: %sOFFER_TTL must be a positive duration", Prefix)
	}
	if c.MaxBytes <= 0 {
		return Config{}, fmt.Errorf("config: %sMAX_BYTES must be a positive number", Prefix)
	}
	return c, nil
}

// Versions maps every component of the stack, named as the stack file
// names it without the prefix, onto its pinned version. The capability
// answer reports them (ADR-034 decision 4).
func (c Config) Versions() map[string]string {
	return map[string]string{
		"certify":        c.DpgVersion,
		"esignet":        c.EsignetVersion,
		"mock-identity":  c.MockIdentityVersion,
		"verify-service": c.VerifyVersion,
		"verify-ui":      c.VerifyVersion,
		"keycloak":       c.KeycloakVersion,
	}
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	return shared.Describe(Prefix, &Config{})
}
