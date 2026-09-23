// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the CREDEBL DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"time"

	shared "github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix starts every variable name of this service.
const Prefix = "VCA_CREDEBL_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8080"`
	// APIURL is the base URL of the CREDEBL api gateway.
	APIURL string `env:"API_URL" required:"true"`
	// Email is the login name of the platform administrator.
	Email string `env:"EMAIL" required:"true"`
	// Password is the login secret of the platform administrator.
	Password string `env:"PASSWORD" required:"true" secret:"true"`
	// CryptoKey is the pass phrase that encrypts the password on the
	// wire.
	CryptoKey string `env:"CRYPTO_KEY" required:"true" secret:"true"`
	// OrgID is the organisation the adapter works in.
	OrgID string `env:"ORG_ID" required:"true"`
	// IssuerID is the OID4VCI issuer of the organisation.
	IssuerID string `env:"ISSUER_ID"`
	// VerifierID is the OID4VP verifier of the organisation. Empty makes
	// the adapter create one at first use.
	VerifierID string `env:"VERIFIER_ID"`
	// VerifierName is the name of the verifier the adapter creates.
	VerifierName string `env:"VERIFIER_NAME" default:"verifiable-credentials-adapters"`
	// PublicURL is the host a wallet reaches the CREDEBL agent on. The
	// adapter rewrites the offer URI onto it.
	PublicURL string `env:"PUBLIC_URL"`
	// InternalURL is the host the CREDEBL agent puts in an offer URI.
	InternalURL string `env:"INTERNAL_URL"`
	// DefaultPin is the transaction code of a pre-authorized offer.
	DefaultPin string `env:"DEFAULT_PIN" secret:"true"`
	// DpgVersion names the CREDEBL release for the capability answer.
	// CREDEBL publishes no version tag, so the default is the image tag
	// the stack file pulls. Set it to the digest a deployment pins.
	DpgVersion string `env:"DPG_VERSION" default:"latest"`
	// KeycloakVersion names the Keycloak release of the stack.
	KeycloakVersion string `env:"KEYCLOAK_VERSION" default:"25.0"`
	// Timeout bounds one call to CREDEBL.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// Retries is the number of extra attempts after a failed call.
	Retries int `env:"RETRIES" default:"2"`
	// MaxBytes bounds a response body from CREDEBL.
	MaxBytes int64 `env:"MAX_BYTES" default:"8388608"`
	// StoreFile keeps the verifier id between restarts. Empty keeps it
	// in memory.
	StoreFile string `env:"STORE_FILE"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := shared.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if c.Timeout <= 0 {
		return Config{}, fmt.Errorf("config: %sTIMEOUT must be a positive duration", Prefix)
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
		"api-gateway":        c.DpgVersion,
		"agent-provisioning": c.DpgVersion,
		"keycloak":           c.KeycloakVersion,
	}
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	return shared.Describe(Prefix, &Config{})
}
