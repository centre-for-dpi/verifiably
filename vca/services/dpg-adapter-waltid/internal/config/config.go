// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the walt.id DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"time"

	shared "github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix starts every variable name of this service.
const Prefix = "VCA_WALTID_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8080"`
	// IssuerURL is the base URL of the walt.id issuer-api.
	IssuerURL string `env:"ISSUER_URL"`
	// VerifierURL is the base URL of the walt.id verifier-api.
	VerifierURL string `env:"VERIFIER_URL"`
	// WalletURL is the base URL of the walt.id wallet-api.
	WalletURL string `env:"WALLET_URL"`
	// StandardVersion is the OID4VCI draft the issuer serves. walt.id
	// puts it in the metadata path.
	StandardVersion string `env:"STANDARD_VERSION" default:"draft13"`
	// DpgVersion names the walt.id release for the capability answer.
	// The issuer, verifier, and wallet APIs share it.
	DpgVersion string `env:"DPG_VERSION" default:"0.18.2"`
	// KeycloakVersion names the Keycloak release of the stack for the
	// capability answer.
	KeycloakVersion string `env:"KEYCLOAK_VERSION" default:"25.0"`
	// IssuerDid pins the signing DID. Empty onboards a key at first use.
	IssuerDid string `env:"ISSUER_DID"`
	// IssuerKey is the JWK wrapper of the signing key, as JSON. Empty
	// onboards a key at first use.
	IssuerKey string `env:"ISSUER_KEY" secret:"true"`
	// IdentityFile keeps the issuer identity that the identity page makes
	// or imports, with mode 0600 (ADR-046 decision 4). The adapter reads
	// it at start. Empty keeps the identity in memory.
	IdentityFile string `env:"IDENTITY_FILE"`
	// VctBase is the base URL of the vct of a custom SD-JWT credential.
	VctBase string `env:"VCT_BASE"`
	// Timeout bounds one call to walt.id.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// Retries is the number of extra attempts after a failed call.
	Retries int `env:"RETRIES" default:"2"`
	// MaxBytes bounds a response body from walt.id.
	MaxBytes int64 `env:"MAX_BYTES" default:"8388608"`
	// StoreFile keeps the wallet sessions and the registered
	// configurations between restarts. Empty keeps them in memory.
	StoreFile string `env:"STORE_FILE"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := shared.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if c.IssuerURL == "" && c.VerifierURL == "" && c.WalletURL == "" {
		return Config{}, fmt.Errorf("config: set at least one of %sISSUER_URL, %sVERIFIER_URL, or %sWALLET_URL",
			Prefix, Prefix, Prefix)
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
		"issuer-api":   c.DpgVersion,
		"verifier-api": c.DpgVersion,
		"wallet-api":   c.DpgVersion,
		"keycloak":     c.KeycloakVersion,
	}
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	return shared.Describe(Prefix, &Config{})
}
