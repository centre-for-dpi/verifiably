// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the CREDEBL DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"strings"
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
	// CREDEBL publishes from its main branch, so the default names the
	// day the stack file pinned the images and the digest of the api
	// gateway (open question G.5).
	DpgVersion string `env:"DPG_VERSION" default:"main at 2026-09-26, sha256:c6c203ffe437"`
	// KeycloakVersion names the Keycloak release of the stack.
	KeycloakVersion string `env:"KEYCLOAK_VERSION" default:"25.0"`
	// Timeout bounds one call to CREDEBL.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// Retries is the number of extra attempts after a failed call.
	Retries int `env:"RETRIES" default:"2"`
	// MaxBytes bounds a response body from CREDEBL.
	MaxBytes int64 `env:"MAX_BYTES" default:"8388608"`
	// MailOffers reports that the stack names a mail provider, so the
	// platform mails an out of band offer. vca setup sets it when the
	// stack .env names EMAIL_PROVIDER.
	MailOffers bool `env:"MAIL_OFFERS" default:"false"`
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

// Images maps every platform component, named as the stack file names
// it without the prefix, onto the image reference the stack file pins:
// the release tag of the image and the digest that the tag latest named
// on 2026-09-26. A test binds the two files.
var Images = map[string]string{
	"schema-file-server":  "latest@sha256:40a071da35ab17530e9fc1b5de88c46b3ae41bcd79c5c5c28661a0195792435a",
	"api-gateway":         "v2.1.3-hotfix.2@sha256:c6c203ffe43703ce752cd6590ab197083bfe35f1eabf37a2c962ddbafdfc0754",
	"user":                "v2.1.3-hotfix.2@sha256:8dc477e5b81bf0314098ab4e3f5ec8eaa0d4980b6db3bcef88b4c83d27f1375e",
	"utility":             "v2.1.3-hotfix.2@sha256:686c8be4b8e57cda63db4a1716645f286dd81c63bbb7b8ca57ac026e69b5ba9d",
	"connection":          "v2.1.3-hotfix.2@sha256:257ba499600e46d220a47d28f80c2550b2c06945864b0ad83f5501e1450c9d73",
	"issuance":            "v2.1.3-hotfix.2@sha256:4e446a46f43c264276a9e4930d0102ca85f4c3ccc1b33ab0e49b6b42be58f235",
	"ledger":              "v2.1.3-hotfix.2@sha256:57239ddb28af36ce32eacdc3776eac21e05824368865e320795c658d8471cb63",
	"organization":        "v2.1.3-hotfix.2@sha256:6a556fabc8ce9bee1e533b6912f2a1ef359e7896cf55960ddbfac86183090005",
	"verification":        "v2.1.3-hotfix.2@sha256:59d5e5c8c29edb7d8b0eeefc10a879e4500b4cf8e6b9a50cd9715b498190f0fb",
	"agent-provisioning":  "v2.1.3-hotfix.2@sha256:a9c8b901f5e54e65a5b9bddfe4dc20e664c4b3b3fb271ce3c89d0a73f3363b5f",
	"agent-service":       "v2.1.3-hotfix.2@sha256:800015d810e7d137a02c927913ac7a844a79a12dd13cf50593204db9c3608a1e",
	"cloud-wallet":        "v2.1.3-hotfix.2@sha256:887c1fab2893a272359c3cdfd609c1a95576d4b103554b3b8815ab7c7fb0a19f",
	"geolocation":         "v2.1.3-hotfix.2@sha256:b8a93090aa4e6101309dd3fd6d7619d6bca0a0c502acf25c52d0acc69a5f197d",
	"notification":        "v2.1.3-hotfix.2@sha256:cdd08600990710d8bfa62aebe9528a4bc9cb97572e4d961749aa7efda4884035",
	"webhook":             "v2.1.3-hotfix.2@sha256:1748c4baa54c2671e39051d94ee34a4734ac18e461a2b808d4bbd61b5effafa9",
	"ecosystem":           "v2.2.1-alpha.4@sha256:dee3dbc5ecf82a298ae7c4567737992aed538529da1894cf002480de08c48706",
	"oid4vc-issuance":     "v2.2.1-alpha.4@sha256:3e9eace80d82b37858d0e4861795a29bb5d436fdcd11f8a31e5be8a17433be7c",
	"oid4vc-verification": "v2.2.1-alpha.4@sha256:501b657a5febda58356600d93edd9d009df00de7877c3dbc06292be4a6c3e5e7",
	"x509":                "v2.2.1-alpha.3@sha256:8de7a06b4d53ed392a2201ef0698c353c0f33af26a2fbb3d28d20e70556a4e12",
	"agent":               "v2.2.1-alpha-jsonld-vc.2.1@sha256:f4a0da1ec90ddc0a8c4bb52fa8599926dbb98cc0033ee8e24e174ec91d9bb817",
}

// ShortRef shortens an image reference of the form tag@sha256:digest to
// the tag and the first twelve hex digits of the digest. A reference
// with no digest stays as it is.
func ShortRef(ref string) string {
	tag, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || len(digest) < 12 {
		return ref
	}
	return tag + "@sha256:" + digest[:12]
}

// Versions maps every component of the stack, named as the stack file
// names it without the prefix, onto its pinned version. The capability
// answer reports them (ADR-034 decision 4).
func (c Config) Versions() map[string]string {
	out := make(map[string]string, len(Images)+1)
	for name, ref := range Images {
		out[name] = ShortRef(ref)
	}
	out["keycloak"] = c.KeycloakVersion
	return out
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	return shared.Describe(Prefix, &Config{})
}
