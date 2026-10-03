// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the CREDEBL DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
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
	DpgVersion string `env:"DPG_VERSION" default:"v2.2.1-alpha.4, sha256:b687cec51f96"`
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
	// StatusList reports that the platform runs with the status list
	// host of the stack, so an OID4VC offer is revocable and Revoke
	// works (P6-C5b). The stack file runs the host, and vca setup sets
	// it for an issuer pair.
	StatusList bool `env:"STATUS_LIST" default:"false"`
	// StoreFile keeps the verifier id and the tenant of each holder
	// between restarts. Empty keeps them in memory.
	StoreFile string `env:"STORE_FILE"`
	// AgentURL is the admin address of the shared agent of the stack.
	// With AgentAPIKey it turns the holder role on (ADR-062).
	AgentURL string `env:"AGENT_URL"`
	// AgentAPIKey is the API key of the shared agent. vca setup writes
	// it from the stack .env into a holder pair.
	AgentAPIKey string `env:"AGENT_API_KEY" secret:"true"`
	// HolderLabel is the label a holder wallet shows the other party of
	// a DIDComm connection.
	HolderLabel string `env:"HOLDER_LABEL" default:"Wallet"`
	// Peer is the identity of the service on the compose network and the
	// callers of its Connect services, from the VCA_PEER_ variables of its
	// identity file (ADR-075). They carry no service prefix.
	Peer peerauth.Settings
}

// HolderRole reports whether the settings turn the holder role on.
func (c Config) HolderRole() bool { return c.AgentURL != "" && c.AgentAPIKey != "" }

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := shared.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	peer, perr := peerauth.Load(getenv)
	if perr != nil {
		return Config{}, perr
	}
	c.Peer = peer
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
// the tag of the release line v2.2.1 and the digest of that tag, read
// on 2026-09-27 (ADR-066). A test binds the two files.
var Images = map[string]string{
	"schema-file-server":  "latest@sha256:40a071da35ab17530e9fc1b5de88c46b3ae41bcd79c5c5c28661a0195792435a",
	"api-gateway":         "v2.2.1-alpha.4@sha256:b687cec51f96329a0c25515ec35c6207d45d1a125aa976bbe5d84c884b39dc02",
	"user":                "v2.2.1-alpha.4@sha256:3ea3c3d189b5934a0fa32f920a483f25162d0375dd93e7968f29d566e81dd450",
	"utility":             "v2.2.1-alpha.3@sha256:406fa96220fec8e369cbbf38bf1be9b26f2558dd2fd8691c79b64895d02db7b9",
	"connection":          "v2.2.1-alpha.4@sha256:4011bcbc243e5d02252149321e9f69217abd3fb34294fb55952f5b36485afd23",
	"issuance":            "v2.2.1-alpha.4@sha256:5b9b8441321d576311270f742941c8b3e80ccc0f3a4ac2b81f80995d5ed7bcc0",
	"ledger":              "v2.2.1-alpha.4@sha256:5a12ea655b1addf6b638849d8f691371e4934c4b2cab4344cbdcdf33a63acc80",
	"organization":        "v2.2.1-alpha.4@sha256:fccdce10f0fffba7541696b1f85ffe983ff6aaeaf221c249cbc487aa26033163",
	"verification":        "v2.2.1-alpha.4@sha256:42e1e3d0cf7c623ccbdc89a0212b646912ddd373802e6ef9695ec9a46ec5da87",
	"agent-provisioning":  "v2.2.1-alpha.4@sha256:55bf811a27c1771e92b03cbc83f9dff6d9ebe1fcdb9c0c8b37c47c6b68fefde5",
	"agent-service":       "v2.2.1-alpha.4@sha256:2ae284729f95b1eae4ad21032befd0d7af0895cbb1a2059c13e3c12a0c5b9370",
	"cloud-wallet":        "v2.2.1-alpha.4@sha256:6693137f5a158202e921b078af666c0c694c6689eab3167f24c2a02a75830d77",
	"geolocation":         "v2.2.1-alpha.4@sha256:3a8adccec88913da21f31e7fdb44bdac92ecc8f6226594788bd5d877a34c9fb2",
	"notification":        "v2.2.1-alpha.4@sha256:a06257b9ee06e12b1359f771286a869de2d8ebc7db92291b1b274472c81ddb72",
	"webhook":             "v2.2.1-alpha.4@sha256:da45e48fde5fb0856ac88ebc780269f89566cb222acd70427ddef2e299b4d8b2",
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
