// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the Inji DPG adapter from the
// environment. It uses the shared services/internal/config loader.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
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
	// SigningDidURL is the issuer DID URL of a configuration the adapter
	// registers. Empty keeps the default of Certify.
	SigningDidURL string `env:"SIGNING_DID_URL"`
	// LdpKeyAppID names the Certify key application of ldp_vc proofs.
	LdpKeyAppID string `env:"LDP_KEY_APP_ID" default:"CERTIFY_VC_SIGN_ED25519"`
	// LdpKeyRefID names the Certify key reference of ldp_vc proofs.
	LdpKeyRefID string `env:"LDP_KEY_REF_ID" default:"ED25519_SIGN"`
	// LdpSignatureAlgo is the signature algorithm of ldp_vc proofs.
	LdpSignatureAlgo string `env:"LDP_SIGNATURE_ALGO" default:"EdDSA"`
	// LdpCryptoSuite is the proof type of ldp_vc credentials.
	LdpCryptoSuite string `env:"LDP_CRYPTO_SUITE" default:"Ed25519Signature2020"`
	// SdJwtKeyAppID names the Certify key application of SD-JWT VCs.
	SdJwtKeyAppID string `env:"SD_JWT_KEY_APP_ID" default:"CERTIFY_VC_SIGN_EC_R1"`
	// SdJwtKeyRefID names the Certify key reference of SD-JWT VCs.
	SdJwtKeyRefID string `env:"SD_JWT_KEY_REF_ID" default:"EC_SECP256R1_SIGN"`
	// SdJwtSignatureAlgo is the signature algorithm of SD-JWT VCs.
	SdJwtSignatureAlgo string `env:"SD_JWT_SIGNATURE_ALGO" default:"ES256"`
	// MdocKeyAppID names the Certify key application of mDocs.
	MdocKeyAppID string `env:"MDOC_KEY_APP_ID" default:"CERTIFY_VC_SIGN_EC_R1"`
	// MdocKeyRefID names the Certify key reference of mDocs.
	MdocKeyRefID string `env:"MDOC_KEY_REF_ID" default:"EC_SECP256R1_SIGN"`
	// MdocSignatureAlgo is the COSE signature algorithm of mDocs.
	MdocSignatureAlgo string `env:"MDOC_SIGNATURE_ALGO" default:"ES256"`
	// RenderingTemplateID names the SVG template of the Certify
	// deployment, as mosip.certify.data-provider-plugin.rendering-template-id
	// sets it. A registered ldp_vc configuration then names it.
	RenderingTemplateID string `env:"RENDERING_TEMPLATE_ID"`
	// CertifyPlugins names the plugins of the Certify deployment, comma
	// separated, as its properties set them. The DPG information lists
	// them. The default is the plugin set of the stack sample.
	CertifyPlugins string `env:"CERTIFY_PLUGINS" default:"MockCSVDataProviderPlugin,LoggerAuditService"`
	// CADomain is the partner domain of an uploaded CA certificate.
	CADomain string `env:"CA_DOMAIN" default:"DEVICE"`
}

// Plugins returns the plugin names of CertifyPlugins.
func (c Config) Plugins() []string {
	var out []string
	for _, p := range strings.Split(c.CertifyPlugins, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// Profiles returns the Certify keys that a registered configuration
// names. The stack keeps the keys (ADR-001 decision 3).
func (c Config) Profiles() inji.Profiles {
	return inji.Profiles{
		DidURL: c.SigningDidURL,
		Ldp: inji.SigningProfile{AppID: c.LdpKeyAppID, RefID: c.LdpKeyRefID,
			Algorithm: c.LdpSignatureAlgo, CryptoSuite: c.LdpCryptoSuite},
		SdJwt: inji.SigningProfile{AppID: c.SdJwtKeyAppID, RefID: c.SdJwtKeyRefID, Algorithm: c.SdJwtSignatureAlgo},
		Mdoc: inji.SigningProfile{AppID: c.MdocKeyAppID, RefID: c.MdocKeyRefID,
			Algorithm: c.MdocSignatureAlgo, CryptoSuite: c.MdocSignatureAlgo},
	}
}

// Describe lists the variables for the start log and the documentation.
func Describe() ([]shared.Variable, error) {
	return shared.Describe(Prefix, &Config{})
}
