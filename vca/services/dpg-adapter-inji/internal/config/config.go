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
	// MimotoURL is the base URL of Mimoto, the backend of Inji Web. It
	// turns on the holder role.
	MimotoURL string `env:"MIMOTO_URL"`
	// MimotoProvider names the token login provider of Mimoto that
	// trusts the ID tokens of the holder login.
	MimotoProvider string `env:"MIMOTO_PROVIDER" default:"google"`
	// WebURL is the public address of Inji Web, where a holder claims a
	// credential into the Mimoto wallet.
	WebURL string `env:"WEB_URL"`
	// MimotoVersion names the Mimoto release of the stack.
	MimotoVersion string `env:"MIMOTO_VERSION" default:"0.21.0"`
	// WebVersion names the Inji Web release of the stack.
	WebVersion string `env:"WEB_VERSION" default:"0.16.0"`
	// PublicURL is the address a wallet reaches this adapter on. The
	// authorization code offer lives under it.
	PublicURL string `env:"PUBLIC_URL"`
	// AuthorizationServer is the issuer URL of the identity provider of
	// the authorization code flow when the holder authorization server
	// is off: a deployment outside the stack file names its own.
	AuthorizationServer string `env:"AUTHORIZATION_SERVER"`
	// AuthzIssuer is the issuer of the holder authorization server of
	// the adapter: its public URL with /authz (ADR-052). Empty turns the
	// server off.
	AuthzIssuer string `env:"AUTHZ_ISSUER"`
	// AuthzAudience is the credential endpoint of the Certify that
	// trusts the server. Empty derives it from OfferIssuer.
	AuthzAudience string `env:"AUTHZ_AUDIENCE"`
	// AuthzKeySecret is the pair session key. It seals the token key of
	// the server in the store.
	AuthzKeySecret string `env:"AUTHZ_KEY_SECRET" secret:"true"`
	// WalletClients lists the wallet clients of the server as a JSON
	// array of objects with client_id, redirect_uris, and an optional
	// public jwk.
	WalletClients string `env:"WALLET_CLIENTS"`
	// HolderOIDCDiscoveryURL, HolderOIDCClientID, HolderOIDCPublicURL and
	// HolderOIDCInternalAuthority seed the holder provider the server
	// signs a holder in at. vca setup names the holder realm of the stack
	// Keycloak. An admin can put another provider in the registry.
	HolderOIDCDiscoveryURL      string `env:"HOLDER_OIDC_DISCOVERY_URL"`
	HolderOIDCClientID          string `env:"HOLDER_OIDC_CLIENT_ID"`
	HolderOIDCPublicURL         string `env:"HOLDER_OIDC_PUBLIC_URL"`
	HolderOIDCInternalAuthority string `env:"HOLDER_OIDC_INTERNAL_AUTHORITY"`
	// HolderOIDCVerifiedClaims lists, comma separated, the ID token
	// claims beyond email, phone_number and sub that the holder provider
	// verifies. A binding rule matches only verified claims (ADR-056
	// decision 2). Name a claim only when the provider proves it, never
	// for a claim the holder picks at registration.
	HolderOIDCVerifiedClaims string `env:"HOLDER_OIDC_VERIFIED_CLAIMS"`
	// AdminJWKSURL is the key set of the admin pair. The admin portal
	// edits the provider registry of the holder authorization server
	// with a session that key set signed, on the compose network. Empty
	// serves no provider RPC.
	AdminJWKSURL string `env:"ADMIN_JWKS_URL"`
	// DataSourceURL is the data source service of the pair. A claim that
	// no offer names finds its subject there. Empty turns such claims
	// off.
	DataSourceURL string `env:"DATA_SOURCE_URL"`
	// OfferIssuer is the credential_issuer value of an authorization
	// code offer through the identity provider: the Certify that takes
	// its tokens. Empty uses CertifyURL. An offer with a presentation
	// during issuance names the Certify of CertifyURL.
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
	// EsignetURL is the eSignet of the stack on the compose network.
	// Setup sets it only when the operator names a real authenticator,
	// and the feature answer lists eSignet only then (ADR-053).
	EsignetURL string `env:"ESIGNET_URL"`
	// HolderEsignetClientID and HolderEsignetClientKey seed the eSignet
	// of the stack as the holder provider of the holder authorization
	// server (ADR-053 decision 4). The key is the base64 text of the DER
	// bytes of the RSA key that signs the client assertion. vca setup
	// sets both only when the pair runs eSignet.
	HolderEsignetClientID  string `env:"HOLDER_ESIGNET_CLIENT_ID"`
	HolderEsignetClientKey string `env:"HOLDER_ESIGNET_CLIENT_KEY" secret:"true"`
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
	// them. The default is the plugin set of the stack file: both Certify
	// containers read the VCA claims store through the Postgres data
	// provider, and log the audit (ADR-051 decision 1).
	CertifyPlugins string `env:"CERTIFY_PLUGINS" default:"PostgresDataProviderPlugin,LoggerAuditService"`
	// ClaimsDir is the directory of the VCA claims store. The stack file
	// mounts it in the adapter and, read only, in the Postgres of
	// Certify, where file_fdw reads every file (ADR-051 decision 2).
	// Empty means no store, so the issuer role stages no subject.
	ClaimsDir string `env:"CLAIMS_DIR"`
	// ClaimsSweep is the interval of the sweep of expired rows.
	ClaimsSweep time.Duration `env:"CLAIMS_SWEEP" default:"1m"`
	// IARIdentityClaims lists the claims of a presented credential that
	// Certify takes as the subject of a presentation during issuance,
	// comma separated. The stack sets the same list in
	// mosip.certify.iar.identity-data.
	IARIdentityClaims string `env:"IAR_IDENTITY_CLAIMS" default:"vcaSubject"`
	// CADomain is the partner domain of an uploaded CA certificate.
	CADomain string `env:"CA_DOMAIN" default:"DEVICE"`
	// PresentationDuringIssuance says that Certify reaches Inji Verify
	// and holds a presentation definition, so its interactive
	// authorization endpoint checks a presentation before it issues.
	PresentationDuringIssuance bool `env:"PRESENTATION_DURING_ISSUANCE" default:"false"`
}

// Audience returns the credential endpoint that the tokens of the
// holder authorization server name.
func (c Config) Audience() string {
	if c.AuthzAudience != "" {
		return c.AuthzAudience
	}
	issuer := c.OfferIssuer
	if issuer == "" {
		issuer = c.CertifyURL
	}
	if issuer == "" {
		return ""
	}
	return strings.TrimRight(issuer, "/") + "/v1/certify/issuance/credential"
}

// Plugins returns the plugin names of CertifyPlugins.
func (c Config) Plugins() []string { return list(c.CertifyPlugins) }

// IdentityClaims returns the claim names of IARIdentityClaims.
func (c Config) IdentityClaims() []string { return list(c.IARIdentityClaims) }

// VerifiedClaims returns the claims the holder provider verifies beyond
// the standard ones.
func (c Config) VerifiedClaims() []string { return list(c.HolderOIDCVerifiedClaims) }

// list splits a comma separated value and drops the empty items.
func list(value string) []string {
	var out []string
	for _, p := range strings.Split(value, ",") {
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
	if c.CertifyURL == "" && c.VerifyURL == "" && c.MimotoURL == "" {
		return Config{}, fmt.Errorf("config: set %sCERTIFY_URL, %sVERIFY_URL or %sMIMOTO_URL", Prefix, Prefix, Prefix)
	}
	if c.Timeout <= 0 {
		return Config{}, fmt.Errorf("config: %sTIMEOUT must be a positive duration", Prefix)
	}
	if c.OfferTTL <= 0 {
		return Config{}, fmt.Errorf("config: %sOFFER_TTL must be a positive duration", Prefix)
	}
	if c.ClaimsSweep <= 0 {
		return Config{}, fmt.Errorf("config: %sCLAIMS_SWEEP must be a positive duration", Prefix)
	}
	if c.MaxBytes <= 0 {
		return Config{}, fmt.Errorf("config: %sMAX_BYTES must be a positive number", Prefix)
	}
	return c, nil
}

// Versions maps every component of the stack onto its pinned version.
// A name is the stack file service without the inji- prefix, except
// inji-web, which keeps its full name. The capability
// answer reports them (ADR-034 decision 4).
func (c Config) Versions() map[string]string {
	return map[string]string{
		"certify":        c.DpgVersion,
		"esignet":        c.EsignetVersion,
		"verify-service": c.VerifyVersion,
		"verify-ui":      c.VerifyVersion,
		"keycloak":       c.KeycloakVersion,
		"mimoto":         c.MimotoVersion,
		"inji-web":       c.WebVersion,
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
