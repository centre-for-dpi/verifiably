// Package waltid implements backend.Adapter against walt.id Community Stack
// v0.18.2 (issuer-api + verifier-api + wallet-api).
//
// Endpoint mapping is grounded in the v0.18.2 source code (not guessed):
//   - Issuer-api routes: /onboard/issuer, /openid4vc/{jwt|sdjwt|mdoc}/issue,
//     /{standardVersion}/.well-known/openid-credential-issuer.
//   - Verifier-api routes: POST /openid4vc/verify, GET /openid4vc/session/{id}.
//     No direct-credential-verification endpoint exists at v0.18.2 — VerifyDirect
//     returns backend.ErrNotSupported.
//   - Wallet-api routes: /wallet-api/auth/{register,login},
//     /wallet-api/wallet/accounts/wallets,
//     /wallet-api/wallet/{walletId}/exchange/{resolveCredentialOffer,useOfferRequest,usePresentationRequest},
//     /wallet-api/wallet/{walletId}/credentials.
package waltid

import (
	"encoding/json"
	"os"
)

// Config is the per-backend config blob the registry passes in.
// Shape matches the "config" object under a "type":"waltid" backend in
// backends.json. All URLs are required; the credentials block is optional
// (if absent, the adapter registers a fresh demo account on first use).
type Config struct {
	IssuerBaseURL string `json:"issuerBaseUrl"`
	// Issuer2BaseURL points at the walt.id issuer-api2 service, used ONLY for
	// mso_mdoc. Empty disables mdoc issuance with a clear error rather than
	// silently falling back to the legacy issuer-api, which cannot type CBOR
	// and would emit a credential no conformant reader accepts.
	Issuer2BaseURL  string   `json:"issuer2BaseUrl"`
	VerifierBaseURL string   `json:"verifierBaseUrl"`
	WalletBaseURL   string   `json:"walletBaseUrl"`
	StandardVersion string   `json:"standardVersion"` // "draft13" (default) or "draft11"
	DemoAccount     Account  `json:"demoAccount"`
	// IssuerKey / IssuerDID pin a stable onboarding result so every demo run
	// issues from the same DID. Both are optional — when empty, the adapter
	// onboards a new key on first use and caches it in-process. Shape of
	// IssuerKey mirrors /onboard/issuer response (a JWK wrapper).
	IssuerKey json.RawMessage `json:"issuerKey"`
	IssuerDID string          `json:"issuerDid"`
	// CatalogPath points at credential-issuer-metadata.conf as visible from
	// the verifiably-go process — typically a host-mounted bind into the
	// container (e.g. /app/issuer-api-config/credential-issuer-metadata.conf).
	// When empty, custom-schema saves fall back to the in-memory borrow trick
	// so the adapter still works in dev setups that don't mount the file in.
	CatalogPath string `json:"catalogPath"`
	// IssuerServiceName is the Compose service name of the walt.id issuer-api
	// container (default "issuer-api"). The adapter restarts this container
	// after appending to the HOCON catalog so walt.id reloads its
	// credential_configurations_supported map.
	IssuerServiceName string `json:"issuerServiceName"`
	// Issuer2MetadataPath points at issuer-api2's own RUNTIME
	// credential-issuer-metadata.conf as visible from the verifiably-go process
	// (e.g. /app/issuer2-config/credential-issuer-metadata.conf) — never the
	// committed *.baseline.conf beside it, which is only the seed
	// seed_issuer2_configs copies from on first deploy. Editing the baseline
	// would put the operator's display name in git and lose it on the next
	// checkout, which is the bug the split exists to prevent. Unlike
	// CatalogPath this file is never APPENDED to — issuer-api2's configurations
	// are pre-provisioned per ISO docType — it is edited in place so a custom
	// mdoc schema's own name reaches the wallet instead of the raw docType.
	// When empty, mdoc saves skip the edit entirely and the wellknown keeps
	// whatever the mounted file already says, so a deployment that doesn't
	// mount issuer2's config behaves exactly as it did before this existed.
	Issuer2MetadataPath string `json:"issuer2MetadataPath"`
	// Issuer2ServiceName is the Compose service name of the walt.id issuer-api2
	// container (default "issuer-api2"). Restarted after an Issuer2MetadataPath
	// edit so issuer-api2 republishes its wellknown — and only then: mdoc
	// issuance itself runs through this service, so an unchanged file must not
	// cost a restart.
	Issuer2ServiceName string `json:"issuer2ServiceName"`
}

// Account holds credentials for the demo wallet user this adapter logs in as.
type Account struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UnmarshalConfig extracts a Config from a raw json.RawMessage.
//
// CatalogPath and IssuerServiceName fall through to env vars
// (WALTID_CATALOG_PATH, WALTID_ISSUER_SERVICE) when the JSON omits them, so
// deploy.sh can wire the runtime mount path without touching backends.json.
// Empty values mean "feature disabled" — SaveCustomSchema/DeleteCustomSchema
// no-op rather than erroring, which keeps dev setups (no docker socket,
// no mounted catalog) working.
//
// Issuer2MetadataPath / Issuer2ServiceName follow the identical pattern
// (WALTID_ISSUER2_METADATA_PATH, WALTID_ISSUER2_SERVICE). Empty
// Issuer2MetadataPath likewise means "feature disabled": the mdoc display-name
// edit is skipped and the save proceeds.
func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, err
		}
	}
	if c.StandardVersion == "" {
		c.StandardVersion = "draft13"
	}
	if c.CatalogPath == "" {
		c.CatalogPath = os.Getenv("WALTID_CATALOG_PATH")
	}
	if c.IssuerServiceName == "" {
		c.IssuerServiceName = os.Getenv("WALTID_ISSUER_SERVICE")
	}
	if c.Issuer2MetadataPath == "" {
		c.Issuer2MetadataPath = os.Getenv("WALTID_ISSUER2_METADATA_PATH")
	}
	if c.Issuer2ServiceName == "" {
		c.Issuer2ServiceName = os.Getenv("WALTID_ISSUER2_SERVICE")
	}
	return c, nil
}
