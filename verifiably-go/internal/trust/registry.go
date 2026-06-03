// Package trust implements a national trust registry: a signed, authoritative
// list of issuer DIDs authorized to issue specific credential types.
//
// The registry exposes a simple interface so the HTTP handler layer is
// independent of the storage backend. The default implementation is
// PostgreSQL-backed with an in-memory fallback for dev/test. A future
// implementation can satisfy the same interface using OpenID Federation
// entity-statement resolution without touching any handler code.
package trust

import (
	"context"
	"errors"
	"time"
)

// ErrUntrusted is returned by IsTrusted when the issuer DID is not in the
// registry for the requested schema. Callers can errors.Is(err, ErrUntrusted)
// to distinguish a deliberate "not authorised" from a lookup failure.
var ErrUntrusted = errors.New("issuer not in trust registry")

// Registry is the trust-registry contract. Implementations must be safe for
// concurrent use.
type Registry interface {
	// IsTrusted returns nil when issuerDID is authorised to issue credentials
	// of type schemaID and the authorisation has not expired. Returns
	// ErrUntrusted when the issuer is absent or expired. Returns another error
	// only on I/O failure.
	IsTrusted(ctx context.Context, issuerDID, schemaID string) error

	// TrustedIssuers returns the full registry snapshot, sorted by DID.
	// Used by the /trust-registry public endpoint and the admin list page.
	TrustedIssuers(ctx context.Context) ([]TrustedIssuer, error)

	// Add creates or replaces a trusted issuer entry.
	Add(ctx context.Context, e TrustedIssuer) error

	// Remove deletes the entry for the given DID. No-op when the DID is
	// not present.
	Remove(ctx context.Context, did string) error
}

// TrustedIssuer is one entry in the trust registry.
type TrustedIssuer struct {
	DID         string   `json:"did"`
	DisplayName string   `json:"display_name"`
	// Schemas lists the credential schema IDs this issuer is authorised to
	// issue. An empty slice means "all schemas" (wildcard — use sparingly).
	Schemas []string `json:"schemas"`

	// ServiceEndpoint is the base URL of the issuer's verifiably-go deployment.
	// Used by the Hub to fetch schemas and check healthz.
	// Example: "https://issuer-a.gov"
	ServiceEndpoint string `json:"service_endpoint,omitempty"`

	// StatusListEndpoints are the public URLs of this issuer's revocation lists.
	// The Hub fetches and caches these for offline verification.
	StatusListEndpoints []string `json:"status_list_endpoints,omitempty"`

	// StatusListPolicy governs Hub behaviour when a status list is unavailable.
	// "fail-closed" (default): treat credential as invalid.
	// "fail-open": treat as valid with a visible warning.
	StatusListPolicy string `json:"status_list_policy,omitempty"`

	// VerifierAPIKey is the Bearer token the Hub uses when calling this
	// member's /api/v1/verify/request endpoint. Optional — leave empty if
	// the member's verify API is open or not yet configured.
	VerifierAPIKey string `json:"verifier_api_key,omitempty"`

	AccreditedAt time.Time `json:"accredited_at"`
	// ValidUntil is the expiry of the accreditation. Zero means no expiry.
	ValidUntil time.Time `json:"valid_until,omitempty"`
}

// IsExpired reports whether the accreditation has passed its ValidUntil date.
// An entry with a zero ValidUntil never expires.
func (e TrustedIssuer) IsExpired() bool {
	return !e.ValidUntil.IsZero() && time.Now().After(e.ValidUntil)
}

// AuthorisesSchema reports whether this entry covers the given schema ID.
// An empty Schemas slice is a wildcard.
func (e TrustedIssuer) AuthorisesSchema(schemaID string) bool {
	if len(e.Schemas) == 0 {
		return true
	}
	for _, s := range e.Schemas {
		if s == schemaID {
			return true
		}
	}
	return false
}
