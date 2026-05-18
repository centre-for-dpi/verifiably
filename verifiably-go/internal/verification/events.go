// Package verification defines the audit log for every credential verification
// event processed by this deployment. The Hub uses it to power
// GET /api/ecosystem/issuers/{did}/stats (Fase 7) and trust registry health
// dashboards (Fase 9). No PII is stored — privacy by design.
package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Event records one completed verification. Fields are restricted to what
// is needed for ecosystem analytics without identifying individual holders.
// "Completed" means the adapter returned a terminal result (valid or invalid)
// — pending/timeout states are not logged.
type Event struct {
	// ID is a random 24-hex-char identifier, unique per event.
	ID string

	// IssuerDID is the credential issuer's DID as extracted from the VP.
	// Empty when the adapter could not identify the issuer.
	IssuerDID string

	// SchemaID is the schema config-ID used to build the VP request.
	// May be empty for operator verifier flows where the session schema
	// is only tracked by name.
	SchemaID string

	// SchemaName is the human-readable credential type (e.g. "DNI Digital").
	SchemaName string

	// VerifierDPG is the Registry adapter key (vendor name) that handled this
	// verification (e.g. "waltid", "credebl", "issuer-a").
	VerifierDPG string

	// DeploymentID identifies this verifiably-go instance, typically set to
	// VERIFIABLY_PUBLIC_URL so the Hub can correlate events across deployments.
	DeploymentID string

	// Status is "valid" or "invalid".
	Status string

	// TrustStatus is "trusted", "untrusted", "unknown", or "" (not checked).
	TrustStatus string

	// StatusListSrc is "live", "cached", "unknown", or "" (revocation not checked).
	StatusListSrc string

	VerifiedAt time.Time
}

// Log is the persistence contract for verification events.
// Implementations must be safe for concurrent use.
type Log interface {
	// Append persists one completed verification event. Non-blocking callers
	// should run this in a goroutine; any error is logged by the caller.
	Append(ctx context.Context, e Event) error

	// QueryByIssuer returns all events for the given issuer DID within
	// the past `period` duration, ordered newest-first. Used by
	// GET /api/ecosystem/issuers/{did}/stats (Fase 7).
	QueryByIssuer(ctx context.Context, issuerDID string, period time.Duration) ([]Event, error)
}

// NewID generates a cryptographically random 24-hex-char event identifier.
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
