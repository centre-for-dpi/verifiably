package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// This is the end-to-end, in-process proof of the opt-in expiry policy on the
// W3C/JSON-LD path — the one format the temporal gate did NOT enforce before
// (SD-JWT already flattens valid_until to the top level; ERR-3 proved that path
// live). It drives the REAL verify pipeline a presentation hits:
//
//	vp.FromVCObject (Raw = the VC object, credentialSubject nested)
//	  → NormalizedCredential.TemporalBounds (new credentialSubject fallback)
//	    → attachTemporalVerdict (downgrades Valid + appends the reason)
//
// so it proves the derived valid_until claim is actually enforced for a W3C
// credential, not just that TemporalBounds parses a hand-built map.
func TestW3CExpiryEnforcedEndToEnd(t *testing.T) {
	// A W3C VCDM 2.0 VC object shaped exactly as an issued credential carrying
	// an opt-in expiry: the valid_until policy claim lives inside
	// credentialSubject alongside ordinary claims (issuance.go writes every
	// subject field there; the builder's Expiry toggle adds valid_until).
	vc := func(validUntil string) map[string]any {
		return map[string]any{
			"@context": []any{"https://www.w3.org/ns/credentials/v2"},
			"type":     []any{"VerifiableCredential", "AlumniCard"},
			"issuer":   "did:web:verifiably.in-labs.cdpi.dev",
			"credentialSubject": map[string]any{
				"id":          "did:example:holder",
				"givenName":   "Maria",
				"valid_until": validUntil,
			},
		}
	}
	pipeline := func(validUntil string, now time.Time) *backend.VerificationResult {
		cred := vp.FromVCObject(vc(validUntil))
		res := &backend.VerificationResult{Valid: true, Method: "w3c_vcdm_2", Credentials: []backend.NormalizedCredential{cred}}
		attachTemporalVerdict(res, now)
		return res
	}

	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)

	// Expired → DENIED, with an "expired" reason surfaced to the verifier UI.
	expired := pipeline("2020-01-01T00:00:00Z", now)
	if expired.Valid {
		t.Fatal("W3C credential past its credentialSubject.valid_until must be DENIED")
	}
	if !strings.Contains(expired.Method, "expired") {
		t.Errorf("denial reason must mention expiry, got %q", expired.Method)
	}

	// Still-valid (future valid_until) → AUTHORIZED (positive control: the gate
	// isn't just failing everything, and an unexpired expiry claim is honoured).
	live := pipeline("2030-01-01T00:00:00Z", now)
	if !live.Valid {
		t.Fatalf("W3C credential within its validity window must stay valid, got denied: %q", live.Method)
	}

	// No expiry claim at all → AUTHORIZED (off-by-default: a credential that
	// never opted into an expiry is never temporally constrained).
	none := vp.FromVCObject(map[string]any{
		"type":              []any{"VerifiableCredential"},
		"credentialSubject": map[string]any{"id": "did:example:holder", "givenName": "Maria"},
	})
	res := &backend.VerificationResult{Valid: true, Credentials: []backend.NormalizedCredential{none}}
	attachTemporalVerdict(res, now)
	if !res.Valid {
		t.Errorf("credential with no expiry must be unconstrained, got denied: %q", res.Method)
	}
}
