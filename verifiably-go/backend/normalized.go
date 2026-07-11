package backend

import "time"

// This file defines a format-agnostic, per-credential view of a verified
// presentation. The verifier adapters (inji-verify, walt.id, credebl) collapse
// a verified VP into a single flat DisclosedFields map today, which is lossy:
// per-credential attribution and holder binding are discarded. The delegated-
// access feature needs them, so adapters additionally populate the structures
// below from data they ALREADY parse. These types are deliberately generic (no
// delegation semantics) so the normalization is reusable by any cross-credential
// policy, not just delegation. The delegation interpretation lives in
// internal/delegation, which consumes these types.

// NormalizedCredential is one credential extracted from a host-verified
// presentation, in a format-independent shape. Adapters fill it best-effort:
// Raw is the decoded credential object (a JSON-LD VC object or an SD-JWT payload),
// from which higher-level policy code reads whatever it needs; Claims is the
// stringified view used for display.
type NormalizedCredential struct {
	Types     []string          // VC type(s) (JSON-LD) or the SD-JWT `vct`
	SubjectID string            // credentialSubject.id (JSON-LD) or `sub` (SD-JWT)
	Issuer    string            // issuer DID/URL
	Format    string            // "w3c_vcdm_2", "jwt_vc_json", "vc+sd-jwt", ...
	Claims    map[string]string // disclosed/visible claims, stringified (nested → JSON)
	Raw       map[string]any    // the decoded credential object, for structured reads

	// HostStatus is the host verifier's PER-CREDENTIAL verdict for this credential,
	// when the host returns one (Inji Verify's vcResults[].verificationStatus,
	// "SUCCESS"/"INVALID"). Empty when the host reports only a single VP-level
	// verdict (walt.id/credebl). Surfaced so a combined-presentation result can
	// show each credential's own host outcome — e.g. Inji flags a delegation
	// credential INVALID on its bitstring status while verifiably's own gate
	// clears it.
	HostStatus string
}

// HolderBinding describes the key the presenter proved control of, when the host
// surfaces it. For a JSON-LD VP this is the VP holder DID; for SD-JWT it is the
// thumbprint of the `cnf` key proven via the KB-JWT. Confirmed reflects whether
// the host verifier asserted the binding (we trust that verdict — invariant I3).
type HolderBinding struct {
	ID            string // holder DID, when present
	KeyThumbprint string // JWK thumbprint of the cnf/holder key, when present
	Confirmed     bool   // host asserted holder-binding validity
}

// DelegationResult is the verdict of the delegation evaluator, stored on
// VerificationResult.Delegation. Evaluated is false when the presentation is not
// a delegation presentation (no delegation credential present) — in that case the
// verifier handler leaves the base verdict untouched. When Evaluated is true and
// Authorized is false, the handler downgrades Valid and surfaces Reason.
type DelegationResult struct {
	Evaluated  bool   // a delegation credential was present and assessed
	Authorized bool   // all checks passed
	Reason     string // human-readable explanation (first failure when not Authorized)
	Linkage    bool   // delegation.onBehalfOf matched the identity credential's subject
	Invocation bool   // the presenter is the named delegate (holder binding)
	Capability bool   // controller==issuer, within validity, action permitted
	NotRevoked bool   // neither credential is revoked (status checked)
	Trusted    bool   // the delegation issuer is in the trust registry

	// DelegationIndex / SubjectIndex are the positions in the presentation's
	// Credentials slice of the delegation credential and the identity it is about,
	// as identified by the evaluator (findDelegation / findIdentity). -1 when not
	// resolved. Lets the UI attribute each check (linkage/invocation/capability)
	// to the specific credential card it concerns.
	DelegationIndex int
	SubjectIndex    int
}

// CredCheck is one per-credential policy outcome shown on a credential card in a
// combined-presentation result. Status is "pass", "fail", or "na" (the check
// doesn't apply — e.g. a credential that carries no status reference).
type CredCheck struct {
	Label  string
	Status string
	Note   string
}

// CredentialView is the per-credential card shown for a combined (delegated-pair
// or multi-credential) presentation: the credential's disclosed claims plus the
// checks attributed to it. Built by the handler from a NormalizedCredential + the
// DelegationResult; empty for single-credential verifies (which keep the flat
// result card). Role is "subject", "delegation", or "" (a plain member of a
// multi-credential presentation with no delegation relationship).
type CredentialView struct {
	Title      string
	Role       string
	Issuer     string
	Format     string
	HostStatus string
	Claims     map[string]string
	Checks     []CredCheck
}

// TemporalBounds returns the credential's own validity window, read from Raw in
// a format-agnostic way: W3C VCDM 2.0 validFrom/validUntil, VCDM 1.1
// issuanceDate/expirationDate (RFC3339 strings), SD-JWT/JWT nbf/exp
// (NumericDate seconds), and the SD-JWT flat delegation underscore convention
// valid_from/valid_until (see internal/delegation/build.go). A zero time.Time
// for either bound means it is absent
// (no constraint on that side — a credential with no expiry is valid
// indefinitely). Callers enforce "now within [notBefore, notAfter]".
func (c NormalizedCredential) TemporalBounds() (notBefore, notAfter time.Time) {
	notBefore = firstRawTime(c.Raw, "validFrom", "issuanceDate", "nbf", "valid_from")
	notAfter = firstRawTime(c.Raw, "validUntil", "expirationDate", "exp", "valid_until")
	// W3C/JSON-LD: a valid_from/valid_until expiry-POLICY claim lands inside
	// credentialSubject (only SD-JWT flattens claims to the top level, where the
	// lookups above already find it). Read it from there as a fallback so the
	// opt-in expiry policy is enforced across formats + DPGs. Scoped to the
	// underscore policy keys ONLY — never validUntil/expirationDate — so a
	// subject's own date attribute (e.g. a passport expirationDate claim) is
	// never mistaken for the credential's validity window.
	if notBefore.IsZero() {
		notBefore = subjectTime(c.Raw, "valid_from")
	}
	if notAfter.IsZero() {
		notAfter = subjectTime(c.Raw, "valid_until")
	}
	return
}

// subjectTime reads a temporal key from the credential's credentialSubject
// object (W3C JSON-LD shape), returning the zero time when absent/unparseable.
func subjectTime(raw map[string]any, key string) time.Time {
	cs, ok := raw["credentialSubject"].(map[string]any)
	if !ok {
		return time.Time{}
	}
	return firstRawTime(cs, key)
}

// firstRawTime returns the first of keys present in raw that parses to a time —
// an RFC3339 string (W3C dates) or a positive number of seconds since the epoch
// (JWT NumericDate). Returns the zero time.Time when none is present/parseable.
func firstRawTime(raw map[string]any, keys ...string) time.Time {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if ts, err := time.Parse(time.RFC3339, t); err == nil {
				return ts.UTC()
			}
		case float64:
			// JSON numbers decode to float64; JWT NumericDate is seconds.
			if t > 0 {
				return time.Unix(int64(t), 0).UTC()
			}
		}
	}
	return time.Time{}
}
