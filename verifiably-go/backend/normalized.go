package backend

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
}
