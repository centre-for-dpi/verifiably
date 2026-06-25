// Package delegation implements the presentation-side evaluator for delegated
// access: given a host-verified presentation containing a subject identity
// credential plus an issuer-signed delegation credential, it decides whether the
// presenting delegate is authorised to act on behalf of the subject.
//
// It is DPG- and format-agnostic. It runs over the normalized, per-credential
// view of the VP (backend.NormalizedCredential) that the verifier adapters
// populate, and it NEVER re-verifies issuer signatures or holder binding — those
// are the host verifier's job, and we trust that verdict (ADR invariant I3). The
// evaluator owns exactly the four checks no deployed DPG performs: linkage,
// invocation binding, capability/caveats, and uniform revocation status. Status
// and trust lookups are injected as functions so this package stays pure and
// unit-testable, and so it depends on neither the status-list cache nor the trust
// registry directly.
package delegation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
)

// StatusChecker reports whether the credential referenced by ref is revoked.
// It is satisfied by the verifier handler composing the status-list cache with
// the bitstring/token decoders. A non-nil error means the status could not be
// determined; the evaluator treats that as a deny when Options.FailClosed is set.
type StatusChecker func(ctx context.Context, ref StatusRef) (revoked bool, err error)

// TrustChecker returns nil when issuerDID is authorised to issue schemaID. It is
// satisfied directly by trust.Registry.IsTrusted.
type TrustChecker func(ctx context.Context, issuerDID, schemaID string) error

// StatusRef points at a revocation list entry, extracted from a credential's
// `credentialStatus` (JSON-LD BitstringStatusListEntry) or `status.status_list`
// (SD-JWT IETF Token Status List).
type StatusRef struct {
	Type    string // "BitstringStatusListEntry" | "TokenStatusList"
	URI     string // statusListCredential / status_list.uri
	Index   int64  // statusListIndex / status_list.idx
	Purpose string // "revocation" by default
	Issuer  string // issuer DID, for the cache fetch + signature verification
}

// Capability is the normalized delegated authority carried by the delegation
// credential — in JSON-LD via a termsOfUse entry of type DelegationCapability, or
// in SD-JWT via the top-level `delegation` claim. They are normalized to the
// same shape so the decision logic has a single code path (ADR D5).
type Capability struct {
	Controller             string   // root authority; must equal the credential issuer
	OnBehalfOf             string   // the subject the delegate acts for (linkage anchor)
	Delegate               string   // the delegate (should equal the delegation credential subject)
	AllowedAction          []string // permitted actions; empty => unconstrained
	ValidUntil             string   // RFC3339; empty => no caveat (status list governs)
	AllowFurtherDelegation bool
	HasChain               bool // a parent capability / re-delegation chain was present
}

// Options configures one evaluation.
type Options struct {
	// Now is the evaluation time; the zero value means time.Now(). Injected for
	// deterministic tests.
	Now time.Time
	// RequestedAction is the action the verifier is authorising (e.g. "present").
	// Empty => the AllowedAction caveat is not enforced.
	RequestedAction string
	// Status checks revocation. nil => status is not checked (and, when
	// FailClosed, the result is denied for any credential carrying a status ref).
	Status StatusChecker
	// Trust enforces issuer trust. nil => trust is not enforced.
	Trust TrustChecker
	// FailClosed makes an unknown status or trust result a deny rather than a pass.
	// Per ADR Q5/I3 this should be true in production.
	FailClosed bool
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Evaluate inspects a verified credential set for a delegated-access relation.
// When no delegation credential is present it returns {Evaluated:false} and the
// caller leaves the base verdict unchanged. Otherwise it returns a full verdict;
// Authorized is true only when linkage, invocation, capability and status all pass
// (and trust, when enforced).
func Evaluate(ctx context.Context, creds []backend.NormalizedCredential, holder *backend.HolderBinding, opts Options) backend.DelegationResult {
	delegIdx, cap := findDelegation(creds)
	if delegIdx < 0 {
		return backend.DelegationResult{Evaluated: false}
	}
	deleg := creds[delegIdx]
	res := backend.DelegationResult{Evaluated: true}

	// Identity credential = the subject credential the delegation is about.
	// Prefer one whose subject anchor matches onBehalfOf; otherwise the first
	// non-delegation credential.
	identity, okID := findIdentity(creds, delegIdx, cap.OnBehalfOf)
	if !okID {
		res.Reason = "no subject identity credential was presented alongside the delegation"
		return res
	}

	// 1. Linkage — the delegation must be about the presented subject.
	anchor := subjectAnchor(identity)
	if cap.OnBehalfOf == "" || anchor == "" || !sameRef(cap.OnBehalfOf, anchor) {
		res.Reason = fmt.Sprintf("linkage failed: delegation onBehalfOf %q does not match subject %q", cap.OnBehalfOf, anchor)
		return res
	}
	res.Linkage = true

	// 2. Invocation — the presenter must be the named delegate. The credential
	// binds the delegate as its subject; when the host surfaces holder binding,
	// the presenter must match that delegate. We trust the host's signature/
	// holder-binding verdict (I3) and only check identity equality here.
	delegate := cap.Delegate
	if delegate == "" {
		delegate = deleg.SubjectID
	}
	if delegate == "" {
		res.Reason = "delegation credential names no delegate"
		return res
	}
	if cap.Delegate != "" && deleg.SubjectID != "" && !sameRef(cap.Delegate, deleg.SubjectID) {
		res.Reason = fmt.Sprintf("invocation failed: capability delegate %q is not the delegation subject %q", cap.Delegate, deleg.SubjectID)
		return res
	}
	if holder != nil && holder.Confirmed {
		if hid := holderRef(holder); hid != "" && !sameRef(hid, delegate) {
			res.Reason = fmt.Sprintf("invocation failed: presenter %q is not the delegate %q", hid, delegate)
			return res
		}
	}
	res.Invocation = true

	// 3. Capability — root authority, validity window, permitted action, no chain.
	if cap.HasChain && !cap.AllowFurtherDelegation {
		res.Reason = "re-delegation chain present but further delegation is not allowed (v1 rejects chains)"
		return res
	}
	if cap.HasChain {
		res.Reason = "re-delegation chains are not supported in v1"
		return res
	}
	if cap.Controller != "" && deleg.Issuer != "" && !sameRef(cap.Controller, deleg.Issuer) {
		res.Reason = fmt.Sprintf("capability controller %q is not the credential issuer %q", cap.Controller, deleg.Issuer)
		return res
	}
	if cap.ValidUntil != "" {
		until, err := parseTime(cap.ValidUntil)
		if err != nil {
			res.Reason = fmt.Sprintf("capability validUntil %q is not a valid timestamp", cap.ValidUntil)
			return res
		}
		if opts.now().After(until) {
			res.Reason = fmt.Sprintf("delegation expired on %s", cap.ValidUntil)
			return res
		}
	}
	if opts.RequestedAction != "" && len(cap.AllowedAction) > 0 && !containsFold(cap.AllowedAction, opts.RequestedAction) {
		res.Reason = fmt.Sprintf("action %q is not permitted by the delegation (allowed: %s)", opts.RequestedAction, strings.Join(cap.AllowedAction, ", "))
		return res
	}
	res.Capability = true

	// 4. Status — neither credential may be revoked. Checked uniformly across
	// formats. Fail closed on unknown status when configured.
	for _, c := range []backend.NormalizedCredential{identity, deleg} {
		ref, has := statusRef(c)
		if !has {
			continue
		}
		if opts.Status == nil {
			if opts.FailClosed {
				res.Reason = "revocation status could not be checked (no status checker)"
				return res
			}
			continue
		}
		revoked, err := opts.Status(ctx, ref)
		if err != nil {
			if opts.FailClosed {
				res.Reason = fmt.Sprintf("revocation status unavailable for %s (fail-closed)", ref.URI)
				return res
			}
			continue
		}
		if revoked {
			res.Reason = "a presented credential has been revoked"
			return res
		}
	}
	res.NotRevoked = true

	// 5. Trust — the delegation issuer must be authorised (the authority). Trust
	// enforcement is opt-in by configuration: when no checker is wired (no trust
	// registry) it is not enforced, matching the platform's existing advisory
	// posture. Revocation status (step 4) remains the hard fail-closed gate.
	if opts.Trust != nil {
		schema := primaryType(deleg.Types)
		if err := opts.Trust(ctx, deleg.Issuer, schema); err != nil {
			res.Reason = fmt.Sprintf("delegation issuer %q is not trusted: %v", deleg.Issuer, err)
			return res
		}
		res.Trusted = true
	}

	res.Authorized = true
	res.Reason = "delegation authorised"
	return res
}
