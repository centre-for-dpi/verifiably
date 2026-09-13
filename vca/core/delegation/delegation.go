// SPDX-License-Identifier: Apache-2.0

// Package delegation evaluates delegated access: a presentation that holds
// a subject identity credential and an issuer signed delegation credential.
// It decides whether the presenter may act on behalf of the subject.
//
// The evaluator is a pure rule set over vc.Credential values. It does not
// verify signatures or holder binding. The verifier service does that and
// passes its verdict in. Status and trust lookups are injected functions.
//
// The capability model follows the ZCAP-LD vocabulary for JSON-LD
// (termsOfUse entry of type DelegationCapability) and a flat "delegation"
// claim for SD-JWT. Lifted from the legacy internal/delegation package.
package delegation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// StatusChecker reports whether the credential at ref is revoked.
// A non-nil error means the status is unknown.
type StatusChecker func(ctx context.Context, ref StatusRef) (revoked bool, err error)

// TrustChecker returns nil when issuerDID may issue schemaID.
type TrustChecker func(ctx context.Context, issuerDID, schemaID string) error

// StatusRef points at a status list entry.
type StatusRef struct {
	Type    string // "BitstringStatusListEntry" or "TokenStatusList"
	URI     string
	Index   int64
	Purpose string
	Issuer  string
}

// Capability is the normalised delegated authority.
type Capability struct {
	Controller             string   // root authority, must equal the issuer
	OnBehalfOf             string   // the subject the delegate acts for
	Delegate               string   // the delegate
	AllowedAction          []string // permitted actions, empty means any
	ValidUntil             string   // RFC 3339, empty means no caveat
	AllowFurtherDelegation bool
	HasChain               bool // a parent capability was present
}

// Options configure one evaluation.
type Options struct {
	Now             time.Time // zero means time.Now()
	RequestedAction string    // empty means AllowedAction is not enforced
	Status          StatusChecker
	Trust           TrustChecker
	FailClosed      bool // an unknown status is a deny
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Result is the verdict of Evaluate.
type Result struct {
	Evaluated  bool   // a delegation credential was present
	Authorized bool   // every check passed
	Reason     string // first failure, or "delegation authorised"
	Linkage    bool
	Invocation bool
	Capability bool
	NotRevoked bool
	Trusted    bool // advisory, not a gate
	// DelegationIndex and SubjectIndex are positions in the credential
	// slice, or -1 when not resolved.
	DelegationIndex int
	SubjectIndex    int
}

// Evaluate inspects a verified credential set for a delegated access
// relation. When no delegation credential is present it returns
// Evaluated false and the caller keeps its base verdict.
func Evaluate(ctx context.Context, creds []vc.Credential, holder *vc.HolderBinding, opts Options) Result {
	delegIdx, cap := findDelegation(creds)
	if delegIdx < 0 {
		return Result{DelegationIndex: -1, SubjectIndex: -1}
	}
	deleg := creds[delegIdx]
	res := Result{Evaluated: true, DelegationIndex: delegIdx, SubjectIndex: -1}

	subjIdx, identity, ok := findIdentity(creds, delegIdx, cap.OnBehalfOf)
	if !ok {
		res.Reason = "no subject identity credential was presented alongside the delegation"
		return res
	}
	res.SubjectIndex = subjIdx

	// 1. Linkage: the delegation must name the presented subject.
	if cap.OnBehalfOf == "" || !subjectIdentifies(identity, cap.OnBehalfOf) {
		res.Reason = fmt.Sprintf("linkage failed: delegation onBehalfOf %q matches none of the identity credential's identifiers %v",
			cap.OnBehalfOf, subjectIdentifiers(identity))
		return res
	}
	res.Linkage = true

	// 2. Invocation: the presenter must be the named delegate.
	delegate := deleg.SubjectID
	if delegate == "" {
		delegate = cap.Delegate
	}
	confirmed := holder != nil && holder.Confirmed
	if delegate == "" && !confirmed {
		res.Reason = "delegation credential names no delegate"
		return res
	}
	if confirmed && delegate != "" {
		if hid := holderRef(holder); hid != "" && !sameRef(hid, deleg.SubjectID) && !sameRef(hid, cap.Delegate) {
			res.Reason = fmt.Sprintf("invocation failed: presenter %q is neither the delegation subject nor the named delegate", hid)
			return res
		}
	}
	res.Invocation = true

	// 3. Capability: validity windows, chain, controller, caveat, action.
	if reason := checkCapability(identity, deleg, cap, opts); reason != "" {
		res.Reason = reason
		return res
	}
	res.Capability = true

	// 4. Status: neither credential may be revoked.
	if reason := checkStatus(ctx, []vc.Credential{identity, deleg}, opts); reason != "" {
		res.Reason = reason
		return res
	}
	res.NotRevoked = true

	// 5. Trust is a signal, not a gate.
	if opts.Trust != nil && deleg.Issuer != "" {
		if err := opts.Trust(ctx, deleg.Issuer, deleg.PrimaryType()); err == nil {
			res.Trusted = true
		}
	}

	res.Authorized = true
	res.Reason = "delegation authorised"
	return res
}

func checkCapability(identity, deleg vc.Credential, cap Capability, opts Options) string {
	now := opts.now()
	for _, c := range []vc.Credential{identity, deleg} {
		notBefore, notAfter := c.TemporalBounds()
		if !notBefore.IsZero() && now.Before(notBefore) {
			return fmt.Sprintf("%s is not yet valid (validFrom %s)", c.PrimaryType(), notBefore.UTC().Format(time.RFC3339))
		}
		if !notAfter.IsZero() && now.After(notAfter) {
			return fmt.Sprintf("%s has expired (validUntil %s)", c.PrimaryType(), notAfter.UTC().Format(time.RFC3339))
		}
	}
	if cap.HasChain {
		if !cap.AllowFurtherDelegation {
			return "re-delegation chain present but further delegation is not allowed"
		}
		return "re-delegation chains are not supported"
	}
	if cap.Controller != "" && deleg.Issuer != "" && !sameRef(cap.Controller, deleg.Issuer) {
		return fmt.Sprintf("capability controller %q is not the credential issuer %q", cap.Controller, deleg.Issuer)
	}
	if cap.ValidUntil != "" {
		until, err := parseTime(cap.ValidUntil)
		if err != nil {
			return fmt.Sprintf("capability validUntil %q is not a valid timestamp", cap.ValidUntil)
		}
		if now.After(until) {
			return fmt.Sprintf("delegation expired on %s", cap.ValidUntil)
		}
	}
	if opts.RequestedAction != "" && len(cap.AllowedAction) > 0 && !containsFold(cap.AllowedAction, opts.RequestedAction) {
		return fmt.Sprintf("action %q is not permitted by the delegation (allowed: %s)", opts.RequestedAction, strings.Join(cap.AllowedAction, ", "))
	}
	return ""
}

func checkStatus(ctx context.Context, creds []vc.Credential, opts Options) string {
	for _, c := range creds {
		ref, has := StatusRefOf(c)
		if !has {
			continue
		}
		if opts.Status == nil {
			if opts.FailClosed {
				return "revocation status could not be checked (no status checker)"
			}
			continue
		}
		revoked, err := opts.Status(ctx, ref)
		if err != nil {
			if opts.FailClosed {
				return fmt.Sprintf("revocation status unavailable for %s (fail-closed)", ref.URI)
			}
			continue
		}
		if revoked {
			return "a presented credential has been revoked"
		}
	}
	return ""
}
