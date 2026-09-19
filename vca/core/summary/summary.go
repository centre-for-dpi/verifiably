// SPDX-License-Identifier: Apache-2.0

// Package summary builds the card of one credential (ADR-025 decision 2,
// ADR-026 decision 4). A card carries the type, the issuer, the claims
// the page shows, the validity window, the decoded JSON, and the checks
// of that credential. The results service and the combined service share
// it (ADR-002 decision 7).
//
// The package is pure. It reads the credential and the check results,
// and it returns a new message.
package summary

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

// MaxDisplayFields caps the claims one card shows.
const MaxDisplayFields = 20

// Trust words a card carries.
const (
	// TrustUnknown says that no trust check ran.
	TrustUnknown = "unknown"
	// TrustTrusted says that the issuer is in the trust list.
	TrustTrusted = "trusted"
	// TrustUntrusted says that the issuer is not in the trust list.
	TrustUntrusted = "untrusted"
	// TrustUnavailable says that the trust check did not finish.
	TrustUnavailable = "unavailable"
)

// Options configure Build.
type Options struct {
	// Index selects the checks of this credential by credential index.
	// A negative Index takes every check.
	Index int
	// Role names the part the credential plays in a combined check.
	// Empty leaves the role out.
	Role string
	// FallbackTitle is the card title when the credential carries no
	// type. Empty leaves the title empty.
	FallbackTitle string
}

// Build makes the card of one credential. checks holds the check results
// of the whole evaluation.
func Build(cred *commonv1.Credential, checks []*policyv1.CheckResult, opts Options) *resultsv1.CredentialSummary {
	out := &resultsv1.CredentialSummary{
		Format: cred.GetFormat(),
		Trust:  TrustUnknown,
		Role:   opts.Role,
	}
	parsed, err := vc.Parse(cred.GetPayload())
	if err == nil {
		out.Type = parsed.PrimaryType()
		out.Title = Title(parsed, opts.FallbackTitle)
		out.Issuer = parsed.Issuer
		out.DisplayFields = DisplayFields(parsed)
		out.Validity = Validity(parsed)
		out.DecodedJson = Decoded(parsed)
	}
	for _, c := range checks {
		if opts.Index >= 0 && int(c.GetCredentialIndex()) != opts.Index {
			continue
		}
		out.Checks = append(out.Checks, c)
		if c.GetName() == policy.NameTrustChain {
			out.Trust = TrustWord(c)
			if name := c.GetEvidence()["issuer_name"]; name != "" {
				out.IssuerName = name
			}
		}
	}
	return out
}

// Title returns the card title. It uses the primary type, then fallback.
func Title(c vc.Credential, fallback string) string {
	if t := c.PrimaryType(); t != "" {
		return t
	}
	return fallback
}

// TrustWord maps the trust chain outcome to a plain word.
func TrustWord(c *policyv1.CheckResult) string {
	switch c.GetOutcome() {
	case policyv1.Outcome_OUTCOME_PASS:
		return TrustTrusted
	case policyv1.Outcome_OUTCOME_FAIL:
		return TrustUntrusted
	case policyv1.Outcome_OUTCOME_ERROR:
		return TrustUnavailable
	case policyv1.Outcome_OUTCOME_SKIP, policyv1.Outcome_OUTCOME_UNSPECIFIED:
	}
	return TrustUnknown
}

// DisplayFields returns the claims the card shows, capped in number.
func DisplayFields(c vc.Credential) map[string]string {
	if len(c.Claims) == 0 {
		return nil
	}
	out := make(map[string]string, len(c.Claims))
	for name, value := range c.Claims {
		if len(out) >= MaxDisplayFields {
			break
		}
		out[name] = value
	}
	return out
}

// Validity returns the validity window of a credential.
func Validity(c vc.Credential) *commonv1.ValidityWindow {
	from, until := c.TemporalBounds()
	if from.IsZero() && until.IsZero() {
		return nil
	}
	out := &commonv1.ValidityWindow{}
	if !from.IsZero() {
		out.ValidFrom = timestamppb.New(from)
	}
	if !until.IsZero() {
		out.ValidUntil = timestamppb.New(until)
	}
	return out
}

// Decoded returns the credential as indented JSON for the disclosure.
func Decoded(c vc.Credential) string {
	raw, err := json.MarshalIndent(c.Raw, "", "  ")
	if err != nil {
		return ""
	}
	return string(raw)
}
