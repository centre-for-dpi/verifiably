// SPDX-License-Identifier: Apache-2.0

// Package policy holds the verifier presentation checks of ADR-024.
//
// A check is a named function over a normalised presentation and a
// context. It returns one CheckResult per credential, or one result for
// the whole presentation. A check never writes state. Every side effect
// is an injected port on Context: key resolution, status list fetching,
// schema fetching, and the trust list lookup. A test injects a fake port
// and gets a pure function.
//
// The mandatory checks of ADR-024 decision 2 always run. VCA does them
// itself, so a fault in a backend cannot make a bad presentation pass.
//
// Standards covered:
//   - JSON Web Signature (https://www.rfc-editor.org/rfc/rfc7515.html)
//   - SD-JWT key binding (https://www.rfc-editor.org/rfc/rfc9901.html)
//   - Bitstring Status List (https://www.w3.org/TR/vc-bitstring-status-list/)
//   - Token Status List (https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
//   - VC JSON Schema (https://www.w3.org/TR/vc-json-schema/)
package policy

import (
	"context"
	"sort"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// Outcome names the result of one check.
type Outcome string

// The four outcomes of a check.
const (
	// Pass means the check found no problem.
	Pass Outcome = "PASS"
	// Fail means the check found a problem.
	Fail Outcome = "FAIL"
	// Skip means the check does not apply to this presentation.
	Skip Outcome = "SKIP"
	// Error means the check could not run.
	Error Outcome = "ERROR"
)

// WholePresentation is the credential index of a result that covers the
// presentation and not one credential.
const WholePresentation = -1

// DefaultLeeway is the clock skew the temporal checks accept.
const DefaultLeeway = 60 * time.Second

// The names of the checks this package knows.
const (
	NameSignature  = "signature"
	NameKeyBinding = "key_binding"
	NameNotBefore  = "nbf"
	NameExpiry     = "exp"
	NameAudience   = "audience"
	NameNonce      = "nonce"
	NameStatus     = "status"
	NameTrustChain = "trust_chain"
	NameSchema     = "schema"
	// NameDerivedProof is the check that BBS selective disclosure will
	// use (ADR-031 decision 2). It is reserved and returns SKIP.
	NameDerivedProof = "derived_proof"
)

// CheckResult is the outcome of one check (ADR-024 decision 1).
type CheckResult struct {
	// Name is the check name.
	Name string
	// Result is the outcome.
	Result Outcome
	// Detail says why, in Simplified Technical English.
	Detail string
	// Evidence holds what the check looked at, keyed by name. It never
	// holds personal data.
	Evidence map[string]string
	// CredentialIndex is the position of the credential in the
	// presentation. WholePresentation covers every credential.
	CredentialIndex int
}

// Credential is one credential of a presentation.
type Credential struct {
	// Format is the wire format, for example dc+sd-jwt or jwt_vc_json.
	Format vc.Format
	// Token is the compact token. It is empty for a JSON credential.
	Token string
	// VC is the decoded, format independent view.
	VC vc.Credential
}

// Presentation is the input of every check (ADR-023 decision 2).
type Presentation struct {
	// Carrier names how the presentation arrived.
	Carrier string
	// Nonce is the nonce the wallet echoed, for OID4VP.
	Nonce string
	// Audience is the audience the wallet echoed, for OID4VP.
	Audience string
	// Holder is the key the presenter proved control of.
	Holder *vc.HolderBinding
	// Credentials are the credentials the ingestion service split out.
	Credentials []Credential
}

// KeyResolver returns the keys that can verify a token from issuer.
// The service builds it from core/did and from a JWKS endpoint.
type KeyResolver func(ctx context.Context, issuer, kid string) (jose.JWKS, error)

// Fetcher returns the bytes of the document at url. The service wraps a
// cache around it (ADR-024 decision 3).
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Trust is the answer of a trust list lookup.
type Trust struct {
	// Trusted reports whether the issuer is on an enabled trust list.
	Trusted bool
	// DisplayName is the name of the issuer on the list.
	DisplayName string
	// ListURL is the list the answer came from.
	ListURL string
	// Reason says why the issuer is not trusted.
	Reason string
}

// TrustLookup asks the trust registry about one issuer and one
// credential type (ADR-011, ADR-024 decision 4).
type TrustLookup func(ctx context.Context, issuer, credentialType string) (Trust, error)

// Context carries the expectations and the ports of one evaluation.
type Context struct {
	// Now is the time of evaluation. Zero means time.Now.
	Now time.Time
	// Leeway is the clock skew the temporal checks accept.
	// Zero means DefaultLeeway.
	Leeway time.Duration
	// Audience is the audience the verifier expects.
	Audience string
	// Nonce is the nonce the verifier sent.
	Nonce string
	// Params are the parameters of the check that runs now.
	Params map[string]string
	// Keys resolves issuer keys. A nil port makes the signature check
	// report ERROR.
	Keys KeyResolver
	// Status fetches a status list document.
	Status Fetcher
	// Schemas fetches a JSON Schema document.
	Schemas Fetcher
	// Trust looks an issuer up on the trust lists.
	Trust TrustLookup
}

// At returns the time of evaluation.
func (c Context) At() time.Time {
	if c.Now.IsZero() {
		return time.Now()
	}
	return c.Now
}

// Skew returns the clock skew the temporal checks accept.
func (c Context) Skew() time.Duration {
	if c.Leeway <= 0 {
		return DefaultLeeway
	}
	return c.Leeway
}

// Param returns the parameter with name, or fallback when it is empty.
func (c Context) Param(name, fallback string) string {
	if v := c.Params[name]; v != "" {
		return v
	}
	return fallback
}

// Func runs one check over a presentation.
type Func func(ctx context.Context, p Presentation, pc Context) []CheckResult

// Check is one named check with its documentation.
type Check struct {
	// Name is the check name.
	Name string
	// Description is one sentence of help text.
	Description string
	// Mandatory marks a check that always runs (ADR-024 decision 2).
	Mandatory bool
	// Params documents the parameters, keyed by name.
	Params map[string]string
	// Run is the check itself.
	Run Func
}

// Checks returns every check this package knows, in run order. The
// mandatory checks come first.
func Checks() []Check {
	return []Check{
		{
			Name:        NameSignature,
			Description: "Check the issuer signature of every credential.",
			Mandatory:   true,
			Run:         signature,
		},
		{
			Name:        NameKeyBinding,
			Description: "Check the SD-JWT disclosure digests and the key binding JWT.",
			Mandatory:   true,
			Run:         keyBinding,
		},
		{
			Name:        NameNotBefore,
			Description: "Check that the credential is already valid.",
			Mandatory:   true,
			Run:         notBefore,
		},
		{
			Name:        NameExpiry,
			Description: "Check that the credential is not expired.",
			Mandatory:   true,
			Run:         expiry,
		},
		{
			Name:        NameAudience,
			Description: "Check that the presentation names this verifier.",
			Mandatory:   true,
			Run:         audience,
		},
		{
			Name:        NameNonce,
			Description: "Check that the presentation echoes the nonce of the request.",
			Mandatory:   true,
			Run:         nonce,
		},
		{
			Name:        NameStatus,
			Description: "Check the credential against its status list.",
			Params: map[string]string{
				"fail_mode": "open keeps an unreachable list out of the verdict, closed fails the check",
			},
			Run: status,
		},
		{
			Name:        NameTrustChain,
			Description: "Check that every issuer is on an enabled trust list and that the chain links up.",
			Params: map[string]string{
				"require_chain": "true makes a presentation without a chain link fail",
			},
			Run: trustChain,
		},
		{
			Name:        NameSchema,
			Description: "Check the credential against the JSON Schema it declares.",
			Run:         schema,
		},
		{
			Name:        NameClaimPredicate,
			Description: "Check a claim against a rule that DCQL cannot hold, for example a date range.",
			Params: map[string]string{
				"path":  "the dotted claim path, for example birth_date",
				"op":    "before, after, at_least_years, or at_most_years",
				"value": "a date such as 2008-01-31, or a whole number of years",
				"type":  "the credential type the rule applies to; empty applies it to every credential with the claim",
			},
			Run: claimPredicate,
		},
		{
			Name:        NameDerivedProof,
			Description: "Check a BBS derived proof. The check is reserved and returns SKIP.",
			Run:         derivedProof,
		},
	}
}

// Find returns the check with name.
func Find(name string) (Check, bool) {
	for _, c := range Checks() {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

// Setting selects one check of a policy set.
type Setting struct {
	// Name is the check name.
	Name string
	// Params are the parameters of the check.
	Params map[string]string
	// Blocking makes a FAIL of this check an INVALID verdict. A
	// mandatory check is always blocking.
	Blocking bool
}

// Set is a named, versioned list of checks (ADR-024 decision 6).
type Set struct {
	// ID is the set id.
	ID string
	// Version is the version of the set.
	Version int32
	// Settings are the checks, in run order.
	Settings []Setting
}

// Verdict names the overall result of an evaluation.
type Verdict string

// The three verdicts.
const (
	// Valid means every blocking check passed or did not apply.
	Valid Verdict = "VALID"
	// Invalid means at least one blocking check failed.
	Invalid Verdict = "INVALID"
	// Indeterminate means no blocking check failed and at least one
	// check could not run.
	Indeterminate Verdict = "INDETERMINATE"
)

// Report is the output of Evaluate.
type Report struct {
	// Verdict is the overall result.
	Verdict Verdict
	// Results are the check results, in run order.
	Results []CheckResult
	// SetID is the policy set the evaluation used.
	SetID string
	// Version is the policy set version.
	Version int32
}

// Evaluate runs the mandatory checks and then the checks of set
// (ADR-024 decisions 1, 2, and 6). The verdict is the conjunction.
func Evaluate(ctx context.Context, p Presentation, pc Context, set Set) Report {
	report := Report{SetID: set.ID, Version: set.Version}
	blocking := map[int]bool{}
	for _, c := range Checks() {
		if !c.Mandatory {
			continue
		}
		for _, r := range c.Run(ctx, p, with(pc, paramsOf(set, c.Name))) {
			blocking[len(report.Results)] = true
			report.Results = append(report.Results, r)
		}
	}
	for _, s := range set.Settings {
		c, ok := Find(s.Name)
		if !ok {
			report.Results = append(report.Results, CheckResult{
				Name: s.Name, Result: Error, CredentialIndex: WholePresentation,
				Detail: "the service does not know this check",
			})
			continue
		}
		if c.Mandatory {
			continue
		}
		for _, r := range c.Run(ctx, p, with(pc, s.Params)) {
			blocking[len(report.Results)] = s.Blocking
			report.Results = append(report.Results, r)
		}
	}
	report.Verdict = verdictOf(report.Results, blocking)
	return report
}

// paramsOf returns the parameters the set gives to the check with name.
func paramsOf(set Set, name string) map[string]string {
	for _, s := range set.Settings {
		if s.Name == name {
			return s.Params
		}
	}
	return nil
}

// with returns pc with the parameters of one check.
func with(pc Context, params map[string]string) Context {
	pc.Params = params
	return pc
}

// verdictOf folds the results into one verdict.
func verdictOf(results []CheckResult, blocking map[int]bool) Verdict {
	indeterminate := false
	for i, r := range results {
		switch r.Result {
		case Fail:
			if blocking[i] {
				return Invalid
			}
		case Error:
			indeterminate = true
		case Pass, Skip:
		}
	}
	if indeterminate {
		return Indeterminate
	}
	return Valid
}

// Names returns the sorted names of every known check. The portal and
// the ListChecks RPC use it.
func Names() []string {
	out := make([]string, 0, len(Checks()))
	for _, c := range Checks() {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

// result builds one CheckResult.
func result(name string, outcome Outcome, index int, detail string, evidence map[string]string) CheckResult {
	return CheckResult{Name: name, Result: outcome, CredentialIndex: index, Detail: detail, Evidence: evidence}
}

// noCredentials returns the result of a check on an empty presentation.
func noCredentials(name string) []CheckResult {
	return []CheckResult{result(name, Skip, WholePresentation, "the presentation has no credential", nil)}
}
