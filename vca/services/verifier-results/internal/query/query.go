// SPDX-License-Identifier: Apache-2.0

// Package query filters stored results (ADR-025 decision 4). Every
// function is pure, so the same filter serves the Query RPC, the Export
// RPC, and the portal pages.
package query

import (
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

// Match reports whether one result matches the filter. A nil filter
// matches every result.
func Match(f *resultsv1.Filter, r *resultsv1.VerificationResult) bool {
	if f == nil {
		return true
	}
	at := r.GetEvaluatedAt().AsTime()
	if from := f.GetFrom(); from != nil && at.Before(from.AsTime()) {
		return false
	}
	if to := f.GetTo(); to != nil && at.After(to.AsTime()) {
		return false
	}
	if v := f.GetVerdict(); v != policyv1.EvaluateResponse_VERDICT_UNSPECIFIED && r.GetVerdict() != v {
		return false
	}
	if id := f.GetTemplateId(); id != "" && r.GetTemplateId() != id {
		return false
	}
	if t := f.GetTenantId(); t != "" && r.GetTenantId() != t {
		return false
	}
	if issuer := f.GetIssuer(); issuer != "" && !hasIssuer(r, issuer) {
		return false
	}
	return true
}

// hasIssuer reports whether a credential of the result has the issuer.
func hasIssuer(r *resultsv1.VerificationResult, issuer string) bool {
	for _, c := range r.GetCredentials() {
		if c.GetIssuer() == issuer {
			return true
		}
	}
	return false
}

// Apply returns the results that match the filter, in the input order.
func Apply(f *resultsv1.Filter, all []*resultsv1.VerificationResult) []*resultsv1.VerificationResult {
	out := make([]*resultsv1.VerificationResult, 0, len(all))
	for _, r := range all {
		if Match(f, r) {
			out = append(out, r)
		}
	}
	return out
}
