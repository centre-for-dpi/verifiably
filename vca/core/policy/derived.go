// SPDX-License-Identifier: Apache-2.0

package policy

import "context"

// DerivedProofDetail is the reason the derived proof check reports.
const DerivedProofDetail = "reserved for BBS: not implemented"

// derivedProof reserves the check name of BBS selective disclosure
// (ADR-031 decision 2). The W3C Data Integrity BBS cryptosuites are a
// Candidate Recommendation Draft, so no VCA code verifies a derived
// proof yet. The check returns SKIP, so a result set still names it.
func derivedProof(_ context.Context, p Presentation, _ Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameDerivedProof)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, result(NameDerivedProof, Skip, i, DerivedProofDetail,
			map[string]string{"format": string(c.Format)}))
	}
	return out
}
