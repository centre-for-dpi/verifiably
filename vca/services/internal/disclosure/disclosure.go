// SPDX-License-Identifier: Apache-2.0

// Package disclosure holds the rule that consent equals disclosure
// (ADR-081): a holder adapter compares the claims its wallet would send
// with the claims the holder consented to before the wallet answers.
package disclosure

import (
	"slices"
	"strings"
)

// Whole is the claim path that stands for every claim of a credential.
// A wallet that sends each credential whole needs the consent of the
// holder to this path.
const Whole = "*"

// Missing returns the claims of sent that consented leaves out, in the
// order of sent. A claim matches a consented path by its full dotted
// path or by its last segment, as the consent screen names a claim by
// its path. The path Whole consents to every claim.
func Missing(sent, consented []string) []string {
	if slices.Contains(consented, Whole) {
		return nil
	}
	var out []string
	for _, c := range sent {
		if c == Whole || !covered(c, consented) {
			out = append(out, c)
		}
	}
	return out
}

// covered reports whether one consented path names the claim.
func covered(claim string, consented []string) bool {
	for _, p := range consented {
		if p == claim || last(p) == last(claim) {
			return true
		}
	}
	return false
}

// last returns the last segment of a dotted claim path.
func last(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// Refusal is the sentence a holder adapter answers with when its wallet
// would send claims the holder did not consent to.
func Refusal(missing []string) string {
	return "this wallet cannot leave out " + strings.Join(missing, ", ") +
		"; the consent screen lists each claim it sends, so tick them all or decline"
}
