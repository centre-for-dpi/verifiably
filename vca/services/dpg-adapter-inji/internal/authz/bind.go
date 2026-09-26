// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// matches reports whether the ID token of the holder meets the binding
// rule of an offer: the token claim and the subject claim hold the same
// non empty text, and the provider vouches for the token claim (ADR-056
// decision 2). An email compares without the case of ASCII letters, as
// mail systems do. vouched lists the claims the provider record names
// beyond the standard ones.
func (b Binding) matches(claims, subject map[string]any, vouched []string) bool {
	if b.TokenClaim == "" || b.SubjectClaim == "" {
		return false
	}
	got, ok := tokenValue(claims, b.TokenClaim, vouched)
	if !ok {
		return false
	}
	want, ok := subject[b.SubjectClaim].(string)
	want = strings.TrimSpace(want)
	if !ok || want == "" {
		return false
	}
	if b.TokenClaim == "email" {
		return asciiLower(got) == asciiLower(want)
	}
	return got == want
}

// tokenValue returns the text of one claim of the sign in when the
// provider vouches for it (ADR-056 decision 2, oidcflow.VouchedValue).
func tokenValue(claims map[string]any, name string, vouched []string) (string, bool) {
	return oidcflow.VouchedValue(claims, name, vouched)
}

// asciiLower folds the ASCII capitals of s and nothing else. Unicode
// folding would equate the Kelvin sign with k, so an address that no
// mail system delivers to could match (review finding 16).
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}
