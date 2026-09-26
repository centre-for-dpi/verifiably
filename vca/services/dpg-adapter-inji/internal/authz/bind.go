// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"slices"
	"strings"
)

// The claims whose verified flag a provider sends (OpenID Connect Core
// 1.0 section 5.1). The value counts only when the flag says true.
var verifiedFlags = map[string]string{
	"email":        "email_verified",
	"phone_number": "phone_number_verified",
}

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

// tokenValue returns the text of one claim of an ID token when the
// provider vouches for it: sub always, email and phone_number only when
// their verified flag is true, and any other claim only when the
// provider record lists it. A missing flag is no assertion, so it
// counts as unverified.
func tokenValue(claims map[string]any, name string, vouched []string) (string, bool) {
	v, ok := claims[name].(string)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return "", false
	}
	if flag, known := verifiedFlags[name]; known {
		return v, isTrue(claims[flag])
	}
	return v, name == "sub" || slices.Contains(vouched, name)
}

// isTrue reports whether a verified flag says true: the JSON true, or
// the text true that some providers send.
func isTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
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
