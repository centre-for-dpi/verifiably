// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"strings"
)

// matches reports whether the ID token of the holder meets the binding
// rule of an offer: the token claim and the subject claim hold the same
// non empty text. An email compares without case, as mail systems do,
// and a token that says the email is not verified never matches
// (OpenID Connect Core 1.0 section 5.1).
func (b Binding) matches(claims, subject map[string]any) bool {
	if b.TokenClaim == "" || b.SubjectClaim == "" {
		return false
	}
	got, ok := tokenValue(claims, b.TokenClaim)
	if !ok {
		return false
	}
	want, ok := subject[b.SubjectClaim].(string)
	want = strings.TrimSpace(want)
	if !ok || want == "" {
		return false
	}
	if b.TokenClaim == "email" {
		return strings.EqualFold(got, want)
	}
	return got == want
}

// tokenValue returns the text of one claim of an ID token. The email
// claim counts only when the token does not say it is unverified.
func tokenValue(claims map[string]any, name string) (string, bool) {
	v, ok := claims[name].(string)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return "", false
	}
	if name == "email" {
		switch verified := claims["email_verified"].(type) {
		case bool:
			if !verified {
				return "", false
			}
		case string:
			if strings.EqualFold(verified, "false") {
				return "", false
			}
		}
	}
	return v, true
}
