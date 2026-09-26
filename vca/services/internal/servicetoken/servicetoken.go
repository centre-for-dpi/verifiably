// SPDX-License-Identifier: Apache-2.0

// Package servicetoken derives the bearer token that one service of a
// pair shows another service of the same pair. Both hold the session key
// of the pair, so both derive the same token, and the key never travels.
// Each purpose gets its own token, so a token for one call opens no
// other call.
package servicetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// DataSourceLookup is the purpose of the token that the holder
// authorization server of a DPG adapter shows to
// DataSourceService.Lookup of its pair.
const DataSourceLookup = "vca/data-source/lookup"

// MinSecretBytes is the shortest pair secret that gives a token.
const MinSecretBytes = 16

// Derive returns the token of purpose under the pair secret: the
// HMAC-SHA256 of the purpose, in base64url without padding. A secret
// shorter than MinSecretBytes or an empty purpose gives no token.
func Derive(secret, purpose string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) < MinSecretBytes || purpose == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	// A hash write never fails.
	anyval.DiscardWrite(mac.Write([]byte("vca service token\x00" + purpose)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Set puts token on the Authorization header of a call.
func Set(h http.Header, token string) {
	h.Set("Authorization", "Bearer "+token)
}

// Matches reports whether the Authorization header of a call carries
// want. The compare takes constant time. An empty want matches nothing.
func Matches(h http.Header, want string) bool {
	auth := h.Get("Authorization")
	if want == "" || len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return false
	}
	got := strings.TrimSpace(auth[7:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
