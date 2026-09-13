// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// ClaimPath returns the string values at a dot path into claims, for
// example realm_access.roles. A string value yields one element. An
// array yields its string elements. Any other value yields nothing.
func ClaimPath(claims map[string]any, path string) []string {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			return nil
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	switch v := cur.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// PairwiseSubject joins iss and sub as iss|sub (ADR-020 decision 1).
func PairwiseSubject(iss, sub string) string {
	return strings.TrimRight(iss, "/") + "|" + sub
}

// HashSubject returns the base64url HMAC-SHA256 of pairwise under salt.
// The result is the wallet key. It does not reveal iss or sub.
func HashSubject(salt []byte, pairwise string) string {
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(pairwise))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
