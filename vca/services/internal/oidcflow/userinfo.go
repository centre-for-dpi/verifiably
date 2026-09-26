// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// ErrNoUserinfo reports a provider whose metadata names no userinfo
// endpoint.
var ErrNoUserinfo = errors.New("oidcflow: the provider publishes no userinfo endpoint")

// VerifiedFlags maps a claim to the flag that says the provider verified
// it (OpenID Connect Core 1.0 section 5.1). The claim counts only when
// the flag says true (ADR-056 decision 2).
var VerifiedFlags = map[string]string{
	"email":        "email_verified",
	"phone_number": "phone_number_verified",
}

// tokenClaims are the claims that describe a token, never a person. A
// userinfo answer never replaces them.
var tokenClaims = []string{
	"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "azp", "at_hash", "c_hash",
	"auth_time", "acr", "amr", "sid",
}

// VouchedValue returns the text of one claim when the provider vouches
// for it (ADR-056 decision 2): sub always, email and phone_number only
// when their verified flag says true, and any other claim only when
// verified, the list of the provider record, names it. A missing flag is
// no assertion, so it counts as unverified.
func VouchedValue(claims map[string]any, name string, verified []string) (string, bool) {
	v, ok := claims[name].(string)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return "", false
	}
	if flag, known := VerifiedFlags[name]; known {
		return v, isTrue(claims[flag])
	}
	return v, name == "sub" || slices.Contains(verified, name)
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

// mergeable reports whether a userinfo answer may add the claim: email
// and phone_number with their flag, or a claim the record lists. The
// claims of a token and the flags themselves never count.
func mergeable(name string, verified []string) bool {
	if slices.Contains(tokenClaims, name) {
		return false
	}
	for _, flag := range VerifiedFlags {
		if name == flag {
			return false
		}
	}
	_, flagged := VerifiedFlags[name]
	return flagged || slices.Contains(verified, name)
}

// MergeVouched returns the claims of the ID token plus the claims of the
// userinfo answer that the provider vouches for and the ID token does
// not. A flagged claim comes with its flag. The ID token claims stay as
// they are, sub and the other token claims never change, and the input
// maps stay untouched.
func MergeVouched(idClaims, userinfo map[string]any, verified []string) map[string]any {
	out := maps.Clone(idClaims)
	if out == nil {
		out = map[string]any{}
	}
	names := append([]string{"email", "phone_number"}, verified...)
	for _, name := range names {
		if !mergeable(name, verified) {
			continue
		}
		if _, ok := VouchedValue(out, name, verified); ok {
			continue
		}
		if _, ok := VouchedValue(userinfo, name, verified); !ok {
			continue
		}
		out[name] = userinfo[name]
		if flag, ok := VerifiedFlags[name]; ok {
			out[flag] = userinfo[flag]
		}
	}
	return out
}

// Vouched returns the claims of a completed login in which the provider
// vouches for the claim name. When the ID token vouches for it, the ID
// token claims come back and no request leaves. When the provider could
// vouch for the claim, the userinfo answer fills in what the ID token
// lacks (MergeVouched). eSignet, for one, sends the claims of a person
// only there. A provider without a userinfo endpoint leaves the ID token
// claims as they are.
func (f *Flow) Vouched(ctx context.Context, p Provider, res Result, name string) (map[string]any, error) {
	if _, ok := VouchedValue(res.Claims, name, p.VerifiedClaims); ok || !mergeable(name, p.VerifiedClaims) {
		return res.Claims, nil
	}
	info, err := f.Userinfo(ctx, p, res)
	if errors.Is(err, ErrNoUserinfo) {
		return res.Claims, nil
	}
	if err != nil {
		return nil, err
	}
	return MergeVouched(res.Claims, info, p.VerifiedClaims), nil
}

// Userinfo reads the userinfo answer of a completed login with its
// access token (OpenID Connect Core 1.0 section 5.3). A JWT answer
// (application/jwt) must carry a signature of a key of the provider key
// set. Its iss must be the provider and its aud must name the client
// whenever the answer carries them, and an exp must lie ahead. Plain
// JSON comes over the channel of this call. Either way the sub must be
// the sub of the ID token (section 5.3.2), or no claim of the answer
// counts. An encrypted answer fails: register the client for a signed
// one.
func (f *Flow) Userinfo(ctx context.Context, p Provider, res Result) (map[string]any, error) {
	m, err := f.Metadata(ctx, p)
	if err != nil {
		return nil, err
	}
	if m.UserinfoEndpoint == "" {
		return nil, ErrNoUserinfo
	}
	if res.AccessToken == "" {
		return nil, wrap(ErrProviderError, "the login gave no access token for userinfo")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.UserinfoEndpoint, nil)
	if err != nil {
		return nil, wrap(ErrUpstream, "build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+res.AccessToken)
	req.Header.Set("Accept", "application/jwt, application/json")
	answer, err := f.client().Do(req)
	if err != nil {
		return nil, wrap(ErrUpstream, "userinfo endpoint: %v", err)
	}
	defer func() { anyval.Discard(answer.Body.Close()) }()
	// A read failure leaves the body empty, which the checks refuse.
	body := anyval.OrZero(io.ReadAll(io.LimitReader(answer.Body, maxBody)))
	if answer.StatusCode != http.StatusOK {
		return nil, wrap(ErrProviderError, "userinfo endpoint returned %d", answer.StatusCode)
	}
	var claims map[string]any
	switch mediaType(answer.Header.Get("Content-Type")) {
	case "application/jwt":
		if claims, err = f.verifyUserinfo(ctx, p, m, strings.TrimSpace(string(body))); err != nil {
			return nil, err
		}
	case "application/json":
		if err := json.Unmarshal(body, &claims); err != nil || claims == nil {
			return nil, wrap(ErrProviderError, "userinfo endpoint returned JSON that is no object")
		}
	default:
		return nil, wrap(ErrProviderError, "userinfo endpoint returned the media type %q", answer.Header.Get("Content-Type"))
	}
	if sub := anyval.As[string](claims["sub"]); sub == "" || sub != res.Subject {
		return nil, wrap(ErrSessionInvalid, "userinfo names another sub than the ID token")
	}
	return claims, nil
}

// verifyUserinfo checks a userinfo JWT against the provider key set. On
// a missing key it fetches the key set once more, which covers key
// rotation.
func (f *Flow) verifyUserinfo(ctx context.Context, p Provider, m Metadata, token string) (map[string]any, error) {
	if strings.Count(token, ".") != 2 {
		return nil, wrap(ErrSessionInvalid, "userinfo is no signed JWT; an encrypted answer needs a client registered for a signed one")
	}
	keys, err := f.Cache.JWKS(ctx, m.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	raw, _, err := jose.VerifyWithJWKS(token, keys, oidc.Algorithms)
	if errors.Is(err, jose.ErrNoKey) {
		if keys, err = f.Cache.JWKS(ctx, m.JWKSURI, true); err != nil {
			return nil, err
		}
		raw, _, err = jose.VerifyWithJWKS(token, keys, oidc.Algorithms)
	}
	if err != nil {
		return nil, wrap(ErrSessionInvalid, "userinfo: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil || claims == nil {
		return nil, wrap(ErrSessionInvalid, "userinfo: the payload is no JSON object")
	}
	if iss, ok := claims["iss"]; ok && strings.TrimRight(anyval.As[string](iss), "/") != strings.TrimRight(m.Issuer, "/") {
		return nil, wrap(ErrSessionInvalid, "userinfo: another issuer")
	}
	if aud, ok := claims["aud"]; ok && !slices.Contains(audienceList(aud), p.ClientID) {
		return nil, wrap(ErrSessionInvalid, "userinfo: another audience")
	}
	if exp, ok := claims["exp"]; ok {
		at, isNumber := exp.(float64)
		if !isNumber || !f.now().Before(time.Unix(int64(at), 0)) {
			return nil, wrap(ErrSessionInvalid, "userinfo: expired")
		}
	}
	return claims, nil
}

// mediaType returns the media type of a Content-Type header, or "" when
// it does not parse.
func mediaType(header string) string {
	media, _, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	return media
}

// audienceList reads aud, a string or an array of strings (RFC 7519).
func audienceList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
