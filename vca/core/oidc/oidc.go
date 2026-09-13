// SPDX-License-Identifier: Apache-2.0

// Package oidc holds the pure parts of an OpenID Connect relying party:
// PKCE (RFC 7636), discovery document parsing (OpenID Connect Discovery
// 1.0) and ID token claim verification against a JWKS (OpenID Connect
// Core 1.0 section 3.1.3.7).
//
// The HTTP calls (discovery fetch, token exchange, userinfo) live in the
// services. Lifted from the legacy internal/auth/oidc package.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Algorithms accepted for provider tokens.
var Algorithms = []jose.Algorithm{jose.RS256, jose.ES256}

// DefaultLeeway is the clock skew tolerance for nbf.
const DefaultLeeway = 60 * time.Second

// Errors returned by VerifyToken.
var (
	ErrIssuer   = errors.New("oidc: token iss does not match the provider")
	ErrExpired  = errors.New("oidc: token expired")
	ErrNotYet   = errors.New("oidc: token not yet valid")
	ErrAudience = errors.New("oidc: token aud does not include the client")
)

// NewVerifier returns a random PKCE code_verifier (43 characters).
func NewVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewState returns a random state value for the authorisation round trip.
func NewState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge returns the S256 code_challenge of a verifier (RFC 7636 section 4.2).
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyChallenge reports whether challenge is the S256 challenge of verifier.
// The comparison runs in constant time.
func VerifyChallenge(verifier, challenge string) bool {
	return subtle.ConstantTimeCompare([]byte(Challenge(verifier)), []byte(challenge)) == 1
}

// Discovery is the subset of an OpenID Provider metadata document.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// ParseDiscovery decodes a provider metadata document. The issuer,
// authorization and token endpoints are required.
func ParseDiscovery(raw []byte) (Discovery, error) {
	var d Discovery
	if err := json.Unmarshal(raw, &d); err != nil {
		return Discovery{}, fmt.Errorf("oidc: discovery: %w", err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return Discovery{}, errors.New("oidc: discovery document lacks issuer, authorization_endpoint or token_endpoint")
	}
	return d, nil
}

// DiscoveryURL returns the well-known URL of an issuer.
func DiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// Rebase returns a copy of d with every endpoint moved to authority
// (scheme://host:port). Providers often advertise endpoints on their own
// hostname, which a server behind a different network name cannot reach.
func (d Discovery) Rebase(authority string) Discovery {
	d.AuthorizationEndpoint = SwapAuthority(d.AuthorizationEndpoint, authority)
	d.TokenEndpoint = SwapAuthority(d.TokenEndpoint, authority)
	d.UserinfoEndpoint = SwapAuthority(d.UserinfoEndpoint, authority)
	d.JWKSURI = SwapAuthority(d.JWKSURI, authority)
	return d
}

// Authority returns scheme://host of a URL, or "" when raw has none.
func Authority(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SwapAuthority replaces the scheme and host of endpoint with authority
// and keeps path and query. It returns endpoint unchanged when either
// value is empty or does not parse.
func SwapAuthority(endpoint, authority string) string {
	if endpoint == "" || authority == "" {
		return endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	a, err := url.Parse(authority)
	if err != nil || a.Scheme == "" || a.Host == "" {
		return endpoint
	}
	u.Scheme = a.Scheme
	u.Host = a.Host
	return u.String()
}

// AuthorizeURL builds the authorisation request URL with PKCE S256.
func AuthorizeURL(authorizeEndpoint, clientID, redirectURI, state, verifier string, scopes []string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {Challenge(verifier)},
		"code_challenge_method": {"S256"},
		"prompt":                {"login"},
	}
	sep := "?"
	if strings.Contains(authorizeEndpoint, "?") {
		sep = "&"
	}
	return authorizeEndpoint + sep + q.Encode()
}

// TokenOptions configure VerifyToken.
type TokenOptions struct {
	// Issuers lists the accepted iss values (internal and public forms).
	Issuers []string
	// ClientID, when set, must appear in aud or azp.
	ClientID string
	Now      time.Time     // zero: time.Now()
	Leeway   time.Duration // zero: DefaultLeeway
}

// VerifyToken verifies a JWT issued by the provider: signature against
// keys (selected by kid, RS256 or ES256), iss, exp (required), nbf and,
// when ClientID is set, aud or azp. It returns the claims.
func VerifyToken(token string, keys jose.JWKS, opts TokenOptions) (map[string]any, error) {
	// Reject on issuer before any signature work.
	unverified, err := jose.PeekPayload(token)
	if err != nil {
		return nil, err
	}
	if err := checkIssuer(unverified, opts.Issuers); err != nil {
		return nil, err
	}
	raw, _, err := jose.VerifyWithJWKS(token, keys, Algorithms)
	if err != nil {
		return nil, err
	}
	// raw is the payload PeekPayload parsed above, so it is an object.
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	if err := checkTimes(claims, opts); err != nil {
		return nil, err
	}
	if err := checkAudience(claims, opts.ClientID); err != nil {
		return nil, err
	}
	return claims, nil
}

func checkIssuer(claims map[string]any, issuers []string) error {
	iss, _ := claims["iss"].(string)
	for _, k := range issuers {
		if k != "" && strings.TrimRight(iss, "/") == strings.TrimRight(k, "/") {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrIssuer, iss)
}

func checkTimes(claims map[string]any, opts TokenOptions) error {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= 0 {
		return errors.New("oidc: token has no exp claim")
	}
	if !now.Before(time.Unix(int64(exp), 0)) {
		return ErrExpired
	}
	if nbf, ok := claims["nbf"].(float64); ok && nbf > 0 && now.Add(leeway).Before(time.Unix(int64(nbf), 0)) {
		return ErrNotYet
	}
	return nil
}

func checkAudience(claims map[string]any, clientID string) error {
	if clientID == "" {
		return nil
	}
	for _, a := range audiences(claims["aud"]) {
		if a == clientID {
			return nil
		}
	}
	if azp, _ := claims["azp"].(string); azp == clientID {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrAudience, clientID)
}

// audiences reads aud, which is a string or an array of strings (RFC 7519).
func audiences(v any) []string {
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

// StringClaims returns the string valued claims, for profile prefill.
func StringClaims(claims map[string]any) map[string]string {
	out := make(map[string]string, len(claims))
	for k, v := range claims {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
