// SPDX-License-Identifier: Apache-2.0

// Package oid4vp builds and reads OpenID for Verifiable Presentations
// 1.0 request objects (ADR-023 decision 5).
//
// The verifier signs a request object as a JWT with ES256 and serves it
// at a request URI. A wallet reads the request object, asks the citizen,
// and posts the answer to the response URI.
//
// A request URI the service reads from another party is allowlisted and
// size limited. An empty allowlist refuses every request URI, because an
// unrestricted fetch is a server side request forgery.
package oid4vp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// TypeRequestObject is the typ header of a request object.
const TypeRequestObject = "oauth-authz-req+jwt"

// MediaTypeRequestObject is the media type of a served request object.
const MediaTypeRequestObject = "application/oauth-authz-req+jwt"

// ResponseModeDirectPost is the response mode of ADR-023 decision 5.
const ResponseModeDirectPost = "direct_post"

// ResponseModeDirectPostJWT encrypts the answer in a JWT.
const ResponseModeDirectPostJWT = "direct_post.jwt"

// AudienceSelfIssued is the audience of a request object for a wallet.
const AudienceSelfIssued = "https://self-issued.me/v2"

// ErrRefused reports that the allowlist refused a request URI.
var ErrRefused = errors.New("oid4vp: the allowlist refused the request URI")

// ParseResponseMode reads a response mode. Empty means direct_post.
func ParseResponseMode(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", ResponseModeDirectPost:
		return ResponseModeDirectPost, nil
	case ResponseModeDirectPostJWT:
		return ResponseModeDirectPostJWT, nil
	}
	return "", fmt.Errorf("oid4vp: the response mode %q is not direct_post or direct_post.jwt", value)
}

// Request holds the values of one request object.
type Request struct {
	// ClientID is the verifier identifier.
	ClientID string
	// ResponseURI is the URL the wallet posts the answer to.
	ResponseURI string
	// ResponseMode is direct_post or direct_post.jwt.
	ResponseMode string
	// Nonce is the value the wallet binds its answer to.
	Nonce string
	// State is the state parameter of the request.
	State string
	// DCQL is the query, as a JSON string.
	DCQL string
	// IssuedAt is the creation time.
	IssuedAt time.Time
	// ExpiresAt is the time the request stops working.
	ExpiresAt time.Time
}

// Claims returns the claim set of the request object.
func (r Request) Claims() (map[string]any, error) {
	claims := map[string]any{
		"iss":           r.ClientID,
		"aud":           AudienceSelfIssued,
		"client_id":     r.ClientID,
		"response_type": "vp_token",
		"response_mode": r.ResponseMode,
		"response_uri":  r.ResponseURI,
		"nonce":         r.Nonce,
		"state":         r.State,
		"iat":           r.IssuedAt.Unix(),
		"exp":           r.ExpiresAt.Unix(),
	}
	if strings.TrimSpace(r.DCQL) != "" {
		var query any
		if err := json.Unmarshal([]byte(r.DCQL), &query); err != nil {
			return nil, fmt.Errorf("oid4vp: read the DCQL query: %w", err)
		}
		claims["dcql_query"] = query
	}
	return claims, nil
}

// Sign returns the request object as a signed JWT.
func (r Request) Sign(key crypto.PrivateKey, kid string) (string, error) {
	claims, err := r.Claims()
	if err != nil {
		return "", err
	}
	token, err := jose.Sign(key, kid, TypeRequestObject, claims)
	if err != nil {
		return "", fmt.Errorf("oid4vp: sign the request object: %w", err)
	}
	return token, nil
}

// AuthorizeURL returns the URL a wallet opens. The wallet reads the
// request object from the request URI.
func AuthorizeURL(scheme, clientID, requestURI string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("request_uri", requestURI)
	return scheme + "?" + values.Encode()
}

// DefaultScheme is the URL scheme of a wallet on the same device.
const DefaultScheme = "openid4vp://authorize"

// Allowlist says which hosts the service may read a request object from.
type Allowlist struct {
	// Hosts lists the allowed host names. An entry that starts with a
	// dot matches the domain and every name below it. An empty list
	// refuses every request URI.
	Hosts []string
	// AllowPlainHTTP lets the fetcher use http. Development only.
	AllowPlainHTTP bool
}

// Check reads the URL and reports whether the service may fetch it.
func (a Allowlist) Check(raw string) (*url.URL, error) {
	if len(a.Hosts) == 0 {
		return nil, fmt.Errorf("%w: no host is allowed, set the allowed hosts first", ErrRefused)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a URL", ErrRefused, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !a.AllowPlainHTTP {
			return nil, fmt.Errorf("%w: %s is not https", ErrRefused, raw)
		}
	default:
		return nil, fmt.Errorf("%w: the scheme %q is not http or https", ErrRefused, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: a URL with a user name is not allowed", ErrRefused)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return nil, fmt.Errorf("%w: the URL has no host", ErrRefused)
	}
	for _, allowed := range a.Hosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == host || (strings.HasPrefix(allowed, ".") && strings.HasSuffix(host, allowed)) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("%w: the host %q is not on the allowed list", ErrRefused, host)
}

// Fetcher reads a request object from an allowed host.
type Fetcher struct {
	// Allow holds the allowed hosts.
	Allow Allowlist
	// Client performs the request. Nil means a client with Timeout.
	Client *http.Client
	// Timeout bounds one fetch. Zero means 10 seconds.
	Timeout time.Duration
	// MaxBytes caps the fetched object. Zero means 128 kibibytes.
	MaxBytes int
}

// Fetch reads the request object at raw.
func (f Fetcher) Fetch(ctx context.Context, raw string) (string, error) {
	u, err := f.Allow.Check(raw)
	if err != nil {
		return "", err
	}
	client := f.Client
	if client == nil {
		timeout := f.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = 128 << 10
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("oid4vp: %w", err)
	}
	req.Header.Set("Accept", MediaTypeRequestObject+", application/jwt")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oid4vp: read %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oid4vp: %s answered %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return "", fmt.Errorf("oid4vp: read %s: %w", u, err)
	}
	if len(body) > limit {
		return "", fmt.Errorf("oid4vp: the request object at %s is larger than %d bytes", u, limit)
	}
	return strings.TrimSpace(string(body)), nil
}

// ReadRequestObject reads the claims of a request object. It does not
// check the signature, because the trust of the verifier comes from the
// trust registry, not from the token.
func ReadRequestObject(token string) (map[string]any, error) {
	claims, err := jose.PeekPayload(strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("oid4vp: read the request object: %w", err)
	}
	return claims, nil
}
