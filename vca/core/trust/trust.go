// SPDX-License-Identifier: Apache-2.0

// Package trust models a trust registry: a signed list of issuer DIDs that
// are authorised to issue named credential schemas.
//
// The list is published as a JWT (RFC 7519) signed with ES256 or EdDSA.
// The legacy HS256 mode is dropped: a shared secret cannot serve a
// federation. Storage and HTTP live in the trust-registry service.
package trust

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// TypeJWT is the typ header of a signed trust list.
const TypeJWT = "trust-list+jwt"

// DefaultTTL is the list validity used when BuildOptions.TTL is zero.
const DefaultTTL = 24 * time.Hour

// Policy names for StatusListPolicy.
const (
	FailClosed = "fail-closed"
	FailOpen   = "fail-open"
)

// ErrUntrusted reports that an issuer is not authorised for a schema.
var ErrUntrusted = errors.New("trust: issuer not in trust registry")

// ErrExpired reports that a signed list has passed its exp claim.
var ErrExpired = errors.New("trust: list expired")

// Entry is one trusted issuer.
type Entry struct {
	DID         string `json:"did"`
	DisplayName string `json:"display_name,omitempty"`
	// Schemas lists the credential schema IDs the issuer may issue.
	// An empty list means every schema.
	Schemas []string `json:"schemas,omitempty"`
	// ServiceEndpoint is the base URL of the issuer deployment.
	ServiceEndpoint string `json:"service_endpoint,omitempty"`
	// StatusListEndpoints are the public URLs of the issuer's status lists.
	StatusListEndpoints []string `json:"status_list_endpoints,omitempty"`
	// StatusListPolicy is FailClosed (default) or FailOpen.
	StatusListPolicy string    `json:"status_list_policy,omitempty"`
	AccreditedAt     time.Time `json:"accredited_at"`
	// ValidUntil is the end of the accreditation. Zero means no end.
	ValidUntil time.Time `json:"valid_until,omitempty"`
}

// IsExpired reports whether the accreditation has ended at now.
func (e Entry) IsExpired(now time.Time) bool {
	return !e.ValidUntil.IsZero() && now.After(e.ValidUntil)
}

// AuthorisesSchema reports whether the entry covers schemaID.
func (e Entry) AuthorisesSchema(schemaID string) bool {
	if len(e.Schemas) == 0 {
		return true
	}
	for _, s := range e.Schemas {
		if s == schemaID {
			return true
		}
	}
	return false
}

// Validate checks the entry fields.
func (e Entry) Validate() error {
	if e.DID == "" {
		return errors.New("trust: entry has no did")
	}
	switch e.StatusListPolicy {
	case "", FailClosed, FailOpen:
		return nil
	}
	return fmt.Errorf("trust: unknown status list policy %q", e.StatusListPolicy)
}

// Lookup returns nil when issuerDID is authorised for schemaID at now.
// It returns ErrUntrusted when the issuer is absent, expired or not
// authorised for the schema.
func Lookup(entries []Entry, issuerDID, schemaID string, now time.Time) error {
	for _, e := range entries {
		if e.DID != issuerDID {
			continue
		}
		if e.IsExpired(now) || !e.AuthorisesSchema(schemaID) {
			return ErrUntrusted
		}
		return nil
	}
	return ErrUntrusted
}

// Sorted returns a copy of entries ordered by DID.
func Sorted(entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	copy(out, entries)
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out
}

// List is the claim set of a signed trust list.
type List struct {
	Issuer    string    `json:"iss"`
	IssuedAt  time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
	Entries   []Entry   `json:"issuers"`
}

// BuildOptions configure Build.
type BuildOptions struct {
	Issuer string        // iss claim, the registry identifier
	Kid    string        // kid header, optional
	Now    time.Time     // zero: time.Now()
	TTL    time.Duration // zero: DefaultTTL
}

// Build signs a trust list JWT with an ES256 or EdDSA key.
func Build(entries []Entry, key crypto.PrivateKey, opts BuildOptions) (string, error) {
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return "", err
		}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	now = now.UTC()
	claims := map[string]any{
		"iss":     opts.Issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
		"issuers": Sorted(entries),
	}
	return jose.Sign(key, opts.Kid, TypeJWT, claims)
}

// Verify checks the signature and exp of a trust list JWT and returns it.
// keys holds the registry public keys, selected by kid when present.
func Verify(token string, keys jose.JWKS, now time.Time) (List, error) {
	raw, _, err := jose.VerifyWithJWKS(token, keys, jose.SigningAlgorithms)
	if err != nil {
		return List{}, err
	}
	var claims struct {
		Issuer    string  `json:"iss"`
		IssuedAt  int64   `json:"iat"`
		ExpiresAt int64   `json:"exp"`
		Entries   []Entry `json:"issuers"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return List{}, fmt.Errorf("trust: claims: %w", err)
	}
	if claims.ExpiresAt == 0 {
		return List{}, errors.New("trust: exp claim missing")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.After(time.Unix(claims.ExpiresAt, 0)) {
		return List{}, ErrExpired
	}
	return List{
		Issuer:    claims.Issuer,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		Entries:   claims.Entries,
	}, nil
}
