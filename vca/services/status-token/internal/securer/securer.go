// SPDX-License-Identifier: Apache-2.0

// Package securer signs an IETF Token Status List (ADR-019 decisions 1
// and 2). One bit array produces two representations:
//
//	application/statuslist+jwt  a compact JWS with typ "statuslist+jwt"
//	application/statuslist+cwt  a COSE_Sign1 message with typ "statuslist+cwt"
//
// The JWT is the default. A verifier asks for the CWT with an Accept
// header. Both carry the same bits, the same issuer, and the same
// times, so a verifier reaches the same answer from either one.
//
// The status width is 1, 2, 4, or 8 bits (ADR-019 decision 3). The
// width is a property of the list, not of the representation.
package securer

import (
	"fmt"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
)

// Media types of the two representations (draft-ietf-oauth-status-list
// section 5).
const (
	MediaTypeJWT = "application/statuslist+jwt"
	MediaTypeCWT = "application/statuslist+cwt"
)

// Token secures a list as a Status List JWT and a Status List CWT.
type Token struct {
	// TTL is the "ttl" claim, the time a verifier may cache the list.
	// Zero leaves the claim out.
	TTL time.Duration
	// AggregationURI is the optional aggregation_uri claim.
	AggregationURI string
}

// New returns the securer of this service.
func New(ttl time.Duration, aggregationURI string) lists.Securer {
	return Token{TTL: ttl, AggregationURI: aggregationURI}
}

// Kind reports that this securer signs token lists.
func (Token) Kind() lists.Kind { return lists.KindToken }

// MediaTypes returns the two media types, JWT first.
func (Token) MediaTypes() []string { return []string{MediaTypeJWT, MediaTypeCWT} }

// Secure builds both representations from one bit array.
func (t Token) Secure(rec lists.Record, issuer keys.Issuer, url string, signedAt, expiresAt time.Time) ([]lists.Unsigned, error) {
	if rec.Kind != lists.KindToken {
		return nil, fmt.Errorf("%w: %s", lists.ErrBadKind, rec.Kind)
	}
	if err := lists.CheckPurpose(rec.Purpose); err != nil {
		return nil, err
	}
	list, err := rec.TokenList()
	if err != nil {
		return nil, fmt.Errorf("securer: %w", err)
	}
	claims := token.Claims{
		Issuer: issuer.DID(), Subject: url, IssuedAt: signedAt, ExpiresAt: expiresAt,
		TTL: t.TTL, AggregationURI: t.AggregationURI,
	}
	key := issuer.Active()
	jwt, err := jose.Sign(key.Private, issuer.Kid(key), token.TypeJWT, token.JWTClaims(claims, list))
	if err != nil {
		return nil, fmt.Errorf("securer: %w", err)
	}
	alg, sign, err := token.KeySigner(key.Private)
	if err != nil {
		return nil, fmt.Errorf("securer: %w", err)
	}
	cwt, err := token.SignCWT(token.CWTClaims(claims, list), alg, []byte(issuer.Kid(key)), sign)
	if err != nil {
		return nil, fmt.Errorf("securer: %w", err)
	}
	return []lists.Unsigned{
		{MediaType: MediaTypeJWT, Body: []byte(jwt)},
		{MediaType: MediaTypeCWT, Body: cwt},
	}, nil
}
