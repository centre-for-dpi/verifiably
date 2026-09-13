// SPDX-License-Identifier: Apache-2.0

// Package securer signs a W3C Bitstring Status List as a VCDM 2.0
// credential (ADR-018 decisions 1 and 2). It replaces the legacy
// Ed25519Signature2020 proof.
//
// Two securing methods exist in the ADR. This package implements the
// JOSE method of VC JOSE COSE: the credential is the payload of a
// compact JWS with the media type "vc+jwt". The algorithm is ES256 or
// EdDSA, taken from the signing key. The Data Integrity method
// "eddsa-rdfc-2022" needs RDF canonicalisation (URDNA2015), which the
// module does not carry yet. DataIntegrity returns a clear error that
// names the follow-up.
package securer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
)

// MediaType is the media type of a secured list credential
// (VC JOSE COSE section 3.2.1).
const MediaType = "application/vc+jwt"

// Type is the "typ" header value of the compact JWS.
const Type = "vc+jwt"

// Methods the service understands.
const (
	// MethodJOSE secures the credential as a compact JWS.
	MethodJOSE = "jose"
	// MethodDataIntegrity secures the credential with an
	// eddsa-rdfc-2022 Data Integrity proof. It is a follow-up.
	MethodDataIntegrity = "eddsa-rdfc-2022"
)

// ErrNotImplemented reports a securing method the service does not
// carry yet.
var ErrNotImplemented = errors.New("securer: securing method is not implemented")

// Methods lists every method name the configuration accepts.
func Methods() []string { return []string{MethodJOSE, MethodDataIntegrity} }

// New returns the securer for method. It reports ErrNotImplemented for
// eddsa-rdfc-2022 and an unknown method error for anything else.
func New(method string) (lists.Securer, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", MethodJOSE:
		return JOSE{}, nil
	case MethodDataIntegrity:
		return nil, fmt.Errorf("%w: %s needs RDF canonicalisation (URDNA2015). "+
			"Use %s until a canonicaliser is in the module. See docs/status-bitstring.md",
			ErrNotImplemented, MethodDataIntegrity, MethodJOSE)
	}
	return nil, fmt.Errorf("securer: unknown method %q, use one of %s", method, strings.Join(Methods(), ", "))
}

// JOSE secures a list credential as a compact JWS with typ "vc+jwt".
type JOSE struct{}

// Kind reports that this securer signs bitstring lists.
func (JOSE) Kind() lists.Kind { return lists.KindBitstring }

// MediaTypes returns the single media type of this securer.
func (JOSE) MediaTypes() []string { return []string{MediaType} }

// Secure builds the BitstringStatusListCredential and signs it.
func (JOSE) Secure(rec lists.Record, issuer keys.Issuer, url string, signedAt, expiresAt time.Time) ([]lists.Unsigned, error) {
	doc, err := Credential(rec, issuer.DID(), url, signedAt, expiresAt)
	if err != nil {
		return nil, err
	}
	key := issuer.Active()
	token, err := jose.Sign(key.Private, issuer.Kid(key), Type, doc)
	if err != nil {
		return nil, fmt.Errorf("securer: %w", err)
	}
	return []lists.Unsigned{{MediaType: MediaType, Body: []byte(token)}}, nil
}

// Credential builds the unsigned VCDM 2.0 credential of rec. It adds
// validUntil so a verifier sees when a newer copy is due.
func Credential(rec lists.Record, issuerDID, url string, signedAt, expiresAt time.Time) (map[string]any, error) {
	if rec.Kind != lists.KindBitstring {
		return nil, fmt.Errorf("%w: %s", lists.ErrBadKind, rec.Kind)
	}
	if err := lists.CheckPurpose(rec.Purpose); err != nil {
		return nil, err
	}
	if rec.Size < bitstring.MinSize {
		return nil, fmt.Errorf("securer: a published list needs at least %d entries, got %d", bitstring.MinSize, rec.Size)
	}
	doc := bitstring.Credential(url, issuerDID, bitstring.Purpose(rec.Purpose), rec.BitstringList(), signedAt)
	doc["validUntil"] = expiresAt.UTC().Format(time.RFC3339)
	return doc, nil
}

// DataIntegrity is the placeholder securer of the eddsa-rdfc-2022
// method. Every call returns ErrNotImplemented.
type DataIntegrity struct{}

// Kind reports that this securer signs bitstring lists.
func (DataIntegrity) Kind() lists.Kind { return lists.KindBitstring }

// MediaTypes returns the media type of a credential with a proof.
func (DataIntegrity) MediaTypes() []string { return []string{"application/vc"} }

// Secure always fails. The method needs RDF canonicalisation.
func (DataIntegrity) Secure(lists.Record, keys.Issuer, string, time.Time, time.Time) ([]lists.Unsigned, error) {
	return nil, fmt.Errorf("%w: %s needs RDF canonicalisation (URDNA2015)", ErrNotImplemented, MethodDataIntegrity)
}
