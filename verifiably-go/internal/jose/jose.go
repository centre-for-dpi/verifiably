// Package jose holds small JOSE/JWK primitives shared across the issuer-signing
// (trust registry, status lists) and token-verifying (OIDC) paths. Stdlib
// crypto only — no third-party JOSE library — to match the rest of the
// codebase and keep these hot paths CGO-free.
package jose

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// DecodeBase64URLBigInt decodes a base64url big-endian integer as used for JWK
// RSA modulus/exponent and EC coordinates. Per RFC 7515 the encoding is
// unpadded, but some issuers emit padding anyway, so this falls back to padded
// base64 before failing.
func DecodeBase64URLBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(b), nil
}

// VerifyES256 verifies a JWS ES256 (ECDSA P-256 + SHA-256) signature over
// signingInput (the raw `base64url(header).base64url(payload)` bytes). sig is
// the JWS raw R||S concatenation — 32 bytes each, NOT ASN.1. Returns nil on a
// valid signature.
func VerifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("jose: ES256 signature must be 64 bytes, got %d", len(sig))
	}
	h := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return fmt.Errorf("jose: ES256 signature verification failed")
	}
	return nil
}
