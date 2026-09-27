// SPDX-License-Identifier: Apache-2.0

// Package holderkey builds the JWTs that the holder key of the browser
// store signs, and checks the signatures the browser returns (ADR-073).
// The private key never leaves the browser. The portal hands the page
// the signing input of a JWT, the page signs it with ES256 through
// WebCrypto, and the portal joins the two parts after it checks them.
//
// Two JWTs need the key: the proof of an OID4VCI credential request
// (OID4VCI 1.0 appendix F.1), and the key binding JWT of an SD-JWT
// presentation (RFC 9901 section 4.3).
package holderkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
)

// TypeProof is the typ of an OID4VCI proof JWT.
const TypeProof = "openid4vci-proof+jwt"

// TypeKB is the typ of an SD-JWT key binding JWT.
const TypeKB = sdjwt.TypeKB

// Errors the package returns.
var (
	// ErrKey reports a key that is not a public P-256 key.
	ErrKey = errors.New("holderkey: the key is not a public P-256 key")
	// ErrSignature reports a signature that the key does not verify.
	ErrSignature = errors.New("holderkey: the signature does not match the key")
	// ErrBinding reports a key binding JWT that does not cover the
	// answer: another token, audience, or nonce.
	ErrBinding = errors.New("holderkey: the key binding does not cover the answer")
	// ErrPresentation reports an SD-JWT presentation with no trailing
	// tilde, which a key binding JWT cannot cover.
	ErrPresentation = errors.New("holderkey: the presentation does not end with a tilde")
)

// ParseKey reads the public JWK that the browser sends: an EC key on
// P-256 with no private part.
func ParseKey(raw string) (jose.JWK, error) {
	key, err := jose.ParseJWK([]byte(strings.TrimSpace(raw)))
	if err != nil {
		return jose.JWK{}, fmt.Errorf("%w: %w", ErrKey, err)
	}
	pub, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return jose.JWK{}, ErrKey
	}
	return key, nil
}

// ProofInput returns the signing input of the proof of a credential
// request: the header names the key, the payload the issuer, the time,
// and the nonce of the issuer.
func ProofInput(key jose.JWK, audience, nonce string, now time.Time) (string, error) {
	jwk, err := jose.JWKToMap(key)
	if err != nil {
		return "", err
	}
	payload := map[string]any{"aud": audience, "iat": now.Unix()}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	return input(map[string]any{"alg": string(jose.ES256), "typ": TypeProof, "jwk": jwk}, payload), nil
}

// BindingInput returns the signing input of the key binding JWT of an
// SD-JWT presentation. presentation is the issuer JWT with the chosen
// disclosures, up to and with its last tilde.
func BindingInput(presentation, audience, nonce string, now time.Time) (string, error) {
	if !strings.HasSuffix(presentation, "~") {
		return "", ErrPresentation
	}
	return input(map[string]any{"alg": string(jose.ES256), "typ": TypeKB}, map[string]any{
		"iat": now.Unix(), "aud": audience, "nonce": nonce, "sd_hash": SDHash(presentation),
	}), nil
}

// SDHash returns the sd_hash of a presentation: the base64url SHA-256
// digest of its text up to and with the last tilde.
func SDHash(presentation string) string {
	sum := sha256.Sum256([]byte(presentation))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Join appends the signature of the browser to a signing input and
// returns the JWT, once the key verifies it.
func Join(signingInput, signature string, key jose.JWK) (string, error) {
	jwt := signingInput + "." + strings.TrimSpace(signature)
	if _, _, err := jose.Verify(jwt, key.Key, []jose.Algorithm{jose.ES256}); err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return jwt, nil
}

// Bound returns the holder key that an SD-JWT names in cnf.jwk. ok is
// false for a credential with no holder key.
func Bound(credential string) (jose.JWK, bool) {
	pres, err := sdjwt.Parse(credential)
	if err != nil {
		return jose.JWK{}, false
	}
	payload, err := jose.PeekPayload(pres.IssuerJWT)
	if err != nil {
		return jose.JWK{}, false
	}
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return jose.JWK{}, false
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return jose.JWK{}, false
	}
	key, err := jose.JWKFromMap(jwk)
	return key, err == nil
}

// input encodes a header and a payload as the signing input of a JWS.
// Both hold only texts, numbers, and a JWK map, so they always encode.
func input(header, payload map[string]any) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString(anyval.Must(json.Marshal(header))) + "." + enc.EncodeToString(anyval.Must(json.Marshal(payload)))
}

// CheckBinding reports whether a key binding JWT of the browser covers
// an answer: the holder key signed it, its typ is kb+jwt, and it names
// the audience, the nonce, and the sd_hash of the token.
func CheckBinding(kb, presentation, audience, nonce string, key jose.JWK) error {
	raw, hdr, err := jose.Verify(kb, key.Key, []jose.Algorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if hdr.Typ != TypeKB {
		return fmt.Errorf("%w: typ %q", ErrBinding, hdr.Typ)
	}
	var claims struct {
		Aud    string `json:"aud"`
		Nonce  string `json:"nonce"`
		SDHash string `json:"sd_hash"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fmt.Errorf("%w: %w", ErrBinding, err)
	}
	if claims.Aud != audience || claims.Nonce != nonce || claims.SDHash != SDHash(presentation) {
		return ErrBinding
	}
	return nil
}
