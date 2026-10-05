// SPDX-License-Identifier: Apache-2.0

// Package holderkey builds the JWTs that the holder key of the browser
// store signs, and checks the signatures the browser returns (ADR-073).
// The private key never leaves the browser. The portal hands the page
// the signing input of a JWT, the page signs it with ES256 through
// WebCrypto, and the portal joins the two parts after it checks them.
//
// Three JWTs need the key: the proof of an OID4VCI credential request
// (OID4VCI 1.0 appendix F.1), the key binding JWT of an SD-JWT
// presentation (RFC 9901 section 4.3), and the VP JWT around a
// jwt_vc_json credential (ADR-083 decision 5).
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
	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
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

// ErrVP reports a VP JWT that does not cover the answer: another
// credential, audience, or nonce.
var ErrVP = errors.New("holderkey: the VP JWT does not cover the answer")

// BoundJWT returns the holder key that a jwt_vc_json credential names,
// and its holder id: cnf.jwk, else the key of a did:jwk or did:key
// subject. ok is false for a credential with no holder key.
func BoundJWT(credential string) (jose.JWK, string, bool) {
	payload, err := jose.PeekPayload(credential)
	if err != nil || strings.Contains(credential, "~") {
		return jose.JWK{}, "", false
	}
	subject := vc.FromObject(payload).SubjectID
	if cnf, ok := payload["cnf"].(map[string]any); ok {
		if m, isMap := cnf["jwk"].(map[string]any); isMap {
			key, kerr := jose.JWKFromMap(m)
			return key, subject, kerr == nil
		}
	}
	doc, err := did.KeyDocument(subject)
	if err != nil {
		if doc, err = did.JWKDocument(subject); err != nil {
			return jose.JWK{}, "", false
		}
	}
	key, err := jose.JWKFromMap(doc.VerificationMethod[0].PublicKeyJWK)
	return key, subject, err == nil
}

// Binds reports whether the browser store can bind a credential to its
// key: an SD-JWT or a JWT credential that names a holder key. An mDoc
// and a JSON-LD credential go as issued (ADR-083 decision 3).
func Binds(credential string) bool {
	if _, ok := Bound(credential); ok {
		return true
	}
	_, _, ok := BoundJWT(credential)
	return ok
}

// VPInput returns the signing input of the VP JWT that carries a
// jwt_vc_json credential (OID4VP 1.0 appendix B.1.3.1). The header
// names the key, the payload the holder, the audience, the nonce and
// the time.
func VPInput(credential, holder string, key jose.JWK, audience, nonce string, now time.Time) (string, error) {
	jwk, err := jose.JWKToMap(key)
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": string(jose.ES256), "typ": "JWT", "jwk": jwk}
	switch {
	case strings.HasPrefix(holder, "did:jwk:"):
		header["kid"] = holder + "#0"
	case strings.HasPrefix(holder, "did:key:"):
		header["kid"] = holder + "#" + strings.TrimPrefix(holder, "did:key:")
	}
	vp := map[string]any{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": []string{credential},
	}
	payload := map[string]any{"aud": audience, "nonce": nonce, "iat": now.Unix(), "vp": vp}
	if holder != "" {
		payload["iss"], vp["holder"] = holder, holder
	}
	return input(header, payload), nil
}

// CheckVP reports whether a VP JWT of the browser covers an answer: the
// holder key signed it, and it names the audience, the nonce, and the
// credential.
func CheckVP(vp, credential, audience, nonce string, key jose.JWK) error {
	raw, _, err := jose.Verify(vp, key.Key, []jose.Algorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	var claims struct {
		Aud   string `json:"aud"`
		Nonce string `json:"nonce"`
		VP    struct {
			Credentials []string `json:"verifiableCredential"`
		} `json:"vp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fmt.Errorf("%w: %w", ErrVP, err)
	}
	if claims.Aud != audience || claims.Nonce != nonce || len(claims.VP.Credentials) != 1 || claims.VP.Credentials[0] != credential {
		return ErrVP
	}
	return nil
}
