// SPDX-License-Identifier: Apache-2.0

// Package jose signs and verifies compact JWS tokens and parses JWK material.
// It wraps github.com/go-jose/go-jose/v4 (RFC 7515, RFC 7517, RFC 7518).
// It supports ES256 and EdDSA for signing. It supports RS256 in addition
// for verification of tokens issued by identity providers.
// The package is pure. It holds no state and performs no I/O.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gojose "github.com/go-jose/go-jose/v4"
)

// Algorithm is a JWS signature algorithm name (RFC 7518 section 3.1).
type Algorithm string

// Supported algorithms.
const (
	ES256 Algorithm = "ES256"
	EdDSA Algorithm = "EdDSA"
	RS256 Algorithm = "RS256"
)

// SigningAlgorithms lists the algorithms Sign accepts.
var SigningAlgorithms = []Algorithm{ES256, EdDSA}

// ErrSignatureInvalid reports that the signature did not match the key.
var ErrSignatureInvalid = errors.New("jose: signature verification failed")

// ErrNoKey reports that no key in a JWKS matched the token header.
var ErrNoKey = errors.New("jose: no matching key")

// JWK is a JSON Web Key (RFC 7517).
type JWK = gojose.JSONWebKey

// JWKS is a JSON Web Key Set (RFC 7517 section 5).
type JWKS = gojose.JSONWebKeySet

// Header is the subset of a JWS protected header the callers need.
type Header struct {
	Alg string
	Kid string
	Typ string
}

// AlgorithmFor returns the JWS algorithm that matches the key type.
// The curve of an ECDSA key is checked when the key signs.
func AlgorithmFor(key crypto.PrivateKey) (Algorithm, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return ES256, nil
	case ed25519.PrivateKey:
		return EdDSA, nil
	}
	return "", fmt.Errorf("jose: unsupported private key type %T", key)
}

// GenerateKey creates a new private key for alg.
func GenerateKey(alg Algorithm) (crypto.PrivateKey, error) {
	switch alg {
	case ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("jose: cannot generate key for alg %q", alg)
}

// Sign returns a compact JWS over the JSON encoding of claims.
// The header carries alg, typ and, when kid is not empty, kid.
func Sign(key crypto.PrivateKey, kid, typ string, claims any) (string, error) {
	alg, err := AlgorithmFor(key)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jose: marshal claims: %w", err)
	}
	opts := (&gojose.SignerOptions{}).WithType(gojose.ContentType(typ))
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.SignatureAlgorithm(alg), Key: key}, opts)
	if err != nil {
		return "", fmt.Errorf("jose: new signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("jose: sign: %w", err)
	}
	// CompactSerialize fails only for multi-signature objects. Sign makes one.
	out, _ := jws.CompactSerialize()
	return out, nil
}

// PeekHeader decodes the protected header of a compact JWS without verification.
func PeekHeader(token string) (Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, fmt.Errorf("jose: token must have 3 segments, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, fmt.Errorf("jose: decode header: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	return Header{Alg: h.Alg, Kid: h.Kid, Typ: h.Typ}, nil
}

// PeekPayload decodes the payload of a compact JWS without verification.
// Callers must verify the token before they trust the claims.
func PeekPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jose: token must have 3 segments, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jose: decode payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("jose: parse payload: %w", err)
	}
	return m, nil
}

// Verify checks the signature of a compact JWS with one public key.
// The token alg must be one of algs. It returns the verified payload.
func Verify(token string, key crypto.PublicKey, algs []Algorithm) ([]byte, Header, error) {
	jws, hdr, err := parse(token, algs)
	if err != nil {
		return nil, Header{}, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, hdr, ErrSignatureInvalid
	}
	return payload, hdr, nil
}

// VerifyWithJWKS checks the signature with a key from the set.
// When the header has a kid, only keys with that kid are tried.
// When the header has no kid, every key in the set is tried.
func VerifyWithJWKS(token string, set JWKS, algs []Algorithm) ([]byte, Header, error) {
	jws, hdr, err := parse(token, algs)
	if err != nil {
		return nil, Header{}, err
	}
	candidates := set.Keys
	if hdr.Kid != "" {
		candidates = set.Key(hdr.Kid)
	}
	if len(candidates) == 0 {
		return nil, hdr, ErrNoKey
	}
	for _, k := range candidates {
		if payload, err := jws.Verify(k.Key); err == nil {
			return payload, hdr, nil
		}
	}
	return nil, hdr, ErrSignatureInvalid
}

func parse(token string, algs []Algorithm) (*gojose.JSONWebSignature, Header, error) {
	hdr, err := PeekHeader(token)
	if err != nil {
		return nil, Header{}, err
	}
	allowed := make([]gojose.SignatureAlgorithm, 0, len(algs))
	for _, a := range algs {
		allowed = append(allowed, gojose.SignatureAlgorithm(a))
	}
	jws, err := gojose.ParseSigned(token, allowed)
	if err != nil {
		return nil, hdr, fmt.Errorf("jose: parse: %w", err)
	}
	return jws, hdr, nil
}

// ParseJWK decodes one JSON Web Key.
func ParseJWK(raw []byte) (JWK, error) {
	var k JWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return JWK{}, fmt.Errorf("jose: parse jwk: %w", err)
	}
	if !k.Valid() {
		return JWK{}, errors.New("jose: invalid jwk")
	}
	return k, nil
}

// ParseJWKS decodes a JSON Web Key Set. Keys that fail to parse are skipped.
// It returns an error when the set holds no usable key.
func ParseJWKS(raw []byte) (JWKS, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return JWKS{}, fmt.Errorf("jose: parse jwks: %w", err)
	}
	var set JWKS
	for _, rk := range doc.Keys {
		k, err := ParseJWK(rk)
		if err != nil {
			continue
		}
		set.Keys = append(set.Keys, k)
	}
	if len(set.Keys) == 0 {
		return JWKS{}, errors.New("jose: jwks has no usable key")
	}
	return set, nil
}

// PublicJWK wraps a public key as a JWK with the given kid.
// Private keys are reduced to their public half.
func PublicJWK(key any, kid string) (JWK, error) {
	var pub crypto.PublicKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
		pub = k
	default:
		return JWK{}, fmt.Errorf("jose: unsupported key type %T", key)
	}
	jwk := JWK{Key: pub, KeyID: kid, Use: "sig"}
	if alg, err := algForPublic(pub); err == nil {
		jwk.Algorithm = string(alg)
	}
	return jwk, nil
}

func algForPublic(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("jose: unsupported curve %s", k.Curve.Params().Name)
		}
		return ES256, nil
	case ed25519.PublicKey:
		return EdDSA, nil
	}
	return RS256, nil
}

// Thumbprint returns the base64url SHA-256 JWK thumbprint (RFC 7638).
func Thumbprint(k JWK) (string, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jose: thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// JWKFromMap converts a decoded JWK object into a JWK.
func JWKFromMap(m map[string]any) (JWK, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return JWK{}, fmt.Errorf("jose: marshal jwk: %w", err)
	}
	return ParseJWK(raw)
}

// JWKToMap converts a JWK into its JSON object form.
func JWKToMap(k JWK) (map[string]any, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("jose: marshal jwk: %w", err)
	}
	// The JSON came from the marshaller one line above, so it always parses.
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, nil
}
