package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// jwksTTL bounds how long parsed signing keys are cached before a refresh.
// IdPs rotate keys; a miss on `kid` also forces an immediate refetch, so this
// is just an upper bound for picking up rotations proactively.
const jwksTTL = 10 * time.Minute

type jwkDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// publicKeys fetches and parses this provider's JWKS, caching the result for
// jwksTTL. forceRefresh bypasses the cache (used when a token's kid isn't
// found, to pick up a just-rotated key). The map is keyed by kid; keys without
// a kid are stored under "".
func (p *Provider) publicKeys(ctx context.Context, forceRefresh bool) (map[string]crypto.PublicKey, error) {
	p.jwksMu.Lock()
	defer p.jwksMu.Unlock()
	if !forceRefresh && p.jwks != nil && time.Since(p.jwksAt) < jwksTTL {
		return p.jwks, nil
	}
	m, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	if m.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: provider %q advertises no jwks_uri", p.cfg.ID)
	}
	var doc jwkDoc
	if err := p.client.DoJSON(ctx, http.MethodGet, m.JWKSURI, nil, &doc, nil); err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks %s: %w", m.JWKSURI, err)
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, j := range doc.Keys {
		key, err := jwkToKey(j)
		if err != nil {
			continue // skip unsupported key types rather than failing the whole set
		}
		keys[j.Kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("oidc: jwks for %q had no usable keys", p.cfg.ID)
	}
	p.jwks = keys
	p.jwksAt = time.Now()
	return keys, nil
}

// jwkToKey converts a single JWK into an RSA or EC public key. Only the
// signature-capable key types OIDC IdPs use are supported (RSA, EC P-256).
func jwkToKey(j jwk) (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64uBigInt(j.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(j.E, "="))
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, fmt.Errorf("rsa jwk: zero exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("ec jwk: unsupported curve %q", j.Crv)
		}
		x, err := b64uBigInt(j.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uBigInt(j.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", j.Kty)
	}
}

// VerifyToken verifies a JWT issued by THIS provider: it checks the signature
// against the provider's published JWKS (selected by `kid`), confirms the `iss`
// claim matches this provider's issuer, and that the token is unexpired. On
// success it returns the token's string-valued claims.
//
// It returns an error if the token wasn't issued by this provider or fails any
// check — a caller iterating providers should treat any error as "not mine /
// invalid" and try the next provider. The `aud` claim is intentionally NOT
// checked: access tokens and id_tokens carry different audiences across IdPs,
// and issuer + signature + expiry already bind the token to this provider.
func (p *Provider) VerifyToken(ctx context.Context, raw string) (map[string]string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: token is not a JWT (got %d segments)", len(parts))
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, fmt.Errorf("oidc: decode JWT header: %w", err)
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return nil, fmt.Errorf("oidc: unsupported JWT alg %q (only RS256, ES256)", hdr.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode JWT signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	if err := p.verifyWithJWKS(ctx, hdr.Kid, hdr.Alg, signingInput, sig); err != nil {
		return nil, err
	}

	var rawClaims map[string]json.RawMessage
	if err := decodeSegment(parts[1], &rawClaims); err != nil {
		return nil, fmt.Errorf("oidc: decode JWT claims: %w", err)
	}
	if err := p.validateClaims(rawClaims); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(rawClaims))
	for k := range rawClaims {
		if s, ok := decodeString(rawClaims, k); ok {
			out[k] = s
		}
	}
	return out, nil
}

// verifyWithJWKS selects the key by kid and verifies the signature, refetching
// the JWKS once if the kid is absent (covers a key rotation between cache fills).
func (p *Provider) verifyWithJWKS(ctx context.Context, kid, alg string, signingInput, sig []byte) error {
	keys, err := p.publicKeys(ctx, false)
	if err != nil {
		return err
	}
	if _, ok := keys[kid]; !ok && kid != "" {
		// Unknown kid — the IdP may have rotated. Refetch once.
		if refreshed, rerr := p.publicKeys(ctx, true); rerr == nil {
			keys = refreshed
		}
	}
	// Candidate keys: the kid match if present, otherwise every key in the set
	// (some IdPs omit kid when they publish a single key).
	var candidates []crypto.PublicKey
	if k, ok := keys[kid]; ok {
		candidates = []crypto.PublicKey{k}
	} else {
		for _, k := range keys {
			candidates = append(candidates, k)
		}
	}
	for _, key := range candidates {
		if verifySignature(alg, key, signingInput, sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("oidc: JWT signature verification failed")
}

// validateClaims checks issuer and expiry. The token's `iss` must match one of
// this provider's known issuer forms (discovered, internal, or public) — that
// is what binds the token to this provider despite the docker-internal vs
// browser-facing URL split.
func (p *Provider) validateClaims(claims map[string]json.RawMessage) error {
	iss, _ := decodeString(claims, "iss")
	known := []string{}
	if p.meta != nil {
		known = append(known, p.meta.Issuer)
	}
	known = append(known, p.cfg.IssuerURL, p.cfg.PublicIssuerURL)
	matched := false
	for _, k := range known {
		if k != "" && strings.TrimRight(iss, "/") == strings.TrimRight(k, "/") {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("oidc: token iss %q does not match provider %q", iss, p.cfg.ID)
	}
	if rawExp, ok := claims["exp"]; ok {
		var exp int64
		if err := json.Unmarshal(rawExp, &exp); err == nil && exp > 0 {
			if time.Now().Unix() >= exp {
				return fmt.Errorf("oidc: token expired")
			}
		}
	}
	return nil
}

// verifySignature checks a JWS signature for RS256 or ES256 over signingInput.
func verifySignature(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	h := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RS256 needs an RSA key")
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ES256 needs an EC key")
		}
		// JWS ES256 signatures are raw R||S, 32 bytes each — not ASN.1.
		if len(sig) != 64 {
			return fmt.Errorf("ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, h[:], r, s) {
			return fmt.Errorf("ES256 verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}

// decodeSegment base64url-decodes a JWT segment and JSON-unmarshals it.
func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// b64uBigInt decodes a base64url (unpadded) big-endian integer, as used for
// JWK RSA modulus and EC coordinates.
func b64uBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
