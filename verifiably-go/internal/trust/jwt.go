package trust

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BuildJWT returns a compact HS256 JWT whose payload is the trust registry
// snapshot. Used as a dev/fallback path when VERIFIABLY_TRUST_SIGNING_KEY is
// not set. Verifiers need the HMAC secret out-of-band to validate the token.
//
// For production federation, use BuildJWTES256 + publish the public key at
// /.well-known/jwks.json so any verifier can validate without a shared secret.
func BuildJWT(issuers []TrustedIssuer, issuerID string, secret []byte, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()

	hdr, err := b64j(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := b64j(map[string]any{
		"iss":     issuerID,
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
		"issuers": issuers,
	})
	if err != nil {
		return "", err
	}

	sigInput := hdr + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return sigInput + "." + sig, nil
}

// BuildJWTES256 returns a compact ES256 JWT signed with the ECDSA P-256 key.
// The public key must be published at /.well-known/jwks.json so verifiers can
// validate without a shared secret — mandatory for production federation and
// the upgrade path to OpenID Federation 1.0.
func BuildJWTES256(issuers []TrustedIssuer, issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()

	hdr, err := b64j(map[string]string{"alg": "ES256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := b64j(map[string]any{
		"iss":     issuerID,
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
		"issuers": issuers,
	})
	if err != nil {
		return "", err
	}

	sigInput := hdr + "." + payload
	hash := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", fmt.Errorf("trust: ES256 sign: %w", err)
	}

	// JWT ES256 signature is R || S, each zero-padded to 32 bytes (P-256 curve size).
	const curveBytes = 32
	sig := make([]byte, 2*curveBytes)
	r.FillBytes(sig[:curveBytes])
	s.FillBytes(sig[curveBytes:])

	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// PublicKeyToJWK converts an ECDSA P-256 public key to a JWK map.
// The returned map is suitable for embedding directly in a JWKS response.
func PublicKeyToJWK(pub *ecdsa.PublicKey) map[string]any {
	const curveBytes = 32
	xBytes := make([]byte, curveBytes)
	yBytes := make([]byte, curveBytes)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		"alg": "ES256",
		"use": "sig",
	}
}

// VerifyJWT checks the HS256 signature and exp claim. Returns the decoded
// payload on success. Used by tests; production verifiers should use a proper
// JWT library with full claim validation.
func VerifyJWT(token string, secret []byte) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("trust: malformed JWT")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return nil, fmt.Errorf("trust: JWT signature invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("trust: JWT payload decode: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("trust: JWT payload unmarshal: %w", err)
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("trust: JWT expired")
		}
	}
	return claims, nil
}

func b64j(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("trust: marshal JWT part: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
