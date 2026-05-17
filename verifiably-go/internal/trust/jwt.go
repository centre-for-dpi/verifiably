package trust

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BuildJWT returns a compact HS256 JWT whose payload is the trust registry
// snapshot. The token is valid for ttl (default 24 h when zero). The secret
// is the raw HMAC-SHA256 key — derive it from VERIFIABLY_SESSION_SECRET via
// sha256.Sum256 before passing it here, so it's always exactly 32 bytes.
//
// Wallets that want to verify the token need the same secret out-of-band.
// For a production national deployment, replace HS256 with ES256 and publish
// the corresponding public key at /.well-known/jwks.json.
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

// VerifyJWT checks the HS256 signature and exp claim. Returns the decoded
// payload on success. Used by tests; production wallets should use a proper
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
