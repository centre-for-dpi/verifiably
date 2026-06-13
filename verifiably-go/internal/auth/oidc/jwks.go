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
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/jose"
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
	// Fast path: serve from cache without holding the lock across the network
	// fetch below. Holding jwksMu during the HTTP call would serialize every
	// concurrent token verification behind one (possibly slow/hanging) JWKS
	// fetch. The cost is a rare thundering herd on a cold/expired cache — two
	// concurrent fetches, both harmless — which is far cheaper than blocking.
	if !forceRefresh {
		p.jwksMu.Lock()
		cached := p.jwks
		fresh := p.jwks != nil && time.Since(p.jwksAt) < jwksTTL
		p.jwksMu.Unlock()
		if fresh {
			return cached, nil
		}
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
	p.jwksMu.Lock()
	p.jwks = keys
	p.jwksAt = time.Now()
	p.jwksMu.Unlock()
	return keys, nil
}

// jwkToKey converts a single JWK into an RSA or EC public key. Only the
// signature-capable key types OIDC IdPs use are supported (RSA, EC P-256).
func jwkToKey(j jwk) (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := jose.DecodeBase64URLBigInt(j.N)
		if err != nil {
			return nil, err
		}
		eBig, err := jose.DecodeBase64URLBigInt(j.E)
		if err != nil {
			return nil, err
		}
		e := int(eBig.Int64())
		if e == 0 {
			return nil, fmt.Errorf("rsa jwk: zero exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("ec jwk: unsupported curve %q", j.Crv)
		}
		x, err := jose.DecodeBase64URLBigInt(j.X)
		if err != nil {
			return nil, err
		}
		y, err := jose.DecodeBase64URLBigInt(j.Y)
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

	var rawClaims map[string]json.RawMessage
	if err := decodeSegment(parts[1], &rawClaims); err != nil {
		return nil, fmt.Errorf("oidc: decode JWT claims: %w", err)
	}
	// Fast reject on issuer BEFORE any JWKS fetch or signature work. A caller
	// iterating N providers (verifyCitizenToken) must not pay N network fetches
	// for a token that only one provider's `iss` can match.
	if err := p.checkIssuer(rawClaims); err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode JWT signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := p.verifyWithJWKS(ctx, hdr.Kid, hdr.Alg, signingInput, sig); err != nil {
		return nil, err
	}

	// Temporal + audience checks run AFTER signature verification — they only
	// matter once we know the claims are authentic.
	if err := p.checkTemporalAudience(rawClaims); err != nil {
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

// checkIssuer confirms the token's `iss` matches one of this provider's known
// issuer forms (discovered, internal, or public) — that is what binds the token
// to this provider despite the docker-internal vs browser-facing URL split.
// Uses only config + already-discovered metadata (no forced network), so it is
// safe to call before the JWKS fetch as a fast reject.
func (p *Provider) checkIssuer(claims map[string]json.RawMessage) error {
	iss, _ := decodeString(claims, "iss")
	known := []string{p.cfg.IssuerURL, p.cfg.PublicIssuerURL}
	if p.meta != nil {
		known = append(known, p.meta.Issuer)
	}
	for _, k := range known {
		if k != "" && strings.TrimRight(iss, "/") == strings.TrimRight(k, "/") {
			return nil
		}
	}
	return fmt.Errorf("oidc: token iss %q does not match provider %q", iss, p.cfg.ID)
}

// nbfLeewaySeconds tolerates small clock skew between the IdP and this server
// when checking `nbf` (not-before), avoiding spurious rejects of freshly-minted
// tokens.
const nbfLeewaySeconds = 60

// checkTemporalAudience validates `exp`, `nbf`, and `aud`. It runs only after
// the signature is verified.
//
//   - exp: reject once expired (no leeway).
//   - nbf: reject a token that becomes valid more than nbfLeewaySeconds in the
//     future (clock-skew tolerant).
//   - aud: when this provider has a ClientID AND the token carries an `aud`
//     claim, the ClientID must appear in the audience. This rejects tokens minted
//     by the same IdP for a different relying party (RFC 7519 §4.1.3, OIDC Core
//     §3.1.3.7). Tokens without `aud` are allowed — issuer + signature bind them
//     to this provider. For Keycloak access_tokens to pass this check, configure
//     an "Audience" client-scope mapper that adds the clientId to `aud`.
func (p *Provider) checkTemporalAudience(claims map[string]json.RawMessage) error {
	now := time.Now().Unix()
	if exp, ok := decodeInt(claims, "exp"); ok && exp > 0 && now >= exp {
		return fmt.Errorf("oidc: token expired")
	}
	if nbf, ok := decodeInt(claims, "nbf"); ok && nbf > 0 && now+nbfLeewaySeconds < nbf {
		return fmt.Errorf("oidc: token not yet valid (nbf)")
	}
	if p.cfg.ClientID != "" {
		if auds, ok := decodeAudiences(claims); ok && len(auds) > 0 {
			found := false
			for _, a := range auds {
				if a == p.cfg.ClientID {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("oidc: token aud does not include client %q", p.cfg.ClientID)
			}
		}
	}
	return nil
}

// decodeInt extracts a numeric claim as int64. JWT numeric date claims are
// JSON numbers.
func decodeInt(m map[string]json.RawMessage, key string) (int64, bool) {
	raw, ok := m[key]
	if !ok {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	return n, true
}

// decodeAudiences extracts the `aud` claim, which per RFC 7519 may be either a
// single string or an array of strings.
func decodeAudiences(m map[string]json.RawMessage) ([]string, bool) {
	raw, ok := m["aud"]
	if !ok {
		return nil, false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, true
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, true
	}
	return nil, false
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
		return jose.VerifyES256(pub, signingInput, sig)
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
