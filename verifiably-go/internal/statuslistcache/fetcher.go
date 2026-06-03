package statuslistcache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/didresolver"
)

// Fetcher implements Cache. It fetches status list JWTs from live endpoints,
// verifies their ES256 signatures against the issuer DID document, and
// persists copies to a JSON-backed store for availability when the issuer
// endpoint is unreachable.
type Fetcher struct {
	store    *jsonStore
	resolver didresolver.Resolver
	ttl      time.Duration
}

// NewFetcher creates a Fetcher that caches status lists under stateDir/status-list-cache/.
func NewFetcher(stateDir string, resolver didresolver.Resolver) *Fetcher {
	return &Fetcher{
		store:    newJSONStore(filepath.Join(stateDir, "status-list-cache")),
		resolver: resolver,
		ttl:      6 * time.Hour,
	}
}

// Fetch retrieves the status list at listURL for issuerDID.
// Tries a live fetch (3 s timeout) first; on failure returns the cached copy.
// JWT signature verification is attempted but failures only produce a warning
// (except clear signature mismatches which return an error regardless of policy).
func (f *Fetcher) Fetch(ctx context.Context, issuerDID, listURL string) (Result, error) {
	rawJWT, err := f.fetchLive(ctx, listURL)
	if err == nil {
		if verifyErr := f.verifyJWT(ctx, rawJWT, issuerDID); verifyErr != nil {
			slog.Warn("status list: JWT verification warning", "url", listURL, "err", verifyErr)
			if strings.Contains(verifyErr.Error(), "signature") {
				return Result{Source: "unknown"}, fmt.Errorf("status list signature invalid: %w", verifyErr)
			}
		}
		r := Result{
			RawJWT:    rawJWT,
			Source:    "live",
			CachedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(f.ttl),
		}
		if saveErr := f.store.save(entry{
			IssuerDID: issuerDID,
			ListURL:   listURL,
			RawJWT:    rawJWT,
			CachedAt:  r.CachedAt,
			ExpiresAt: r.ExpiresAt,
		}); saveErr != nil {
			slog.Warn("status list: cache write failed", "url", listURL, "err", saveErr)
		}
		return r, nil
	}

	slog.Warn("status list: live fetch failed, trying cache", "url", listURL, "err", err)
	if cached, ok := f.store.load(listURL); ok {
		return Result{
			RawJWT:    cached.RawJWT,
			Source:    "cached",
			CachedAt:  cached.CachedAt,
			ExpiresAt: cached.ExpiresAt,
		}, nil
	}
	return Result{Source: "unknown"}, fmt.Errorf("status list unavailable and no cache for %s: %w", listURL, err)
}

// fetchLive GETs the status list URL with a 3-second timeout.
// It handles two response formats: a raw JWT string or a JSON object containing
// the JWT under one of the common key names ("token", "jwt", "verifiableCredential").
func (f *Fetcher) fetchLive(ctx context.Context, listURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", listURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", listURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	raw := strings.TrimSpace(string(body))
	if strings.HasPrefix(raw, "{") {
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			for _, key := range []string{"token", "jwt", "verifiableCredential"} {
				if v, ok := obj[key].(string); ok && strings.Contains(v, ".") {
					return v, nil
				}
			}
		}
	}
	return raw, nil
}

// verifyJWT attempts ES256 JWT signature verification against the issuer's DID document.
// Resolution and format failures produce warnings but do not block caching.
// A detected signature mismatch returns an error.
func (f *Fetcher) verifyJWT(ctx context.Context, rawJWT, issuerDID string) error {
	if f.resolver == nil || rawJWT == "" {
		return nil
	}
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil // not a JWT — skip verification
	}
	// Try to override issuerDID with the JWT's own `iss` claim.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		var payload struct {
			Iss string `json:"iss"`
		}
		if json.Unmarshal(payloadJSON, &payload) == nil && strings.HasPrefix(payload.Iss, "did:") {
			issuerDID = payload.Iss
		}
	}
	if !strings.HasPrefix(issuerDID, "did:") {
		return nil
	}
	doc, err := f.resolver.Resolve(ctx, issuerDID)
	if err != nil {
		slog.Warn("status list: DID resolution failed (skipping sig check)", "did", issuerDID, "err", err)
		return nil
	}
	if len(doc.VerificationMethods) == 0 {
		return nil // no keys to verify against
	}
	for _, vm := range doc.VerificationMethods {
		if vm.PublicKeyJWK == nil {
			continue
		}
		if err := verifyES256JWT(parts, vm.PublicKeyJWK); err == nil {
			return nil
		}
	}
	return fmt.Errorf("signature verification failed against %d DID key(s)", len(doc.VerificationMethods))
}

// verifyES256JWT verifies an ES256 JWT given its base64url-encoded parts and a JWK map.
// Only P-256 EC keys are supported.
func verifyES256JWT(parts []string, jwk map[string]any) error {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	if kty != "EC" || crv != "P-256" {
		return fmt.Errorf("unsupported JWK type: %s/%s", kty, crv)
	}
	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return fmt.Errorf("decode y: %w", err)
	}
	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// Signing input: base64url(header) + "." + base64url(payload)
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	// ES256 signature is R||S, 32 bytes each for P-256.
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid ES256 signature length: %d (want 64)", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(&pub, h[:], r, s) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}
