package statuslistcache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/didresolver"
	"github.com/verifiably/verifiably-go/internal/jose"
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
	rawJWT, err := f.fetchLiveRetry(ctx, listURL)
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

// fetchLiveRetry retries fetchLive a few times with a short backoff so a cold
// endpoint — the status list just after issuance, or a cold hairpin route —
// does not fail-closed on the first attempt (the "first verify fails, retry
// succeeds" flakiness, B4). A fast failure (connection refused) retries almost
// immediately; only a hanging endpoint pays the per-attempt timeout.
func (f *Fetcher) fetchLiveRetry(ctx context.Context, listURL string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 400 * time.Millisecond):
			}
		}
		raw, err := f.fetchLive(ctx, listURL)
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}
	return "", lastErr
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
	// Ask for the JOSE-secured (JWS) status list so we can verify its signature.
	// The status-list endpoint now defaults to a JSON-LD VC (for external W3C
	// verifiers like MOSIP Inji Verify that JSON.parse the response); we're a
	// signature-verifying consumer, so we opt into the JWS form explicitly.
	req.Header.Set("Accept", "application/vc+jwt")
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
	if rawJWT == "" {
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
	// did:jwk embeds the public key directly, so no network resolution is needed.
	// Skipping it (the resolver only handles did:web) left did:jwk-signed status
	// lists — walt.id's — with their signatures UNVERIFIED, i.e. revocation
	// trusted on faith (P2).
	if strings.HasPrefix(issuerDID, "did:jwk:") {
		jwk, err := decodeDIDJWK(issuerDID)
		if err != nil {
			slog.Warn("status list: invalid did:jwk issuer (skipping sig check)", "did", issuerDID, "err", err)
			return nil
		}
		if verr := verifyES256JWT(parts, jwk); verr != nil {
			// Only a genuine P-256 signature mismatch is fatal; an unsupported key
			// type or malformed field means we can't check it here — skip rather
			// than false-deny a legitimate credential.
			if errors.Is(verr, jose.ErrSignatureInvalid) {
				return fmt.Errorf("status list did:jwk signature invalid: %w", verr)
			}
			slog.Warn("status list: did:jwk sig check skipped", "did", issuerDID, "err", verr)
			return nil
		}
		return nil
	}
	// Other DID methods (did:web) require the resolver.
	if f.resolver == nil {
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
	x, err := jose.DecodeBase64URLBigInt(xStr)
	if err != nil {
		return fmt.Errorf("decode x: %w", err)
	}
	y, err := jose.DecodeBase64URLBigInt(yStr)
	if err != nil {
		return fmt.Errorf("decode y: %w", err)
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	// Signing input: base64url(header) + "." + base64url(payload).
	return jose.VerifyES256(&pub, []byte(parts[0]+"."+parts[1]), sigBytes)
}

// decodeDIDJWK decodes a did:jwk identifier (did:jwk:<base64url(JWK JSON)>, an
// optional #fragment ignored) into its JWK map. did:jwk carries the public key
// inline, so verification needs no network resolution.
func decodeDIDJWK(did string) (map[string]any, error) {
	enc := strings.TrimPrefix(did, "did:jwk:")
	if i := strings.IndexByte(enc, '#'); i >= 0 {
		enc = enc[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(enc); err != nil {
			return nil, fmt.Errorf("did:jwk base64url: %w", err)
		}
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("did:jwk JWK JSON: %w", err)
	}
	return jwk, nil
}
