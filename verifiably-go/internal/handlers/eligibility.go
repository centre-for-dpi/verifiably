package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/verifiably/verifiably-go/backend"
)

// eligibilityResult is one credential's eligibility verdict for a citizen.
type eligibilityResult struct {
	ID            string   `json:"id"`
	Available     bool     `json:"available"`
	MissingClaims []string `json:"missing_claims,omitempty"`
}

// evaluateEligibility decides, per credential configuration, whether the
// citizen's verified claims cover every claim the credential carries — i.e.
// whether it can be self-issued from their identity with no operator data
// entry. It matches claims via resolveClaim, the same field↔claim logic
// National ID prefill uses (snake/camel + EN/ES aliases), so the two features
// stay in lockstep by construction. The citizen's claims are normalized ONCE
// here, not per credential.
//
// A credential is `available` only when it declares at least one claim AND the
// citizen covers all of them. A configuration with NO declared claims is
// reported `available=false`: in the discovery catalog an empty claim list
// means "claims unknown" (the metadata path serves cheap, unresolved field
// previews), not "needs nothing". Marking those unavailable is the conservative,
// honest direction — a "Disponible para ti" badge must not over-promise. The
// same applies to credentials that genuinely need issuer-gated data the
// citizen's identity can't supply (a diploma's "degree").
func evaluateEligibility(configs []backend.CredentialConfig, claims map[string]string) []eligibilityResult {
	byNorm := normalizeClaims(claims)
	out := make([]eligibilityResult, 0, len(configs))
	for _, c := range configs {
		var missing []string
		for _, name := range c.Claims {
			if _, ok := resolveClaim(name, byNorm); !ok {
				missing = append(missing, name)
			}
		}
		out = append(out, eligibilityResult{
			ID:            c.ID,
			Available:     len(c.Claims) > 0 && len(missing) == 0,
			MissingClaims: missing,
		})
	}
	return out
}

// APICheckEligibility handles POST /api/v1/credentials/eligible.
//
// Returns which of this member's credentials can be self-issued from a given
// citizen identity — powering a "Disponible para ti" filter in the wallet.
// Eligibility is claims-coverage (see evaluateEligibility): a conservative,
// honest signal that needs no citizen-data registry.
//
// Two auth paths:
//
//  1. API key (Bearer) + optional claims/id_token in body — operator path.
//     Claims may be passed directly (pre-verified upstream) or via id_token
//     (verified here against the IdP's JWKS).
//
//  2. OIDC access_token or id_token in body, no API key — citizen self-check
//     path. The token is verified against the configured providers' JWKS. This
//     is the path the wallet uses to pre-filter the discovery catalog before
//     showing credentials to the citizen. The full (unscoped) catalog is used
//     so the citizen sees eligibility across all schemas this member offers.
//
// The claims body and token may carry PII — neither is logged.
func (h *H) APICheckEligibility(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var body struct {
		AccessToken string            `json:"access_token,omitempty"`
		IDToken     string            `json:"id_token,omitempty"`
		Claims      map[string]string `json:"claims,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	// Citizen self-check path: access_token or id_token in body, no API key.
	// Uses the full (unscoped) catalog so the citizen sees all credentials this
	// member issues, not just those owned by a particular API key holder.
	citizenTok := body.AccessToken
	if citizenTok == "" {
		citizenTok = body.IDToken
	}
	if citizenTok != "" {
		if _, hasKey := h.APIKeys.Authenticate(r); !hasKey {
			if h.RateLimiter != nil && !h.RateLimiter.Allow("citizen-eligible", r) {
				apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			claims, err := h.verifyCitizenToken(r.Context(), citizenTok)
			if err != nil {
				apiError(w, http.StatusUnauthorized, "token verification failed")
				return
			}
			meta, err := h.cachedIssuerMetadata(r.Context())
			if err != nil {
				if errors.Is(err, backend.ErrNotSupported) {
					apiJSON(w, http.StatusOK, map[string]any{"credentials": []eligibilityResult{}})
					return
				}
				apiError(w, http.StatusBadGateway, "issuer metadata unavailable: "+err.Error())
				return
			}
			results := evaluateEligibility(meta.CredentialsSupported, claims)
			apiJSON(w, http.StatusOK, map[string]any{"credentials": results})
			return
		}
	}

	// Operator path: API key required.
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}

	claims := body.Claims
	if body.IDToken != "" {
		verified, err := h.verifyCitizenToken(r.Context(), body.IDToken)
		if err != nil {
			apiError(w, http.StatusUnauthorized, "id_token verification failed")
			return
		}
		claims = verified
	}

	meta, err := h.Adapter.GetIssuerMetadata(apiCtx(r, keyName))
	if err != nil {
		if errors.Is(err, backend.ErrNotSupported) {
			apiJSON(w, http.StatusOK, map[string]any{"credentials": []eligibilityResult{}})
			return
		}
		apiError(w, http.StatusBadGateway, "issuer metadata unavailable: "+err.Error())
		return
	}

	results := evaluateEligibility(meta.CredentialsSupported, claims)
	apiJSON(w, http.StatusOK, map[string]any{"credentials": results})
}

// verifyCitizenToken verifies a citizen's OIDC token against the configured
// identity providers, returning the verified claims from the first provider
// that accepts it. The token's own `iss` binds it to exactly one provider, so
// trying each in turn is safe — non-issuers reject it. Returns an error when no
// provider can verify it (wrong issuer, bad signature, expired, or none
// configured). The token is never logged.
func (h *H) verifyCitizenToken(ctx context.Context, raw string) (map[string]string, error) {
	if h.AuthReg == nil {
		return nil, errors.New("no identity providers configured")
	}
	for _, p := range h.AuthReg.All() {
		claims, err := p.VerifyToken(ctx, raw)
		if err == nil {
			return claims, nil
		}
		slog.Warn("verifyCitizenToken: provider rejected token", "provider", p.ID(), "err", err)
	}
	return nil, errors.New("no configured provider could verify the token")
}
