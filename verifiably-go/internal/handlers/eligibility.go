package handlers

import (
	"context"
	"encoding/json"
	"errors"
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
// Given the citizen's verified claims in the request body, it returns which of
// this member's credentials can be self-issued from that identity — powering a
// "Disponible para ti" badge in the wallet. Eligibility here is claims-coverage
// (see evaluateEligibility): a conservative, honest signal that needs no
// citizen-data registry.
//
// Auth: API key (Bearer), like the other /api/v1 endpoints — the wallet backend
// calls it with the citizen's claims it already obtained at login. Per-citizen
// OIDC-token verification (against the IdP's JWKS) and registry-backed
// eligibility are the auth_code activation step (see National ID Nivel 2).
//
// The claims body may carry PII, so it is never logged.
func (h *H) APICheckEligibility(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var body struct {
		// IDToken, when present, is the citizen's OIDC token. It is verified
		// against the configured providers' JWKS and its claims OVERRIDE the
		// raw Claims below — the verified, trustworthy path. Claims alone is the
		// fallback for callers that have already verified the identity upstream.
		IDToken string            `json:"id_token,omitempty"`
		Claims  map[string]string `json:"claims,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
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
		// A verifier-only / non-issuing member has nothing to be eligible for.
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
		if claims, err := p.VerifyToken(ctx, raw); err == nil {
			return claims, nil
		}
	}
	return nil, errors.New("no configured provider could verify the token")
}
