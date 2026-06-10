package handlers

import (
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
// entry. It reuses identityPrefill, so a claim counts as covered exactly when
// National ID prefill would fill it (same snake/camel + EN/ES alias matching) —
// the two features stay in lockstep by construction.
//
// A configuration with no declared claims is available (nothing to satisfy).
// Credentials that need data the citizen's identity doesn't carry — a diploma's
// "degree", a licence's "category" — come back available=false with the gaps
// listed, which is the honest answer: those require an issuer's own data, not
// the citizen's national ID.
func evaluateEligibility(configs []backend.CredentialConfig, claims map[string]string) []eligibilityResult {
	out := make([]eligibilityResult, 0, len(configs))
	for _, c := range configs {
		filled := identityPrefill(c.Claims, claims)
		var missing []string
		for _, name := range c.Claims {
			if _, ok := filled[name]; !ok {
				missing = append(missing, name)
			}
		}
		out = append(out, eligibilityResult{
			ID:            c.ID,
			Available:     len(missing) == 0,
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
		Claims map[string]string `json:"claims"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
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

	results := evaluateEligibility(meta.CredentialsSupported, body.Claims)
	apiJSON(w, http.StatusOK, map[string]any{"credentials": results})
}
