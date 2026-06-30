package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/vctypes"
)

// selfIssueRequest is the body of POST /api/v1/credentials/self-issue.
type selfIssueRequest struct {
	// IDToken is the citizen's OIDC id_token (legacy field — prefer AccessToken).
	IDToken string `json:"id_token,omitempty"`
	// AccessToken is the citizen's OIDC access_token. Preferred over IDToken
	// because the wallet reliably refreshes the access_token on every
	// refreshUser() call, whereas Keycloak may not return a new id_token in
	// refresh responses. Both are verified against the same JWKS.
	AccessToken string `json:"access_token,omitempty"`
	// CredentialConfigurationID is the OID4VCI configuration the citizen picked
	// from the discovery catalog (e.g. "BankId_jwt_vc_json" or a bare schema id).
	CredentialConfigurationID string `json:"credential_configuration_id"`
}

type selfIssueResult struct {
	CredentialID string `json:"credential_id,omitempty"`
	OfferURI     string `json:"offer_uri"`
	PIN          string `json:"pin,omitempty"`
	Flow         string `json:"flow"`
}

// APISelfIssue handles POST /api/v1/credentials/self-issue.
//
// This is the holder-initiated, identity-bound issuance entry point (National
// ID Nivel 2, auth_code activation step c+d): an authenticated citizen asks
// this member to issue a credential to themselves. Unlike the operator API
// (POST /api/v1/credentials/issue — API-key auth, operator supplies subject
// data), here the citizen's verified OIDC id_token is the only credential:
//
//   - the token is verified against the configured IdPs' JWKS (signature, iss, exp);
//   - eligibility is re-checked server-side (claims-coverage) — the citizen can
//     only self-issue what their identity already covers, never an issuer-gated
//     credential (e.g. a diploma's `degree`);
//   - the subject fields are prefilled from the verified claims, NEVER from the
//     request body, so a caller cannot inject arbitrary subject data;
//   - HolderDID is bound to the token `sub`, so the issued VC carries
//     credentialSubject.id / sub (the walt.id builder emits it).
//
// It returns a pre-auth credential offer URI the wallet hands straight to its
// OID4VCI receive flow. The cryptographic `cnf` key binding is performed by the
// DPG from the wallet's proof during the credential request — verifiably-go is
// not in that exchange, so our part is populating HolderDID, not minting `cnf`.
//
// Public + CORS like the other discovery endpoints; the id_token is the
// authN/authZ. The token and the citizen's claims carry PII and are never logged.
func (h *H) APISelfIssue(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.RateLimiter != nil && !h.RateLimiter.Allow("self-issue", r) {
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var body selfIssueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	// Accept access_token (preferred, always fresh after refresh) or id_token
	// (legacy — kept for backwards compatibility with older wallet builds).
	citizenToken := body.AccessToken
	if citizenToken == "" {
		citizenToken = body.IDToken
	}
	if citizenToken == "" {
		apiError(w, http.StatusUnauthorized, "access_token or id_token required")
		return
	}
	if body.CredentialConfigurationID == "" {
		apiError(w, http.StatusBadRequest, "credential_configuration_id required")
		return
	}

	claims, err := h.verifyCitizenToken(r.Context(), citizenToken)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "token verification failed")
		return
	}
	holderDID := strings.TrimSpace(claims["sub"])
	if holderDID == "" {
		apiError(w, http.StatusUnauthorized, "id_token has no sub claim")
		return
	}

	ctx := r.Context()
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		// A verifier-only / non-issuing member has nothing to self-issue.
		if errors.Is(err, backend.ErrNotSupported) {
			apiError(w, http.StatusNotFound, "this member does not issue credentials")
			return
		}
		apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
		return
	}
	schema, ok := selfIssueResolveSchema(schemas, body.CredentialConfigurationID)
	if !ok {
		apiError(w, http.StatusNotFound, "credential configuration not found: "+body.CredentialConfigurationID)
		return
	}
	schema = h.resolveFields(schema)

	// Eligibility gate — identical claims-coverage logic to /eligible, so the
	// two never drift: a citizen can never self-issue a credential whose claims
	// their verified identity does not cover.
	configs := backend.CredentialConfigsFromSchemas([]vctypes.Schema{schema})
	elig := evaluateEligibility(configs, claims)
	if len(elig) == 0 || !elig[0].Available {
		var missing []string
		if len(elig) > 0 {
			missing = elig[0].MissingClaims
		}
		slog.Warn("api: self-issue eligibility failed — token missing claims",
			"config", body.CredentialConfigurationID,
			"missing_claims", missing,
		)
		apiJSON(w, http.StatusForbidden, map[string]any{
			"error":          "not eligible: your identity does not cover this credential's claims",
			"missing_claims": missing,
		})
		return
	}

	// Subject data comes only from the verified claims (eligibility guarantees
	// full coverage), never from the request body.
	subjectData := identityPrefill(schemaFieldNames(schema), claims)

	issuerDpg := h.firstIssuerDPG(ctx)
	if issuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}
	binding, err := h.allocateStatusListBinding(schema)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "status list: "+err.Error())
		return
	}

	issueStart := time.Now()
	res, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg:   issuerDpg,
		Schema:      schema,
		SubjectData: subjectData,
		Flow:        "pre_auth",
		HolderDID:   holderDID,
		StatusList:  binding,
	})
	issueDur := time.Since(issueStart)
	metrics.ObserveDuration("adapter_duration_seconds", issueDur, "dpg", issuerDpg, "op", "self_issue")
	if err != nil {
		metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "error")
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "ok")

	credID := h.apiRecordIssuance("self-service", schema, issuerDpg, res.OfferURI, subjectData, binding)
	slog.Info("api: self-service credential offer minted",
		"credential_id", credID,
		"config", body.CredentialConfigurationID,
		"schema", schema.ID,
		"dpg", issuerDpg,
		"duration_ms", issueDur.Milliseconds(),
	)
	// holderDID (token sub) and subjectData are identifying — deliberately not logged.

	apiJSON(w, http.StatusOK, selfIssueResult{
		CredentialID: credID,
		OfferURI:     res.OfferURI,
		PIN:          res.PIN,
		Flow:         res.Flow,
	})
}

// selfIssueResolveSchema maps an OID4VCI credential_configuration_id back to a
// schema. It tries the exact id first (findSchemaByID covers both the bare
// schema id and any registered variant id), then falls back to the
// "<schemaID>_<wireFormat>" form the walt.id catalog emits (e.g.
// "BankId_jwt_vc_json"), choosing the longest matching schema-id prefix so a
// shorter id can't shadow a longer one.
func selfIssueResolveSchema(schemas []vctypes.Schema, configID string) (vctypes.Schema, bool) {
	if s, ok := findSchemaByID(schemas, configID); ok {
		return s, true
	}
	best := -1
	var pick vctypes.Schema
	for _, s := range schemas {
		if strings.HasPrefix(configID, s.ID+"_") && len(s.ID) > best {
			pick = s
			best = len(s.ID)
		}
	}
	if best >= 0 {
		return pick, true
	}
	return vctypes.Schema{}, false
}

// schemaFieldNames extracts the credential's field names for claim prefill and
// the eligibility check.
func schemaFieldNames(s vctypes.Schema) []string {
	out := make([]string, 0, len(s.FieldsSpec))
	for _, f := range s.FieldsSpec {
		out = append(out, f.Name)
	}
	return out
}
