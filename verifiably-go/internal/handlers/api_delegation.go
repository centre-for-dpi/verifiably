package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

type apiDelegationIssueRequest struct {
	IssuerDpg  string `json:"issuerDpg,omitempty"`
	IssuerDID  string `json:"issuerDid,omitempty"`  // optional; default = the DPG's signing DID
	Flow       string `json:"flow,omitempty"`       // pre_auth (default) | auth_code
	ContextURL string `json:"contextUrl,omitempty"` // default = <public>/static/contexts/delegated-access-v1.jsonld
	Std        string `json:"std,omitempty"`        // w3c_vcdm_2 (default) | w3c_vcdm_1 | "sd_jwt_vc (IETF)"
	Subject    struct {
		Type       string            `json:"type,omitempty"` // default BirthCertificate
		SubjectDID string            `json:"subjectDid,omitempty"`
		SubjectRef string            `json:"subjectRef"` // REQUIRED — stable linkage anchor
		Claims     map[string]string `json:"claims,omitempty"`
		ValidFrom  string            `json:"validFrom,omitempty"`
		ValidUntil string            `json:"validUntil,omitempty"`
	} `json:"subject"`
	Delegation struct {
		Type          string   `json:"type,omitempty"` // default DelegatedAccessCredential
		DelegateID    string   `json:"delegateId"`     // REQUIRED — the delegate (holder)
		Role          string   `json:"role,omitempty"`
		AllowedAction []string `json:"allowedAction,omitempty"`
		ValidFrom     string   `json:"validFrom,omitempty"`
		ValidUntil    string   `json:"validUntil,omitempty"`
	} `json:"delegation"`
}

type apiDelegationCredResult struct {
	CredentialID string `json:"credentialId"`
	Type         string `json:"type"`
	OfferURI     string `json:"offerUri"`
	PIN          string `json:"pin,omitempty"`
}

type apiDelegationIssueResult struct {
	Subject              apiDelegationCredResult `json:"subject"`
	Delegation           apiDelegationCredResult `json:"delegation"`
	StatusListCredential string                  `json:"statusListCredential,omitempty"`
	StatusListIndex      int                     `json:"statusListIndex,omitempty"`
}

// APIDelegationIssue issues a delegated-access credential PAIR — a subject
// identity credential and an issuer-signed delegation credential (nested
// onBehalfOf + termsOfUse capability + revocation status), both W3C VCDM 2.0.
//
// It reuses the existing custom-schema machinery: SaveCustomSchema registers the
// two credential TYPES in the DPG catalog (idempotent), and the nested §6 bodies
// are supplied verbatim via the CredentialData override (the flat SubjectData map
// cannot express them). The DPG signs both (invariant I1).
//
// POST /api/v1/delegation/issue
func (h *H) APIDelegationIssue(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow(keyName, r) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded — retry in 60 s")
		return
	}
	var req apiDelegationIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Subject.SubjectRef) == "" {
		apiError(w, http.StatusBadRequest, "subject.subjectRef required (the stable linkage anchor)")
		return
	}
	// delegateId is OPTIONAL: when omitted, credentialSubject.id is left unset so
	// the DPG's OID4VCI binds it to the claiming holder (the delegate) at claim
	// time — the holder-bound Type-I model. Set it only to pin a known delegate DID.
	ctx := apiCtx(r, keyName)
	issuerDpg := req.IssuerDpg
	if issuerDpg == "" {
		issuerDpg = h.firstIssuerDPG(ctx)
	}
	if issuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}
	flow := orDefault(req.Flow, "pre_auth")
	std := orDefault(req.Std, "w3c_vcdm_2")
	subjType := orDefault(req.Subject.Type, "BirthCertificate")
	delegType := orDefault(req.Delegation.Type, "DelegatedAccessCredential")
	req.IssuerDpg, req.Std, req.Flow = issuerDpg, std, flow

	// Register both credential types (idempotent), then issue the pair via the
	// shared core — the same path each bulk row uses (see APIDelegationIssueBulk).
	subjSchema, delegSchema, err := h.registerDelegationSchemas(ctx, issuerDpg, subjType, delegType, std)
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	out, err := h.issueDelegationPairCore(ctx, keyName, req, subjSchema, delegSchema)
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	slog.Info("api: delegation pair issued",
		"subject_id", out.Subject.CredentialID, "delegation_id", out.Delegation.CredentialID, "dpg", issuerDpg, "api_key", keyName)
	apiJSON(w, http.StatusCreated, out)
}

// delegationCredSchema builds the custom-schema descriptor for one delegated-
// access credential type at the given data-model tier (std). The ID is suffixed
// per std so each data model gets its OWN catalog config (no cross-model collision).
func delegationCredSchema(typeName, issuerDpg string, fields []string, std string) vctypes.Schema {
	fs := make([]vctypes.FieldSpec, 0, len(fields))
	for _, f := range fields {
		fs = append(fs, vctypes.FieldSpec{Name: f, Datatype: "string"})
	}
	id := "da-" + strings.ToLower(typeName)
	switch {
	case strings.Contains(std, "sd_jwt"):
		id += "-sdjwt"
	case std == "w3c_vcdm_1":
		id += "-v1"
	}
	return vctypes.Schema{
		ID:              id,
		Name:            typeName,
		Desc:            "Delegated-access " + typeName,
		Std:             std,
		DPGs:            []string{issuerDpg},
		Custom:          true,
		AdditionalTypes: []string{typeName},
		FieldsSpec:      fs,
	}
}

// delegationContextURL is the deployment's hosted @context URL (served by the
// static file handler). Empty when VERIFIABLY_PUBLIC_URL is unset.
func delegationContextURL() string {
	base := strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/")
	if base == "" {
		return ""
	}
	return base + "/static/contexts/delegated-access-v1.jsonld"
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

type apiDelegationVerifyRequest struct {
	VerifierDpg    string `json:"verifierDpg,omitempty"`
	SubjectType    string `json:"subjectType,omitempty"`    // default BirthCertificate
	DelegationType string `json:"delegationType,omitempty"` // default DelegatedAccessCredential
	WireFormat     string `json:"wireFormat,omitempty"`     // default jwt_vc_json
}

// APIDelegationVerifyRequest creates an OID4VP request for the delegated-access
// PAIR — one input-descriptor for the subject identity credential and one for
// the delegation credential — so the holder's wallet presents both. The
// evaluator then runs at result time.
//
// POST /api/v1/delegation/verify/request
func (h *H) APIDelegationVerifyRequest(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req apiDelegationVerifyRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional
	ctx := apiCtx(r, keyName)
	verifierDpg := req.VerifierDpg
	if verifierDpg == "" {
		verifierDpg = h.firstVerifierDPG(ctx)
	}
	if verifierDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no verifier DPG available")
		return
	}
	subjType := orDefault(req.SubjectType, "BirthCertificate")
	delegType := orDefault(req.DelegationType, "DelegatedAccessCredential")
	wf := orDefault(req.WireFormat, "jwt_vc_json")
	delegFields := []string{"onBehalfOf"}
	if strings.Contains(wf, "sd-jwt") {
		// the capability claim must be disclosed for the evaluator to read it
		delegFields = []string{"onBehalfOf", "delegation"}
	}
	templates := []vctypes.OID4VPTemplate{
		delegationVerifyTemplate(subjType, []string{"subjectRef"}, wf),
		delegationVerifyTemplate(delegType, delegFields, wf),
	}
	res, err := h.Adapter.RequestPresentation(ctx, backend.PresentationRequest{
		VerifierDpg: verifierDpg,
		Templates:   templates,
		Policies:    []string{"signature", "expired", "not-before"},
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"requestUri": res.RequestURI,
		"state":      res.State,
		"requested":  []string{subjType, delegType},
	})
}

// APIDelegationVerifyResult polls a delegation verify request and runs the
// delegated-access evaluator over the presented pair.
//
// GET /api/v1/delegation/verify/result/{state}
func (h *H) APIDelegationVerifyResult(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	state := r.PathValue("state")
	if state == "" {
		apiError(w, http.StatusBadRequest, "state required")
		return
	}
	res, err := h.Adapter.FetchPresentationResult(r.Context(), state, "")
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.attachDelegationVerdict(r, &res)
	out := map[string]any{
		"pending":         res.Pending,
		"valid":           res.Valid,
		"method":          res.Method,
		"credentialCount": len(res.Credentials),
		"disclosed":       res.DisclosedFields,
	}
	if res.Delegation != nil {
		out["delegation"] = res.Delegation
	}
	apiJSON(w, http.StatusOK, out)
}

func delegationVerifyTemplate(typeName string, fields []string, wireFormat string) vctypes.OID4VPTemplate {
	tpl := vctypes.OID4VPTemplate{
		Title:          typeName,
		CredentialType: typeName,
		WireFormat:     wireFormat,
		Fields:         fields,
		Disclosure:     "full",
	}
	if strings.Contains(wireFormat, "sd-jwt") {
		// SD-JWT: match by vct, selectively disclose the requested claims (which
		// must include everything the evaluator reads — e.g. `delegation`).
		tpl.Format = "sd_jwt_vc (IETF)"
		tpl.Vct = typeName
		tpl.Disclosure = "selective"
	} else {
		tpl.Format = "w3c_vcdm_2"
	}
	return tpl
}
