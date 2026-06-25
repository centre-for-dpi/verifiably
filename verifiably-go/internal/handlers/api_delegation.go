package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/vctypes"
)

type apiDelegationIssueRequest struct {
	IssuerDpg  string `json:"issuerDpg,omitempty"`
	IssuerDID  string `json:"issuerDid,omitempty"`  // optional; default = the DPG's signing DID
	Flow       string `json:"flow,omitempty"`       // pre_auth (default) | auth_code
	ContextURL string `json:"contextUrl,omitempty"` // default = <public>/static/contexts/delegated-access-v1.jsonld
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
	if strings.TrimSpace(req.Delegation.DelegateID) == "" {
		apiError(w, http.StatusBadRequest, "delegation.delegateId required (the delegate / holder)")
		return
	}
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
	ctxURL := orDefault(req.ContextURL, delegationContextURL())
	subjType := orDefault(req.Subject.Type, "BirthCertificate")
	delegType := orDefault(req.Delegation.Type, "DelegatedAccessCredential")

	// 1. Register both credential types in the DPG catalog (idempotent reuse of
	//    the existing custom-schema path). Flat fields suffice — the catalog only
	//    needs the type to exist; the nested body comes from the override below.
	subjSchema := delegationCredSchema(subjType, issuerDpg, []string{"subjectRef", "givenName"})
	delegSchema := delegationCredSchema(delegType, issuerDpg, []string{"onBehalfOf", "role"})
	if err := h.Adapter.SaveCustomSchema(ctx, subjSchema); err != nil {
		apiError(w, http.StatusBadGateway, "register subject schema: "+err.Error())
		return
	}
	if err := h.Adapter.SaveCustomSchema(ctx, delegSchema); err != nil {
		apiError(w, http.StatusBadGateway, "register delegation schema: "+err.Error())
		return
	}

	// 2. Subject identity credential (no revocation slot).
	subjBody, err := json.Marshal(delegation.BuildSubjectCredential(delegation.SubjectCredentialSpec{
		ContextURL: ctxURL, Issuer: req.IssuerDID, SubjectDID: req.Subject.SubjectDID,
		SubjectRef: req.Subject.SubjectRef, Type: subjType, Claims: req.Subject.Claims,
		ValidFrom: req.Subject.ValidFrom, ValidUntil: req.Subject.ValidUntil,
	}))
	if err != nil {
		apiError(w, http.StatusInternalServerError, "build subject credential: "+err.Error())
		return
	}
	subjRes, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg: issuerDpg, Schema: subjSchema, Flow: flow, CredentialData: subjBody,
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, "issue subject credential: "+err.Error())
		return
	}
	subjID := h.apiRecordIssuance(keyName, subjSchema, issuerDpg, subjRes.OfferURI,
		map[string]string{"subjectRef": req.Subject.SubjectRef}, nil)

	// 3. Delegation credential — allocate a revocation slot, embed it, issue.
	binding, err := h.allocateStatusListBinding(delegSchema)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "status list: "+err.Error())
		return
	}
	var status *delegation.StatusEntry
	if binding != nil {
		status = &delegation.StatusEntry{PublishURL: binding.PublishURL, Index: binding.Index}
	}
	delegBody, err := json.Marshal(delegation.BuildDelegationCredential(delegation.DelegationCredentialSpec{
		ContextURL: ctxURL, Issuer: req.IssuerDID, DelegateID: req.Delegation.DelegateID,
		OnBehalfOf: req.Subject.SubjectRef, Role: req.Delegation.Role,
		AllowedAction: req.Delegation.AllowedAction, ValidFrom: req.Delegation.ValidFrom,
		ValidUntil: req.Delegation.ValidUntil, Status: status,
	}))
	if err != nil {
		apiError(w, http.StatusInternalServerError, "build delegation credential: "+err.Error())
		return
	}
	delegRes, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg: issuerDpg, Schema: delegSchema, Flow: flow, CredentialData: delegBody, StatusList: binding,
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, "issue delegation credential: "+err.Error())
		return
	}
	delegID := h.apiRecordIssuance(keyName, delegSchema, issuerDpg, delegRes.OfferURI,
		map[string]string{"onBehalfOf": req.Subject.SubjectRef, "delegate": req.Delegation.DelegateID}, binding)

	out := apiDelegationIssueResult{
		Subject:    apiDelegationCredResult{CredentialID: subjID, Type: subjType, OfferURI: subjRes.OfferURI, PIN: subjRes.PIN},
		Delegation: apiDelegationCredResult{CredentialID: delegID, Type: delegType, OfferURI: delegRes.OfferURI, PIN: delegRes.PIN},
	}
	if binding != nil {
		out.StatusListCredential = binding.PublishURL
		out.StatusListIndex = binding.Index
	}
	slog.Info("api: delegation pair issued",
		"subject_id", subjID, "delegation_id", delegID, "dpg", issuerDpg, "api_key", keyName)
	apiJSON(w, http.StatusCreated, out)
}

// delegationCredSchema builds the custom-schema descriptor for one delegated-
// access credential type. Std is fixed to w3c_vcdm_2 (T1).
func delegationCredSchema(typeName, issuerDpg string, fields []string) vctypes.Schema {
	fs := make([]vctypes.FieldSpec, 0, len(fields))
	for _, f := range fields {
		fs = append(fs, vctypes.FieldSpec{Name: f, Datatype: "string"})
	}
	return vctypes.Schema{
		ID:              "da-" + strings.ToLower(typeName),
		Name:            typeName,
		Desc:            "Delegated-access " + typeName,
		Std:             "w3c_vcdm_2",
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
