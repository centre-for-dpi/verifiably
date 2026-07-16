package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/jobs"
	"github.com/verifiably/verifiably-go/vctypes"
)

// registerDelegationSchemas registers the subject + delegation credential TYPES
// in the DPG catalog (idempotent). Split out of APIDelegationIssue so a bulk job
// registers ONCE and fans out issuance per row — re-registering per row would
// restart issuer-api (walt.id) on every credential.
func (h *H) registerDelegationSchemas(ctx context.Context, issuerDpg, subjType, delegType, std string) (vctypes.Schema, vctypes.Schema, error) {
	subjSchema := delegationCredSchema(subjType, issuerDpg, []string{"subjectRef", "givenName"}, std)
	delegSchema := delegationCredSchema(delegType, issuerDpg, []string{"onBehalfOf", "role", "delegation"}, std)
	if err := h.Adapter.SaveCustomSchema(ctx, subjSchema); err != nil {
		return subjSchema, delegSchema, fmt.Errorf("register subject schema: %w", err)
	}
	if err := h.Adapter.SaveCustomSchema(ctx, delegSchema); err != nil {
		return subjSchema, delegSchema, fmt.Errorf("register delegation schema: %w", err)
	}
	return subjSchema, delegSchema, nil
}

// issueDelegationPairCore issues ONE subject+delegation pair against schemas that
// are ALREADY registered. Shared by the single-issue endpoint (APIDelegationIssue)
// and by each row of a bulk job. req.IssuerDpg/Std/Flow are expected resolved.
func (h *H) issueDelegationPairCore(ctx context.Context, keyName string, req apiDelegationIssueRequest, subjSchema, delegSchema vctypes.Schema) (apiDelegationIssueResult, error) {
	issuerDpg := req.IssuerDpg
	std := orDefault(req.Std, "w3c_vcdm_2")
	flow := orDefault(req.Flow, "pre_auth")
	ctxURL := orDefault(req.ContextURL, delegationContextURL())
	subjType, delegType := subjSchema.Name, delegSchema.Name
	sdjwt := strings.Contains(std, "sd_jwt")

	// 1. Subject identity credential (no revocation slot).
	subjSpec := delegation.SubjectCredentialSpec{
		DataModel: std, ContextURL: ctxURL, Issuer: req.IssuerDID, SubjectDID: req.Subject.SubjectDID,
		SubjectRef: req.Subject.SubjectRef, Type: subjType, Claims: req.Subject.Claims,
		ValidFrom: req.Subject.ValidFrom, ValidUntil: req.Subject.ValidUntil,
	}
	subjReq := backend.IssueRequest{IssuerDpg: issuerDpg, Schema: subjSchema, Flow: flow}
	if sdjwt {
		subjReq.SubjectData = delegation.SubjectClaims(subjSpec)
	} else {
		body, err := json.Marshal(delegation.BuildSubjectCredential(subjSpec))
		if err != nil {
			return apiDelegationIssueResult{}, fmt.Errorf("build subject credential: %w", err)
		}
		subjReq.CredentialData = body
	}
	subjRes, err := h.Adapter.IssueToWallet(ctx, subjReq)
	if err != nil {
		return apiDelegationIssueResult{}, fmt.Errorf("issue subject credential: %w", err)
	}
	subjID := h.apiRecordIssuance(keyName, subjSchema, issuerDpg, subjRes.OfferURI,
		map[string]string{"subjectRef": req.Subject.SubjectRef}, nil)

	// 2. Delegation credential — allocate a revocation slot, embed it, issue.
	binding, err := h.allocateStatusListBinding(delegSchema)
	if err != nil {
		return apiDelegationIssueResult{}, fmt.Errorf("status list: %w", err)
	}
	delegSpec := delegation.DelegationCredentialSpec{
		DataModel: std, ContextURL: ctxURL, Type: delegType, Issuer: req.IssuerDID, DelegateID: req.Delegation.DelegateID,
		OnBehalfOf: req.Subject.SubjectRef, Role: req.Delegation.Role,
		AllowedAction: req.Delegation.AllowedAction, ValidFrom: req.Delegation.ValidFrom,
		ValidUntil: req.Delegation.ValidUntil,
	}
	delegReq := backend.IssueRequest{IssuerDpg: issuerDpg, Schema: delegSchema, Flow: flow, StatusList: binding}
	if sdjwt {
		delegReq.SubjectData = delegation.DelegationClaims(delegSpec)
	} else {
		if binding != nil {
			delegSpec.Status = &delegation.StatusEntry{PublishURL: binding.PublishURL, Index: binding.Index}
		}
		body, err := json.Marshal(delegation.BuildDelegationCredential(delegSpec))
		if err != nil {
			return apiDelegationIssueResult{}, fmt.Errorf("build delegation credential: %w", err)
		}
		delegReq.CredentialData = body
	}
	delegRes, err := h.Adapter.IssueToWallet(ctx, delegReq)
	if err != nil {
		return apiDelegationIssueResult{}, fmt.Errorf("issue delegation credential: %w", err)
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
	return out, nil
}

type apiDelegationBulkRow struct {
	SubjectRef    string            `json:"subjectRef"`
	Claims        map[string]string `json:"claims,omitempty"`
	DelegateID    string            `json:"delegateId,omitempty"`
	Role          string            `json:"role,omitempty"`
	AllowedAction []string          `json:"allowedAction,omitempty"`
	ValidUntil    string            `json:"validUntil,omitempty"`
}

type apiDelegationBulkRequest struct {
	IssuerDpg      string                 `json:"issuerDpg,omitempty"`
	IssuerDID      string                 `json:"issuerDid,omitempty"`
	Flow           string                 `json:"flow,omitempty"`
	ContextURL     string                 `json:"contextUrl,omitempty"`
	Std            string                 `json:"std,omitempty"`
	SubjectType    string                 `json:"subjectType,omitempty"`
	DelegationType string                 `json:"delegationType,omitempty"`
	Rows           []apiDelegationBulkRow `json:"rows"`
}

// APIDelegationIssueBulk fans out delegated-access PAIR issuance across many rows
// via the async job queue: it registers the two credential types ONCE, then
// submits a single job whose per-row workFn issues a subject+delegation pair.
// Returns 202 + a jobId; progress streams over the existing bulk-job SSE
// (/issuer/issue/bulk/status/{id}).
//
// POST /api/v1/delegation/issue/bulk
func (h *H) APIDelegationIssueBulk(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow(keyName, r) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded — retry in 60 s")
		return
	}
	if h.BulkJobQueue == nil {
		apiError(w, http.StatusServiceUnavailable, "bulk job queue not configured")
		return
	}
	var req apiDelegationBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Rows) == 0 {
		apiError(w, http.StatusBadRequest, "rows required (one per delegation pair)")
		return
	}
	ctx := apiCtx(r, keyName)
	issuerDpg := orDefault(req.IssuerDpg, h.firstIssuerDPG(ctx))
	if issuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}
	std := orDefault(req.Std, "w3c_vcdm_2")
	subjType := orDefault(req.SubjectType, "BirthCertificate")
	delegType := orDefault(req.DelegationType, "DelegatedAccessCredential")

	// Register the two TYPES once — re-registering per row would restart issuer-api.
	subjSchema, delegSchema, err := h.registerDelegationSchemas(ctx, issuerDpg, subjType, delegType, std)
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Flatten each row to a string map the queue persists; the workFn rebuilds the
	// per-pair request from it (claim:* keys carry arbitrary subject claims).
	rows := make(jobs.Rows, 0, len(req.Rows))
	for _, row := range req.Rows {
		if strings.TrimSpace(row.SubjectRef) == "" {
			apiError(w, http.StatusBadRequest, "each row needs subjectRef")
			return
		}
		m := map[string]string{
			"subjectRef":    row.SubjectRef,
			"delegateId":    row.DelegateID,
			"role":          row.Role,
			"allowedAction": strings.Join(row.AllowedAction, ","),
			"validUntil":    row.ValidUntil,
		}
		for k, v := range row.Claims {
			m["claim:"+k] = v
		}
		rows = append(rows, m)
	}

	jobID, err := h.BulkJobQueue.Submit(ctx, rows, func(ctx context.Context, row map[string]string) error {
		pr := apiDelegationIssueRequest{IssuerDpg: issuerDpg, IssuerDID: req.IssuerDID, Flow: req.Flow, ContextURL: req.ContextURL, Std: std}
		pr.Subject.Type = subjType
		pr.Subject.SubjectRef = row["subjectRef"]
		pr.Subject.ValidUntil = row["validUntil"]
		pr.Subject.Claims = map[string]string{}
		for k, v := range row {
			if strings.HasPrefix(k, "claim:") {
				pr.Subject.Claims[strings.TrimPrefix(k, "claim:")] = v
			}
		}
		pr.Delegation.Type = delegType
		pr.Delegation.DelegateID = row["delegateId"]
		pr.Delegation.Role = row["role"]
		if a := strings.TrimSpace(row["allowedAction"]); a != "" {
			pr.Delegation.AllowedAction = strings.Split(a, ",")
		}
		pr.Delegation.ValidUntil = row["validUntil"]
		_, err := h.issueDelegationPairCore(ctx, keyName, pr, subjSchema, delegSchema)
		return err
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "submit bulk job: "+err.Error())
		return
	}
	slog.Info("api: bulk delegation job submitted", "job_id", jobID, "rows", len(rows), "dpg", issuerDpg, "api_key", keyName)
	apiJSON(w, http.StatusAccepted, map[string]any{
		"jobId": jobID, "total": len(rows), "subjectType": subjType, "delegationType": delegType,
		"statusUrl": "/issuer/issue/bulk/status/" + jobID,
	})
}
