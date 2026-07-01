package handlers

import (
	"context"
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// SubjectProvisioner upserts dynamic claims into the Inji auth-code data-provider
// table (certify.vc_subject), keyed by the eSignet subject id. Implemented by
// *pg.SubjectStore; nil when INJI_CERTIFY_DATABASE_URL is unset.
type SubjectProvisioner interface {
	ProvisionSubject(ctx context.Context, subjectID string, claims map[string]string) error
	// ListCredentials returns the discoverable credentials ({key, scope, displayName}).
	ListCredentials(ctx context.Context) ([]map[string]string, error)
	// CredentialScope returns the eSignet scope for a credential_config key.
	CredentialScope(ctx context.Context, key string) (string, error)
	// CredentialClaimSpec returns the format + @context + vct for claiming a credential.
	CredentialClaimSpec(ctx context.Context, key string) (format, vcContext, vct string, err error)
	// ApplyAuthcodeSchema creates a Flow B credential (extraction view +
	// credential_config, any data model) in one transaction.
	ApplyAuthcodeSchema(ctx context.Context, viewDDL, key, vcTemplateB64, credFormat, display, scope string, displayOrder []string, sdJwtVct, vcContext, credType, credsub *string, ownerKey string) error
	// ListMyCredentials returns the active credentials created by the given owner (issuer).
	ListMyCredentials(ctx context.Context, ownerKey string) ([]map[string]string, error)
	// CredentialFields returns a credential's claim field names (for the provisioning form).
	CredentialFields(ctx context.Context, key string) ([]string, error)
	// UpsertIdentity enrolls a foundational citizen identity (demographics) in the
	// authoritative identity registry, keyed by the RAW individualId. Used by the
	// registrar bulk identity-load — the holder never writes here.
	UpsertIdentity(ctx context.Context, individualID string, demographics map[string]string) error
	// GetIdentity returns an enrolled identity's demographics, or (nil, nil) when
	// the individualId is not enrolled. The gate the activation flow checks.
	GetIdentity(ctx context.Context, individualID string) (map[string]string, error)
	// DeleteCredential removes an auth-code credential (credential_config + owner
	// row), owner-checked. Backs the issuer schema-browser Delete for DB-backed
	// Inji credentials (the registry adapter only knows in-memory custom schemas).
	DeleteCredential(ctx context.Context, key, ownerKey string) error
}

type apiProvisionSubjectRequest struct {
	IndividualID string            `json:"individualId"`
	ClientID     string            `json:"clientId,omitempty"`
	Claims       map[string]string `json:"claims,omitempty"`
	// Convenience: top-level claim fields are also accepted and merged into Claims.
	FullName    string `json:"fullName,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
	Gender      string `json:"gender,omitempty"`
	DateOfBirth string `json:"dateOfBirth,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
}

// defaultAuthCodeClientID is the OIDC client used by the Inji auth-code (Inji Web)
// flow. The eSignet `sub` (PSU-token) is derived from individualId + this client,
// so it must match the client the holder authenticates with.
func defaultAuthCodeClientID() string {
	if v := strings.TrimSpace(os.Getenv("VERIFIABLY_AUTHCODE_CLIENT_ID")); v != "" {
		return v
	}
	return "wallet-demo-client"
}

// esignetSubjectID reproduces eSignet's PSU-token:
//
//	base64url-nopad( SHA3-256( individualId + clientId ) )
//
// This is what the access-token `sub` carries and what the Certify Postgres
// data-provider binds as :id — so vc_subject must be keyed by it, not the raw
// individualId.
func esignetSubjectID(individualID, clientID string) string {
	sum := sha3.Sum256([]byte(individualID + clientID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// APIProvisionSubject upserts a subject's dynamic claims into certify.vc_subject
// so that, after the holder authenticates via eSignet (auth-code flow), Inji
// Certify issues a credential carrying these claims. Self-service replacement
// for the manual `INSERT INTO certify.vc_subject` (Flow A).
//
// POST /api/v1/subjects
//
//	{ "individualId": "9090909090", "clientId": "wallet-demo-client",
//	  "fullName": "Grace Hopper", "givenName": "Grace", "email": "grace@x" }
//
// Returns the computed subjectId (the eSignet PSU-token the row is keyed by).
func (h *H) APIProvisionSubject(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.Subjects == nil {
		apiError(w, http.StatusServiceUnavailable, "subject provisioning not enabled (INJI_CERTIFY_DATABASE_URL not set)")
		return
	}
	var req apiProvisionSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	individualID := strings.TrimSpace(req.IndividualID)
	if individualID == "" {
		apiError(w, http.StatusBadRequest, "individualId required")
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = defaultAuthCodeClientID()
	}
	claims := map[string]string{}
	for k, v := range req.Claims {
		if s := strings.TrimSpace(v); s != "" {
			claims[k] = s
		}
	}
	for k, v := range map[string]string{
		"fullName": req.FullName, "givenName": req.GivenName, "familyName": req.FamilyName,
		"gender": req.Gender, "dateOfBirth": req.DateOfBirth, "email": req.Email, "phoneNumber": req.PhoneNumber,
	} {
		if s := strings.TrimSpace(v); s != "" {
			claims[k] = s
		}
	}
	if len(claims) == 0 {
		apiError(w, http.StatusBadRequest, "at least one claim required")
		return
	}
	subjectID := esignetSubjectID(individualID, clientID)
	if err := h.Subjects.ProvisionSubject(apiCtx(r, keyName), subjectID, claims); err != nil {
		apiError(w, http.StatusInternalServerError, "provision failed: "+err.Error())
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"individualId": individualID,
		"clientId":     clientID,
		"subjectId":    subjectID,
		"claims":       claims,
	})
}
