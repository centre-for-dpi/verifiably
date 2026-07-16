package handlers

// inji_ledger.go — the issuer's issued-credentials view + revoke for the Inji
// auth-code track. Auth-code credentials are claimed asynchronously by holders
// via eSignet, so verifiably never runs recordIssuance for them (unlike walt.id/
// credebl/pre-auth, which verifiably drives synchronously). Instead this reads
// the authoritative record from Certify's own ledger (certify.ledger, via
// SubjectStore.ListLedger, owner-scoped to the issuer's credential_configs) and
// revokes through Certify's status API. The page stays DPG-scoped: an issuer on
// the Inji auth-code track sees ONLY auth-code credentials — never merged with
// another DPG's entries.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/vctypes"
)

// injiLedgerItems builds the issued-credentials list for the Inji auth-code
// track: the ledger entries for every credential_config this issuer owns, mapped
// to the same display shape the list template renders for the other DPGs.
func (h *H) injiLedgerItems(ctx context.Context, ownerKey, dpg string) ([]issuance.IssuedCredential, error) {
	if h.Subjects == nil {
		return nil, nil
	}
	owned, err := h.Subjects.ListMyCredentials(ctx, ownerKey)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(owned))
	for _, c := range owned {
		if k := c["key"]; k != "" {
			keys = append(keys, k)
		}
	}
	rows, err := h.Subjects.ListLedger(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := make([]issuance.IssuedCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, ledgerRowToIssued(row, dpg, ownerKey))
	}
	return out, nil
}

// ledgerRowToIssued maps one certify.ledger row (as returned by
// SubjectStore.ListLedger) into an issuance.IssuedCredential for the template.
// The row ID is the base64url of the Certify credentialId (a URL with slashes),
// so it survives a path segment on the revoke/reinstate routes.
func ledgerRowToIssued(row map[string]string, dpg, ownerKey string) issuance.IssuedCredential {
	idx, _ := strconv.Atoi(row["statusListIndex"])
	issuedAt, _ := time.Parse(time.RFC3339, row["issuedAt"])
	c := issuance.IssuedCredential{
		ID:         base64.RawURLEncoding.EncodeToString([]byte(row["credentialId"])),
		SchemaName: row["credentialType"],
		Std:        "w3c_vcdm_2",
		Format:     "ldp_vc",
		IssuerDpg:  dpg,
		OwnerKey:   ownerKey,
		IssuedAt:   issuedAt,
		Source:     "inji",
		// The credential's claim fields (from certify.ledger.indexed_attributes) +
		// the credentialId, rendered + searched on the card like the other DPGs.
		SubjectFields: ledgerClaims(row),
		StatusList: &issuance.StatusListEntry{
			Type:   "bitstring",
			ListID: row["statusListCredentialId"],
			Index:  idx,
		},
	}
	if row["revoked"] == "true" {
		t := issuedAt
		if ra, err := time.Parse(time.RFC3339, row["revokedAt"]); err == nil {
			t = ra
		}
		c.RevokedAt = &t
	}
	return c
}

// ledgerClaims turns a ledger row's indexed_attributes JSON (row["claims"]) into
// the displayable/searchable claim map for the card. Certify's indexed-mapping
// (`credentialSubject=$.credentialSubject`) nests the claims under
// "credentialSubject"; unwrap that if present, else use the object as-is. The
// holder `id` (a long did:jwk) is dropped as noise. Always includes credentialId.
func ledgerClaims(row map[string]string) map[string]string {
	out := map[string]string{}
	var top map[string]any
	if raw := row["claims"]; raw != "" && json.Unmarshal([]byte(raw), &top) == nil {
		claims := top
		if sub, ok := top["credentialSubject"].(map[string]any); ok && len(top) == 1 {
			claims = sub
		}
		for k, v := range claims {
			if k == "id" || k == "@context" || k == "type" {
				continue
			}
			switch v.(type) {
			case map[string]any, []any:
				continue // skip nested structures — keep the card scannable
			}
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	if cid := row["credentialId"]; cid != "" {
		out["credentialId"] = cid
	}
	return out
}

// recordInjiSDJWTIssuance logs an auth-code SD-JWT credential in verifiably's
// IssuanceLog at provision time. Certify never writes SD-JWT to its ledger, so
// this is the ONLY record of these credentials — it's what lets
// /issuer/credentials list them and revoke them through the token status list.
// The token status Index is the per-holder slot allocated in runBulkProvision.
func (h *H) recordInjiIssuance(sess *Session, schema vctypes.Schema, holderID string, claims map[string]string, idx int, kind string) {
	if h.IssuanceLog == nil {
		return
	}
	listID := ""
	if store := h.storeForKind(kind); store != nil {
		listID = store.GetListID()
	}
	format := "vc+sd-jwt"
	if kind == "bitstring" {
		format = "ldp_vc"
	}
	rec := issuance.IssuedCredential{
		ID:            newIssuanceID(),
		SchemaID:      schema.ID,
		SchemaName:    schema.Name,
		Std:           schema.Std,
		Format:        format,
		IssuerDpg:     sess.IssuerDpg,
		OwnerKey:      sessionOwnerKey(sess),
		HolderHint:    holderID,
		SubjectFields: claims,
		Source:        "inji",
		StatusList: &issuance.StatusListEntry{
			Type:   kind,
			ListID: listID,
			Index:  idx,
		},
	}
	if _, err := h.IssuanceLog.Append(rec); err != nil {
		fmt.Printf("issuance log: append inji %s %s: %v\n", kind, rec.ID, err)
	}
}

// findLedgerRow returns the owner-scoped ledger row for a base64url-encoded row
// ID, and the decoded Certify credentialId. ok is false when the credential
// isn't among the caller's owned credentials (treated as not-found so a guess
// can't probe another issuer's credentials).
func (h *H) findLedgerRow(ctx context.Context, ownerKey, rowID string) (row map[string]string, credentialID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(rowID)
	if err != nil {
		return nil, "", false
	}
	credentialID = string(raw)
	if h.Subjects == nil {
		return nil, credentialID, false
	}
	owned, err := h.Subjects.ListMyCredentials(ctx, ownerKey)
	if err != nil {
		return nil, credentialID, false
	}
	keys := make([]string, 0, len(owned))
	for _, c := range owned {
		if k := c["key"]; k != "" {
			keys = append(keys, k)
		}
	}
	rows, err := h.Subjects.ListLedger(ctx, keys)
	if err != nil {
		return nil, credentialID, false
	}
	for _, r := range rows {
		if r["credentialId"] == credentialID {
			return r, credentialID, true
		}
	}
	return nil, credentialID, false
}

// setInjiCredentialStatus flips a credential's revocation bit through Certify's
// status API (POST /v1/certify/credentials/status). revoke=true revokes,
// revoke=false reinstates. Certify queues the change and its async job re-signs
// the bitstring status-list VC.
func setInjiCredentialStatus(ctx context.Context, credentialID, statusListCredentialID string, index int, revoke bool) error {
	body, _ := json.Marshal(map[string]any{
		"credentialId": credentialID,
		"status":       revoke,
		"credentialStatus": map[string]any{
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":        "revocation",
			"statusListIndex":      index,
			"statusListCredential": statusListCredentialID,
		},
	})
	ep := injiCertifyUpstream() + "/v1/certify/credentials/status"
	status, respBody, err := postJSON(ctx, ep, body, "")
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("certify status %d: %s", status, truncateForLog(string(respBody), 200))
	}
	// A 2xx with an {"errors":[...]} envelope is still a failure in Certify's API.
	var env struct {
		Errors []struct {
			ErrorMessage string `json:"errorMessage"`
		} `json:"errors"`
	}
	if json.Unmarshal(respBody, &env) == nil && len(env.Errors) > 0 {
		return fmt.Errorf("certify: %s", env.Errors[0].ErrorMessage)
	}
	return nil
}

// RevokeInjiCredential revokes an Inji auth-code credential (POST
// /issuer/credentials/inji/{id}/revoke); ReinstateInjiCredential reinstates it.
// Both are owner-checked and re-render the credential's row.
func (h *H) RevokeInjiCredential(w http.ResponseWriter, r *http.Request) {
	h.setInjiCredentialRevocation(w, r, true)
}

func (h *H) ReinstateInjiCredential(w http.ResponseWriter, r *http.Request) {
	h.setInjiCredentialRevocation(w, r, false)
}

func (h *H) setInjiCredentialRevocation(w http.ResponseWriter, r *http.Request, revoke bool) {
	sess := h.Sessions.MustGet(w, r)
	owner := sessionOwnerKey(sess)
	id := r.PathValue("id")
	if id == "" {
		id = r.FormValue("id")
	}
	// Auth-code credentials verifiably owns revocation for (SD-JWT token + W3C
	// bitstring) are recorded in verifiably's IssuanceLog with a status binding.
	// Dispatch those to their own status list; everything else is a certify.ledger
	// row revoked through Certify's status API below.
	if h.IssuanceLog != nil {
		if rec, ok := h.IssuanceLog.Get(id); ok {
			if rec.OwnerKey != owner {
				http.Error(w, "credential not found", http.StatusNotFound)
				return
			}
			h.setInjiStatusRevocation(w, r, rec, revoke)
			return
		}
	}
	row, credentialID, ok := h.findLedgerRow(r.Context(), owner, id)
	if !ok {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	idx, _ := strconv.Atoi(row["statusListIndex"])
	if err := setInjiCredentialStatus(r.Context(), credentialID, row["statusListCredentialId"], idx, revoke); err != nil {
		h.errorToast(w, r, "Status update: "+err.Error())
		return
	}
	// Re-fetch so the row reflects the new state (ListLedger reads the latest
	// status transaction we just inserted).
	if fresh, _, ok := h.findLedgerRow(r.Context(), owner, id); ok {
		row = fresh
	}
	h.renderFragment(w, r, "fragment_issued_credentials_row", ledgerRowToIssued(row, sess.IssuerDpg, owner))
}

// setInjiStatusRevocation revokes/reinstates an auth-code credential verifiably
// owns (SD-JWT token OR W3C bitstring) by flipping its bit in the matching store,
// dispatched by rec.StatusList.Type. Formerly setInjiTokenRevocation (token-only) via
// verifiably's IETF token status list (the credential's SD-JWT carries a
// status_list ref to it), then updates the IssuanceLog row and re-renders it.
// The status-list adapter is reused unchanged — this only drives it.
func (h *H) setInjiStatusRevocation(w http.ResponseWriter, r *http.Request, rec issuance.IssuedCredential, revoke bool) {
	if rec.StatusList == nil || rec.StatusList.Type == "" {
		h.errorToast(w, r, "This credential has no status binding and cannot be revoked through verifiably-go.")
		return
	}
	store := h.storeForKind(rec.StatusList.Type)
	if store == nil {
		h.errorToast(w, r, "Status list "+rec.StatusList.Type+" not configured.")
		return
	}
	var err error
	if revoke {
		err = store.Revoke(rec.StatusList.Index)
	} else {
		err = store.Reinstate(rec.StatusList.Index)
	}
	if err != nil {
		h.errorToast(w, r, "Status update: "+err.Error())
		return
	}
	var updated issuance.IssuedCredential
	if revoke {
		updated, err = h.IssuanceLog.MarkRevoked(rec.ID, rec.OwnerKey)
	} else {
		updated, err = h.IssuanceLog.MarkReinstate(rec.ID, rec.OwnerKey)
	}
	if err != nil {
		h.errorToast(w, r, "Mark status: "+err.Error())
		return
	}
	h.renderFragment(w, r, "fragment_issued_credentials_row", updated)
}
