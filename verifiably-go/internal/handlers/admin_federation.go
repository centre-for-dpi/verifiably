package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/trust"
)

// ShowFederationMembers handles GET /admin/federation/members.
// When called via HTMX (e.g. from the edit form's Cancel button) it returns
// only the fragment_federation_list so the list re-renders in place.
func (h *H) ShowFederationMembers(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	members, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		h.errorToast(w, r, "Could not load members: "+err.Error())
		return
	}
	data := map[string]any{
		"Members":        members,
		"MemberKeys":     h.memberKeyMap(r, members),
		"MemberHealth":   h.memberHealthMap(members),
		"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
	}
	if isHTMX(r) {
		h.renderFragment(w, r, "fragment_federation_list", data)
		return
	}
	h.render(w, r, "admin_federation", h.pageData(sess, data))
}

// memberKeyMap builds a map[DID]bool indicating which members have an active
// API key. Returns an empty map when IssuerAPIKeyStore is nil or on error.
func (h *H) memberKeyMap(r *http.Request, members []trust.TrustedIssuer) map[string]bool {
	out := make(map[string]bool, len(members))
	if h.IssuerAPIKeyStore == nil {
		return out
	}
	for _, m := range members {
		has, _ := h.IssuerAPIKeyStore.HasKey(r.Context(), m.DID)
		out[m.DID] = has
	}
	return out
}

// memberHealthMap returns the last known endpoint health per DID from the
// health monitor. Returns an empty map when TrustHealthMonitor is nil.
func (h *H) memberHealthMap(members []trust.TrustedIssuer) map[string]trust.EndpointStatus {
	out := make(map[string]trust.EndpointStatus, len(members))
	if h.TrustHealthMonitor == nil {
		return out
	}
	for _, m := range members {
		out[m.DID] = h.TrustHealthMonitor.EndpointStatus(m.DID)
	}
	return out
}

// RegisterFederationMember handles POST /admin/federation/members.
// Accepts JSON body or form values: did, display_name, service_endpoint,
// schemas (comma-separated), status_list_endpoints (comma-separated),
// status_list_policy ("fail-closed"|"fail-open"), valid_until (YYYY-MM-DD).
func (h *H) RegisterFederationMember(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}

	var entry trust.TrustedIssuer
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		_ = r.ParseForm()
		entry.DID = strings.TrimSpace(r.FormValue("did"))
		entry.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		entry.ServiceEndpoint = strings.TrimRight(strings.TrimSpace(r.FormValue("service_endpoint")), "/")
		entry.StatusListPolicy = strings.TrimSpace(r.FormValue("status_list_policy"))
		if entry.StatusListPolicy == "" {
			entry.StatusListPolicy = "fail-closed"
		}
		for _, s := range strings.Split(r.FormValue("schemas"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				entry.Schemas = append(entry.Schemas, s)
			}
		}
		for _, ep := range strings.Split(r.FormValue("status_list_endpoints"), ",") {
			if ep = strings.TrimSpace(ep); ep != "" {
				entry.StatusListEndpoints = append(entry.StatusListEndpoints, ep)
			}
		}
		entry.VerifierAPIKey = strings.TrimSpace(r.FormValue("verifier_api_key"))
		if vu := strings.TrimSpace(r.FormValue("valid_until")); vu != "" {
			t, err := time.Parse("2006-01-02", vu)
			if err != nil {
				http.Error(w, "valid_until must be YYYY-MM-DD", http.StatusBadRequest)
				return
			}
			entry.ValidUntil = t.UTC()
		}
	}

	if entry.DID == "" {
		h.errorToast(w, r, "DID is required")
		return
	}
	if !strings.HasPrefix(entry.DID, "did:web:") {
		h.errorToast(w, r, "DID must be a did:web: identifier (e.g. did:web:issuer.gov)")
		return
	}

	// Healthz check — non-blocking if ServiceEndpoint absent.
	if entry.ServiceEndpoint != "" {
		if err := federationHealthz(r.Context(), entry.ServiceEndpoint); err != nil {
			h.errorToast(w, r, fmt.Sprintf("Healthz check failed for %s: %v", entry.ServiceEndpoint, err))
			return
		}
	}

	// DID resolution — warn only; don't block registration (DID may not be
	// publicly reachable in dev/staging environments).
	if h.DIDResolver != nil {
		if _, err := h.DIDResolver.Resolve(r.Context(), entry.DID); err != nil {
			slog.Warn("federation: DID resolution failed (registering anyway)", "did", entry.DID, "err", err)
		}
	}

	if err := h.TrustRegistry.Add(r.Context(), entry); err != nil {
		slog.Error("federation: register member", "did", entry.DID, "err", err)
		h.errorToast(w, r, "Could not register member: "+err.Error())
		return
	}
	slog.Info("federation: member registered", "did", entry.DID, "name", entry.DisplayName)

	// Wire the verifier adapter live so OID4VP routing works without a restart.
	if entry.ServiceEndpoint != "" && h.MemberVerifierRegistrar != nil {
		h.MemberVerifierRegistrar.RegisterMemberVerifier(entry.DID, entry.ServiceEndpoint, entry.VerifierAPIKey)
	}

	if isHTMX(r) {
		members, _ := h.TrustRegistry.TrustedIssuers(r.Context())
		h.renderFragment(w, r, "fragment_federation_list", map[string]any{
			"Members":        members,
			"MemberKeys":     h.memberKeyMap(r, members),
			"MemberHealth":   h.memberHealthMap(members),
			"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
		})
		return
	}
	http.Redirect(w, r, "/admin/federation/members", http.StatusSeeOther)
}

// DeleteFederationMember handles POST /admin/federation/members/{did}/delete.
func (h *H) DeleteFederationMember(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	did := r.PathValue("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}
	if err := h.TrustRegistry.Remove(r.Context(), did); err != nil {
		slog.Error("federation: remove member", "did", did, "err", err)
		h.errorToast(w, r, "Could not remove member: "+err.Error())
		return
	}
	slog.Info("federation: member removed", "did", did)

	if isHTMX(r) {
		members, _ := h.TrustRegistry.TrustedIssuers(r.Context())
		h.renderFragment(w, r, "fragment_federation_list", map[string]any{
			"Members":        members,
			"MemberKeys":     h.memberKeyMap(r, members),
			"MemberHealth":   h.memberHealthMap(members),
			"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
		})
		return
	}
	http.Redirect(w, r, "/admin/federation/members", http.StatusSeeOther)
}

// IssueAPIKey handles POST /admin/federation/members/{did}/api-key.
// Generates a new API key for the issuer, returns fragment_api_key_display
// with the plaintext shown once. Replaces any existing key for the same DID.
func (h *H) IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.IssuerAPIKeyStore == nil {
		http.Error(w, "API key store not configured", http.StatusServiceUnavailable)
		return
	}
	did := r.PathValue("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}
	key, err := h.IssuerAPIKeyStore.Issue(r.Context(), did)
	if err != nil {
		slog.Error("federation: issue API key", "did", did, "err", err)
		h.errorToast(w, r, "Could not generate API key: "+err.Error())
		return
	}
	slog.Info("federation: API key issued", "did", did)
	h.renderFragment(w, r, "fragment_api_key_display", map[string]any{
		"DID":    did,
		"APIKey": key,
	})
}

// RevokeAPIKey handles POST /admin/federation/members/{did}/api-key/revoke.
// Deletes the issuer's API key and re-renders the member list.
func (h *H) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.IssuerAPIKeyStore == nil {
		http.Error(w, "API key store not configured", http.StatusServiceUnavailable)
		return
	}
	did := r.PathValue("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}
	if err := h.IssuerAPIKeyStore.Revoke(r.Context(), did); err != nil {
		slog.Error("federation: revoke API key", "did", did, "err", err)
		h.errorToast(w, r, "Could not revoke API key: "+err.Error())
		return
	}
	slog.Info("federation: API key revoked", "did", did)
	members, _ := h.TrustRegistry.TrustedIssuers(r.Context())
	h.renderFragment(w, r, "fragment_federation_list", map[string]any{
		"Members":        members,
		"MemberKeys":     h.memberKeyMap(r, members),
		"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
	})
}

// ShowEditFederationMember handles GET /admin/federation/members/{did}/edit.
// Returns fragment_federation_edit_form pre-filled with the member's current data.
func (h *H) ShowEditFederationMember(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	did := r.PathValue("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}
	issuers, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		h.errorToast(w, r, "Could not load members: "+err.Error())
		return
	}
	var member *trust.TrustedIssuer
	for i := range issuers {
		if issuers[i].DID == did {
			member = &issuers[i]
			break
		}
	}
	if member == nil {
		http.Error(w, "member not found", http.StatusNotFound)
		return
	}
	h.renderFragment(w, r, "fragment_federation_edit_form", map[string]any{
		"Member": member,
	})
}

// UpdateFederationMember handles POST /admin/federation/members/{did}/edit.
// All fields except DID (immutable) can be updated. If verifier_api_key is
// blank the existing key is preserved.
func (h *H) UpdateFederationMember(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	did := r.PathValue("did")
	if did == "" {
		http.Error(w, "did is required", http.StatusBadRequest)
		return
	}

	// Load existing entry to preserve immutable/sensitive fields.
	issuers, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		h.errorToast(w, r, "Could not load member: "+err.Error())
		return
	}
	var existing *trust.TrustedIssuer
	for i := range issuers {
		if issuers[i].DID == did {
			existing = &issuers[i]
			break
		}
	}
	if existing == nil {
		h.errorToast(w, r, "Member not found")
		return
	}

	_ = r.ParseForm()
	entry := trust.TrustedIssuer{
		DID:          did,
		AccreditedAt: existing.AccreditedAt,
		DisplayName:  strings.TrimSpace(r.FormValue("display_name")),
		ServiceEndpoint: strings.TrimRight(strings.TrimSpace(r.FormValue("service_endpoint")), "/"),
	}
	entry.StatusListPolicy = strings.TrimSpace(r.FormValue("status_list_policy"))
	if entry.StatusListPolicy == "" {
		entry.StatusListPolicy = "fail-closed"
	}
	for _, s := range strings.Split(r.FormValue("schemas"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			entry.Schemas = append(entry.Schemas, s)
		}
	}
	for _, ep := range strings.Split(r.FormValue("status_list_endpoints"), ",") {
		if ep = strings.TrimSpace(ep); ep != "" {
			entry.StatusListEndpoints = append(entry.StatusListEndpoints, ep)
		}
	}
	if vu := strings.TrimSpace(r.FormValue("valid_until")); vu != "" {
		t, err := time.Parse("2006-01-02", vu)
		if err != nil {
			h.errorToast(w, r, "valid_until must be YYYY-MM-DD")
			return
		}
		entry.ValidUntil = t.UTC()
	}
	// Preserve existing verifier API key when the field is left blank.
	if key := strings.TrimSpace(r.FormValue("verifier_api_key")); key != "" {
		entry.VerifierAPIKey = key
	} else {
		entry.VerifierAPIKey = existing.VerifierAPIKey
	}

	// Healthz check — non-blocking if ServiceEndpoint absent.
	if entry.ServiceEndpoint != "" {
		if err := federationHealthz(r.Context(), entry.ServiceEndpoint); err != nil {
			h.errorToast(w, r, fmt.Sprintf("Healthz check failed for %s: %v", entry.ServiceEndpoint, err))
			return
		}
	}

	if err := h.TrustRegistry.Add(r.Context(), entry); err != nil {
		slog.Error("federation: update member", "did", did, "err", err)
		h.errorToast(w, r, "Could not update member: "+err.Error())
		return
	}
	slog.Info("federation: member updated", "did", did)

	// Re-wire verifier adapter with updated config.
	if entry.ServiceEndpoint != "" && h.MemberVerifierRegistrar != nil {
		h.MemberVerifierRegistrar.RegisterMemberVerifier(entry.DID, entry.ServiceEndpoint, entry.VerifierAPIKey)
	}

	members, _ := h.TrustRegistry.TrustedIssuers(r.Context())
	h.renderFragment(w, r, "fragment_federation_list", map[string]any{
		"Members":        members,
		"MemberKeys":     h.memberKeyMap(r, members),
		"MemberHealth":   h.memberHealthMap(members),
		"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
	})
}

// federationHealthz pings GET {serviceEndpoint}/healthz (5 s timeout).
func federationHealthz(ctx context.Context, serviceEndpoint string) error {
	hzURL := strings.TrimRight(serviceEndpoint, "/") + "/healthz"
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hzURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", hzURL, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", hzURL, resp.StatusCode)
	}
	return nil
}
