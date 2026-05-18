package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/trust"
)

// ── Public endpoint ───────────────────────────────────────────────────────────

// ServeTrustRegistry handles GET /trust-registry.
// Returns a signed JWT whose payload is the full trusted-issuer list.
// Uses ES256 when TrustSigningKey is set (production); falls back to HS256
// (dev / no key configured). Cache-Control 1 h; JWT exp 24 h.
func (h *H) ServeTrustRegistry(w http.ResponseWriter, r *http.Request) {
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	issuers, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		slog.Error("trust registry: list issuers", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	issuerID := h.TrustJWTIssuer
	if issuerID == "" {
		issuerID = "verifiably-go"
	}

	var jwt string
	if h.TrustSigningKey != nil {
		jwt, err = trust.BuildJWTES256(issuers, issuerID, h.TrustSigningKey, 24*time.Hour)
	} else {
		jwt, err = trust.BuildJWT(issuers, issuerID, h.TrustJWTSecret, 24*time.Hour)
	}
	if err != nil {
		slog.Error("trust registry: build JWT", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(jwt))
}

// ServeJWKS handles GET /.well-known/jwks.json.
// Returns the ES256 public key in JWK Set format so any verifier can validate
// the /trust-registry JWT without a shared secret.
// Returns 404 when no signing key is configured (should not happen in production).
func (h *H) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	if h.TrustSigningKey == nil {
		http.NotFound(w, r)
		return
	}
	jwk := trust.PublicKeyToJWK(&h.TrustSigningKey.PublicKey)
	jwks := map[string]any{
		"keys": []any{jwk},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(jwks)
}

// ── Admin handlers ────────────────────────────────────────────────────────────

// ShowTrustRegistry handles GET /admin/trust — lists all trusted issuers.
func (h *H) ShowTrustRegistry(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	if h.TrustRegistry == nil {
		http.Error(w, "trust registry not configured", http.StatusServiceUnavailable)
		return
	}
	issuers, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		h.errorToast(w, r, "Could not load trust registry: "+err.Error())
		return
	}
	h.render(w, r, "admin_trust", h.pageData(sess, map[string]any{
		"Issuers": issuers,
	}))
}

// AddTrustedIssuer handles POST /admin/trust.
// Accepts JSON body or form values: did, display_name, schemas (comma-separated),
// valid_until (YYYY-MM-DD, optional).
func (h *H) AddTrustedIssuer(w http.ResponseWriter, r *http.Request) {
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
		for _, s := range strings.Split(r.FormValue("schemas"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				entry.Schemas = append(entry.Schemas, s)
			}
		}
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
	if err := h.TrustRegistry.Add(r.Context(), entry); err != nil {
		slog.Error("trust registry: add issuer", "did", entry.DID, "err", err)
		h.errorToast(w, r, "Could not add issuer: "+err.Error())
		return
	}
	slog.Info("trust registry: issuer added", "did", entry.DID, "display_name", entry.DisplayName)

	// HTMX: re-render only the list fragment so the table updates in-place.
	if isHTMX(r) {
		issuers, _ := h.TrustRegistry.TrustedIssuers(r.Context())
		h.renderFragment(w, r, "fragment_trust_list", map[string]any{"Issuers": issuers})
		return
	}
	http.Redirect(w, r, "/admin/trust", http.StatusSeeOther)
}

// DeleteTrustedIssuer handles DELETE /admin/trust/{did}.
func (h *H) DeleteTrustedIssuer(w http.ResponseWriter, r *http.Request) {
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
		slog.Error("trust registry: remove issuer", "did", did, "err", err)
		h.errorToast(w, r, "Could not remove issuer: "+err.Error())
		return
	}
	slog.Info("trust registry: issuer removed", "did", did)

	if isHTMX(r) {
		issuers, _ := h.TrustRegistry.TrustedIssuers(r.Context())
		h.renderFragment(w, r, "fragment_trust_list", map[string]any{"Issuers": issuers})
		return
	}
	http.Redirect(w, r, "/admin/trust", http.StatusSeeOther)
}
