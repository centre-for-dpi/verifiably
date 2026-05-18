package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ecosystemIssuerStats is the JSON response for GET /api/ecosystem/issuers/{did}/stats.
type ecosystemIssuerStats struct {
	IssuerDID  string           `json:"issuer_did"`
	PeriodDays int              `json:"period_days"`
	Verified   verificationAgg  `json:"verified"`
}

type verificationAgg struct {
	Total    int           `json:"total"`
	Valid    int           `json:"valid"`
	Invalid  int           `json:"invalid"`
	BySchema []schemaStats `json:"by_schema"`
}

type schemaStats struct {
	Schema  string `json:"schema"`
	Total   int    `json:"total"`
	Valid   int    `json:"valid"`
	Invalid int    `json:"invalid"`
}

// GetEcosystemIssuerStats handles GET /api/ecosystem/issuers/{did}/stats.
// Authorization: Bearer <issuer-api-key>. The key must match the DID in the
// path — a key for DID A cannot query stats for DID B.
func (h *H) GetEcosystemIssuerStats(w http.ResponseWriter, r *http.Request) {
	if h.IssuerAPIKeyStore == nil {
		http.Error(w, "ecosystem API not configured", http.StatusServiceUnavailable)
		return
	}
	if h.VerificationLog == nil {
		http.Error(w, "verification log not configured", http.StatusServiceUnavailable)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="verifiably-ecosystem"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	keyDID, err := h.IssuerAPIKeyStore.Validate(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="verifiably-ecosystem"`)
		http.Error(w, "invalid API key", http.StatusUnauthorized)
		return
	}

	pathDID := r.PathValue("did")
	if pathDID != keyDID {
		http.Error(w, "forbidden: API key does not belong to this DID", http.StatusForbidden)
		return
	}

	events, err := h.VerificationLog.QueryByIssuer(r.Context(), pathDID, 30*24*time.Hour)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	stats := ecosystemIssuerStats{
		IssuerDID:  pathDID,
		PeriodDays: 30,
	}
	bySchema := map[string]*schemaStats{}
	for _, e := range events {
		stats.Verified.Total++
		if e.Status == "valid" {
			stats.Verified.Valid++
		} else {
			stats.Verified.Invalid++
		}
		label := e.SchemaName
		if label == "" {
			label = e.SchemaID
		}
		if label == "" {
			label = "unknown"
		}
		entry := bySchema[label]
		if entry == nil {
			entry = &schemaStats{Schema: label}
			bySchema[label] = entry
		}
		entry.Total++
		if e.Status == "valid" {
			entry.Valid++
		} else {
			entry.Invalid++
		}
	}
	for _, s := range bySchema {
		stats.Verified.BySchema = append(stats.Verified.BySchema, *s)
	}
	// Insertion sort by total desc for stable output.
	for i := 1; i < len(stats.Verified.BySchema); i++ {
		for j := i; j > 0 && stats.Verified.BySchema[j].Total > stats.Verified.BySchema[j-1].Total; j-- {
			stats.Verified.BySchema[j], stats.Verified.BySchema[j-1] = stats.Verified.BySchema[j-1], stats.Verified.BySchema[j]
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
