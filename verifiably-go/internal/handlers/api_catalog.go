package handlers

// api_catalog.go — Static capabilities catalog endpoint.
//
// Routes:
//
//   GET /api/v1/catalog    returns DPGs, credential standards and verification
//                          templates available in this deployment.
//
// Auth: Authorization: Bearer <key>  (same as the rest of /api/v1/).
//
// The response is intentionally read-only and fully derived from the adapter's
// live configuration, so it always reflects the actual runtime state of the
// deployment without any additional maintenance overhead.

import (
	"net/http"
	"sort"

	"github.com/verifiably/verifiably-go/vctypes"
)

// ── Wire types ────────────────────────────────────────────────────────────────

type apiCatalogResult struct {
	IssuerDPGs            []apiDPGInfo                      `json:"issuer_dpgs"`
	VerifierDPGs          []apiDPGInfo                      `json:"verifier_dpgs"`
	CredentialStandards   []string                          `json:"credential_standards"`
	VerificationTemplates map[string]apiVerificationTemplate `json:"verification_templates"`
}

type apiDPGInfo struct {
	ID           string          `json:"id"`
	Version      string          `json:"version,omitempty"`
	Tag          string          `json:"tag,omitempty"`
	Tagline      string          `json:"tagline,omitempty"`
	Formats      []string        `json:"formats,omitempty"`
	Flows        []string        `json:"flows,omitempty"`
	SupportsPDF  bool            `json:"supports_pdf,omitempty"`
	Capabilities []apiCapability `json:"capabilities,omitempty"`
}

type apiCapability struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
}

type apiVerificationTemplate struct {
	Title      string   `json:"title"`
	Fields     []string `json:"fields"`
	Format     string   `json:"format"`
	Disclosure string   `json:"disclosure,omitempty"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// APICatalog handles GET /api/v1/catalog.
// It returns the static configuration of the deployment in a single call so
// API clients can discover available DPGs, supported credential standards and
// preset verification templates without needing multiple round-trips.
// Errors from individual sub-queries are handled gracefully: a failing DPG
// query returns an empty slice rather than a 500 so the rest of the response
// is still useful.
func (h *H) APICatalog(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	ctx := apiCtx(r, keyName)

	// Issuer DPGs
	issuerDPGMap, _ := h.Adapter.ListIssuerDpgs(ctx)
	issuerDPGs := sortedDPGInfos(issuerDPGMap)

	// Verifier DPGs
	verifierDPGMap, _ := h.Adapter.ListVerifierDpgs(ctx)
	verifierDPGs := sortedDPGInfos(verifierDPGMap)

	// Credential standards — derived from the full schema catalog so the list
	// reflects exactly what this deployment can issue, not a hardcoded enum.
	standards := []string{}
	if schemas, err := h.Adapter.ListAllSchemas(ctx); err == nil {
		seen := map[string]bool{}
		for _, s := range schemas {
			if s.Std != "" && !seen[s.Std] {
				seen[s.Std] = true
				standards = append(standards, s.Std)
			}
		}
		sort.Strings(standards)
	}

	// Verification templates (OID4VP presets)
	templates := map[string]apiVerificationTemplate{}
	if tpls, err := h.Adapter.ListOID4VPTemplates(ctx); err == nil {
		for key, tpl := range tpls {
			fields := tpl.Fields
			if fields == nil {
				fields = []string{}
			}
			templates[key] = apiVerificationTemplate{
				Title:      tpl.Title,
				Fields:     fields,
				Format:     tpl.Format,
				Disclosure: tpl.Disclosure,
			}
		}
	}

	apiJSON(w, http.StatusOK, apiCatalogResult{
		IssuerDPGs:            issuerDPGs,
		VerifierDPGs:          verifierDPGs,
		CredentialStandards:   standards,
		VerificationTemplates: templates,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// sortedDPGInfos converts a DPG map to a stable-sorted slice for the API response.
func sortedDPGInfos(dpgs map[string]vctypes.DPG) []apiDPGInfo {
	ids := make([]string, 0, len(dpgs))
	for id := range dpgs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]apiDPGInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, dpgToAPIInfo(id, dpgs[id]))
	}
	return out
}

// dpgToAPIInfo converts a vctypes.DPG to its API representation.
func dpgToAPIInfo(id string, d vctypes.DPG) apiDPGInfo {
	flows := []string{}
	if d.FlowPreAuth {
		flows = append(flows, "pre_auth")
	}
	if d.FlowAuthCode {
		flows = append(flows, "auth_code")
	}

	caps := make([]apiCapability, 0, len(d.Capabilities))
	for _, c := range d.Capabilities {
		caps = append(caps, apiCapability{
			Kind:  c.Kind,
			Key:   c.Key,
			Title: c.Title,
			Body:  c.Body,
		})
	}

	formats := d.Formats
	if formats == nil {
		formats = []string{}
	}

	return apiDPGInfo{
		ID:           id,
		Version:      d.Version,
		Tag:          d.Tag,
		Tagline:      d.Tagline,
		Formats:      formats,
		Flows:        flows,
		SupportsPDF:  d.DirectPDF,
		Capabilities: caps,
	}
}
