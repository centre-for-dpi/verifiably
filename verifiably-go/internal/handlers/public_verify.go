package handlers

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/verification"
	"github.com/verifiably/verifiably-go/vctypes"
)

// publicPageData is passed to the layout_public template.
type publicPageData struct {
	Title           string
	ContentTemplate string
	Body            any
}

// renderPublicPage renders a full public page using layout_public (no auth nav).
// For HTMX boost targets that set HX-Target: main, only the content block is rendered.
func (h *H) renderPublicPage(w http.ResponseWriter, r *http.Request, page string, body any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pd := publicPageData{
		Title:           publicPageTitle(page),
		ContentTemplate: "content_public_" + page,
		Body:            body,
	}
	tmplName := "layout_public"
	if isHTMX(r) && r.Header.Get("HX-Target") == "main" {
		tmplName = pd.ContentTemplate
	}
	if err := h.Templates.ExecuteTemplate(w, tmplName, pd); err != nil {
		log.Printf("public template error (page=%s): %v", page, err)
		http.Error(w, "internal server error", 500)
	}
}

func publicPageTitle(page string) string {
	switch page {
	case "verify":
		return "Verificar credencial"
	}
	return "Verificación"
}

// ShowPublicVerify handles GET /verify.
// In Hub mode uses the federated SchemaCache (schemas from all trusted issuers).
// In non-Hub mode falls back to the local adapter's custom schemas.
func (h *H) ShowPublicVerify(w http.ResponseWriter, r *http.Request) {
	var schemas []vctypes.Schema
	if h.SchemaCache != nil {
		schemas = h.SchemaCache.Schemas()
	} else {
		all, _ := h.Adapter.ListAllSchemas(r.Context())
		for _, s := range all {
			if s.Custom {
				schemas = append(schemas, s)
			}
		}
	}
	h.renderPublicPage(w, r, "verify", map[string]any{
		"Schemas": schemas,
	})
}

// PublicVerifyRequest handles POST /verify/request.
// Rate-limited by IP using the shared RateLimiter ("public-verify" key bucket).
// Returns fragment_public_qr with the OID4VP QR code and polling setup.
func (h *H) PublicVerifyRequest(w http.ResponseWriter, r *http.Request) {
	if h.RateLimiter != nil && !h.RateLimiter.Allow("public-verify", r) {
		h.errorToast(w, r, "Demasiadas solicitudes — intentá de nuevo en un momento")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Solicitud inválida")
		return
	}
	schemaID := strings.TrimSpace(r.FormValue("schema_id"))
	if schemaID == "" {
		h.errorToast(w, r, "Seleccioná un tipo de documento")
		return
	}

	schemas, err := h.Adapter.ListAllSchemas(r.Context())
	if err != nil {
		h.errorToast(w, r, "No se pudo cargar el catálogo de credenciales")
		return
	}
	var picked *vctypes.Schema
	for i := range schemas {
		if schemas[i].HasVariantID(schemaID) {
			s := schemas[i].ApplyVariant(schemaID)
			picked = &s
			break
		}
	}
	if picked == nil {
		h.errorToast(w, r, "Tipo de documento no reconocido")
		return
	}

	// Use SourceDeployment (set by the schema aggregator in Fase 3) to route
	// the OID4VP request to the correct member's verifier adapter. Falls back
	// to the first available verifier when SourceDeployment is absent or
	// doesn't match any registered adapter (e.g. non-Hub deployments).
	verifierDpgs, err := h.Adapter.ListVerifierDpgs(r.Context())
	if err != nil || len(verifierDpgs) == 0 {
		h.errorToast(w, r, "No hay verificadores disponibles en este momento")
		return
	}
	dpgKey := picked.SourceDeployment
	if _, ok := verifierDpgs[dpgKey]; !ok {
		dpgKey = ""
		for k := range verifierDpgs {
			dpgKey = k
			break
		}
	}

	credType := picked.BaseType()
	if picked.Custom {
		credType = picked.CustomTypeName()
	}
	var fields []string
	for _, f := range picked.FieldsSpec {
		fields = append(fields, f.Name)
	}
	tpl := vctypes.OID4VPTemplate{
		Title:          picked.Name,
		Fields:         fields,
		Format:         picked.Std,
		Disclosure:     "full credential shared",
		CredentialType: credType,
	}

	res, err := h.Adapter.RequestPresentation(r.Context(), backend.PresentationRequest{
		VerifierDpg: dpgKey,
		TemplateKey: "custom",
		Template:    &tpl,
		Policies:    []string{"signature", "expired", "not-before"},
	})
	if err != nil {
		slog.Warn("public verify: RequestPresentation failed",
			"dpg", dpgKey, "schema", picked.Name, "err", err)
		h.errorToast(w, r, "No se pudo generar la solicitud de verificación")
		return
	}

	h.renderFragment(w, r, "fragment_public_qr", map[string]any{
		"RequestURI":  res.RequestURI,
		"State":       res.State,
		"SchemaTitle": picked.Name,
	})
}

// PublicVerifyResult handles GET /verify/result/{state}.
// Called by HTMX polling every 3 seconds from the citizen's browser.
// Returns fragment_public_result — either a "pending" spinner or the final badge.
func (h *H) PublicVerifyResult(w http.ResponseWriter, r *http.Request) {
	state := r.PathValue("state")
	if state == "" {
		http.Error(w, "state required", http.StatusBadRequest)
		return
	}

	res, err := h.Adapter.FetchPresentationResult(r.Context(), state, "custom")
	if err != nil {
		h.renderFragment(w, r, "fragment_public_result", map[string]any{
			"State":   state,
			"Pending": false,
			"Error":   "Error al recuperar el resultado",
		})
		return
	}

	if res.Pending {
		h.renderFragment(w, r, "fragment_public_result", map[string]any{
			"State":   state,
			"Pending": true,
		})
		return
	}

	h.attachTrustStatus(r, &res)
	h.attachIssuerDisplay(r, &res)

	statusListSource := h.checkStatusListAvailability(r, res.Issuer)
	if statusListSource == "" && res.CheckedRevocation {
		statusListSource = "live"
	}

	slog.Info("public verify: result",
		"valid", res.Valid,
		"issuer", res.Issuer,
		"trust", res.TrustStatus,
		"status_list_source", statusListSource,
	)

	// Write verification event — non-blocking; never delays the HTTP response.
	if h.VerificationLog != nil {
		evtStatus := "invalid"
		if res.Valid {
			evtStatus = "valid"
		}
		evt := verification.Event{
			ID:            verification.NewID(),
			IssuerDID:     res.Issuer,
			SchemaName:    res.CredentialTitle,
			DeploymentID:  os.Getenv("VERIFIABLY_PUBLIC_URL"),
			Status:        evtStatus,
			TrustStatus:   res.TrustStatus,
			StatusListSrc: statusListSource,
			VerifiedAt:    time.Now().UTC(),
		}
		go func(e verification.Event) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.VerificationLog.Append(ctx, e); err != nil {
				slog.Warn("verification log: append failed", "err", err)
			}
		}(evt)
	}

	h.renderFragment(w, r, "fragment_public_result", map[string]any{
		"State":             state,
		"Pending":           false,
		"Error":             "",
		"Valid":             res.Valid,
		"TrustStatus":       res.TrustStatus,
		"TrustReason":       res.TrustReason,
		"Issuer":            res.Issuer,
		"IssuerDisplay":     res.IssuerDisplay,
		"CredentialTitle":   res.CredentialTitle,
		"Format":            res.Format,
		"CheckedRevocation": res.CheckedRevocation,
		"DisclosedFields":   res.DisclosedFields,
		"StatusListSource":  statusListSource,
		"VerifiedAt":        time.Now().UTC().Format("02/01/2006 15:04 UTC"),
	})
}

// checkStatusListAvailability checks the Hub's status list cache for the given
// issuer's registered endpoints. Returns "live", "cached", "unknown", or "" when
// no cache is wired or the issuer has no registered status list endpoints.
func (h *H) checkStatusListAvailability(r *http.Request, issuerDID string) string {
	if h.StatusListCache == nil || h.TrustRegistry == nil || issuerDID == "" {
		return ""
	}
	issuers, err := h.TrustRegistry.TrustedIssuers(r.Context())
	if err != nil {
		return ""
	}
	for _, issuer := range issuers {
		if issuer.DID != issuerDID {
			continue
		}
		if len(issuer.StatusListEndpoints) == 0 {
			return ""
		}
		result, err := h.StatusListCache.Fetch(r.Context(), issuerDID, issuer.StatusListEndpoints[0])
		if err != nil {
			return "unknown"
		}
		return result.Source
	}
	return ""
}
