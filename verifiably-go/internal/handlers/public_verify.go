package handlers

import (
	"bytes"
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
	Lang            string
	Body            any
}

// renderPublicPage renders a full public page using layout_public (no auth nav).
// For HTMX boost targets that set HX-Target: main, only the content block is rendered.
// Applies the same post-render translation pass as render() when a non-English language is active.
func (h *H) renderPublicPage(w http.ResponseWriter, r *http.Request, page string, body any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	lang := langFromRequest(r)
	pd := publicPageData{
		Title:           publicPageTitle(page),
		ContentTemplate: "content_public_" + page,
		Lang:            lang,
		Body:            body,
	}
	tmplName := "layout_public"
	if isHTMX(r) && r.Header.Get("HX-Target") == "main" {
		tmplName = pd.ContentTemplate
	}
	if lang == "" || lang == "en" || h.Translator == nil {
		if err := h.Templates.ExecuteTemplate(w, tmplName, pd); err != nil {
			log.Printf("public template error (page=%s): %v", page, err)
			http.Error(w, "internal server error", 500)
		}
		return
	}
	var buf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&buf, tmplName, pd); err != nil {
		log.Printf("public template error (page=%s): %v", page, err)
		http.Error(w, "internal server error", 500)
		return
	}
	_, _ = w.Write(translateHTML(r.Context(), buf.Bytes(), lang, h.Translator))
}

func publicPageTitle(page string) string {
	switch page {
	case "verify":
		return "Verify credential"
	}
	return "Verification"
}

// publicSchemas returns the schemas available for the public /verify portal.
// In Hub mode reads from the federation schema cache; otherwise falls back to
// the adapter's custom schemas (useful for single-node deployments).
func (h *H) publicSchemas(ctx context.Context) []vctypes.Schema {
	if h.SchemaCache != nil {
		return h.SchemaCache.Schemas()
	}
	all, _ := h.Adapter.ListAllSchemas(ctx)
	var out []vctypes.Schema
	for _, s := range all {
		if s.Custom {
			out = append(out, s)
		}
	}
	return out
}

// publicVerifyData builds the template body for the public verify page.
// Mirrors verifierCustomData but uses the session's PublicVerify* fields
// so the two flows never clobber each other's filter state.
func publicVerifyData(sess *Session, allSchemas []vctypes.Schema) map[string]any {
	schemas := verifierPresentableSchemas(allSchemas)

	filtered := make([]vctypes.Schema, 0, len(schemas))
	for _, s := range schemas {
		if sess.PublicVerifyFilter != "all" && !schemaHasStd(s, sess.PublicVerifyFilter) {
			continue
		}
		if sess.PublicVerifyFilter != "all" {
			s = promoteVariantOfStd(s, sess.PublicVerifyFilter)
		}
		if q := strings.ToLower(sess.PublicVerifyQuery); q != "" {
			hay := strings.ToLower(s.Name + " " + s.Desc + " " + s.Std)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, s)
	}

	stds := []string{"all"}
	seen := map[string]bool{"all": true}
	for _, s := range schemas {
		if !seen[s.Std] {
			seen[s.Std] = true
			stds = append(stds, s.Std)
		}
		for _, v := range s.Variants {
			if !seen[v.Std] {
				seen[v.Std] = true
				stds = append(stds, v.Std)
			}
		}
	}

	return map[string]any{
		"Schemas":    filtered,
		"AllSchemas": schemas,
		"Stds":       stds,
		"Filter":     sess.PublicVerifyFilter,
		"Query":      sess.PublicVerifyQuery,
		"SchemaID":   sess.PublicVerifySchemaID,
		"Template":   sess.PublicVerifyTemplate,
	}
}

// ShowPublicVerify handles GET /verify.
// In Hub mode uses the federated SchemaCache (schemas from all trusted issuers).
// In non-Hub mode falls back to the local adapter's custom schemas.
func (h *H) ShowPublicVerify(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.PublicVerifyFilter == "" {
		sess.PublicVerifyFilter = "all"
	}
	schemas := h.publicSchemas(r.Context())
	body := publicVerifyData(sess, schemas)
	h.renderPublicPage(w, r, "verify", body)
}

// BuildPublicVerifyTemplate handles POST /verify/build.
// Re-renders the schema browser fragment when the user changes the format
// filter, types in the search box, or clicks a schema's format chip.
// Mirrors BuildVerifierTemplate but operates on the public portal's session
// state and the federation schema cache instead of the local adapter.
func (h *H) BuildPublicVerifyTemplate(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Bad form: "+err.Error())
		return
	}

	schemas := h.publicSchemas(r.Context())

	if f := r.FormValue("filter"); f != "" {
		sess.PublicVerifyFilter = f
	}
	if sess.PublicVerifyFilter == "" {
		sess.PublicVerifyFilter = "all"
	}
	if _, hasQ := r.Form["q"]; hasQ {
		sess.PublicVerifyQuery = r.FormValue("q")
	}

	schemaID := r.FormValue("schema_id")
	if schemaID != "" {
		sess.PublicVerifySchemaID = schemaID
	}
	schemaID = sess.PublicVerifySchemaID

	var picked *vctypes.Schema
	if schemaID != "" {
		for i := range schemas {
			if schemas[i].HasVariantID(schemaID) {
				applied := schemas[i].ApplyVariant(schemaID)
				picked = &applied
				break
			}
		}
	}

	if picked != nil {
		// Compute field selection: preserve user's checked boxes on
		// filter/search re-renders; default to all fields on new schema pick.
		var selected []string
		if r.FormValue("schema_id") == "" {
			// Filter/search re-render — keep existing checked fields.
			if raw := r.Form["field_key"]; len(raw) > 0 {
				valid := make(map[string]bool, len(picked.FieldsSpec))
				for _, f := range picked.FieldsSpec {
					valid[f.Name] = true
				}
				for _, f := range raw {
					if valid[f] {
						selected = append(selected, f)
					}
				}
			}
		}
		if len(selected) == 0 {
			for _, f := range picked.FieldsSpec {
				selected = append(selected, f.Name)
			}
		}
		sess.PublicVerifyTemplate = &vctypes.OID4VPTemplate{
			Title:      picked.Name,
			Fields:     selected,
			Format:     picked.Std,
			Disclosure: disclosureSummary(r.FormValue("disclosure"), selected),
		}
	}

	body := publicVerifyData(sess, schemas)
	h.renderFragment(w, r, "fragment_public_verify_body", body)
}

// PublicVerifyRequest handles POST /verify/request.
// Rate-limited by IP using the shared RateLimiter ("public-verify" key bucket).
// Returns fragment_public_qr with the OID4VP QR code and polling setup.
func (h *H) PublicVerifyRequest(w http.ResponseWriter, r *http.Request) {
	if h.RateLimiter != nil && !h.RateLimiter.Allow("public-verify", r) {
		h.errorToast(w, r, "Too many requests — try again in a moment")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Invalid request")
		return
	}

	schemaID := strings.TrimSpace(r.FormValue("schema_id"))
	if schemaID == "" {
		h.errorToast(w, r, "Select a document type first")
		return
	}

	schemas := h.publicSchemas(r.Context())
	var picked *vctypes.Schema
	for i := range schemas {
		if schemas[i].HasVariantID(schemaID) {
			s := schemas[i].ApplyVariant(schemaID)
			picked = &s
			break
		}
	}
	if picked == nil {
		h.errorToast(w, r, "Document type not recognized")
		return
	}

	// Field list: use submitted checkboxes or default to all schema fields.
	fields := r.Form["field_key"]
	if len(fields) == 0 {
		for _, f := range picked.FieldsSpec {
			fields = append(fields, f.Name)
		}
	}
	valid := make(map[string]bool, len(picked.FieldsSpec))
	for _, f := range picked.FieldsSpec {
		valid[f.Name] = true
	}
	cleaned := fields[:0]
	for _, f := range fields {
		if valid[f] {
			cleaned = append(cleaned, f)
		}
	}
	fields = cleaned

	disclosure := r.FormValue("disclosure")
	if disclosure == "" {
		disclosure = "full"
	}

	// Credential type — same logic as assembleCustomTemplate.
	credType := picked.BaseType()
	vct := ""
	if picked.Custom {
		credType = picked.CustomTypeName()
		if strings.HasPrefix(picked.Std, "sd_jwt_vc") {
			vct = picked.CustomTypeName()
		}
	}

	tpl := vctypes.OID4VPTemplate{
		Title:          picked.Name,
		Fields:         fields,
		Format:         picked.Std,
		Disclosure:     disclosureSummary(disclosure, fields),
		CredentialType: credType,
		Vct:            vct,
	}

	// Route by SourceDeployment to the correct member's verifier adapter.
	verifierDpgs, err := h.Adapter.ListVerifierDpgs(r.Context())
	if err != nil || len(verifierDpgs) == 0 {
		h.errorToast(w, r, "No verifiers available at this time")
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

	res, err := h.Adapter.RequestPresentation(r.Context(), backend.PresentationRequest{
		VerifierDpg: dpgKey,
		TemplateKey: "custom",
		Template:    &tpl,
		Policies:    []string{"signature", "expired", "not-before"},
	})
	if err != nil {
		slog.Warn("public verify: RequestPresentation failed",
			"dpg", dpgKey, "schema", picked.Name, "err", err)
		h.errorToast(w, r, "El servicio de verificación del emisor no está disponible en este momento. Intente de nuevo más tarde.")
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
			"Error":   "Error retrieving result",
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
