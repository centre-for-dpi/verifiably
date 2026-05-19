package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/internal/verification"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ShowVerify renders the verifier page (OID4VP request generator + direct
// verify). The custom-request card (the only UI path now) needs the schema
// catalog so the user can pick which credential type to request.
func (h *H) ShowVerify(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.VerifierDpg == "" {
		h.redirect(w, r, "/verifier/dpg")
		return
	}
	dpgs, _ := h.Adapter.ListVerifierDpgs(r.Context())
	schemas, err := h.Adapter.ListAllSchemas(r.Context())
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	if sess.VerifierSchemaFilter == "" {
		sess.VerifierSchemaFilter = "all"
	}
	body := verifierCustomData(sess, schemas, dpgs[sess.VerifierDpg])
	h.render(w, r, "verifier_verify", h.pageData(sess, body))
}

// verifierPresentableSchemas drops variants the backend verifier can't
// accept, and drops schemas whose every variant would be rejected. Walt.id's
// verifier refuses `jwt_vc_json-ld` (missing from its VCFormat enum) and
// `dc+sd-jwt` (rejected by VerifierService.getPresentationFormat). Showing
// them in the verifier picker is a pure footgun — the user builds a request
// they can never satisfy.
func verifierPresentableSchemas(schemas []vctypes.Schema) []vctypes.Schema {
	out := make([]vctypes.Schema, 0, len(schemas))
	for _, s := range schemas {
		// Mirror the issuer schema page: only show user-built schemas. The
		// walt.id stock catalog is hidden in the issuer flow, so surfacing
		// it on the verifier card grid would create a confusing one-way
		// asymmetry where operators can verify against credential types
		// they were never able to issue.
		if !s.Custom {
			continue
		}
		if len(s.Variants) == 0 {
			// Custom schemas carry no variants — trust the adapter that
			// surfaced them (they've already passed the issuer flow).
			out = append(out, s)
			continue
		}
		kept := make([]vctypes.SchemaVariant, 0, len(s.Variants))
		for _, v := range s.Variants {
			if v.CanPresent {
				kept = append(kept, v)
			}
		}
		if len(kept) == 0 {
			continue
		}
		s.Variants = kept
		// If the card's primary ID+Std referenced a dropped variant,
		// rebase onto the first kept one so the default click-target is
		// always a presentable format.
		found := false
		for _, v := range kept {
			if v.ID == s.ID {
				found = true
				break
			}
		}
		if !found {
			s = s.ApplyVariant(kept[0].ID)
		}
		out = append(out, s)
	}
	return out
}

// verifierCustomData builds the template body for the verifier page. Shared
// between the full-page render and the /verifier/verify/build partial so the
// card grid, filter chips, and preview all stay consistent when HTMX swaps
// the custom-request body on card selection.
func verifierCustomData(sess *Session, schemas []vctypes.Schema, dpg vctypes.DPG) map[string]any {
	schemas = verifierPresentableSchemas(schemas)
	// Filter by std: a card qualifies if ANY of its variants matches the
	// active filter. When a non-"all" filter is active we also promote the
	// matching variant to the card's default so selecting it picks a
	// configuration id in that format.
	filtered := make([]vctypes.Schema, 0, len(schemas))
	for _, s := range schemas {
		if sess.VerifierSchemaFilter != "all" && !schemaHasStd(s, sess.VerifierSchemaFilter) {
			continue
		}
		if sess.VerifierSchemaFilter != "all" {
			s = promoteVariantOfStd(s, sess.VerifierSchemaFilter)
		}
		if q := strings.ToLower(sess.VerifierSchemaQuery); q != "" {
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
		"VerifierDpgObj": dpg,
		"Schemas":        filtered,
		"AllSchemas":     schemas,
		"Stds":           stds,
		"Filter":         sess.VerifierSchemaFilter,
		"Query":          sess.VerifierSchemaQuery,
		"CustomTemplate": sess.CustomOID4VPTemplate,
		"CustomSchemaID": sess.CustomOID4VPSchemaID,
	}
}

// GenerateRequest creates an OID4VP presentation request from the
// "Build a custom request" form: schema_id picks the credential type (and
// via its variant id, the wire format); field_key[] + disclosure pick what
// the holder will be asked to share. Assembles the template inline so one
// click sends the request — no intermediate "assemble" step.
func (h *H) GenerateRequest(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Bad form: "+err.Error())
		return
	}
	tpl, err := h.assembleCustomTemplate(r, sess)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	sess.CustomOID4VPTemplate = &tpl
	sess.CustomOID4VPSchemaID = r.FormValue("schema_id")
	policies := r.Form["policy"]
	if len(policies) == 0 {
		// The user submitted with no boxes checked. Default to the three
		// essential checks so the verifier still runs sensibly — otherwise
		// walt.id accepts ANY VC (no signature check) which would silently
		// pass tampered credentials.
		policies = []string{"signature", "expired", "not-before"}
	}
	req := backend.PresentationRequest{
		VerifierDpg: sess.VerifierDpg,
		TemplateKey: "custom",
		Template:    &tpl,
		Policies:    policies,
		WebhookURL:  strings.TrimSpace(r.FormValue("webhook_url")),
	}
	verifyStart := time.Now()
	res, err := h.Adapter.RequestPresentation(r.Context(), req)
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(verifyStart), "dpg", sess.VerifierDpg, "op", "verify")
	if err != nil {
		metrics.Inc("verification_requested_total", "dpg", sess.VerifierDpg, "schema", tpl.Title, "status", "error")
		h.errorToast(w, r, err.Error())
		return
	}
	metrics.Inc("verification_requested_total", "dpg", sess.VerifierDpg, "schema", tpl.Title, "status", "ok")
	sess.CurrentOID4VPLink = res.RequestURI
	sess.CurrentOID4VPState = res.State
	sess.CurrentOID4VPTemplate = "custom"
	h.renderFragment(w, r, "fragment_oid4vp_request_output", res)
}

// assembleCustomTemplate builds a OID4VPTemplate from the custom-request
// form fields on r: schema_id picks the schema, field_key[] is the list of
// fields to request (defaults to all schema fields if none are checked),
// disclosure is "selective" or "full".
func (h *H) assembleCustomTemplate(r *http.Request, sess *Session) (vctypes.OID4VPTemplate, error) {
	schemaID := r.FormValue("schema_id")
	if schemaID == "" {
		return vctypes.OID4VPTemplate{}, fmt.Errorf("pick a schema first")
	}
	schemas, err := h.Adapter.ListAllSchemas(r.Context())
	if err != nil {
		return vctypes.OID4VPTemplate{}, fmt.Errorf("could not load schemas: %w", err)
	}
	var picked *vctypes.Schema
	for i := range schemas {
		if schemas[i].HasVariantID(schemaID) {
			resolved := h.resolveFields(schemas[i].ApplyVariant(schemaID))
			picked = &resolved
			break
		}
	}
	if picked == nil {
		return vctypes.OID4VPTemplate{}, fmt.Errorf("unknown schema %q", schemaID)
	}
	fields := r.Form["field_key"]
	if len(fields) == 0 {
		// No boxes checked → request every field the schema declares.
		for _, f := range picked.FieldsSpec {
			fields = append(fields, f.Name)
		}
	}
	// Reject fields that aren't in the schema.
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
	// Pull the canonical credential type + full vct URL off the picked
	// variant so the verifier's PD filter matches the wallet's held
	// credential exactly. The previous title→guess path appended "Credential"
	// to everything, which broke types whose real name doesn't end that way
	// (e.g. walt.id's "BankId") and used a bare short type instead of the
	// full vct URL walt.id's SD-JWT matcher requires.
	//
	// Custom schemas need a different code path because Variants is empty
	// (vctypes.Schema.Variants is "Empty for custom schemas") and BaseType()
	// falls through to Schema.ID — which is the random "custom-..." string,
	// NOT what the wallet stored. Using ID here was the cause of "your
	// wallet has no credential matching this request (verifier asked for
	// custom-... in vc+sd-jwt format)" reported on 2026-04-29.
	credType := picked.BaseType()
	vct := ""
	wireFormat := ""
	if picked.Custom {
		credType = picked.CustomTypeName()
		// For SD-JWT VC, the wallet matches the held credential's `vct`
		// claim against the PD filter's `vct`. The walt.id adapter issues
		// custom SD-JWT credentials with vct=CustomTypeName(), so the
		// verifier must ask for that same string.
		if strings.HasPrefix(picked.Std, "sd_jwt_vc") {
			vct = picked.CustomTypeName()
		}
		// wireFormat stays empty — adapter falls back to credentialFormatForStd
		// which maps "sd_jwt_vc (IETF)" → "vc+sd-jwt". Custom schemas don't
		// expose a per-variant wire-format chip yet so picking the default
		// is the right behaviour.
	} else {
		for _, v := range picked.Variants {
			if v.ID == picked.ID {
				vct = v.Vct
				wireFormat = v.Format
				break
			}
		}
	}
	return vctypes.OID4VPTemplate{
		Title:          picked.Name,
		Fields:         fields,
		Format:         picked.Std,
		Disclosure:     disclosureSummary(disclosure, fields),
		CredentialType: credType,
		Vct:            vct,
		WireFormat:     wireFormat,
	}, nil
}

// BuildVerifierTemplate re-renders the card grid + field picker fragment
// for the verifier's custom-request form. Accepts three kinds of input:
//   - schema_id=<variant id>: user picked a card's format chip.
//   - filter=<std>: user clicked a std-filter chip above the cards.
//   - q=<text>: user typed in the search box.
//
// Any of these re-renders the whole fragment_verifier_custom_body so the
// card list, active-chip highlighting, hidden schema_id input, and field
// picker stay in sync without juggling multiple OOB swaps.
func (h *H) BuildVerifierTemplate(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.VerifierDpg == "" {
		h.redirect(w, r, "/verifier/dpg")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "Bad form: "+err.Error())
		return
	}
	schemas, err := h.Adapter.ListAllSchemas(r.Context())
	if err != nil {
		h.errorToast(w, r, "Could not load schemas: "+err.Error())
		return
	}

	// Filter state (persisted on session so a re-render from a chip/search
	// click doesn't lose the other's selection).
	if f := r.FormValue("filter"); f != "" {
		sess.VerifierSchemaFilter = f
	}
	if sess.VerifierSchemaFilter == "" {
		sess.VerifierSchemaFilter = "all"
	}
	if _, hasQ := r.Form["q"]; hasQ {
		sess.VerifierSchemaQuery = r.FormValue("q")
	}

	// Schema selection. A non-empty schema_id on this POST means the user
	// just clicked a card's format chip — resolve it against variants and
	// pin sess.CustomOID4VPSchemaID so Generate picks it up.
	schemaID := r.FormValue("schema_id")
	if schemaID != "" {
		sess.CustomOID4VPSchemaID = schemaID
	}
	schemaID = sess.CustomOID4VPSchemaID

	var picked *vctypes.Schema
	if schemaID != "" {
		for i := range schemas {
			if schemas[i].HasVariantID(schemaID) {
				resolved := h.resolveFields(schemas[i].ApplyVariant(schemaID))
				picked = &resolved
				break
			}
		}
	}

	// Compute selected fields. Preserve prior selections for the same
	// schema; default to every field when the user just switched to a new
	// schema (signaled by the schema_id query param being present).
	var selected []string
	if picked != nil {
		if r.FormValue("schema_id") == "" {
			// Re-render driven by filter/search — keep the user's checks.
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
		preview := vctypes.OID4VPTemplate{
			Title:      picked.Name,
			Fields:     selected,
			Format:     picked.Std,
			Disclosure: disclosureSummary(r.FormValue("disclosure"), selected),
		}
		sess.CustomOID4VPTemplate = &preview
	}

	dpgs, _ := h.Adapter.ListVerifierDpgs(r.Context())
	body := verifierCustomData(sess, schemas, dpgs[sess.VerifierDpg])
	h.renderFragment(w, r, "fragment_verifier_custom_body", body)
}

// disclosureSummary renders the plain-language string shown on the request
// preview — "selective — only X, Y are shared" or "full credential shared".
func disclosureSummary(mode string, fields []string) string {
	if mode == "selective" && len(fields) > 0 {
		return "selective — only " + strings.Join(fields, ", ") + " shared"
	}
	return "full credential shared"
}

// FetchResponse polls the adapter for the current OID4VP session result.
func (h *H) FetchResponse(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.CurrentOID4VPState == "" {
		h.errorToast(w, r, "Generate a request first")
		return
	}
	pollStart := time.Now()
	res, err := h.Adapter.FetchPresentationResult(r.Context(), sess.CurrentOID4VPState, sess.CurrentOID4VPTemplate)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	// Adapters that use a preset-template keyed lookup have no way to
	// reconstruct an inline custom template — paper over the empty
	// Method/Format on the Pending branch so the "awaiting response" card
	// still shows what the user actually asked for.
	if sess.CustomOID4VPTemplate != nil {
		tpl := sess.CustomOID4VPTemplate
		if res.Method == "" || strings.HasSuffix(res.Method, "· ") {
			res.Method = "OID4VP · " + tpl.Disclosure
		}
		if res.Format == "" {
			res.Format = tpl.Format
		}
		if len(res.Requested) == 0 {
			res.Requested = tpl.Fields
		}
		if res.CredentialTitle == "" {
			res.CredentialTitle = tpl.Title
		}
	}
	h.attachIssuerDisplay(r, &res)
	// Terminal state → also emit the OOB button swap so the HTMX poller
	// on #verify-poll-btn stops firing every 3s. Pending stays as a
	// single-fragment response so polling continues.
	if res.Pending {
		h.renderFragment(w, r, "fragment_verify_result", res)
		return
	}
	verifyStatus := "ok"
	if !res.Valid {
		verifyStatus = "error"
	}
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(pollStart), "dpg", sess.VerifierDpg, "op", "verify")
	completedSchemaLabel := sess.CustomOID4VPSchemaID
	if sess.CustomOID4VPTemplate != nil {
		completedSchemaLabel = sess.CustomOID4VPTemplate.Title
	}
	metrics.Inc("verification_completed_total", "dpg", sess.VerifierDpg, "schema", completedSchemaLabel, "status", verifyStatus)
	h.attachTrustStatus(r, &res)

	// Write verification event — non-blocking; never delays the HTTP response.
	if h.VerificationLog != nil {
		evtStatus := "invalid"
		if res.Valid {
			evtStatus = "valid"
		}
		evt := verification.Event{
			ID:           verification.NewID(),
			IssuerDID:    res.Issuer,
			SchemaID:     sess.CustomOID4VPSchemaID,
			SchemaName:   completedSchemaLabel,
			VerifierDPG:  sess.VerifierDpg,
			DeploymentID: os.Getenv("VERIFIABLY_PUBLIC_URL"),
			Status:       evtStatus,
			TrustStatus:  res.TrustStatus,
			VerifiedAt:   time.Now().UTC(),
		}
		go func(e verification.Event) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.VerificationLog.Append(ctx, e); err != nil {
				slog.Warn("verification log: append failed", "err", err)
			}
		}(evt)
	}

	slog.Info("oid4vp verification completed",
		"valid", res.Valid,
		"method", res.Method,
		"format", res.Format,
		"dpg", sess.VerifierDpg,
		"fields_count", len(res.DisclosedFields),
		"duration_ms", time.Since(pollStart).Milliseconds(),
	)
	h.renderFragments(w, r, res, "fragment_verify_result", "fragment_verify_stop_polling")
}

// VerifyDirect handles scan/upload/paste direct verification.
//
//   - paste: credential_data carries the raw VC string.
//   - scan:  credential_data carries the QR text the front-end decoded with
//     jsQR from the camera feed. Server does no additional decoding.
//   - upload: the form posts multipart/form-data with a PNG/JPG image of the
//     QR code. Server decodes it with gozxing, then proceeds exactly like
//     scan/paste.
func (h *H) VerifyDirect(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	// Large uploads are intentionally capped at 8 MB; real QR images fit well
	// under 1 MB but browsers sometimes attach arbitrary sidecars.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		_ = r.ParseForm() // fall back for non-multipart submissions
	}
	method := r.FormValue("method")
	credData := strings.TrimSpace(r.FormValue("credential_data"))

	if method == "upload" && credData == "" {
		decoded, err := decodeUploadedQR(r)
		if err != nil {
			h.errorToast(w, r, "Could not read QR from upload: "+err.Error())
			return
		}
		credData = decoded
	}
	if method == "paste" && credData == "" {
		h.errorToast(w, r, "Paste a credential first")
		return
	}
	if method == "scan" && credData == "" {
		h.errorToast(w, r, "Scanner did not return a credential payload")
		return
	}
	directStart := time.Now()
	res, err := h.Adapter.VerifyDirect(r.Context(), backend.DirectVerifyRequest{
		VerifierDpg: sess.VerifierDpg, Method: method, CredentialData: credData,
	})
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(directStart), "dpg", sess.VerifierDpg, "op", "verify")
	if err != nil {
		metrics.Inc("verification_completed_total", "dpg", sess.VerifierDpg, "schema", "", "status", "error")
		h.errorToast(w, r, err.Error())
		return
	}
	directStatus := "ok"
	if !res.Valid {
		directStatus = "error"
	}
	metrics.Inc("verification_completed_total", "dpg", sess.VerifierDpg, "schema", "", "status", directStatus)
	h.attachTrustStatus(r, &res)
	h.attachIssuerDisplay(r, &res)
	h.renderFragment(w, r, "fragment_verify_result", res)
}

// attachTrustStatus populates VerificationResult.TrustStatus / TrustReason
// by checking the issuer DID against the configured trust registry.
// No-op when TrustRegistry is nil or Issuer is empty.
func (h *H) attachTrustStatus(r *http.Request, res *backend.VerificationResult) {
	if h.TrustRegistry == nil || res.Issuer == "" {
		return
	}
	err := h.TrustRegistry.IsTrusted(r.Context(), res.Issuer, res.CredentialTitle)
	if err == nil {
		res.TrustStatus = "trusted"
		return
	}
	if errors.Is(err, trust.ErrUntrusted) {
		res.TrustStatus = "untrusted"
		res.TrustReason = err.Error()
		return
	}
	// I/O error — mark unknown, log but don't block the result.
	slog.Warn("trust registry lookup failed", "issuer", res.Issuer, "err", err)
	res.TrustStatus = "unknown"
}

// attachIssuerDisplay populates VerificationResult.IssuerDisplay by looking
// up the schema whose Name matches the credential's title in the local
// store and copying its IssuerDisplayName. Best-effort: silent on lookup
// failure so transient catalog issues never block the verify result.
func (h *H) attachIssuerDisplay(r *http.Request, res *backend.VerificationResult) {
	if res == nil || res.IssuerDisplay != "" {
		return
	}
	title := strings.TrimSpace(res.CredentialTitle)
	if title == "" {
		return
	}
	schemas, err := h.Adapter.ListAllSchemas(r.Context())
	if err != nil {
		return
	}
	for _, s := range schemas {
		if strings.EqualFold(strings.TrimSpace(s.Name), title) {
			if iss := strings.TrimSpace(s.IssuerDisplayName); iss != "" {
				res.IssuerDisplay = iss
			}
			return
		}
	}
}
