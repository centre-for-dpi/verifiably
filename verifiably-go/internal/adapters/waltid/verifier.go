package waltid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// oid4vpTemplates is the verifier's built-in preset list. Walt.id doesn't
// expose a "list my configured templates" endpoint — the verifier accepts
// any DCQL/Presentation-Exchange query on every /verify call, so we bundle
// a curated set grounded in the credential types walt.id actually ships
// (see /draft13/.well-known/openid-credential-issuer).
var oid4vpTemplates = map[string]vctypes.OID4VPTemplate{
	"age_over_18": {
		Title:      "Proof of age over 18",
		Fields:     []string{"age_over_18"},
		Format:     "sd_jwt_vc (IETF)",
		Disclosure: "selective — only age_over_18 is shared",
	},
	"university_degree": {
		Title:      "University Degree",
		Fields:     []string{"degree", "classification", "conferred"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"verifiable_id": {
		Title:      "Verifiable ID",
		Fields:     []string{"holder", "dateOfBirth", "nationality"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"kyc_checks": {
		Title:      "KYC checks credential",
		Fields:     []string{"kycComplete", "amlScreeningPassed"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"iso_mdl": {
		Title:      "ISO mDL driver's licence",
		Fields:     []string{"family_name", "given_name", "birth_date", "driving_privileges"},
		Format:     "mso_mdoc",
		Disclosure: "full credential shared",
	},
	"open_badge": {
		Title:      "Open Badge v3",
		Fields:     []string{"achievement", "issuedOn"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"employment": {
		Title:      "Employment record",
		Fields:     []string{"employer", "title", "startDate"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
}

// ListOID4VPTemplates returns the curated preset list.
func (a *Adapter) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	out := make(map[string]vctypes.OID4VPTemplate, len(oid4vpTemplates))
	for k, v := range oid4vpTemplates {
		out[k] = v
	}
	return out, nil
}

// verifyBody matches the POST /openid4vc/verify body shape (VerifierApi.kt:73).
// Walt.id wants `request_credentials` as an array of objects keyed by format.
// For Presentation-Exchange (pre-OID4VP-v1.0), each object has `format` and
// `type`; for OID4VP v1.0 DCQL, it takes a different shape — but v0.18.2 is
// still in the PE-based flow as default.
//
// vc_policies accepts both string entries ("signature", "expired") and
// object entries (`{"policy":"webhook","args":{"url":"…"}}`), so the field
// is []any.
type verifyBody struct {
	RequestCredentials []map[string]any `json:"request_credentials"`
	VPPolicies         []any            `json:"vp_policies,omitempty"`
	VCPolicies         []any            `json:"vc_policies,omitempty"`
}

// RequestPresentation creates a verifier session. Walt.id returns the full
// authorize URL as the plain-text response body.
//
// Accepts either a preset TemplateKey or an inline req.Template; the latter
// wins when both are set. Handlers use the inline path for custom
// user-assembled requests; the keyed path covers the curated presets.
func (a *Adapter) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	// Multi-credential request (e.g. a delegated-access pair): one
	// input-descriptor per template, so the wallet must present all of them.
	// Self-contained so the single-credential path below stays untouched.
	if len(req.Templates) > 0 {
		entries := make([]map[string]any, 0, len(req.Templates))
		var primaryFormat string
		for _, t := range req.Templates {
			e, f := buildRequestEntry(t)
			entries = append(entries, e)
			if primaryFormat == "" {
				primaryFormat = f
			}
		}
		body := verifyBody{
			RequestCredentials: entries,
			VPPolicies:         buildVPPolicies(),
			VCPolicies:         buildVCPolicies(req.Policies, req.WebhookURL, primaryFormat),
		}
		raw, err := a.verifier.DoRaw(ctx, "POST", "/openid4vc/verify", jsonReader(body), "application/json", nil)
		if err != nil {
			return backend.PresentationRequestResult{}, err
		}
		authorizeURL := strings.TrimSpace(string(raw))
		return backend.PresentationRequestResult{
			RequestURI: authorizeURL,
			State:      extractVerifierState(authorizeURL),
			Template:   req.Templates[0],
		}, nil
	}

	var tpl vctypes.OID4VPTemplate
	typeHint := credentialTypeForTemplate(req.TemplateKey)
	if req.Template != nil {
		tpl = *req.Template
		// Custom templates plumb the canonical credential type + full vct
		// URL through the template itself (filled by the handler from the
		// Schema.Variants slice). Use those verbatim — they match exactly
		// what walt.id's wallet holds, which keeps the PD match working
		// when formats differ. Fall back to the title-derived guess only
		// when neither is provided (older templates, custom schemas).
		if tpl.CredentialType != "" {
			typeHint = tpl.CredentialType
		} else {
			typeHint = credentialTypeForCustomTemplate(tpl)
		}
	} else {
		var ok bool
		tpl, ok = oid4vpTemplates[req.TemplateKey]
		if !ok {
			return backend.PresentationRequestResult{}, fmt.Errorf("unknown template key %q", req.TemplateKey)
		}
	}
	// Build the request_credentials entry. For selective disclosure to
	// actually restrict which claims the wallet reveals, we need to pass
	// an EXPLICIT input_descriptor with limit_disclosure=required and one
	// path per requested field. Walt.id's RequestedCredential honors
	// inputDescriptor verbatim when set (RequestedCredential.toInputDescriptor
	// in waltid-verifier-api); the short {format, vct} shape falls back to
	// getDefaultInputDescriptorConstraints which only filters by vct/type —
	// effectively full disclosure. So when tpl.Disclosure is selective and
	// the template lists fields, we build the full input_descriptor here.
	// Prefer the explicit wire format the handler plumbed through —
	// that preserves the user's chip selection within a Std bucket
	// (jwt_vc_json vs ldp_vc vs jwt_vc inside w3c_vcdm_2). Falling back
	// to the Std-mapped default hard-codes jwt_vc_json for w3c_vcdm_2
	// and silently drops the LDP / JWT (legacy) chip choices.
	format := tpl.WireFormat
	if format == "" {
		format = credentialFormatForStd(tpl.Format)
	}
	selective := strings.Contains(strings.ToLower(tpl.Disclosure), "selective")
	var entry map[string]any
	if len(tpl.Fields) > 0 {
		// Always build the full input_descriptor when the verifier is
		// asking for specific fields. limit_disclosure switches between
		// "required" (selective) and "preferred" (full). Bare
		// {format, vct} triggers walt.id to auto-generate a PD the
		// wallet's usePresentationRequest can't deserialize
		// ("Field 'input_descriptors' is required"), so we own PD
		// construction end-to-end.
		entry = buildSelectiveInputDescriptor(format, typeHint, tpl)
		if !selective {
			// Mark limit_disclosure=preferred on the full-disclosure path
			// so the wallet doesn't strip non-listed disclosures.
			if desc, ok := entry["input_descriptor"].(map[string]any); ok {
				if cons, ok := desc["constraints"].(map[string]any); ok {
					cons["limit_disclosure"] = "preferred"
				}
			}
		}
	} else {
		entry = map[string]any{"format": format}
		switch format {
		case "vc+sd-jwt", "dc+sd-jwt":
			if tpl.Vct != "" {
				entry["vct"] = tpl.Vct
			} else {
				entry["vct"] = typeHint
			}
		default:
			entry["type"] = typeHint
		}
	}
	body := verifyBody{
		RequestCredentials: []map[string]any{entry},
		VPPolicies:         buildVPPolicies(),
		VCPolicies:         buildVCPolicies(req.Policies, req.WebhookURL, format),
	}
	raw, err := a.verifier.DoRaw(ctx, "POST", "/openid4vc/verify", jsonReader(body), "application/json", nil)
	if err != nil {
		return backend.PresentationRequestResult{}, err
	}
	authorizeURL := strings.TrimSpace(string(raw))
	state := extractVerifierState(authorizeURL)
	return backend.PresentationRequestResult{
		RequestURI: authorizeURL,
		State:      state,
		Template:   tpl,
	}, nil
}

// buildRequestEntry builds one walt.id request_credentials entry from a
// template — the same logic the single-credential path uses inline, factored
// out so a multi-credential request can build one entry per template. Returns
// the entry and its wire format.
func buildRequestEntry(tpl vctypes.OID4VPTemplate) (map[string]any, string) {
	typeHint := tpl.CredentialType
	if typeHint == "" {
		typeHint = credentialTypeForCustomTemplate(tpl)
	}
	format := tpl.WireFormat
	if format == "" {
		format = credentialFormatForStd(tpl.Format)
	}
	selective := strings.Contains(strings.ToLower(tpl.Disclosure), "selective")
	if len(tpl.Fields) > 0 {
		entry := buildSelectiveInputDescriptor(format, typeHint, tpl)
		if !selective {
			if desc, ok := entry["input_descriptor"].(map[string]any); ok {
				if cons, ok := desc["constraints"].(map[string]any); ok {
					cons["limit_disclosure"] = "preferred"
				}
			}
		}
		return entry, format
	}
	entry := map[string]any{"format": format}
	switch format {
	case "vc+sd-jwt", "dc+sd-jwt":
		if tpl.Vct != "" {
			entry["vct"] = tpl.Vct
		} else {
			entry["vct"] = typeHint
		}
	default:
		entry["type"] = typeHint
	}
	return entry, format
}

// buildSelectiveInputDescriptor returns a request_credentials entry with a
// full inputDescriptor instructing the wallet to reveal ONLY the requested
// fields. The field JSONPaths differ per format:
//
//   - SD-JWT VC (vc+sd-jwt / dc+sd-jwt): claims are top-level, so paths are
//     `$.<field>`. Plus a `$.vct` filter so the wallet picks the right
//     credential when more than one vct could match.
//   - W3C VC-JWT (jwt_vc_json / ldp_vc / jwt_vc): claims are under
//     credentialSubject, so paths are `$.vc.credentialSubject.<field>`.
//     Plus a `$.vc.type` filter.
//   - mso_mdoc: claims are namespace-keyed, so paths are
//     `$['<namespace>']['<field>']`.
//
// limit_disclosure is only meaningful for formats that support selective
// disclosure natively (SD-JWT, mdoc). For plain JWT VC it's advisory —
// walt.id's wallet either returns the whole credential or refuses; we
// mark it "preferred" so the wallet attempts a best-effort and doesn't
// fail the PD match.
func buildSelectiveInputDescriptor(format, typeHint string, tpl vctypes.OID4VPTemplate) map[string]any {
	descriptorID := typeHint
	if descriptorID == "" {
		descriptorID = tpl.Title
	}
	if descriptorID == "" {
		descriptorID = "custom-request"
	}
	fields := []any{}
	switch format {
	case "vc+sd-jwt", "dc+sd-jwt":
		vct := tpl.Vct
		if vct == "" {
			vct = typeHint
		}
		fields = append(fields, map[string]any{
			"path": []string{"$.vct"},
			"filter": map[string]any{
				"type":    "string",
				"pattern": vct,
			},
		})
		for _, f := range tpl.Fields {
			fields = append(fields, map[string]any{
				"path": []string{"$." + f},
			})
		}
	case "mso_mdoc":
		ns := "org.iso.18013.5.1"
		for _, f := range tpl.Fields {
			fields = append(fields, map[string]any{
				"path":           []string{fmt.Sprintf("$['%s']['%s']", ns, f)},
				"intentToRetain": false,
			})
		}
	default:
		fields = append(fields, map[string]any{
			"path": []string{"$.vc.type"},
			"filter": map[string]any{
				"type":    "string",
				"pattern": typeHint,
			},
		})
		for _, f := range tpl.Fields {
			fields = append(fields, map[string]any{
				"path": []string{"$.vc.credentialSubject." + f},
			})
		}
	}
	constraints := map[string]any{"fields": fields}
	switch format {
	case "vc+sd-jwt", "dc+sd-jwt", "mso_mdoc":
		constraints["limit_disclosure"] = "required"
	default:
		constraints["limit_disclosure"] = "preferred"
	}
	return map[string]any{
		"format": format,
		"input_descriptor": map[string]any{
			"id":          descriptorID,
			"format":      map[string]any{format: map[string]any{}},
			"constraints": constraints,
		},
	}
}

// credentialTypeForCustomTemplate derives a walt.id PE "type" filter for a
// user-assembled template. Uses the template's title (Camel-cased words
// joined) if it resembles a credential name; otherwise returns the generic
// VerifiableCredential filter which matches any VC the wallet holds.
func credentialTypeForCustomTemplate(tpl vctypes.OID4VPTemplate) string {
	title := strings.TrimSpace(tpl.Title)
	if title == "" {
		return "VerifiableCredential"
	}
	// Title-case and strip non-alphanumerics to guess a type name.
	var b strings.Builder
	capNext := true
	for _, r := range title {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
			capNext = false
			continue
		}
		if r >= 'a' && r <= 'z' {
			if capNext {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			capNext = false
			continue
		}
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			capNext = false
			continue
		}
		capNext = true
	}
	guess := b.String()
	if guess == "" {
		return "VerifiableCredential"
	}
	if !strings.HasSuffix(guess, "Credential") {
		guess += "Credential"
	}
	return guess
}

// sessionResult is the slim shape this adapter reads out of
// GET /openid4vc/session/{id}. Walt.id returns a rich object including
// policy results, credential submissions, etc.; we consume what the UI needs.
type sessionResult struct {
	SessionID                string          `json:"sessionId"`
	VerificationResult       *bool           `json:"verificationResult,omitempty"`
	OverallVerificationResult *bool          `json:"overallVerificationResult,omitempty"`
	TokenResponse            json.RawMessage `json:"tokenResponse,omitempty"`
	AuthorizationRequest     json.RawMessage `json:"authorizationRequest,omitempty"`
	PolicyResults            json.RawMessage `json:"policyResults,omitempty"`
	VPPolicies               json.RawMessage `json:"vpPolicies,omitempty"`
	VCPolicies               json.RawMessage `json:"vcPolicies,omitempty"`
	Success                  *bool           `json:"success,omitempty"`
	Issued                   string          `json:"issued,omitempty"`
}

// FetchPresentationResult polls GET /openid4vc/session/{id} for a terminal
// verification state. The UI calls this once (on the user's "check result"
// action); we make up to N short-interval polls so a holder that just
// presented via the wallet-api sees the result promptly.
func (a *Adapter) FetchPresentationResult(ctx context.Context, state, templateKey string) (backend.VerificationResult, error) {
	tpl := oid4vpTemplates[templateKey] // zero value for unknown/custom keys is fine — we only use tpl.Fields for shape
	path := "/openid4vc/session/" + url.PathEscape(state)
	var res sessionResult
	deadline := time.Now().Add(8 * time.Second)
	for {
		if err := a.verifier.DoJSON(ctx, "GET", path, nil, &res, nil); err != nil {
			return backend.VerificationResult{}, err
		}
		if isTerminalSession(res) || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !isTerminalSession(res) {
		return backend.VerificationResult{
			Pending: true,
			Method:  fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
			Format:  tpl.Format,
		}, nil
	}

	fields, issuer, subject, issued, title := extractPresentedCredential(res.TokenResponse)
	creds, holder := normalizePresentedCredentials(res.TokenResponse)
	policies := extractAppliedPolicies(res.PolicyResults)
	outcomes := extractPolicyOutcomes(res.PolicyResults)
	if issuer == "" {
		issuer = "(resolved on verification)"
	}
	if subject == "" {
		subject = "(resolved on verification)"
	}
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	return backend.VerificationResult{
		Valid:             overallResult(res),
		Method:            fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
		Format:            tpl.Format,
		Issuer:            issuer,
		Subject:           subject,
		Requested:         tpl.Fields,
		Issued:            issued,
		CheckedRevocation: true,
		PoliciesApplied:   policies,
		PolicyOutcomes:    outcomes,
		DisclosedFields:   fields,
		CredentialTitle:   title,
		Credentials:       creds,
		HolderBinding:     holder,
	}, nil
}

// buildVPPolicies returns the always-on VP-level policies. Every OID4VP
// flow needs signature verification on the presentation envelope and
// presentation-definition matching — making these user-toggleable would
// just let an operator accidentally disable the whole point of the flow.
func buildVPPolicies() []any {
	return []any{"signature", "presentation-definition"}
}

// buildVCPolicies maps the user's selected policy checkboxes onto walt.id's
// vc_policies list shape. String entries are first-class policies; the
// "webhook" option becomes an object policy with the operator's URL in
// args. Unknown policy names are dropped.
//
// "status-list" maps to walt.id's `credential-status` policy
// (id/walt/policies/policies/StatusPolicy, @SerialName "credential-status").
// The policy needs `args` shaped as a sealed StatusPolicyArgument with a
// `discriminator` tag: "w3c" for VCDM 2.0 BSL 2023 or "ietf" for SD-JWT
// IETF Token Status List. Sending the policy as a bare string returns
// "args required"; sending the wrong discriminator throws during
// evaluation when the credential's status entry doesn't match.
//
// Verified end-to-end against waltid-verification-policies-jvm-1.0.0-
// SNAPSHOT.jar (decompiled bytecode) — full pipeline:
//
//   W3C   data.vc.credentialStatus  →  W3CEntry (type, statusPurpose,
//                                       statusListIndex, statusListCredential)
//         GET statusListCredential  →  JWT
//         payload.vc.credentialSubject  →  W3CStatusContent (type,
//                                          statusPurpose, encodedList)
//         args.type    == content.type     (W3CStatusValidator.customValidations)
//         args.purpose == content.statusPurpose
//         W3cStatusListExpansionAlgorithmFactory dispatches on
//         content.type ∈ {"BitstringStatusList", "StatusList2021",
//         "RevocationList2020"} — anything else IllegalArgumentException.
//         BitstringStatusList branch requires multibase base64-url
//         (encodedList prefixed with "u") then GZIP. BigEndianRepresentation
//         (MSB-first) bit reader. Final check: bitValue == args.value.
//
//   IETF  data.status  →  IETFEntry { status_list: { idx, uri } }
//         GET status_list.uri  →  JWT (typ ignored)
//         payload.status_list  →  IETFStatusContent (bits, lst)
//         No type/purpose validation. zlib + base64url decode (no multibase).
//         LittleEndianRepresentation (LSB-first) bit reader.
//         Final check: bitValue == args.value.
//
// Polymorphism gotcha that bit us: args.type is compared against the
// LIST's credentialSubject.type (= "BitstringStatusList"), NOT the
// credential's credentialStatus.type (= "BitstringStatusListEntry").
// Per the W3C spec these are different strings; walt.id only ever
// looks at the list side. value=0 means "expect not revoked".
//
// Other names we tried that didn't work in v0.18.2:
//   - bare "credential-status"        → "args required"
//   - "not-revoked-token-status-list" → 400 "No policy found by name"
//   - "revoked-status-list"           → that's RevocationPolicy, only handles
//                                       VCDM 1.0 RevocationList2020.
func buildVCPolicies(selected []string, webhookURL, format string) []any {
	out := []any{}
	isIETF := format == "vc+sd-jwt" || format == "dc+sd-jwt"
	for _, p := range selected {
		switch p {
		case "signature", "expired", "not-before":
			out = append(out, p)
		case "status-list":
			args := map[string]any{"value": 0}
			if isIETF {
				args["discriminator"] = "ietf"
			} else {
				args["discriminator"] = "w3c"
				args["purpose"] = "revocation"
				// MUST match the list's vc.credentialSubject.type, NOT the
				// credential's credentialStatus.type. Walt.id's
				// W3CStatusValidator compares args.type to content.type
				// (where content is the deserialized credentialSubject of
				// the fetched list). Setting this to BitstringStatusListEntry
				// fails with "Type validation failed: expected
				// BitstringStatusListEntry, but got BitstringStatusList".
				args["type"] = "BitstringStatusList"
			}
			out = append(out, map[string]any{
				"policy": "credential-status",
				"args":   args,
			})
		case "webhook":
			url := strings.TrimSpace(webhookURL)
			if url == "" {
				continue
			}
			out = append(out, map[string]any{
				"policy": "webhook",
				"args":   map[string]any{"url": url},
			})
		}
	}
	return out
}

// extractAppliedPolicies walks walt.id's policyResults blob and returns the
// set of policy names that ran. Walt.id returns policyResults as a nested
// object {results: [{policy: "signature", ...}, ...]} or similar; we scan
// for top-level "policy" keys. Unknown shapes yield nil which the UI
// renders as "(no detail)".
func extractAppliedPolicies(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var any1 any
	if err := json.Unmarshal(raw, &any1); err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if p, ok := x["policy"].(string); ok && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			for _, v2 := range x {
				walk(v2)
			}
		case []any:
			for _, v2 := range x {
				walk(v2)
			}
		}
	}
	walk(any1)
	return out
}

// extractPolicyOutcomes walks walt.id's policyResults blob and returns
// per-policy success+reason detail. Walt.id v0.18.2 emits each policy
// outcome as an object containing `policy` (name) plus EITHER
// `is_success` (boolean) and `error`/`message` (string when failed) OR
// just an embedded exception. We detect failure by either the explicit
// flag being false or the presence of a non-empty error/message string
// alongside the policy name.
//
// Returns nil for empty / unparseable input so callers can fall back to
// extractAppliedPolicies for the older "just names" surface.
func extractPolicyOutcomes(raw json.RawMessage) []backend.PolicyOutcome {
	if len(raw) == 0 {
		return nil
	}
	var any1 any
	if err := json.Unmarshal(raw, &any1); err != nil {
		return nil
	}
	type slot struct {
		passed bool
		reason string
	}
	seen := map[string]slot{}
	order := []string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			name, hasName := x["policy"].(string)
			if hasName && name != "" {
				cur, exists := seen[name]
				if !exists {
					// Default to passed; flip to failed on signal below.
					cur = slot{passed: true}
					order = append(order, name)
				}
				// Walt.id surfaces failure as one of:
				//   - is_success: false
				//   - success:    false
				//   - error/message: non-empty string
				//   - exception (object) carrying message
				if v, ok := x["is_success"].(bool); ok && !v {
					cur.passed = false
				}
				if v, ok := x["success"].(bool); ok && !v {
					cur.passed = false
				}
				for _, k := range []string{"error", "message", "errorMessage"} {
					if s, ok := x[k].(string); ok && s != "" {
						cur.passed = false
						if cur.reason == "" {
							cur.reason = s
						}
					}
				}
				if exc, ok := x["exception"].(map[string]any); ok {
					cur.passed = false
					if s, ok := exc["message"].(string); ok && cur.reason == "" {
						cur.reason = s
					}
				}
				seen[name] = cur
			}
			for _, v2 := range x {
				walk(v2)
			}
		case []any:
			for _, v2 := range x {
				walk(v2)
			}
		}
	}
	walk(any1)
	if len(order) == 0 {
		return nil
	}
	out := make([]backend.PolicyOutcome, 0, len(order))
	for _, name := range order {
		s := seen[name]
		out = append(out, backend.PolicyOutcome{
			Name:   name,
			Passed: s.passed,
			Reason: s.reason,
		})
	}
	return out
}

// extractPresentedCredential parses walt.id's tokenResponse to pull the
// holder-disclosed claim values. Returns (fields, issuer, subject, issued,
// title) — any value can be empty when the shape doesn't match (SD-JWT VC
// vs W3C VC-JWT take different parse paths). Best-effort — fields stay
// nil and the UI gracefully hides the "Presented Credentials" panel.
func extractPresentedCredential(raw json.RawMessage) (map[string]string, string, string, time.Time, string) {
	if len(raw) == 0 {
		return nil, "", "", time.Time{}, ""
	}
	var env struct {
		VPToken any `json:"vp_token"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", "", time.Time{}, ""
	}
	// vp_token can be a string (single VP), an array of strings (multiple
	// VPs), or nested. We flatten to a list of string tokens.
	var tokens []string
	switch v := env.VPToken.(type) {
	case string:
		tokens = []string{v}
	case []any:
		for _, t := range v {
			if s, ok := t.(string); ok {
				tokens = append(tokens, s)
			}
		}
	}
	for _, tok := range tokens {
		if strings.Contains(tok, "~") {
			// SD-JWT VC format: <header.payload.sig>~<disclosure>~…
			fields, iss, sub, issued, title := parseSDJWTVC(tok)
			if len(fields) > 0 {
				return fields, iss, sub, issued, title
			}
			continue
		}
		// W3C VC-JWT wrapped in a VP-JWT.
		fields, iss, sub, issued, title := parseVPJWT(tok)
		if len(fields) > 0 {
			return fields, iss, sub, issued, title
		}
	}
	return nil, "", "", time.Time{}, ""
}

// parseSDJWTVC decodes an SD-JWT-VC presentation: the first segment is the
// credential JWT (base64url header.payload.sig); following tilde-separated
// segments are disclosures — each a base64url-encoded JSON array of
// [salt, claim, value]. We merge the JWT payload's direct claims with the
// disclosed ones so the UI sees the full revealed subject.
func parseSDJWTVC(tok string) (map[string]string, string, string, time.Time, string) {
	parts := strings.Split(tok, "~")
	if len(parts) == 0 {
		return nil, "", "", time.Time{}, ""
	}
	jwt := parts[0]
	payload := decodeJWTPayload(jwt)
	if payload == nil {
		return nil, "", "", time.Time{}, ""
	}
	fields := map[string]string{}
	// Base claims (the non-selectively-disclosable ones that the issuer
	// chose to leave in the clear). Skip the SD control keys and standard
	// JWT claims so the UI doesn't render "_sd: [...]".
	reserved := map[string]bool{
		"_sd": true, "_sd_alg": true, "cnf": true, "iss": true, "iat": true,
		"exp": true, "nbf": true, "sub": true, "vct": true, "status": true,
	}
	for k, v := range payload {
		if reserved[k] {
			continue
		}
		fields[k] = stringifyAny(v)
	}
	// Merge disclosed fields: each is a base64url JSON array
	// [salt, claim, value] or [salt, value] (for array element disclosures).
	for _, seg := range parts[1:] {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		d, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			continue
		}
		var arr []any
		if err := json.Unmarshal(d, &arr); err != nil {
			continue
		}
		if len(arr) == 3 {
			if name, ok := arr[1].(string); ok {
				fields[name] = stringifyAny(arr[2])
			}
		}
	}
	issuer, _ := payload["iss"].(string)
	subject, _ := payload["sub"].(string)
	title, _ := payload["vct"].(string)
	if title != "" {
		if i := strings.LastIndex(title, "/"); i >= 0 {
			title = title[i+1:]
		}
	}
	issued := unixClaim(payload, "iat")
	return fields, issuer, subject, issued, title
}

// parseVPJWT decodes a VP-JWT (VC Data Model 1.1 presentation) and pulls
// the first embedded VC's credentialSubject. Most W3C VC-JWT flows keep
// the subject claims nested there; we stringify leaf values so the UI can
// render them uniformly.
func parseVPJWT(tok string) (map[string]string, string, string, time.Time, string) {
	vp := decodeJWTPayload(tok)
	if vp == nil {
		return nil, "", "", time.Time{}, ""
	}
	// vp.verifiableCredential[] — each is either an embedded object or a
	// nested VC-JWT string.
	vpObj, _ := vp["vp"].(map[string]any)
	if vpObj == nil {
		vpObj = vp
	}
	vcList, _ := vpObj["verifiableCredential"].([]any)
	if len(vcList) == 0 {
		return nil, "", "", time.Time{}, ""
	}
	var vcPayload map[string]any
	switch v := vcList[0].(type) {
	case string:
		vcPayload = decodeJWTPayload(v)
	case map[string]any:
		vcPayload = v
	}
	if vcPayload == nil {
		return nil, "", "", time.Time{}, ""
	}
	vcInner, _ := vcPayload["vc"].(map[string]any)
	if vcInner == nil {
		vcInner = vcPayload
	}
	cs, _ := vcInner["credentialSubject"].(map[string]any)
	if cs == nil {
		return nil, "", "", time.Time{}, ""
	}
	fields := map[string]string{}
	for k, v := range cs {
		if k == "id" {
			continue
		}
		fields[k] = stringifyAny(v)
	}
	issuer := stringifyAny(vcInner["issuer"])
	subject, _ := cs["id"].(string)
	if subject == "" {
		subject, _ = vcPayload["sub"].(string)
	}
	issued := unixClaim(vcPayload, "iat")
	title := ""
	if types, ok := vcInner["type"].([]any); ok {
		for _, t := range types {
			if s, ok := t.(string); ok && s != "VerifiableCredential" {
				title = s
				break
			}
		}
	}
	return fields, issuer, subject, issued, title
}

func decodeJWTPayload(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// try std padding
		if raw2, err2 := base64.URLEncoding.DecodeString(parts[1]); err2 == nil {
			raw = raw2
		} else {
			return nil
		}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func stringifyAny(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func unixClaim(m map[string]any, key string) time.Time {
	v, ok := m[key].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// VerifyDirect — walt.id v0.18.2 has no direct-credential-verification
// endpoint. Return ErrNotSupported. The handler surfaces this as a toast
// instructing the operator to use the OID4VP flow instead.
func (a *Adapter) VerifyDirect(_ context.Context, _ backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, backend.ErrNotSupported
}

// credentialFormatForStd maps the template's Format onto walt.id's format key.
func credentialFormatForStd(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return "jwt_vc_json"
	}
}

// credentialTypeForTemplate picks a sensible credential type for each template key.
// The type names match what walt.id's issuer exposes in
// credential_configurations_supported, so the verifier's Presentation
// Exchange constraint will actually match real credentials issued here.
func credentialTypeForTemplate(key string) string {
	switch key {
	case "age_over_18":
		return "IdentityCredential"
	case "university_degree":
		return "UniversityDegree"
	case "verifiable_id":
		return "VerifiableId"
	case "kyc_checks":
		return "KycChecksCredential"
	case "iso_mdl":
		return "Iso18013DriversLicenseCredential"
	case "open_badge":
		return "OpenBadgeCredential"
	case "employment":
		return "EmploymentRecord"
	default:
		return "VerifiableCredential"
	}
}

// extractVerifierState pulls the session id out of the authorize URL walt.id
// returns. Shape: openid4vp://authorize?...&request_uri=<base>/openid4vc/request/{id}
// or openid4vp://authorize?...&state=<id>.
func extractVerifierState(authorizeURL string) string {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	if s := q.Get("state"); s != "" {
		return s
	}
	if ru := q.Get("request_uri"); ru != "" {
		if i := strings.LastIndex(ru, "/"); i >= 0 && i+1 < len(ru) {
			return ru[i+1:]
		}
	}
	return ""
}

// isTerminalSession returns true when walt.id's verifier has a verdict —
// and ONLY when a verdict exists. Previously we also treated "TokenResponse
// set" as terminal, which caused a race: auto-polling lands between the
// holder's submission arriving and walt.id finishing policy evaluation,
// the session has TokenResponse but no verification flag yet, overallResult
// returns false, the OOB swap stops polling, and the user sees a permanent
// "Credential invalid" even though the eventual verdict was true. The
// token-response fallback can't distinguish "policies still running" from
// "policies finished with no result", so drop it — if walt.id hasn't set
// a flag, we keep polling.
func isTerminalSession(r sessionResult) bool {
	return r.VerificationResult != nil || r.OverallVerificationResult != nil || r.Success != nil
}

func overallResult(r sessionResult) bool {
	if r.OverallVerificationResult != nil {
		return *r.OverallVerificationResult
	}
	if r.VerificationResult != nil {
		return *r.VerificationResult
	}
	if r.Success != nil {
		return *r.Success
	}
	return false
}
