package injicertify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// credentialIssuerMetadata is a minimal shape of
// /v1/certify/.well-known/openid-credential-issuer we care about.
type credentialIssuerMetadata struct {
	CredentialIssuer                  string                                  `json:"credential_issuer"`
	AuthorizationServers              []string                                `json:"authorization_servers"`
	CredentialEndpoint                string                                  `json:"credential_endpoint"`
	CredentialConfigurationsSupported map[string]credentialConfigurationEntry `json:"credential_configurations_supported"`
}

type credentialConfigurationEntry struct {
	Format         string                       `json:"format"`
	Scope          string                       `json:"scope,omitempty"`
	Display        []map[string]json.RawMessage `json:"display,omitempty"`
	Order          []string                     `json:"order,omitempty"`
	CredentialDef  *credentialDefinitionEntry   `json:"credential_definition,omitempty"`
	Vct            string                       `json:"vct,omitempty"`
	// Doctype is the ISO docType Inji Certify advertises for an mso_mdoc
	// config (e.g. "org.iso.18013.5.1.mDL") — confirmed present in a real
	// wellknown response from a schema SaveCustomSchema wrote. ListSchemas
	// needs this to rebuild each field's real Format (driving_privileges'
	// repeater UI, portrait's file upload) via mdoc.MandatoryFields, instead
	// of falling through fieldSpecFor's generic name-based heuristics, which
	// have no case for either — see fieldSpecFor's doc comment.
	Doctype string `json:"doctype,omitempty"`
}

type credentialDefinitionEntry struct {
	Type []string `json:"type"`
}

// ListSchemas fetches the issuer's credential configurations and maps each one
// onto a vctypes.Schema. FieldsSpec comes from the `order` array on each config
// (when present) so operator-facing forms show the real field list the
// credential configuration declares.
func (a *Adapter) ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error) {
	var meta credentialIssuerMetadata
	if err := a.client.DoJSON(ctx, http.MethodGet, "/v1/certify/.well-known/openid-credential-issuer", nil, &meta, nil); err != nil {
		return nil, fmt.Errorf("fetch issuer metadata: %w", err)
	}
	out := make([]vctypes.Schema, 0, len(meta.CredentialConfigurationsSupported))
	for id, cfg := range meta.CredentialConfigurationsSupported {
		std := formatToStd(cfg.Format)
		if std == "" {
			continue
		}
		name := displayName(cfg)
		if name == "" {
			name = humanise(id)
		}
		fields := []vctypes.FieldSpec{}
		// mso_mdoc fields need their REAL Format (driving_privileges'
		// structured repeater, portrait's file upload) — mdoc.MandatoryFields
		// is the single source of truth for that mapping (the same one
		// mdoc.KnownDocTypes/the schema builder itself uses), keyed by field
		// name. Built once per config, outside the per-field loop below.
		// Without this, fieldSpecFor's generic name-based heuristics run
		// instead (they have no case for either field), so driving_privileges
		// silently renders as a plain textbox and its value never reaches
		// backend.IssueRequest.StructuredData — reproduced live: an operator
		// filled the field, submitted, and the adapter's own "driving_privileges
		// es obligatorio" guard fired anyway, because the value had gone into
		// SubjectData as a scalar string instead.
		var mdocFields map[string]vctypes.FieldSpec
		if cfg.Format == "mso_mdoc" && cfg.Doctype != "" {
			mdocFields = make(map[string]vctypes.FieldSpec)
			for _, mf := range mdoc.MandatoryFields(cfg.Doctype) {
				mdocFields[mf.Name] = mf
			}
		}
		// A declared validity marker IS the record that this schema expires.
		// Schema.Expires lives only in verifiably's store and no vendor
		// advertises it, so rebuilding a Schema here without it silently
		// disagrees with the template SaveCustomSchema already wrote: the
		// template asks for ${validUntilEpoch} while issuance, reading this
		// rebuilt schema, declines to POST one — certify then rejects the
		// unresolved marker and the schema cannot be issued at all.
		expires := false
		for _, f := range cfg.Order {
			if isValidityMarker(f) {
				expires = true
			}
			// Internal template markers (the token-status pointer, the validity
			// window) are declared in the config's order so certify's pre-auth
			// data-provider resolves them into the Velocity context — but they are
			// auto-supplied by the issuer, never operator-entered, so keep them out
			// of the issue form's claim fields. The validity window comes from the
			// form's own "Validity window" datetime pickers; surfacing its raw
			// markers renders them as unfillable text boxes ("validFromEpoch *")
			// beside the real control.
			if isInternalMarker(f) {
				continue
			}
			if mf, ok := mdocFields[f]; ok {
				fields = append(fields, mf)
				continue
			}
			fields = append(fields, fieldSpecFor(f))
		}
		if len(fields) == 0 {
			fields = append(fields, vctypes.FieldSpec{Name: "holder", Datatype: "string", Required: true})
		}
		// mso_mdoc's real docType MUST travel with the rebuilt schema —
		// IssueToWallet's mdocDocTypeForSchema(req.Schema) reads
		// AdditionalTypes[0] first and falls back to schema.ID (a
		// "custom-<nano>" string) only when it's empty. Leaving this unset
		// here made mdocNamespaceForDocType derive the claims-nesting
		// namespace from schema.ID itself, so IssueToWallet posted claims
		// nested under the schema's OWN ID instead of the real ISO
		// namespace — reproduced live end-to-end: a real operator-created
		// mDL issued through this exact rebuilt-from-wellknown path failed
		// with "Unknown claims provided: [custom-<nano-id>]", Inji Certify
		// correctly rejecting a claims map keyed by a value that means
		// nothing to it. mdocDocTypeForSchema/mdocNamespaceForDocType
		// (db.go) are the same helpers SaveCustomSchema already uses to
		// derive this from a freshly-submitted form's schema, so a schema
		// round-tripped through ListSchemas must agree.
		var additionalTypes []string
		if cfg.Format == "mso_mdoc" && cfg.Doctype != "" {
			additionalTypes = []string{cfg.Doctype}
		}
		out = append(out, vctypes.Schema{
			ID:              id,
			Name:            name,
			Std:             std,
			DPGs:            []string{issuerDpg},
			Desc:            fmt.Sprintf("Live credential configuration served by %s.", issuerDpg),
			FieldsSpec:      fields,
			AdditionalTypes: additionalTypes,
			// Recovered from the declared markers above, so the rebuilt schema
			// agrees with the template certify already holds: the issue form
			// offers a Validity window, and issuance POSTs the values the
			// template's ${validFromEpoch}/${validUntilEpoch} require.
			Expires: expires,
			// Pin the exact vct the issuer metadata advertises (SD-JWT VC only;
			// empty for ldp_vc/W3C). The verifier's PD needs this so the wallet's
			// matchesVct selects the held token by its vct claim; without it the
			// present fails "No credential found for: vc-1" (F19). CredentialVct
			// prefers this explicit Vct over host-derivation.
			Vct: cfg.Vct,
		})
	}
	return out, nil
}

// ListAllSchemas mirrors ListSchemas for interface completeness.
// GetIssuerMetadata assembles this issuer's OID4VCI credential configurations
// from its full schema catalog. Endpoint URLs are left empty for the HTTP
// handler to fill from the request's public base.
func (a *Adapter) GetIssuerMetadata(ctx context.Context) (backend.IssuerMetadata, error) {
	schemas, err := a.ListAllSchemas(ctx)
	if err != nil {
		return backend.IssuerMetadata{}, err
	}
	return backend.IssuerMetadata{CredentialsSupported: backend.CredentialConfigsFromSchemas(schemas)}, nil
}

func (a *Adapter) ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error) {
	return a.ListSchemas(ctx, a.Vendor)
}

// PrefillSubjectFields — Auth-Code mode returns empty (operator types). Pre-Auth
// mode returns empty too; a future milestone can wire the MOSIP identity plugin
// when that endpoint is exposed by the configured instance.
func (a *Adapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return map[string]string{}, nil
}

// preAuthorizedDataRequest matches POST /v1/certify/pre-authorized-data.
type preAuthorizedDataRequest struct {
	CredentialConfigurationId string         `json:"credential_configuration_id"`
	Claims                    map[string]any `json:"claims"`
}

type mosipError struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

type preAuthorizedDataResponse struct {
	CredentialOfferURI string       `json:"credential_offer_uri"`
	Errors             []mosipError `json:"errors"`
}

// IssueToWallet generates a credential offer. The path diverges by mode:
//
//   - pre_auth: POST /v1/certify/pre-authorized-data and rewrite internal host.
//   - auth_code: build a manual authorization_code-grant offer JSON and host it
//     at verifiably-go's /offers/{vendor}/{id} endpoint (served by main.go).
func (a *Adapter) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	claims := map[string]any{}
	for k, v := range req.SubjectData {
		claims[k] = v
	}

	// mso_mdoc's driving_privileges is an array of objects — it cannot ride
	// in SubjectData (map[string]string). It lives in StructuredData, same
	// convention as waltid/issuer2.go's buildIssuer2Offer. Reading it here,
	// and rejecting 0/>4 categories BEFORE ever calling Inji, replicates
	// the same defense-in-depth waltid's buildIssuer2Offer already has: the
	// handler's own guard (validateDrivingPrivilegesCount) can be bypassed
	// by a direct POST /api/v1/credentials/issue call, so this
	// adapter-level check is the one that must never be skipped.
	//
	// Gated on a.cfg.Mode == ModePreAuth explicitly, not just on the
	// schema's Std: IssueToWallet is shared by BOTH Pre-Auth and Auth-Code,
	// and Auth-Code's offer construction (below) never reads claims at
	// all — an mdoc schema reaching an Auth-Code-mode adapter (only
	// possible via a hand-built API call; the UI never produces this
	// combination) must fall through to that unmodified path, not be
	// rejected by an mdoc-specific guard that has no meaning for a mode
	// this plan explicitly does not support for mdoc.
	//
	// ALSO gated on the schema's real docType being mDL specifically, not
	// on Std=="mso_mdoc" alone: mso_mdoc is the CONTAINER format shared by
	// every ISO docType this system issues (mDL AND Photo ID,
	// org.iso.23220.photoid.1 — see mdoc.KnownDocTypes), but
	// driving_privileges is an mDL-only ISO/IEC 18013-5 Table 3 element —
	// ISO/IEC 23220-1's Photo ID has no such element at all. Before this
	// gate, issuing a Photo ID (a legitimate mso_mdoc docType with zero
	// driving-privilege rows, by design) was unconditionally rejected with
	// this exact "es obligatorio" message — reproduced live: a freshly
	// created Photo ID schema, confirmed to have NO driving_privileges in
	// its own credential_config.display_order, still failed here because
	// this check never looked at which docType was actually being issued.
	if a.cfg.Mode == ModePreAuth && stdToCredentialFormat(req.Schema.Std) == "mso_mdoc" && mdocDocTypeForSchema(req.Schema) == mdoc.MDLDocType {
		n := 0
		if raw, ok := req.StructuredData["driving_privileges"]; ok && len(raw) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return backend.IssueToWalletResult{}, fmt.Errorf("inji: driving_privileges no es un array JSON válido: %w", err)
			}
			n = len(arr)
			// Posted as the RAW JSON STRING, not a decoded []any — confirmed
			// live against Inji Certify v0.14.0 that posting a real array
			// makes CredentialUtils.toJsonMap wrap it as a JSONArray, whose
			// Java toString() Velocity then substitutes for the UNQUOTED
			// ${rootContext['<ns>'].driving_privileges} template marker
			// (see db.go's mdocVCTemplate) — producing Java-map syntax
			// (key=value, unquoted keys) instead of JSON, which fails
			// org.json's own re-parse with "Expected a ',' or '}'". Traced
			// this to the exact difference between our deployment and the
			// spike that DID work: the spike's PostgresDataProviderPlugin
			// query explicitly cast the array to text
			// (CAST(j->'driving_privileges' AS text)), so Velocity received
			// an already-valid JSON STRING to substitute verbatim, never a
			// Java List/JSONArray it would stringify itself. Doing the same
			// cast ourselves — sending the compact JSON string as the claim
			// value instead of the decoded array — reproduces that working
			// path without touching Inji's own code, at the cost of Inji's
			// own claim validation seeing a String here rather than an
			// array (harmless: validateClaimsWithMandatory only checks key
			// presence, never value type). Confirmed end-to-end by decoding
			// a real issued test credential: with this string PLUS the
			// unquoted bracket-notation marker, driving_privileges decodes
			// to a real CBOR array of maps with correctly full-date-tagged
			// issue_date/expiry_date — not a string, not Java toString().
			claims["driving_privileges"] = string(raw)
		}
		if n == 0 {
			return backend.IssueToWalletResult{}, fmt.Errorf(
				"inji: driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos una categoría de conducción antes de emitir")
		}
		if n > mdoc.DrivingPrivilegesMaxCategories {
			return backend.IssueToWalletResult{}, fmt.Errorf(
				"inji: no se pueden emitir %d categorías de conducción en una sola credencial — el máximo es %d",
				n, mdoc.DrivingPrivilegesMaxCategories)
		}
	}

	if len(claims) == 0 {
		// Inji Certify rejects empty claims; fill one sensible default.
		claims["fullName"] = "Demo Holder"
	}

	switch a.cfg.Mode {
	case ModePreAuth:
		// Embed the IETF Token Status List pointer for SD-JWT so the credential is
		// revocable: the template (SaveCustomSchema) carries
		// status.status_list.{idx:${statusIdx}, uri:${statusUri}} and certify
		// substitutes both markers from these pre-authorized claims — SaveCustomSchema
		// DECLARES statusIdx/statusUri in display_order so the PreAuthDataProviderPlugin
		// surfaces these POSTed values into the Velocity context (without that the
		// markers stay unresolved and certify 400s on the unquoted `${statusIdx}`).
		// Keys must be exactly statusIdx/statusUri (the bare marker names — pre-auth
		// has no data-provider view, unlike the auth-code slug-scoped keys). Default
		// to a benign 0/"" when no binding was allocated so the markers never render
		// unresolved.
		// Applies to SD-JWT (IETF token status list) AND VCDM2 ldp_vc (W3C
		// BitstringStatusListEntry credentialStatus, F14). For ldp_vc the allocated
		// binding is a bitstring index/URL; the template's credentialStatus.type
		// tells the verifier which decoder to use, so the SAME statusIdx/statusUri
		// markers serve both formats.
		if cf := stdToCredentialFormat(req.Schema.Std); cf == "vc+sd-jwt" || cf == "ldp_vc" {
			if req.StatusList != nil {
				claims["statusIdx"] = strconv.Itoa(req.StatusList.Index)
				claims["statusUri"] = req.StatusList.PublishURL
			} else {
				claims["statusIdx"] = "0"
				claims["statusUri"] = ""
			}
		}
		// Resolve the validity-window markers the template carries. Until this
		// existed the operator's window was collected by the issue form, put on
		// the request, and then silently dropped here — only the walt.id adapter
		// ever read req.ValidFrom/ValidUntil — so EVERY Inji Certify credential
		// was issued without a window and an expired one verified as valid.
		//
		// Gated on the same flag buildVCTemplate uses: POSTing a marker the
		// template never declared would be rejected as an unknown claim.
		if req.Schema.ExpiresWithWindow() {
			for k, v := range validityClaims(stdToCredentialFormat(req.Schema.Std), req.ValidFrom, req.ValidUntil) {
				claims[k] = v
			}
		}
		// mso_mdoc claims must be POSTed NESTED under the ISO namespace
		// (e.g. {"org.iso.18013.5.1": {family_name: ..., ...}}), not flat —
		// confirmed against Inji Certify v0.14.0's real source
		// (PreAuthorizedCodeService.validateClaims/validateClaimsWithMandatory):
		// for mso_mdoc/vc+sd-jwt it validates providedClaims.keySet() against
		// config.getClaims().keySet(), and getClaims() for mso_mdoc returns
		// credential_config.mso_mdoc_claims AS-IS
		// (CredentialConfigurationServiceImpl.java:379, setClaims(new
		// HashMap<>(getMsoMdocClaims()))) — which SaveCustomSchema wrote with
		// exactly one top-level key, the namespace. Posting flat claims makes
		// EVERY key mismatch that single expected key, failing closed with
		// unknown_claims for every field at once — reproduced live against
		// this deployment's real credential_config row. SD-JWT/ldp_vc are
		// unaffected: they only ever reach here with flat, unnested claims
		// (statusIdx/statusUri/validity markers, all top-level by design),
		// and the same source shows getSdJwtClaims() is used verbatim for
		// SD-JWT's own top-level validation — so nesting must apply to
		// mso_mdoc alone, not become the default for every format sharing
		// this switch branch.
		postClaims := claims
		if stdToCredentialFormat(req.Schema.Std) == "mso_mdoc" {
			ns := mdocNamespaceForDocType(mdocDocTypeForSchema(req.Schema))
			postClaims = map[string]any{ns: claims}
		}
		body := preAuthorizedDataRequest{
			CredentialConfigurationId: req.Schema.ID,
			Claims:                    postClaims,
		}
		var resp preAuthorizedDataResponse
		if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/certify/pre-authorized-data", body, &resp, nil); err != nil {
			return backend.IssueToWalletResult{}, fmt.Errorf("pre-authorized-data: %w", err)
		}
		if len(resp.Errors) > 0 {
			return backend.IssueToWalletResult{}, fmt.Errorf("pre-authorized-data: %s", resp.Errors[0].ErrorCode)
		}
		if resp.CredentialOfferURI == "" {
			return backend.IssueToWalletResult{}, fmt.Errorf("pre-authorized-data: empty credential_offer_uri in response")
		}
		// The inji-preauth-proxy sidecar (docker compose service
		// inji-preauth-proxy, taking over the inji-certify-preauth network
		// identity) intercepts /.well-known/openid-credential-issuer and
		// /v1/certify/issuance/credential transparently, so Inji's raw
		// offer URI resolves through the proxy without any adapter-side
		// rewrite. No /offers/ re-hosting needed.
		offerURI := a.rewritePublic(resp.CredentialOfferURI)
		return backend.IssueToWalletResult{
			OfferURI: offerURI,
			OfferID:  extractOfferID(offerURI),
			Flow:     "pre_auth",
		}, nil

	case ModeAuthCode:
		// Build a manual authorization_code-grant offer. Hosted by verifiably-go
		// at /offers/inji/{id}. Claims are attached as "authorization_details"
		// inside issuer_state so the wallet can surface them.
		issuerState := randomID()
		offer := map[string]any{
			"credential_issuer":              firstNonEmpty(a.cfg.OfferIssuerURL, a.cfg.PublicBaseURL),
			"credential_configuration_ids":   []string{req.Schema.ID},
			"grants": map[string]any{
				"authorization_code": map[string]any{
					"issuer_state":          issuerState,
					"authorization_server":  a.cfg.AuthorizationServer,
				},
			},
		}
		raw, err := json.Marshal(offer)
		if err != nil {
			return backend.IssueToWalletResult{}, err
		}
		a.mu.Lock()
		id := randomID()
		a.authCodeOffers[id] = raw
		a.mu.Unlock()
		// The wallet will fetch this URI. Verifiably-go's main.go exposes
		// /offers/{slug}/{id} and dispatches to OfferJSON. The slug is an
		// ASCII-safe form of the vendor name so dereferencing doesn't trip on
		// punctuation from the display label.
		hostedURL := fmt.Sprintf("%s/offers/%s/%s", publicVerifiablyURL(), a.Slug(), id)
		publicOffer := fmt.Sprintf("openid-credential-offer://?credential_offer_uri=%s",
			url.QueryEscape(hostedURL))
		return backend.IssueToWalletResult{
			OfferURI: publicOffer,
			OfferID:  id,
			Flow:     "auth_code",
		}, nil
	}
	return backend.IssueToWalletResult{}, backend.ErrNotSupported
}

// IssueAsPDF dispatches to the pre-auth-specific implementation in pdf.go
// when the configured mode is Pre-Auth — that flow can run end-to-end
// server-side (no holder wallet, no eSignet), drive the OID4VCI dance,
// and render a paper-deliverable credential. Auth-Code mode still returns
// ErrNotSupported: it requires a live eSignet session we can't fabricate.
func (a *Adapter) IssueAsPDF(ctx context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	if a.cfg.Mode == ModePreAuth {
		return a.issueAsPDFPreAuth(ctx, req)
	}
	return backend.IssueAsPDFResult{}, backend.ErrNotSupported
}

// IssueBulk iterates Rows and issues per row. Populates BulkRowResult so
// the UI's per-row result table can surface each recipient + offer URI +
// status — the same shape the walt.id adapter returns, so the template
// renders identically regardless of backend.
func (a *Adapter) IssueBulk(ctx context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	if len(req.Rows) == 0 {
		return backend.IssueBulkResult{}, fmt.Errorf("injicertify: no rows")
	}
	var out backend.IssueBulkResult
	out.Rows = make([]backend.BulkRowResult, 0, len(req.Rows))
	for i, row := range req.Rows {
		label := rowLabelInji(row)
		// Per-row revocation binding (aligned by index) so each bulk SD-JWT
		// embeds its own status.status_list pointer, like the single path.
		var binding *backend.StatusListBinding
		if i < len(req.StatusLists) {
			binding = req.StatusLists[i]
		}
		res, err := a.IssueToWallet(ctx, backend.IssueRequest{
			IssuerDpg:   req.IssuerDpg,
			Schema:      req.Schema,
			SubjectData: row,
			Flow:        string(a.cfg.Mode),
			StatusList:  binding,
		})
		if err != nil {
			out.Rejected++
			reason := truncate(err.Error(), 140)
			out.Errors = append(out.Errors, backend.BulkError{Row: i + 1, Reason: reason})
			out.Rows = append(out.Rows, backend.BulkRowResult{
				Row: i + 1, Subject: row, Label: label, Status: "failed", Error: reason,
			})
			continue
		}
		out.Accepted++
		out.Rows = append(out.Rows, backend.BulkRowResult{
			Row: i + 1, Subject: row, Label: label, Status: "issued", OfferURI: res.OfferURI,
		})
	}
	return out, nil
}

// rowLabelInji picks a one-line label per row for the bulk-result table.
// Prefers Inji Certify's Farmer Credential identifier fields (fullName,
// farmerID, mobileNumber) and falls back to walt.id-style (holder, firstName
// + familyName) so the same adapter can surface sensible labels regardless
// of which Inji Certify credential configuration the operator picked.
func rowLabelInji(row map[string]string) string {
	keys := []string{"fullName", "holder", "farmerID", "mobileNumber", "name", "personalIdentifier"}
	for _, k := range keys {
		if v := strings.TrimSpace(row[k]); v != "" {
			return v
		}
	}
	first := strings.TrimSpace(row["firstName"])
	last := strings.TrimSpace(row["familyName"])
	if first != "" || last != "" {
		return strings.TrimSpace(first + " " + last)
	}
	for _, v := range row {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "(empty row)"
}

// BootstrapOffers issues one canned credential against the first schema the
// instance exposes. Used to populate the wallet's "paste example" helper.
func (a *Adapter) BootstrapOffers(ctx context.Context) ([]string, error) {
	schemas, err := a.ListSchemas(ctx, a.Vendor)
	if err != nil || len(schemas) == 0 {
		return nil, nil
	}
	// Only the pre-auth card can bootstrap a fully-self-contained offer.
	// Auth-Code offers require a live wallet to hit eSignet — not useful as a
	// demo fixture.
	if a.cfg.Mode != ModePreAuth {
		return nil, nil
	}
	res, err := a.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg:   a.Vendor,
		Schema:      schemas[0],
		SubjectData: map[string]string{},
		Flow:        string(ModePreAuth),
	})
	if err != nil {
		return nil, nil
	}
	return []string{res.OfferURI}, nil
}

// --- helpers ---

func formatToStd(format string) string {
	switch format {
	case "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc":
		return "w3c_vcdm_2"
	case "vc+sd-jwt", "dc+sd-jwt":
		return "sd_jwt_vc (IETF)"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return ""
	}
}

func displayName(cfg credentialConfigurationEntry) string {
	for _, d := range cfg.Display {
		if raw, ok := d["name"]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

func humanise(s string) string {
	var out []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	return string(out)
}

// fieldSpecFor infers a FieldSpec from a claim name. Inji Certify's
// credential_configurations_supported exposes a simple `order` array of
// claim names without per-claim types, so we apply heuristics that cover
// the common cases (dates, numbers, emails, phones, URIs). Unknown names
// fall through to string/required.
func fieldSpecFor(name string) vctypes.FieldSpec {
	lower := strings.ToLower(name)
	f := vctypes.FieldSpec{Name: name, Datatype: "string", Required: true}
	switch {
	// Explicit datetime policy fields: the delegation/expiry valid_until | valid_from
	// (underscore or camelCase) carry a full timestamp, so the issue form must render
	// a datetime-local picker (and SubmitIssue normalizes them to RFC3339). Checked
	// before the date heuristic so they are never demoted to a date-only input.
	case lower == "valid_until" || lower == "validuntil" ||
		lower == "valid_from" || lower == "validfrom":
		f.Format = "datetime"
	// Date fields. The past-tense "…On" / "…At" heuristic (issuedOn, updatedAt) must
	// match the ORIGINAL camelCase / snake_case word boundary, NOT a lowercased tail —
	// otherwise it wrongly swallows names that merely END in those letters
	// (allowedActi·on, instituti·on, form·at, se·at), dating a plain string field that
	// the RFC3339 normalization then empties.
	case strings.Contains(lower, "date") || strings.HasSuffix(lower, "expiry") ||
		strings.HasSuffix(name, "On") || strings.HasSuffix(name, "At") ||
		strings.HasSuffix(lower, "_on") || strings.HasSuffix(lower, "_at"):
		f.Format = "date"
	case strings.Contains(lower, "email"):
		f.Format = "email"
	case strings.Contains(lower, "phone") || strings.Contains(lower, "mobile"):
		f.Format = "tel"
	case strings.Contains(lower, "url") || strings.Contains(lower, "uri"):
		f.Format = "uri"
	case strings.Contains(lower, "area") || strings.HasSuffix(lower, "count") ||
		strings.Contains(lower, "amount") || strings.Contains(lower, "quantity"):
		f.Datatype = "number"
	}
	return f
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// extractOfferID returns the last path segment of the referenced offer URL —
// useful as a stable id for tracing.
func extractOfferID(offerURI string) string {
	if i := strings.LastIndex(offerURI, "/"); i >= 0 && i+1 < len(offerURI) {
		return offerURI[i+1:]
	}
	return ""
}

// publicVerifiablyURL returns the base URL of the verifiably-go instance that
// a wallet will dereference offer URIs against. Overridable via env var so
// compose deployments can announce a LAN/host URL.
func publicVerifiablyURL() string {
	if v := getenv("VERIFIABLY_PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

// getenv is a tiny wrapper so tests can swap it without importing os everywhere.
var getenv = func(key string) string {
	return os.Getenv(key)
}
