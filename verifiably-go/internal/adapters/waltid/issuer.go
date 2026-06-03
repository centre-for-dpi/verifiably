package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// onboardingRequest matches /onboard/issuer body shape (walt.id v0.18.2).
type onboardingRequest struct {
	Key onboardingKey `json:"key"`
	DID onboardingDID `json:"did"`
}

type onboardingKey struct {
	Backend string `json:"backend"`
	KeyType string `json:"keyType"`
}

type onboardingDID struct {
	Method string `json:"method"`
}

type onboardingResponse struct {
	IssuerKey json.RawMessage `json:"issuerKey"`
	IssuerDID string          `json:"issuerDid"`
}

// ensureIssuerKey ensures the adapter has an issuer key + DID, onboarding a
// fresh one on the first call if config didn't pin them.
func (a *Adapter) ensureIssuerKey(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.issuerKey) > 0 && a.issuerDID != "" {
		return nil
	}
	if a.issuer == nil {
		return fmt.Errorf("waltid: issuer role not configured (issuerBaseUrl missing)")
	}
	body := onboardingRequest{
		Key: onboardingKey{Backend: "jwk", KeyType: "secp256r1"},
		DID: onboardingDID{Method: "jwk"},
	}
	var resp onboardingResponse
	if err := a.issuer.DoJSON(ctx, "POST", "/onboard/issuer", body, &resp, nil); err != nil {
		return fmt.Errorf("onboard issuer: %w", err)
	}
	a.issuerKey = resp.IssuerKey
	a.issuerDID = resp.IssuerDID
	return nil
}

// credentialIssuerMetadata is a slim view of /draft13/.well-known/openid-credential-issuer
// — only the fields this adapter reads.
type credentialIssuerMetadata struct {
	CredentialIssuer                  string                                    `json:"credential_issuer"`
	CredentialConfigurationsSupported map[string]credentialConfigurationEntry   `json:"credential_configurations_supported"`
	Display                           []map[string]json.RawMessage              `json:"display,omitempty"`
}

type credentialConfigurationEntry struct {
	Format               string                       `json:"format"`
	Scope                string                       `json:"scope,omitempty"`
	CredentialDefinition *credentialDefinitionEntry   `json:"credential_definition,omitempty"`
	Vct                  string                       `json:"vct,omitempty"`
	DocType              string                       `json:"doctype,omitempty"`
	// Display is the per-configuration human-readable label walt.id
	// advertises (one entry per locale). displayNameFor prefers display[0].name
	// when present because it's the cleanest label.
	Display []struct {
		Name   string `json:"name"`
		Locale string `json:"locale,omitempty"`
	} `json:"display,omitempty"`
}

type credentialDefinitionEntry struct {
	Type []string `json:"type"`
}

// ListSchemas fetches the issuer's credential configurations and groups them
// into one Schema per credential type, not one per (type, format). Walt.id's
// .well-known exposes every credential under several configuration ids — one
// per format (jwt_vc_json, jwt_vc_json-ld, ldp_vc, vc+sd-jwt, dc+sd-jwt,
// mso_mdoc). Rendering each as its own card turns a 30-type list into a 200+
// card wall of near-duplicates.
//
// The grouped Schema's ID is the default variant's configuration id (picked
// via formatRank — the format walt.id's own E2E tests exercise). The
// Variants slice carries every format the type is available in, so the UI
// can render a format chip-row and let the user pick a non-default format
// without scrolling through duplicate cards.
func (a *Adapter) ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error) {
	if a.issuer == nil {
		return nil, fmt.Errorf("waltid: issuer role not configured (issuerBaseUrl missing)")
	}
	var meta credentialIssuerMetadata
	path := fmt.Sprintf("/%s/.well-known/openid-credential-issuer", a.cfg.StandardVersion)
	if err := a.issuer.DoJSON(ctx, "GET", path, nil, &meta, nil); err != nil {
		return nil, fmt.Errorf("fetch issuer metadata: %w", err)
	}
	type entry struct {
		id  string
		cfg credentialConfigurationEntry
	}
	// Bucket by NAME only — variants live inside the bucket.
	buckets := map[string][]entry{}
	order := []string{}
	for id, cfg := range meta.CredentialConfigurationsSupported {
		if formatToStd(cfg.Format) == "" {
			continue // VP-only or unsupported
		}
		name := displayNameFor(id, cfg)
		if _, ok := buckets[name]; !ok {
			order = append(order, name)
		}
		buckets[name] = append(buckets[name], entry{id, cfg})
	}
	// Go map iteration is randomized, so first-seen order is unstable.
	// Sort alphabetically by name so the card grid renders identically
	// across requests — otherwise every re-render (e.g. clicking "Use this
	// schema" or switching a format chip) would shuffle the whole list and
	// lose the user's visual anchor.
	sort.Strings(order)
	out := make([]vctypes.Schema, 0, len(order))
	for _, name := range order {
		bucket := buckets[name]
		// Pick the default (best-ranked) variant as the card's initial selection.
		pick := bucket[0]
		for _, e := range bucket[1:] {
			if formatRank(e.cfg.Format) > formatRank(pick.cfg.Format) {
				pick = e
			}
		}
		// Build the variant list in rank-desc order so the chip row reads
		// naturally from most-common on the left to niche on the right.
		// Dedupe by format — walt.id ships some credentials under both a
		// CamelCase and a snake_case configuration id (e.g. both
		// "IdentityCredential_vc+sd-jwt" and
		// "identity_credential_vc+sd-jwt"), which would otherwise render
		// as two identical chips. When both exist, prefer the id that
		// matches the credential's CamelCase type name — that's the one
		// walt.id's credentials.walt.id/api/vc/<Name> template server keys
		// off, so our prefill fields stay aligned.
		byFormat := map[string]entry{}
		for _, e := range bucket {
			cur, seen := byFormat[e.cfg.Format]
			if !seen || preferConfigID(e.id, cur.id) {
				byFormat[e.cfg.Format] = e
			}
		}
		variants := make([]vctypes.SchemaVariant, 0, len(byFormat))
		for _, e := range byFormat {
			variants = append(variants, vctypes.SchemaVariant{
				ID:         e.id,
				Format:     e.cfg.Format,
				Std:        formatToStd(e.cfg.Format),
				Label:      formatLabel(e.cfg.Format),
				Vct:        e.cfg.Vct,
				CanPresent: verifierSupportsFormat(e.cfg.Format),
			})
		}
		sortVariantsByRank(variants)
		// Re-pick the card's default id from the deduped set (the ranked
		// winner may have been the alternate casing we just dropped).
		if len(variants) > 0 {
			for _, e := range byFormat {
				if e.cfg.Format == variants[0].Format {
					pick = e
					break
				}
			}
		}
		// Don't hit credentials.walt.id per-card here — that's ~800 ms per
		// type × ~45 types = 30 s+ on the first DPG page load, and the card
		// grid only needs name + format chips anyway. Use the hardcoded
		// fallback (good enough for the list view) and let the issue-form
		// handler upgrade to real template fields when the user picks a
		// specific schema.
		out = append(out, vctypes.Schema{
			ID:         pick.id,
			Name:       name,
			Std:        formatToStd(pick.cfg.Format),
			DPGs:       []string{issuerDpg},
			Desc:       fmt.Sprintf("Served by %s in %d format(s).", issuerDpg, len(variants)),
			FieldsSpec: fieldsForCredentialType(pick.id),
			Variants:   variants,
		})
	}
	out = applySchemaAllowlist(out)
	return out, nil
}

// schemaAllowlistDefault is the five-credential demo set we surface in the
// walt.id issuance flow by default — chosen to reduce decision fatigue on
// the schema-picker card grid (walt.id ships ~30 credential configurations
// out-of-the-box, most of which are noise for a demo). To override at
// deploy time, set VERIFIABLY_WALTID_SCHEMA_ALLOWLIST to a comma-separated
// list of display-names. Set it to "*" to disable filtering and see every
// schema walt.id advertises.
var schemaAllowlistDefault = []string{
	"Bank Id",
	"Educational ID",
	"Tax Receipt",
	"University Degree",
}

// applySchemaAllowlist filters the walt.id ListSchemas output to the
// configured display-name allowlist. Case-insensitive trimmed match.
// Schemas not in the allowlist are still served — they just don't appear
// in the UI's card grid (the underlying credential_configurations are
// untouched on walt.id's side, so the issuer can still target a hidden
// schema by id via direct API).
//
// Empty allowlist or "*" → no filtering (every schema passes through).
func applySchemaAllowlist(in []vctypes.Schema) []vctypes.Schema {
	allowed := schemaAllowlistFromEnv()
	if len(allowed) == 0 {
		return in
	}
	out := in[:0]
	for _, s := range in {
		key := strings.ToLower(strings.TrimSpace(s.Name))
		if _, ok := allowed[key]; ok {
			out = append(out, s)
		}
	}
	return out
}

// schemaAllowlistFromEnv returns the allowlist as a lookup set, honouring
// the env override. Returns nil to mean "no filtering".
func schemaAllowlistFromEnv() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("VERIFIABLY_WALTID_SCHEMA_ALLOWLIST"))
	if raw == "*" {
		return nil
	}
	names := schemaAllowlistDefault
	if raw != "" {
		names = strings.Split(raw, ",")
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		k := strings.ToLower(strings.TrimSpace(n))
		if k == "" {
			continue
		}
		out[k] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// preferConfigID returns true when candidate should replace current as the
// canonical id for a (name, format) pair. Prefers the id that starts with an
// uppercase letter (walt.id's CamelCase naming matches its template server);
// falls back to shorter-id as a tiebreaker so "BankId_jwt_vc_json" beats
// "BankId_jwt_vc_json_extra" if two ever collide.
func preferConfigID(candidate, current string) bool {
	candUpper := len(candidate) > 0 && candidate[0] >= 'A' && candidate[0] <= 'Z'
	currUpper := len(current) > 0 && current[0] >= 'A' && current[0] <= 'Z'
	if candUpper != currUpper {
		return candUpper
	}
	return len(candidate) < len(current)
}

// sortVariantsByRank sorts by formatRank desc (best formats first), then
// alphabetically by format for a deterministic tail.
func sortVariantsByRank(vs []vctypes.SchemaVariant) {
	for i := 0; i < len(vs); i++ {
		for j := i + 1; j < len(vs); j++ {
			ri, rj := formatRank(vs[i].Format), formatRank(vs[j].Format)
			if rj > ri || (rj == ri && vs[j].Format < vs[i].Format) {
				vs[i], vs[j] = vs[j], vs[i]
			}
		}
	}
}

// verifierSupportsFormat tracks which formats walt.id Community Stack's
// verifier-api can MATCH credentials for (accepts in the request AND can
// actually round-trip through the wallet's matcher). Derived from:
//
//   - id.walt.w3c.utils.VCFormat enum (missing jwt_vc_json-ld).
//   - VerifierService.getPresentationFormat's allow-list.
//   - Empirical: ldp_vc credentials pass the enum + allow-list checks but
//     walt.id's wallet-api leaves their parsedDocument empty, so the
//     matchCredentialsForPresentationDefinition endpoint returns 0 matches
//     regardless of the PD shape (even walt.id's own default PD). LDP
//     is effectively issue-only at v0.18.2.
//   - jwt_vc (legacy) hasn't been tested as thoroughly but empirically
//     round-trips; kept on the list.
//
// The UI hides non-presentable formats from the verifier chip row and
// badges them "issue-only" on the issuer side.
func verifierSupportsFormat(format string) bool {
	switch format {
	case "jwt_vc_json", "jwt_vc", "vc+sd-jwt", "mso_mdoc":
		return true
	}
	return false
}

// formatLabel returns a short, human-readable label for a walt.id format key.
// Matches the shorthand walt.id's own portal uses in its format dropdown.
// The "dc" in dc+sd-jwt stands for "Digital Credential" — the newer media
// type the IETF SD-JWT VC draft is moving toward (vc+sd-jwt is the earlier
// spelling, still widely supported).
func formatLabel(format string) string {
	switch format {
	case "jwt_vc_json":
		return "JWT · W3C"
	case "jwt_vc_json-ld":
		return "JWT · W3C LD"
	case "ldp_vc":
		return "LDP · W3C"
	case "jwt_vc":
		return "JWT (legacy)"
	case "vc+sd-jwt":
		return "SD-JWT · VC (legacy)"
	case "dc+sd-jwt":
		return "SD-JWT · DC (current)"
	case "mso_mdoc":
		return "mDoc (ISO 18013-5)"
	default:
		return format
	}
}

// formatRank returns a score for a walt.id format; higher wins the
// dedup-pick. The ranking mirrors the combinations walt.id's own
// waltid-e2e-tests suite exercises end-to-end, so the formats we surface
// are the ones with a tested issue → claim → present → verify path.
func formatRank(f string) int {
	switch f {
	case "jwt_vc_json":
		return 100 // walt.id's canonical jwt test (OpenBadgeCredential_jwt_vc_json)
	case "vc+sd-jwt":
		return 90 // walt.id's canonical SD-JWT test (identity_credential_vc+sd-jwt)
	case "dc+sd-jwt":
		return 85 // newer SD-JWT variant walt.id is moving toward
	case "mso_mdoc":
		return 80 // mdoc is its own Std so doesn't actually compete
	case "jwt_vc_json-ld":
		return 30
	case "ldp_vc":
		return 20
	case "jwt_vc":
		return 10
	}
	return 0
}

// ListAllSchemas delegates to ListSchemas — the registry handles aggregation
// across DPGs, so per-adapter "all" is just "mine".
func (a *Adapter) ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error) {
	return a.ListSchemas(ctx, a.Vendor)
}

// borrowConfigIDFor finds a walt.id-known credentialConfigurationId whose
// format matches the requested Std. Used when issuing a custom (user-built)
// schema — walt.id validates configurationId against its pre-loaded
// credential_configurations_supported catalog, so we can't invent a fresh
// one. The credentialData we send still carries the custom type + fields
// and lands in the signed VC verbatim; only the signing envelope inherits
// from the borrowed config.
//
// Preference order mirrors formatRank so we pick the format walt.id's own
// E2E tests actually round-trip. Returns a helpful error if the issuer
// advertises no config for the requested Std at all.
func (a *Adapter) borrowConfigIDFor(ctx context.Context, std string) (string, error) {
	if a.issuer == nil {
		return "", fmt.Errorf("waltid: issuer role not configured (issuerBaseUrl missing)")
	}
	var meta credentialIssuerMetadata
	path := fmt.Sprintf("/%s/.well-known/openid-credential-issuer", a.cfg.StandardVersion)
	if err := a.issuer.DoJSON(ctx, "GET", path, nil, &meta, nil); err != nil {
		return "", fmt.Errorf("fetch issuer metadata: %w", err)
	}
	best := ""
	bestRank := -1
	for id, cfg := range meta.CredentialConfigurationsSupported {
		if formatToStd(cfg.Format) != std {
			continue
		}
		r := formatRank(cfg.Format)
		if r > bestRank {
			bestRank = r
			best = id
		}
	}
	if best == "" {
		return "", fmt.Errorf("the walt.id issuer has no configuration advertising Std %q — can't issue a custom schema in this format", std)
	}
	return best, nil
}

// ResolveSchemaFields enriches a single schema with field shapes from
// credentials.walt.id's template server. Called lazily by handlers that
// need the real field list (issuance form, verifier field picker) — the
// card grid uses the cheap fallback from ListSchemas so the DPG page
// doesn't pay per-type template-fetch latency up-front.
func (a *Adapter) ResolveSchemaFields(schema vctypes.Schema) vctypes.Schema {
	baseType := schema.BaseType()
	if fields := fetchFieldsFromTemplate(baseType); len(fields) > 0 {
		schema.FieldsSpec = fields
	}
	return schema
}

// SaveCustomSchema appends an entry to walt.id's credential-issuer-metadata.conf
// HOCON catalog and restarts issuer-api so the new configurationId becomes
// part of credential_configurations_supported. This is what lets a custom
// schema (e.g. "FarmerCred") issue with its own type — without this hook
// IssueToWallet falls back to borrowing a stock walt.id config and the
// resulting VC is filed under the borrowed type's name.
//
// Phase 1 supports jwt_vc_json (matched by Std="w3c_vcdm_2"). For schemas
// declaring other Std values the catalog edit returns "format not yet
// supported" and the adapter silently leaves the borrow path in place — so
// existing flows keep working until Phase 2 extends format coverage.
//
// Skipped (with a logged note) when CatalogPath is empty: a deploy that
// hasn't bind-mounted the catalog file in still works for stock schemas.
func (a *Adapter) SaveCustomSchema(_ context.Context, schema vctypes.Schema) error {
	if !schema.Custom || a.cfg.CatalogPath == "" {
		return nil
	}
	if len(waltidWireFormatsForStd(schema.Std)) == 0 {
		return nil
	}
	primary, allConfigIDs, changed, err := appendCredentialType(a.cfg.CatalogPath, schema)
	if err != nil {
		return fmt.Errorf("append catalog entry: %w", err)
	}
	// Register the schema's pre-variant ID + every per-format configID
	// against the same primary. IssueToWallet looks up by Schema.ID; that
	// can be either the original "custom-..." ID (the default variant) or
	// a "<TypeName>_<wireFormat>" string after ApplyVariant. Mapping both
	// to the catalog primary means either path resolves to a registered
	// configID without a borrow fallback. We map per-format configIDs to
	// themselves so a future UI that lets users pick a non-default wire
	// format can swap req.Schema.ID without further plumbing.
	a.mu.Lock()
	if a.registeredConfigIDs == nil {
		a.registeredConfigIDs = map[string]string{}
	}
	a.registeredConfigIDs[schema.ID] = primary
	for _, cid := range allConfigIDs {
		a.registeredConfigIDs[cid] = cid
	}
	a.mu.Unlock()
	if !changed {
		return nil
	}
	service := a.cfg.IssuerServiceName
	if service == "" {
		service = "issuer-api"
	}
	if err := restartContainer(service); err != nil {
		return fmt.Errorf("restart %s: %w", service, err)
	}
	return nil
}

// DeleteCustomSchema removes the schema's catalog entry (if any) and
// restarts issuer-api. Mirrors SaveCustomSchema — the registry's in-memory
// custom-schemas slice is cleared by the registry itself; this hook only
// owns the walt.id-side bookkeeping.
//
// Best-effort: a deploy without a CatalogPath, or a delete of a schema
// whose entry never made it into the catalog (Phase-2-only formats), is a
// no-op.
func (a *Adapter) DeleteCustomSchema(_ context.Context, id string) error {
	if a.cfg.CatalogPath == "" {
		return nil
	}
	a.mu.Lock()
	primaryConfigID := a.registeredConfigIDs[id]
	// Drop every key tied to this schema: the schema.ID plus all per-format
	// configIDs. Iterate a snapshot so we can mutate during traversal.
	keys := make([]string, 0, len(a.registeredConfigIDs))
	for k := range a.registeredConfigIDs {
		keys = append(keys, k)
	}
	a.mu.Unlock()
	if primaryConfigID == "" {
		return nil
	}
	// Recover TypeName + Std from the primary configID so removeCredentialType
	// strips every wire-format block (jwt_vc_json + jwt_vc_json-ld + ldp_vc
	// for a w3c_vcdm_2 schema, etc). The wire-format suffix is the part after
	// the last underscore.
	typeName, std := parseTypeAndStdFromConfigID(primaryConfigID)
	a.mu.Lock()
	for _, k := range keys {
		if k == id || strings.HasPrefix(k, typeName+"_") {
			delete(a.registeredConfigIDs, k)
		}
	}
	a.mu.Unlock()
	if err := removeCredentialType(a.cfg.CatalogPath, vctypes.Schema{
		ID:              id,
		Name:            typeName,
		AdditionalTypes: []string{typeName},
		Std:             std,
	}); err != nil {
		return fmt.Errorf("remove catalog entry: %w", err)
	}
	service := a.cfg.IssuerServiceName
	if service == "" {
		service = "issuer-api"
	}
	return restartContainer(service)
}

// parseTypeAndStdFromConfigID reverses the configID format. The wire-format
// suffix (jwt_vc_json, vc+sd-jwt, mso_mdoc, ...) maps back to a Std so
// removeCredentialType can ask waltidWireFormatsForStd for the full sibling
// list. Falls back to w3c_vcdm_2 when the suffix is unrecognised — that's
// the most common Std and removeCredentialType is idempotent against
// missing entries.
func parseTypeAndStdFromConfigID(configID string) (typeName, std string) {
	suffixes := []string{
		"_jwt_vc_json-ld",
		"_jwt_vc_json",
		"_vc+sd-jwt",
		"_dc+sd-jwt",
		"_mso_mdoc",
		"_ldp_vc",
		"_jwt_vc",
	}
	for _, suf := range suffixes {
		if strings.HasSuffix(configID, suf) {
			typeName = strings.TrimSuffix(configID, suf)
			switch suf {
			case "_vc+sd-jwt", "_dc+sd-jwt":
				return typeName, "sd_jwt_vc (IETF)"
			case "_mso_mdoc":
				return typeName, "mso_mdoc"
			default:
				return typeName, "w3c_vcdm_2"
			}
		}
	}
	return configID, "w3c_vcdm_2"
}

// PrefillSubjectFields returns empty: walt.id doesn't carry an identity plugin
// like MOSIP, so the operator fills the form. This is an honest answer — the
// UI's "Manual entry" source is the intended input mode.
func (a *Adapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return map[string]string{}, nil
}

// issuanceRequest mirrors IssuanceRequest (waltid-issuer-api v0.18.2,
// IssuanceRequests.kt:79). Only the fields this adapter sets are included;
// walt.id ignores unknown fields.
type issuanceRequest struct {
	IssuerKey                 json.RawMessage `json:"issuerKey"`
	CredentialConfigurationId string          `json:"credentialConfigurationId"`
	CredentialData            json.RawMessage `json:"credentialData,omitempty"`
	Vct                       string          `json:"vct,omitempty"`
	MdocData                  json.RawMessage `json:"mdocData,omitempty"`
	AuthenticationMethod      string          `json:"authenticationMethod,omitempty"`
	IssuerDid                 string          `json:"issuerDid,omitempty"`
	StandardVersion           string          `json:"standardVersion,omitempty"`
	// SelectiveDisclosure is walt.id's SDMap JSON — for each top-level
	// claim, {sd: true} makes it a selectively-disclosable disclosure in
	// the issued SD-JWT; omitted means the claim stays in the JWT in the
	// clear. Without this, walt.id bakes every claim into the JWT and the
	// issued SD-JWT has zero disclosures — so selective presentation can't
	// actually hide anything. Only set on SD-JWT issuance paths.
	SelectiveDisclosure json.RawMessage `json:"selectiveDisclosure,omitempty"`
}

// IssueToWallet issues a credential to the holder via OID4VCI. Walt.id returns
// the offer URI as a plain-text response body.
func (a *Adapter) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	if err := a.ensureIssuerKey(ctx); err != nil {
		return backend.IssueToWalletResult{}, err
	}
	path, err := issuePathFor(req.Schema.Std)
	if err != nil {
		return backend.IssueToWalletResult{}, err
	}

	// Walt.id rejects any credentialConfigurationId that isn't in its
	// pre-loaded credential_configurations_supported catalog. Custom
	// schemas (built by the user in /issuer/schema/build) have fresh
	// IDs like "custom-abc123" that walt.id has never heard of. For
	// those, borrow a walt.id-known config in the same Std so the
	// signing path works — the credentialData we send carries the
	// custom type + fields, which is what actually lands in the signed
	// VC. The configurationId only drives signing format + metadata;
	// walt.id doesn't cross-check it against the credentialData payload.
	configID := req.Schema.ID
	if req.Schema.Custom {
		// Custom schemas use the catalog entry SaveCustomSchema wrote.
		// Resolution order:
		//   1. registeredConfigIDs[schema.ID] — fastest, populated by the
		//      most recent SaveCustomSchema call this process saw.
		//   2. Deterministic reconstruction: <CustomTypeName>_<wireFormat>.
		//      Survives a verifiably-go restart that wipes the in-memory
		//      map but where walt.id still has the catalog entry from a
		//      prior save. Without this fallback the issuer hits "Invalid
		//      Credential Configuration Id" because borrowConfigIDFor
		//      returns a stock walt.id configID that's the wrong type.
		//   3. borrowConfigIDFor — last-resort for Std values we don't
		//      know how to fan out (currently only legacy jwt_vc).
		a.mu.Lock()
		registered := a.registeredConfigIDs[req.Schema.ID]
		a.mu.Unlock()
		switch {
		case registered != "":
			configID = registered
		default:
			if wireFormats := waltidWireFormatsForStd(req.Schema.Std); len(wireFormats) > 0 {
				typeName := req.Schema.CustomTypeName()
				configID = typeName + "_" + wireFormats[0]
			} else {
				resolved, err := a.borrowConfigIDFor(ctx, req.Schema.Std)
				if err != nil {
					return backend.IssueToWalletResult{}, fmt.Errorf("custom schema: %w", err)
				}
				configID = resolved
			}
		}
	}

	ir := issuanceRequest{
		IssuerKey:                 a.issuerKey,
		CredentialConfigurationId: configID,
		IssuerDid:                 a.issuerDID,
		AuthenticationMethod:      authenticationMethod(req.Flow),
		StandardVersion:           strings.ToUpper(a.cfg.StandardVersion),
	}
	switch req.Schema.Std {
	case "mso_mdoc":
		// mdoc bodies are namespace-keyed: {"<namespace>":{"<field>":"<value>"}}.
		// walt.id's Kotlin IssuanceRequest rejects the VCDM 2.0 shape with a
		// JsonConvertException. Namespace is derived from the doctype by
		// stripping the last dot-segment (e.g. org.iso.18013.5.1.mDL →
		// org.iso.18013.5.1).
		// mdoc revocation flows through MSO/IACA, not bitstring/token status
		// lists, so we don't inject a StatusListBinding here even when one is
		// passed (the handler shouldn't allocate for mso_mdoc; this is a
		// belt-and-braces no-op).
		mdocData, err := buildMdocData(req.Schema, req.SubjectData)
		if err != nil {
			return backend.IssueToWalletResult{}, err
		}
		ir.MdocData = mdocData
	case "sd_jwt_vc (IETF)", "sd_jwt_vc":
		// SD-JWT VC issuance expects credentialData with TOP-LEVEL claim
		// keys (no VCDM @context / type / credentialSubject wrapping).
		// Walt.id's SDMap matches these same top-level keys to decide
		// which become disclosures; a VCDM-wrapped body only makes
		// "credentialSubject" itself disclosable, leaving the individual
		// claims baked into the JWT.
		cd, err := buildSDJWTCredentialData(req.SubjectData, req.StatusList)
		if err != nil {
			return backend.IssueToWalletResult{}, err
		}
		// vct selection precedence (matters because the wallet stores the
		// issued vct verbatim and the verifier's PD filter must hit the
		// SAME string):
		//   1. Schema.Vct — populated from a SchemaVariant for stock
		//      schemas; carries the URL walt.id's catalog advertises.
		//   2. CustomTypeName for custom schemas — "FarmerCredential",
		//      matching the catalog entry buildSDJWTEntry writes AND
		//      what the verifier handler sends in tpl.Vct.
		//   3. Schema.ID as a last resort. Pre-Phase-2 we used this for
		//      custom schemas, but the random "custom-..." ID didn't
		//      align with what the catalog advertised, so the wallet
		//      matcher rejected the verifier's request.
		switch {
		case req.Schema.Vct != "":
			ir.Vct = req.Schema.Vct
		case req.Schema.Custom:
			ir.Vct = req.Schema.CustomTypeName()
		default:
			ir.Vct = req.Schema.ID
		}
		ir.CredentialData = cd
		ir.SelectiveDisclosure = buildSelectiveDisclosureMap(req.SubjectData)
	default:
		cd, err := buildCredentialData(req.Schema, req.SubjectData, req.StatusList)
		if err != nil {
			return backend.IssueToWalletResult{}, err
		}
		ir.CredentialData = cd
	}

	raw, err := a.issuer.DoRaw(ctx, "POST", path, jsonReader(ir), "application/json", nil)
	if err != nil {
		// Specifically diagnose "Invalid Credential Configuration Id" — that
		// either means the catalog write didn't take effect (verifiably-go
		// restarted and lost registeredConfigIDs while walt.id still has the
		// stale boot catalog), or walt.id is silently rejecting our entry.
		// Fetch the live metadata so the user sees what configIDs walt.id
		// actually advertises right now vs what we tried to send.
		if strings.Contains(err.Error(), "Invalid Credential Configuration Id") {
			advertised := a.peekAdvertisedConfigIDs(ctx)
			return backend.IssueToWalletResult{}, fmt.Errorf(
				"%w [DIAG: walt.id rejected configurationId=%q. Advertised configIDs (%d): %s. If the configID we sent is not in this list, the catalog write didn't take effect — try saving the schema again to retrigger the catalog edit + walt.id restart]",
				err, configID, len(advertised), strings.Join(advertised, ", "))
		}
		return backend.IssueToWalletResult{}, err
	}
	return backend.IssueToWalletResult{
		OfferURI: strings.TrimSpace(string(raw)),
		OfferID:  req.Schema.ID + "-" + req.IssuerDpg,
		Flow:     req.Flow,
	}, nil
}

// peekAdvertisedConfigIDs fetches walt.id's openid-credential-issuer
// metadata and returns the keys of credential_configurations_supported.
// Best-effort — used only to diagnose issuance failures, so a fetch
// error returns an empty list rather than failing the caller.
func (a *Adapter) peekAdvertisedConfigIDs(ctx context.Context) []string {
	if a.issuer == nil {
		return nil
	}
	var meta credentialIssuerMetadata
	path := fmt.Sprintf("/%s/.well-known/openid-credential-issuer", a.cfg.StandardVersion)
	if err := a.issuer.DoJSON(ctx, "GET", path, nil, &meta, nil); err != nil {
		return nil
	}
	out := make([]string, 0, len(meta.CredentialConfigurationsSupported))
	for k := range meta.CredentialConfigurationsSupported {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IssueAsPDF — walt.id Community Stack v0.18.2 has no documented QR-on-PDF
// export path. Return ErrNotSupported; the UI disables PDF destination via
// DPG.DirectPDF=false.
func (a *Adapter) IssueAsPDF(_ context.Context, _ backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, backend.ErrNotSupported
}

// IssueBulk iterates Rows and calls IssueToWallet per row. Returns a
// per-row report (offer URI on success, error reason on failure, plus a
// human-readable label for each row) so the UI can render the detail
// table the issuing officer actually needs.
func (a *Adapter) IssueBulk(ctx context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	if len(req.Rows) == 0 {
		return backend.IssueBulkResult{}, fmt.Errorf("waltid: no rows supplied")
	}
	accepted := 0
	rejected := 0
	var errs []backend.BulkError
	rows := make([]backend.BulkRowResult, 0, len(req.Rows))
	for i, row := range req.Rows {
		label := rowLabel(row)
		res, err := a.IssueToWallet(ctx, backend.IssueRequest{
			IssuerDpg:   req.IssuerDpg,
			Schema:      req.Schema,
			SubjectData: row,
			Flow:        "pre_auth",
		})
		if err != nil {
			rejected++
			reason := truncate(err.Error(), 140)
			errs = append(errs, backend.BulkError{Row: i + 1, Reason: reason})
			rows = append(rows, backend.BulkRowResult{
				Row: i + 1, Subject: row, Label: label, Status: "failed", Error: reason,
			})
			continue
		}
		accepted++
		rows = append(rows, backend.BulkRowResult{
			Row: i + 1, Subject: row, Label: label, Status: "issued", OfferURI: res.OfferURI,
		})
	}
	return backend.IssueBulkResult{
		Accepted: accepted, Rejected: rejected, Errors: errs, Rows: rows,
	}, nil
}

// rowLabel picks a one-line label the UI table can display per row.
// Government officers scan these to recognise WHO a credential was for,
// so we prefer named-person fields over opaque ids. Falls back to the
// first non-empty value so every row surfaces something.
func rowLabel(row map[string]string) string {
	if v := strings.TrimSpace(row["holder"]); v != "" {
		return v
	}
	first := strings.TrimSpace(row["firstName"])
	last := strings.TrimSpace(row["familyName"])
	if first != "" || last != "" {
		return strings.TrimSpace(first + " " + last)
	}
	if v := strings.TrimSpace(row["name"]); v != "" {
		return v
	}
	if v := strings.TrimSpace(row["personalIdentifier"]); v != "" {
		return v
	}
	if v := strings.TrimSpace(row["ReceiptId"]); v != "" {
		return v
	}
	// Fallback: first non-empty value in the row.
	for _, v := range row {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "(empty row)"
}

// BootstrapOffers issues a single canned credential against whatever schema is
// declared first on the issuer so the Wallet "paste example" helper has a real
// URI to cycle through. If issuance fails, returns an empty slice + nil error
// so startup doesn't block.
func (a *Adapter) BootstrapOffers(ctx context.Context) ([]string, error) {
	schemas, err := a.ListSchemas(ctx, a.Vendor)
	if err != nil || len(schemas) == 0 {
		return nil, nil
	}
	// Prefer UniversityDegree for consistency, else first in list.
	pick := schemas[0]
	for _, s := range schemas {
		if strings.HasPrefix(s.ID, "UniversityDegree") {
			pick = s
			break
		}
	}
	res, err := a.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg: a.Vendor,
		Schema:    pick,
		SubjectData: map[string]string{
			"holder": "Demo Holder",
		},
		Flow: "pre_auth",
	})
	if err != nil {
		return nil, nil
	}
	return []string{res.OfferURI}, nil
}

// --- helpers ---

// formatToStd maps walt.id's credential-format keys to vctypes.Schema.Std.
// Returns "" for VP-only entries (which aren't issuance schemas).
func formatToStd(format string) string {
	switch format {
	// All W3C VC encodings (JSON, JSON-LD, LDP, and the legacy opaque
	// JWT wrap) surface under a single Std so the dedup collapses them
	// down to one card per credential type.
	case "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc", "jwt_vc":
		return "w3c_vcdm_2"
	case "vc+sd-jwt", "dc+sd-jwt":
		return "sd_jwt_vc (IETF)"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return ""
	}
}

// issuePathFor returns the /openid4vc/{format}/issue endpoint for a standard.
// walt.id routes jwt/sdjwt/mdoc into distinct paths in v0.18.2.
//
// Accepts both the canonical "sd_jwt_vc (IETF)" form (used internally and
// in walt.id's metadata) and the bare "sd_jwt_vc" the schema-builder
// dropdown emits — the canonicalStd shim in handlers/schema.go normalises
// at the boundary, but in-memory schemas saved before that shim landed
// (or from older sessions) still flow through here, so the alias guards
// against a regression.
func issuePathFor(std string) (string, error) {
	switch std {
	case "w3c_vcdm_1", "w3c_vcdm_2", "jwt_vc":
		return "/openid4vc/jwt/issue", nil
	case "sd_jwt_vc (IETF)", "sd_jwt_vc":
		return "/openid4vc/sdjwt/issue", nil
	case "mso_mdoc":
		return "/openid4vc/mdoc/issue", nil
	default:
		return "", fmt.Errorf("waltid: unsupported schema standard %q", std)
	}
}

// authenticationMethod maps the UI's flow choice onto walt.id's enum.
func authenticationMethod(flow string) string {
	switch flow {
	case "auth_code", "authorization_code":
		return "NONE"
	case "pre_auth", "pre_authorized_code", "":
		return "PRE_AUTHORIZED"
	default:
		return strings.ToUpper(flow)
	}
}

// buildSDJWTCredentialData builds the top-level-claims credentialData that
// walt.id's /openid4vc/sdjwt/issue expects. Unlike the VCDM JWT flow (which
// nests under credentialSubject), SD-JWT VC puts each claim at the payload
// root so walt.id's SDMap can mark individual claims as selectively
// disclosable.
func buildSDJWTCredentialData(subject map[string]string, sl *backend.StatusListBinding) (json.RawMessage, error) {
	out := make(map[string]any, len(subject)+1)
	for k, v := range subject {
		out[k] = v
	}
	// IETF Token Status List binding: top-level `status.status_list.{idx,uri}`
	// per draft-ietf-oauth-status-list. Walt.id passes the credentialData
	// claims through into the SD-JWT verbatim, so the verifier sees the
	// status binding without us touching walt.id's signing path.
	if sl != nil && sl.Type == "token" {
		out["status"] = map[string]any{
			"status_list": map[string]any{
				"idx": sl.Index,
				"uri": sl.PublishURL,
			},
		}
	}
	return json.Marshal(out)
}

// buildSelectiveDisclosureMap emits walt.id's SDMap JSON for SD-JWT issuance.
// Every top-level claim from the subject data becomes a selectively-
// disclosable disclosure ({sd: true}), so the holder can later reveal
// them one-by-one during a VP. decoyMode is NONE (no decoy digests) to
// keep the output deterministic; walt.id accepts decoys>0 for privacy-
// hardening production flows but it complicates the test matrix.
//
// Without this, walt.id bakes every claim into the signed JWT in the
// clear and the resulting "SD-JWT" has zero disclosures — making
// selective disclosure at presentation time physically impossible.
func buildSelectiveDisclosureMap(subject map[string]string) json.RawMessage {
	fields := make(map[string]any, len(subject))
	for k := range subject {
		fields[k] = map[string]any{"sd": true}
	}
	m := map[string]any{
		"fields":    fields,
		"decoyMode": "NONE",
		"decoys":    0,
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}

// buildMdocData constructs the namespace-keyed body walt.id's mdoc issuer
// expects. Namespace is derived from the credential's doctype (the Schema's
// base type) by stripping the last dot-segment — mdoc spec convention, so
// "org.iso.18013.5.1.mDL" → "org.iso.18013.5.1". Every subject field lands
// under that namespace; walt.id copies them into the mdoc's data elements.
func buildMdocData(schema vctypes.Schema, subject map[string]string) (json.RawMessage, error) {
	doctype := schema.BaseType()
	if doctype == "" {
		doctype = schema.ID
	}
	namespace := doctype
	if i := strings.LastIndex(doctype, "."); i > 0 {
		namespace = doctype[:i]
	}
	claims := make(map[string]any, len(subject))
	for k, v := range subject {
		claims[k] = v
	}
	doc := map[string]any{namespace: claims}
	return json.Marshal(doc)
}

// buildCredentialData constructs a VCDM 2.0-shaped JSON object from the
// operator's subject input. Types come from the schema id prefix
// (the canonical type before the `_format` suffix).
func buildCredentialData(schema vctypes.Schema, subject map[string]string, sl *backend.StatusListBinding) (json.RawMessage, error) {
	types := []string{"VerifiableCredential"}
	if schema.Custom {
		// Custom schemas may declare AdditionalTypes via the builder's
		// "Extra Type" field; otherwise derive a CamelCase type from the
		// schema name so the signed VC carries a distinct type even when
		// we're signing through a borrowed walt.id configurationId.
		if len(schema.AdditionalTypes) > 0 {
			types = append(types, schema.AdditionalTypes...)
		} else {
			types = append(types, sanitizeTypeName(schema.Name))
		}
	} else {
		baseType := schema.BaseType()
		if baseType == "" {
			baseType = strings.SplitN(schema.ID, "_", 2)[0]
		}
		types = append(types, baseType)
	}
	credSubject := make(map[string]any, len(subject))
	for k, v := range subject {
		credSubject[k] = v
	}
	doc := map[string]any{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/ns/credentials/examples/v1",
		},
		"type":              types,
		"credentialSubject": credSubject,
	}
	// W3C Bitstring Status List 2023 entry. statusListIndex must be a
	// STRING per the spec, even though it's numeric semantically — verifiers
	// reject numeric forms with a "VC-BSL-VALIDATION" error. Walt.id signs
	// whatever credentialStatus we put here verbatim, so this is the only
	// touchpoint needed for VCDM 2.0 revocation.
	if sl != nil && sl.Type == "bitstring" {
		doc["credentialStatus"] = map[string]any{
			"id":                   fmt.Sprintf("%s#%d", sl.PublishURL, sl.Index),
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":        "revocation",
			"statusListIndex":      fmt.Sprintf("%d", sl.Index),
			"statusListCredential": sl.PublishURL,
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sanitizeTypeName title-cases the name and strips non-alphanumerics so a
// custom schema "My Farmer Cred!" renders as "MyFarmerCred" in the VC's
// type array. Falls back to "CustomCredential" when the name is empty or
// has no letters/digits.
func sanitizeTypeName(name string) string {
	var b strings.Builder
	capNext := true
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			capNext = false
		case r >= 'a' && r <= 'z':
			if capNext {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			capNext = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			capNext = false
		default:
			capNext = true
		}
	}
	out := b.String()
	if out == "" {
		return "CustomCredential"
	}
	return out
}

// fieldsForCredentialType returns a curated FieldSpec list for the walt.id
// credential configurations we know about. Walt.id's issuer metadata doesn't
// expose per-claim types, so hand-rolling the list is the only way to get
// meaningful input types (date, number, etc.) in the UI. Unknown ids get a
// minimal {holder} fallback.
func fieldsForCredentialType(id string) []vctypes.FieldSpec {
	base := strings.SplitN(id, "_", 2)[0]
	str := func(name string) vctypes.FieldSpec {
		return vctypes.FieldSpec{Name: name, Datatype: "string", Required: true}
	}
	date := func(name string) vctypes.FieldSpec {
		return vctypes.FieldSpec{Name: name, Datatype: "string", Format: "date", Required: true}
	}
	switch base {
	case "UniversityDegree", "UniversityDegreeCredential":
		return []vctypes.FieldSpec{str("holder"), str("degree"), str("classification"), date("conferred")}
	case "VerifiableId", "VerifiableID", "NaturalPersonVerifiableID":
		return []vctypes.FieldSpec{str("holder"), date("dateOfBirth"), str("nationality"), str("placeOfBirth")}
	case "KycChecksCredential", "KycCredential", "KycDataCredential":
		return []vctypes.FieldSpec{str("holder"), str("kycComplete"), str("amlScreeningPassed"), date("checkedOn")}
	case "Iso18013DriversLicenseCredential":
		return []vctypes.FieldSpec{
			str("family_name"), str("given_name"), date("birth_date"),
			str("document_number"), str("driving_privileges"), date("expiry_date"),
		}
	case "OpenBadgeCredential":
		return []vctypes.FieldSpec{str("holder"), str("achievement"), date("issuedOn")}
	case "BankId":
		return []vctypes.FieldSpec{str("holder"), str("accountNumber"), str("institution")}
	case "VaccinationCertificate":
		return []vctypes.FieldSpec{str("holder"), str("vaccine"), str("manufacturer"), date("administeredOn")}
	case "ePassportCredential", "PassportCh":
		return []vctypes.FieldSpec{
			str("given_name"), str("family_name"), str("passport_number"),
			date("date_of_birth"), str("nationality"), date("expires_at"),
		}
	case "TaxCredential", "TaxReceipt":
		return []vctypes.FieldSpec{str("holder"), str("taxId"), date("period")}
	case "EducationalID":
		return []vctypes.FieldSpec{str("holder"), str("institution"), str("studentId")}
	case "IdentityCredential":
		return []vctypes.FieldSpec{
			str("holder"), date("date_of_birth"),
			{Name: "age_over_18", Datatype: "boolean", Required: false},
		}
	default:
		return []vctypes.FieldSpec{str("holder")}
	}
}

// displayNameFor converts an id like "UniversityDegree_jwt_vc_json" into a
// human-readable schema name ("University Degree"). Falls back to the raw id.
// knownWaltidFormatSuffixes are the `_<format>` trailers walt.id appends to
// every credential configuration id. Stripping them reveals the base type
// name, which can itself contain underscores (e.g. "identity_credential").
// Order matters — longer suffixes first so we don't prematurely match a
// prefix of a longer one ("_jwt_vc" would chop "_jwt_vc_json" otherwise).
var knownWaltidFormatSuffixes = []string{
	"_jwt_vc_json-ld",
	"_jwt_vp_json-ld",
	"_jwt_vc_json",
	"_jwt_vp_json",
	"_vc+sd-jwt",
	"_dc+sd-jwt",
	"_mso_mdoc",
	"_ldp_vc",
	"_ldp_vp",
	"_jwt_vc",
	"_jwt_vp",
}

func displayNameFor(id string, cfg credentialConfigurationEntry) string {
	// 1. Prefer the configuration's declared display name if walt.id
	//    provides one — that's the cleanest possible label.
	if len(cfg.Display) > 0 && strings.TrimSpace(cfg.Display[0].Name) != "" {
		return strings.TrimSpace(cfg.Display[0].Name)
	}
	// 2. Strip the known format suffix from the id. walt.id's config ids
	//    all end with `_<format>`, but the type itself can contain
	//    underscores (see `identity_credential_vc+sd-jwt`), so splitting
	//    on the first underscore is wrong — suffix stripping preserves
	//    the full type name.
	base := id
	for _, suf := range knownWaltidFormatSuffixes {
		if strings.HasSuffix(base, suf) {
			base = strings.TrimSuffix(base, suf)
			break
		}
	}
	if base == "" {
		return id
	}
	// 3. Humanise. Split snake_case on `_`, then insert a space at each
	//    case boundary WITHOUT breaking up acronyms: only split where an
	//    uppercase letter follows a lowercase letter, or where an
	//    uppercase letter is followed by a lowercase letter (the boundary
	//    between an acronym and a following Word). This way "eID" stays
	//    "eID", "PND91Credential" → "PND91 Credential", and
	//    "IdentityCredential" → "Identity Credential".
	var parts []string
	for _, word := range strings.Split(base, "_") {
		if word == "" {
			continue
		}
		runes := []rune(word)
		var out []rune
		for i, r := range runes {
			if i > 0 {
				prev := runes[i-1]
				next := rune(0)
				if i+1 < len(runes) {
					next = runes[i+1]
				}
				lowerPrev := prev >= 'a' && prev <= 'z'
				upperCur := r >= 'A' && r <= 'Z'
				upperPrev := prev >= 'A' && prev <= 'Z'
				lowerNext := next >= 'a' && next <= 'z'
				digitPrev := prev >= '0' && prev <= '9'
				// lowercase → uppercase boundary (aB), or
				// UPPER-UPPER → Upper-lower boundary (HTMLParser → HTML Parser), or
				// digit → letter boundary (91C → 91 C)
				if (lowerPrev && upperCur) ||
					(upperPrev && upperCur && lowerNext) ||
					(digitPrev && (r >= 'A' && r <= 'Z')) {
					out = append(out, ' ')
				}
			}
			out = append(out, r)
		}
		// Title-case the first letter of each snake_case segment.
		if len(out) > 0 && out[0] >= 'a' && out[0] <= 'z' {
			// …but not if this is a known mixed-case identifier (e.g. "eID",
			// "ePassport") — detect by looking at the original first char
			// against second: if second is uppercase, keep the leading
			// lowercase so "eID" doesn't become "EID".
			if len(runes) >= 2 && runes[1] >= 'A' && runes[1] <= 'Z' {
				// keep as-is
			} else {
				out[0] -= 32
			}
		}
		parts = append(parts, string(out))
	}
	return strings.Join(parts, " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// baseTypeFromConfig picks the credential's canonical type name — the one
// walt.id's credentials.walt.id/api/vc/<Name> template server keys off. Prefers
// credential_definition.type[last] (the specific type after "VerifiableCredential"),
// falls back to vct (sd-jwt), falls back to stripping the _format suffix.
func baseTypeFromConfig(id string, cfg credentialConfigurationEntry) string {
	if cfg.CredentialDefinition != nil {
		for i := len(cfg.CredentialDefinition.Type) - 1; i >= 0; i-- {
			t := cfg.CredentialDefinition.Type[i]
			if t != "" && t != "VerifiableCredential" {
				return t
			}
		}
	}
	if cfg.Vct != "" {
		parts := strings.Split(cfg.Vct, "/")
		if p := parts[len(parts)-1]; p != "" {
			return p
		}
	}
	base := id
	for _, suf := range knownWaltidFormatSuffixes {
		if strings.HasSuffix(base, suf) {
			return strings.TrimSuffix(base, suf)
		}
	}
	return base
}

// templateCache caches results from credentials.walt.id/api/vc/<Name> to avoid
// hitting the public template server on every ListSchemas call. An empty slice
// in the cache means we tried and the type isn't known — the caller can fall
// back to the hardcoded field list without re-fetching.
var (
	templateCache   = map[string][]vctypes.FieldSpec{}
	templateCacheMu sync.RWMutex
	templateClient  = &http.Client{Timeout: 4 * time.Second}
)

// fetchFieldsFromTemplate returns the credentialSubject field shape for a
// walt.id credential type by hitting credentials.walt.id's public template
// server. The template is the same data source walt.id's portal uses, so our
// form shows identical field names + types to what walt.id shows in its own
// whitelabel app. Cached for the process lifetime; network or parse failure
// returns an empty slice (caller falls back to the hardcoded defaults).
func fetchFieldsFromTemplate(baseType string) []vctypes.FieldSpec {
	if baseType == "" {
		return nil
	}
	templateCacheMu.RLock()
	if f, ok := templateCache[baseType]; ok {
		templateCacheMu.RUnlock()
		return f
	}
	templateCacheMu.RUnlock()

	url := "https://credentials.walt.id/api/vc/" + baseType
	resp, err := templateClient.Get(url)
	if err != nil {
		templateCacheMu.Lock()
		templateCache[baseType] = nil
		templateCacheMu.Unlock()
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		templateCacheMu.Lock()
		templateCache[baseType] = nil
		templateCacheMu.Unlock()
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var tmpl struct {
		CredentialSubject map[string]json.RawMessage `json:"credentialSubject"`
	}
	if err := json.Unmarshal(body, &tmpl); err != nil {
		return nil
	}
	fields := fieldsFromTemplate(tmpl.CredentialSubject)
	templateCacheMu.Lock()
	templateCache[baseType] = fields
	templateCacheMu.Unlock()
	return fields
}

// fieldsFromTemplate walks a credentialSubject map and infers a FieldSpec per
// top-level key. "id" is dropped because walt.id substitutes it with the
// holder DID at issuance time — forcing an operator to fill it would only
// mislead. Nested objects (like "address") are surfaced as a single string
// field; the operator types JSON into it. All inferred fields are marked
// optional — the template is a SUGGESTION, not a schema, and walt.id's
// backend accepts a subset.
func fieldsFromTemplate(subject map[string]json.RawMessage) []vctypes.FieldSpec {
	if len(subject) == 0 {
		return nil
	}
	// Preserve insertion order of JSON map keys via json.Decoder.
	// json.Unmarshal into map[string]RawMessage doesn't preserve order, so
	// re-scan the raw bytes. Callers of this path reach here via
	// fetchFieldsFromTemplate which already unmarshalled — to keep ordering
	// stable we sort lexicographically BUT hoist common identity keys up
	// front so the form reads naturally.
	priority := map[string]int{
		"given_name":    1,
		"family_name":   2,
		"date_of_birth": 3,
		"birthdate":     3,
		"nationality":   4,
		"email":         5,
		"phone_number":  6,
		"address":       7,
	}
	keys := make([]string, 0, len(subject))
	for k := range subject {
		if k == "id" {
			continue
		}
		keys = append(keys, k)
	}
	// stable-ish sort: priority first, then alphabetical
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			pi, pj := priority[keys[i]], priority[keys[j]]
			if pi == 0 {
				pi = 1000
			}
			if pj == 0 {
				pj = 1000
			}
			if pj < pi || (pj == pi && keys[j] < keys[i]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	out := make([]vctypes.FieldSpec, 0, len(keys))
	for _, k := range keys {
		raw := subject[k]
		spec := vctypes.FieldSpec{Name: k, Datatype: "string"}
		trimmed := strings.TrimSpace(string(raw))
		switch {
		case strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "["):
			// nested object/array — render as JSON string input
			spec.Datatype = "string"
		case trimmed == "true" || trimmed == "false":
			spec.Datatype = "boolean"
		case isNumericLiteral(trimmed):
			spec.Datatype = "number"
		case isDateLiteral(trimmed):
			spec.Datatype = "string"
			spec.Format = "date"
		}
		out = append(out, spec)
	}
	return out
}

func isNumericLiteral(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 && (r == '-' || r == '+') {
			continue
		}
		if r == '.' || r == 'e' || r == 'E' {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isDateLiteral(s string) bool {
	// Trim surrounding quotes from the raw JSON string literal.
	s = strings.Trim(s, `"`)
	if len(s) < 10 {
		return false
	}
	// YYYY-MM-DD at minimum
	return s[4] == '-' && s[7] == '-' &&
		isNumericLiteral(s[:4]) && isNumericLiteral(s[5:7]) && isNumericLiteral(s[8:10])
}
