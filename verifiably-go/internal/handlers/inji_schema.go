package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Flow B issuer UI: create a credential schema on the fly. Generates all four
// per-credential artifacts (credential_config + extraction view + Certify
// scope-query + eSignet scope) and applies them live -- DB via the certify pool,
// the two mounted config files, then restart inji-certify + injiweb-esignet so
// they re-read the files. The Go port of scripts/flow-b.py, wired to the
// file-based eSignet scopes (the same edit-config-then-restart pattern the
// walt.id side uses for its HOCON catalog).

const (
	vocabBase          = "https://vocab.verifiably.local/"
	certifyResourceURL = "http://certify-nginx:80/v1/certify/issuance/credential"
)

var fieldNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
var nonAlnumRe = regexp.MustCompile(`[^a-z0-9]`)

type schemaField struct{ Name, Label string }

func esignetScopeFile() string      { return os.Getenv("INJI_ESIGNET_SCOPE_FILE") }
func certifyScopeQueryFile() string { return os.Getenv("INJI_CERTIFY_SCOPE_QUERY_FILE") }

// ShowIssuerCredentials renders the credentials THIS issuer created (owner-scoped),
// as a card list -- the page the issuer lands on after creating a schema.
func (h *H) ShowIssuerCredentials(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	body := map[string]any{
		"Enabled": h.Subjects != nil,
		"Created": r.URL.Query().Get("created"),
	}
	if h.Subjects != nil {
		if creds, err := h.Subjects.ListMyCredentials(r.Context(), sessionOwnerKey(sess)); err == nil {
			body["Mine"] = creds
		}
	}
	h.render(w, r, "issuer_credentials", h.pageData(sess, body))
}

// RegistryCredentials lists the active credentials from Certify's credential_config
// (key, display name, scope, and the field names from display_order) as JSON. The
// registry-admin console reads this to drive Sunbird entities + records: unlike
// /api/schemas (verifiably's custom-schema store, which omits auth-code creds), this
// covers the auth-code credentials the registry-auto path actually uses.
func (h *H) RegistryCredentials(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if h.Subjects != nil {
		if creds, err := h.Subjects.ListCredentials(r.Context()); err == nil {
			for _, c := range creds {
				fields, _ := h.Subjects.CredentialFields(r.Context(), c["key"])
				if fields == nil {
					fields = []string{}
				}
				out = append(out, map[string]any{
					"key":         c["key"],
					"displayName": c["displayName"],
					"scope":       c["scope"],
					"fields":      fields,
				})
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// registryProvider is one configurable authoritative-data source the provisioning
// form can pre-fill from. Defined entirely by config (VERIFIABLY_REGISTRIES) so
// verifiably carries no knowledge of any specific registry.
type registryProvider struct {
	ID    string `json:"id"`    // selector value, e.g. "sunbird"
	Label string `json:"label"` // human label
	URL   string `json:"url"`   // base URL, e.g. http://156.67.105.185:18091
	Path  string `json:"path"`  // legacy GET-by-id mode: GET <url><path><id> -> flat JSON

	// Sunbird RC search mode (preferred): when Entity is set, look the holder up via
	// POST <url>/api/v1/<Entity>/search keyed by SearchField, instead of GET-by-id.
	Entity      string `json:"entity"`      // Sunbird entity/schema name, e.g. "TestaCardV4"
	SearchField string `json:"searchField"` // field matched against the id (default "individualId")

	// Discover mode: when true, enumerate ALL registered Sunbird entities (via
	// POST <url>/api/v1/Schema/search) and look the holder up in each by SearchField,
	// merging the results -- so any entity the registrar console creates is auto-pulled
	// with no per-entity config drift. Ignores Entity/Path.
	Discover bool `json:"discover"`
}

// registryProviders parses VERIFIABLY_REGISTRIES (a JSON array of registryProvider).
// Empty/unset/invalid -> no providers (the pre-fill UI hides). The specific registries
// are deployment config, never product code.
func registryProviders() []registryProvider {
	raw := strings.TrimSpace(os.Getenv("VERIFIABLY_REGISTRIES"))
	if raw == "" {
		return nil
	}
	var ps []registryProvider
	if err := json.Unmarshal([]byte(raw), &ps); err != nil {
		return nil
	}
	return ps
}

// fetchRegistry looks up one record for a holder from an authoritative registry,
// returning its fields as flat string claims (all entities merged). Kept for
// callers/tests that don't need per-entity attribution; the activation
// provisioner uses fetchRegistryByEntity so it can namespace each entity's claims
// by its credential slug (see subjectClaimKey).
func fetchRegistry(ctx context.Context, p registryProvider, id string) map[string]string {
	merged := map[string]string{}
	found := false
	for _, rec := range fetchRegistryByEntity(ctx, p, id) {
		for k, v := range rec {
			merged[k] = v
			found = true
		}
	}
	if !found {
		return nil
	}
	return merged
}

// fetchRegistryByEntity is fetchRegistry that PRESERVES the source entity for each
// field batch, so the activation provisioner can write each entity's claims under
// that credential's slug (subjectClaimKey) instead of flat-merging every entity
// into one blob — the cross-schema contamination this fixes. Returns
// entityName -> that entity's flattened record. Discover mode yields one entry per
// registered Sunbird entity; single-Entity mode one entry; the legacy GET-by-id
// path a single "" entry (no entity → the caller keeps it flat).
func fetchRegistryByEntity(ctx context.Context, p registryProvider, id string) map[string]map[string]string {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out := map[string]map[string]string{}
	if p.Discover {
		for _, e := range sunbirdSchemas(cctx, p.URL) {
			pe := p
			pe.Entity = e
			if rec := fetchRegistrySunbird(cctx, pe, id); len(rec) > 0 {
				out[e] = rec
			}
		}
		return out
	}
	if p.Entity != "" {
		if rec := fetchRegistrySunbird(cctx, p, id); len(rec) > 0 {
			out[p.Entity] = rec
		}
		return out
	}
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, p.URL+p.Path+url.PathEscape(id), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	var rec map[string]any
	if json.NewDecoder(resp.Body).Decode(&rec) != nil {
		return out
	}
	if flat := flattenRecord(rec, false); len(flat) > 0 {
		out[""] = flat
	}
	return out
}

// sunbirdSchemas lists the registered Sunbird entity names (POST /api/v1/Schema/search
// {"filters":{}} -> {"data":[{"name":...}]}), so a discover-mode provider auto-finds
// every entity the registrar console created. Skips the built-in "Schema" + leftover probes.
func sunbirdSchemas(ctx context.Context, baseURL string) []string {
	body, _ := json.Marshal(map[string]any{"filters": map[string]any{}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/api/v1/Schema/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()
	var raw struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}
	var names []string
	for _, s := range raw.Data {
		if s.Name == "" || s.Name == "Schema" || s.Name == "ZzProbe" {
			continue
		}
		names = append(names, s.Name)
	}
	return names
}

// fetchRegistrySunbird resolves a holder via a Sunbird RC registry's search API
// (POST <url>/api/v1/<Entity>/search keyed by SearchField), returning the first hit's
// fields. Sunbird wraps results as {"totalCount":n,"data":[{...}]} (some builds use
// {"<Entity>":[...]}); both are handled. The os* metadata (osid/osOwner/_os*) is dropped.
func fetchRegistrySunbird(ctx context.Context, p registryProvider, id string) map[string]string {
	field := p.SearchField
	if field == "" {
		field = "individualId"
	}
	body, _ := json.Marshal(map[string]any{
		"filters": map[string]any{field: map[string]any{"eq": id}},
	})
	endpoint := strings.TrimRight(p.URL, "/") + "/api/v1/" + p.Entity + "/search"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var raw map[string]any
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}
	hits, _ := raw["data"].([]any)
	if hits == nil {
		hits, _ = raw[p.Entity].([]any)
	}
	if len(hits) == 0 {
		return nil
	}
	rec, ok := hits[0].(map[string]any)
	if !ok {
		return nil
	}
	return flattenRecord(rec, true)
}

// flattenRecord stringifies a registry record into claims. When stripMeta is set
// (Sunbird), the registry's own metadata keys (osid, osOwner, _os*) are dropped.
func flattenRecord(rec map[string]any, stripMeta bool) map[string]string {
	out := map[string]string{}
	for k, v := range rec {
		if v == nil {
			continue
		}
		if stripMeta && (k == "osid" || k == "osOwner" || strings.HasPrefix(k, "_os")) {
			continue
		}
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// searchRegistryAll pulls EVERY record of one Sunbird entity (POST
// /api/v1/<Entity>/search with empty filters) as provisioning rows — the bulk
// counterpart of fetchRegistrySunbird (which fetches a single holder by id).
// Each row is guaranteed to carry "individualId" (copied from the provider's
// SearchField when the record names the identity differently) so the provision
// sink can key certify.vc_subject.
func searchRegistryAll(ctx context.Context, p registryProvider, entity string) []map[string]string {
	body, _ := json.Marshal(map[string]any{"filters": map[string]any{}})
	endpoint := strings.TrimRight(p.URL, "/") + "/api/v1/" + entity + "/search"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var raw map[string]any
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}
	hits, _ := raw["data"].([]any)
	if hits == nil {
		hits, _ = raw[entity].([]any)
	}
	field := p.SearchField
	if field == "" {
		field = "individualId"
	}
	var out []map[string]string
	for _, h := range hits {
		rec, ok := h.(map[string]any)
		if !ok {
			continue
		}
		row := flattenRecord(rec, true)
		if _, ok := row["individualId"]; !ok {
			if v, ok := row[field]; ok && v != "" {
				row["individualId"] = v
			}
		}
		if len(row) > 0 {
			out = append(out, row)
		}
	}
	return out
}

// fetchRegistryRows pulls every record from the configured Sunbird RC registries
// (VERIFIABLY_REGISTRIES) as provisioning rows. Discover providers enumerate all
// entities; Entity providers pull that one entity; legacy GET-by-id providers are
// skipped (they expose no list endpoint). Used by the Inji auth-code "registry"
// bulk source — the registry-native way to bulk-provision certify.vc_subject.
func fetchRegistryRows(ctx context.Context) ([]map[string]string, error) {
	providers := registryProviders()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no registries configured (VERIFIABLY_REGISTRIES unset)")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var rows []map[string]string
	for _, p := range providers {
		switch {
		case p.Discover:
			for _, e := range sunbirdSchemas(cctx, p.URL) {
				rows = append(rows, searchRegistryAll(cctx, p, e)...)
			}
		case p.Entity != "":
			rows = append(rows, searchRegistryAll(cctx, p, p.Entity)...)
		default:
			// Legacy GET-by-id providers have no bulk list endpoint — skip.
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("registry search returned no records")
	}
	return rows, nil
}

type authcodeArtifacts struct {
	configKey, scope            string
	credFormat, vcTemplateB64   string
	sdJwtVct, context, credType *string
	display                     string
	credsub                     *string
	displayOrder                []string
	viewDDL, scopeQuery         string
}

// applyAuthcodeSchema generates + applies all Flow B artifacts for a schema (any
// data model the builder offers) and restarts certify + esignet so they re-read
// the files. Returns the credential_config key. Shared by the legacy form and
// the rich builder.
func (h *H) applyAuthcodeSchema(ctx context.Context, schema vctypes.Schema, ownerKey string) (string, error) {
	a := buildAuthcodeArtifacts(schema, h.statusURLFor(authcodeVendor, schema.Std))
	// did_url must equal certify's issuer DID (its did.json id / CERTIFY_ISSUER_DID),
	// NOT the hardcoded docker-internal did:web:certify-nginx — otherwise the signed
	// VC's proof.verificationMethod points at an unresolvable DID and every verifier
	// (Inji Verify, etc.) rejects it. Read it live so it tracks the deploy host.
	didURL := certifyIssuerDID(ctx)
	if err := h.Subjects.ApplyAuthcodeSchema(ctx, a.viewDDL, a.configKey, a.vcTemplateB64,
		a.credFormat, a.display, a.scope, a.displayOrder, a.sdJwtVct, a.context, a.credType, a.credsub, ownerKey, didURL); err != nil {
		return "", fmt.Errorf("DB apply failed: %w", err)
	}
	// Replace (not skip) the scope-query mapping: its value is column-dependent, so
	// a rebuild/edit that changed the field set must overwrite a stale entry —
	// appendBraceEntry alone would keep the old columns (it dedups on the scope key).
	// removeBraceEntry no-ops when absent, so first-time creates are unaffected.
	_ = removeBraceEntry(certifyScopeQueryFile(),
		"mosip.certify.data-provider-plugin.postgres.scope-query-mapping", a.scope)
	if err := appendBraceEntry(certifyScopeQueryFile(),
		"mosip.certify.data-provider-plugin.postgres.scope-query-mapping", a.scope, a.scopeQuery); err != nil {
		return "", fmt.Errorf("Certify scope-query write failed: %w", err)
	}
	if err := appendBraceEntry(esignetScopeFile(),
		"mosip.esignet.supported.credential.scopes", a.scope, "'"+a.scope+"'"); err != nil {
		return "", fmt.Errorf("eSignet scope write failed: %w", err)
	}
	if err := appendBraceEntry(esignetScopeFile(),
		"mosip.esignet.credential.scope-resource-mapping", a.scope, "'"+a.scope+"':'"+certifyResourceURL+"'"); err != nil {
		return "", fmt.Errorf("eSignet resource-map write failed: %w", err)
	}
	// Index this schema's claim fields into certify.ledger.indexed_attributes at
	// issuance, so the issuer's /issuer/credentials cards show + search the data
	// fields for THIS (and every future) schema without a manual config edit. The
	// JSONPath is evaluated against the credentialSubject, so the form is
	// `indexed-mappings.<field>=$.<field>`. Idempotent — a field already covered by
	// the committed static union (or a re-applied schema) isn't duplicated.
	for _, f := range a.displayOrder {
		if err := appendPropertyLine(certifyScopeQueryFile(),
			"mosip.certify.indexed-mappings."+f, "$."+f); err != nil {
			return "", fmt.Errorf("Certify indexed-mapping write failed: %w", err)
		}
	}
	for _, c := range []string{"inji-certify", "injiweb-esignet"} {
		if err := dockerRestart(c); err != nil {
			return "", fmt.Errorf("restart %s failed: %w", c, err)
		}
	}
	return a.configKey, nil
}

// appendPropertyLine appends `key=value` to a Java-properties file if a line for
// that exact key isn't already present (idempotent). Used to register a schema's
// per-field indexed-mappings on the certify config, alongside the scope-query
// append. Comments and other keys are left untouched.
func appendPropertyLine(path, key, value string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), key+"=") {
			return nil // already present
		}
	}
	body := string(b)
	if len(body) > 0 && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += key + "=" + value + "\n"
	return os.WriteFile(path, []byte(body), 0644)
}

// buildAuthcodeArtifacts maps a builder schema (any Std) to the per-credential
// auth-code artifacts, reusing injicertify's per-format credential_config logic
// (ldp_vc for W3C VCDM 1.1/2.0, vc+sd-jwt for IETF SD-JWT VC).
func buildAuthcodeArtifacts(schema vctypes.Schema, statusURL string) authcodeArtifacts {
	// Status wiring is added when a status list is configured for this format
	// (statusURL != "" — the caller passes the TOKEN list for SD-JWT, the
	// BITSTRING list for W3C ldp_vc). BOTH formats now get a per-holder status
	// pointer resolved by the data provider: SD-JWT a `status.status_list`, W3C a
	// standard `credentialStatus` BitstringStatusListEntry pointing at ${statusUri}
	// (the bitstring list). The ${statusIdx}/${statusUri} markers resolve from the
	// extraction view's computed columns (statusIdx per-holder, statusUri the
	// constant list URL for this format), so the W3C block points at the CORRECT
	// (bitstring) list — external verifiers (Inji Verify) can then read it too.
	withStatus := statusURL != ""
	cc := injicertify.BuildAuthcodeCredConfig(schema, withStatus)

	configKey, slug := injiConfigKeySlug(schema)
	// The scope suffix records the wire format so the catalog/wallet don't
	// mislabel an SD-JWT credential as ldp. Nothing parses the suffix, so
	// this only affects NEW schemas (existing ones keep their scope).
	scope := slug + "_" + scopeSuffix(cc.CredFormat)
	viewName := "vc_subject_" + slug

	display, _ := json.Marshal([]any{map[string]any{
		"name": schema.Name, "locale": "en",
		"logo":             map[string]any{"url": "https://verifiably.id/static/credential-logo.svg", "alt_text": "Verifiably"},
		"background_color": "#0f172a", "text_color": "#FFFFFF",
		"background_image": map[string]any{"uri": "https://verifiably.id/static/credential-logo.svg"},
	}})

	cs := map[string]any{}
	var order, queryCols []string
	for _, f := range schema.FieldsSpec {
		// statusIdx/statusUri are auto-added as computed view columns below (for
		// both SD-JWT and W3C when withStatus); a same-named schema field would
		// produce a duplicate column and fail CREATE VIEW. Skip them — the status
		// wiring is authoritative (defensive against any caller/UI schema).
		if withStatus && (f.Name == "statusIdx" || f.Name == "statusUri" || f.Name == "statusType") {
			continue
		}
		cs[f.Name] = map[string]any{"display": []any{map[string]any{"name": f.Name, "locale": "en"}}}
		order = append(order, f.Name)
		queryCols = append(queryCols, fmt.Sprintf("\"%s\"", f.Name))
	}
	if withStatus {
		queryCols = append(queryCols, "\"statusIdx\"", "\"statusUri\"")
	}
	// credential_subject display only for the JSON-LD formats (mirrors injicertify).
	var credsub *string
	if cc.CredFormat == "ldp_vc" || cc.CredFormat == "jwt_vc_json" {
		b, _ := json.Marshal(cs)
		s := string(b)
		credsub = &s
	}

	// The view body is the SINGLE source of truth for the per-slug namespacing —
	// shared with the migration reconcile so both agree exactly.
	viewDDL := authcodeViewDDL(slug, order, withStatus, statusURL)
	scopeQuery := fmt.Sprintf("'%s':'select %s from certify.%s where individual_id=:id'",
		scope, strings.Join(queryCols, ", "), viewName)

	return authcodeArtifacts{
		configKey: configKey, scope: scope,
		credFormat: cc.CredFormat, vcTemplateB64: cc.VCTemplateB64,
		sdJwtVct: cc.SDJwtVct, context: cc.Context, credType: cc.CredType,
		display: string(display), credsub: credsub,
		displayOrder: order, viewDDL: viewDDL, scopeQuery: scopeQuery,
	}
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// injiConfigKeySlug derives the credential_config key (the specific type) and
// its lowercase alnum slug from a builder schema. The slug names the extraction
// view (vc_subject_<slug>) and the per-type status claim key, so provision and
// schema-create must agree on it — hence the single shared helper.
func injiConfigKeySlug(schema vctypes.Schema) (configKey, slug string) {
	// Must match injicertify.credentialTypesSorted: AdditionalTypes[0] or
	// Name-no-spaces.
	specific := strings.ReplaceAll(strings.TrimSpace(schema.Name), " ", "")
	if len(schema.AdditionalTypes) > 0 && strings.TrimSpace(schema.AdditionalTypes[0]) != "" {
		specific = strings.TrimSpace(schema.AdditionalTypes[0])
	}
	if specific == "" {
		specific = "Credential"
	}
	configKey = specific
	slug = nonAlnumRe.ReplaceAllString(strings.ToLower(configKey), "")
	if slug == "" {
		slug = "credential"
	}
	return configKey, slug
}

// injiStatusIdxKey is the per-credential-type key under which a subject's
// allocated token-status index is stored in certify.vc_subject.claims. Keyed by
// slug so one individual can hold two SD-JWT credentials without their status
// indices colliding (vc_subject is one claims blob per individual).
func injiStatusIdxKey(slug string) string { return "statusIdx_" + slug }

// subjectClaimKey is the per-credential-type key under which a subject's CLAIM
// value for `field` is stored in certify.vc_subject.claims. certify.vc_subject
// is ONE claims blob per individual (keyed only by the eSignet PSU-token), so
// without a per-slug prefix two credential schemas that reuse a field name
// (onBehalfOf, role, last_name, …) would overwrite each other in the shared blob
// and issue the wrong data. Every writer of vc_subject and the generated
// extraction view (buildAuthcodeArtifacts) MUST route through this one helper so
// the written key and the read key always agree — the same guarantee
// injiStatusIdxKey already gives the status index. Slugs are alnum-only
// (injiConfigKeySlug), so the "." separator is unambiguous and is a valid JSONB
// object key for the ->> operator.
func subjectClaimKey(slug, field string) string { return slug + "." + field }

// authcodeSchemasSafe returns the schema catalog for entity→slug resolution,
// nil-guarding the adapter (which is absent in some test/headless setups) so
// activation degrades to the naming-convention fallback instead of panicking.
func (h *H) authcodeSchemasSafe(ctx context.Context) []vctypes.Schema {
	if h.Adapter == nil {
		return nil
	}
	s, _ := h.Adapter.ListAllSchemas(ctx)
	return s
}

// slugForEntity resolves a Sunbird entity name to the credential slug its
// extraction view uses, so activation can namespace that entity's claims to match
// the view. Prefer an exact match against a known schema's configKey or display
// Name (robust to an operator who named the entity differently from the type);
// fall back to the naming convention lower-alnum(entity), which equals the
// generated view slug when the entity is named for its credential type.
func slugForEntity(schemas []vctypes.Schema, entity string) string {
	for _, s := range schemas {
		ck, sl := injiConfigKeySlug(s)
		if ck == entity || strings.EqualFold(strings.TrimSpace(s.Name), entity) {
			return sl
		}
	}
	_, sl := injiConfigKeySlug(vctypes.Schema{AdditionalTypes: []string{entity}})
	return sl
}

// authcodeViewDDL builds the CREATE OR REPLACE VIEW for a credential's per-slug
// extraction view: one column per field reading the NAMESPACED claim key
// (subjectClaimKey) aliased back to the plain field name — so the scope-query,
// the ${field} template markers, and Certify stay unchanged, only the JSONB key
// carries the slug prefix. For SD-JWT with token status it appends the per-holder
// statusIdx (coalesced to 0 so the unquoted ${statusIdx} marker is a valid JSON
// number) + the constant statusUri. This is the SINGLE definition of the view
// shape, shared by schema-create (buildAuthcodeArtifacts) and the migration
// reconcile so the read side never drifts from what writers namespaced.
func authcodeViewDDL(slug string, fields []string, withStatus bool, statusURL string) string {
	var cols []string
	for _, f := range fields {
		if withStatus && (f == "statusIdx" || f == "statusUri" || f == "statusType") {
			continue
		}
		cols = append(cols, fmt.Sprintf("  claims->>'%s' AS \"%s\"", subjectClaimKey(slug, f), f))
	}
	if withStatus {
		cols = append(cols,
			fmt.Sprintf("  coalesce(claims->>'%s','0') AS \"statusIdx\"", injiStatusIdxKey(slug)),
			fmt.Sprintf("  '%s' AS \"statusUri\"", statusURL))
	}
	// DROP + CREATE (not CREATE OR REPLACE): Postgres refuses to rename/reorder an
	// existing view's columns (SQLSTATE 42P16), so a rebuild or in-place field edit
	// whose column set differs from a leftover view of the same slug would fail. The
	// two statements run as one no-arg simple-protocol Exec (pgx) inside the caller's
	// transaction (ApplyAuthcodeSchema) or a single pool.Exec (ReplaceView) — atomic,
	// so readers never see the view absent.
	return fmt.Sprintf("DROP VIEW IF EXISTS certify.vc_subject_%s;\nCREATE VIEW certify.vc_subject_%s AS\nSELECT individual_id,\n%s\nFROM certify.vc_subject;",
		slug, slug, strings.Join(cols, ",\n"))
}

// ReapplyAuthcodeViews regenerates every active auth-code extraction view into
// the per-slug namespaced form (subjectClaimKey) — the one-off migration for
// credentials created before namespacing. Rebuilds each view straight from its
// credential_config (config key → slug, display_order → fields, credential_format
// → SD-JWT), so it uses the authoritative slug and never depends on schema
// reconstruction. Idempotent (CREATE OR REPLACE with unchanged columns). API-key
// gated. POST /api/v1/admin/reapply-views.
func (h *H) ReapplyAuthcodeViews(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAPIAuth(w, r); !ok {
		return
	}
	if h.Subjects == nil {
		apiError(w, http.StatusServiceUnavailable, "subject provisioning not enabled (INJI_CERTIFY_DATABASE_URL not set)")
		return
	}
	creds, err := h.Subjects.ListCredentials(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "list credentials: "+err.Error())
		return
	}
	reapplied := []string{}
	failed := map[string]string{}
	for _, c := range creds {
		key := c["key"]
		fields, err := h.Subjects.CredentialFields(r.Context(), key)
		if err != nil {
			failed[key] = "fields: " + err.Error()
			continue
		}
		format, _, _, err := h.Subjects.CredentialClaimSpec(r.Context(), key)
		if err != nil {
			failed[key] = "spec: " + err.Error()
			continue
		}
		_, slug := injiConfigKeySlug(vctypes.Schema{AdditionalTypes: []string{key}})
		// Status URL by format: token list for SD-JWT, bitstring list for W3C ldp_vc.
		statusURL := ""
		if format == "vc+sd-jwt" || format == "dc+sd-jwt" {
			statusURL = h.tokenStatusURL(authcodeVendor)
		} else if format == "ldp_vc" {
			statusURL = h.bitstringStatusURL(authcodeVendor)
		}
		if err := h.Subjects.ReplaceView(r.Context(), authcodeViewDDL(slug, fields, statusURL != "", statusURL)); err != nil {
			failed[key] = err.Error()
			continue
		}
		reapplied = append(reapplied, key)
	}
	apiJSON(w, http.StatusOK, map[string]any{"reapplied": reapplied, "failed": failed})
}

// tokenStatusURL returns the absolute URL of the issuer DPG's IETF token
// status list, or "" when it has none — in which case the SD-JWT status
// wiring is skipped entirely so auth-code claims still succeed.
func (h *H) tokenStatusURL(dpg string) string {
	return h.statusPublishURL(dpg, "token")
}

// bitstringStatusURL is the sibling of tokenStatusURL for the W3C (ldp_vc)
// auth-code path.
func (h *H) bitstringStatusURL(dpg string) string {
	return h.statusPublishURL(dpg, "bitstring")
}

func (h *H) statusPublishURL(dpg, kind string) string {
	e := h.statusListFor(dpg, kind)
	if e == nil || e.Store == nil {
		return ""
	}
	return e.Store.GetPublishURL()
}

// statusURLFor returns the status-list URL appropriate to a schema's format: the
// IETF token list for SD-JWT, the W3C bitstring list for ldp_vc. "" (statusless)
// when the matching store isn't configured or the format has no status kind.
//
// dpg selects that issuer's own list. This URL is baked into a Certify
// credential config once per schema, so it must name the list the same
// DPG will later allocate from.
func (h *H) statusURLFor(dpg, std string) string {
	switch statusListKindFor(std) {
	case "token":
		return h.tokenStatusURL(dpg)
	case "bitstring":
		return h.bitstringStatusURL(dpg)
	}
	return ""
}

// statusStoreFor returns the status-list store verifiably OWNS revocation for on
// the auth-code (Certify) issuance path, keyed by a schema's format. Only SD-JWT
// is verifiably-owned: Certify never writes SD-JWT to its ledger, so verifiably's
// TokenStore (IETF token status list, embedded via the template's
// status.status_list) is that credential's ONLY status list.
//
// W3C ldp_vc is Certify-NATIVE and returns nil: a credentialStatus block in the
// vc_template makes Certify set credential_status_purpose={revocation} and manage
// its OWN bitstring list — allocating a fresh index per issuance and overriding
// the template's ${statusIdx}/${statusUri} with Certify's real list. The issued
// VC points at Certify's list (which Inji Verify reads), so verifiably neither
// allocates a parallel slot nor records the credential in its IssuanceLog;
// revocation routes to Certify's status API (setInjiCredentialStatus, reached via
// the certify.ledger revoke path). Returns nil when the store isn't configured.
func (h *H) statusStoreFor(dpg, std string) statuslist.Backend {
	if statusListKindFor(std) != "token" {
		return nil
	}
	if e := h.statusListFor(dpg, "token"); e != nil {
		return e.Store
	}
	return nil
}

// scopeSuffix maps a certify credential format to the scope suffix used in the
// auth-code scope name. It exists so an SD-JWT credential's scope reads
// "<slug>_vc_sd_jwt" rather than the historical hardcoded "_vc_ldp" (which made
// the catalog/wallet mislabel SD-JWT credentials as ldp).
func scopeSuffix(credFormat string) string {
	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		return "vc_sd_jwt"
	case "jwt_vc_json":
		return "vc_jwt"
	default: // ldp_vc and anything unrecognised
		return "vc_ldp"
	}
}

// appendBraceEntry inserts `entry` into the {...} value of the property line whose
// key is propKey -- unless dupKey already appears on that line (idempotent).
func appendBraceEntry(path, propKey, dupKey, entry string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || !strings.HasPrefix(t, propKey) {
			continue
		}
		if strings.Contains(l, "'"+dupKey+"'") {
			return nil // already present
		}
		idx := strings.LastIndex(l, "}")
		if idx < 0 {
			return fmt.Errorf("no '}' on line for %s", propKey)
		}
		open := strings.Index(l, "{")
		sep := ","
		if open >= 0 && strings.TrimSpace(l[open+1:idx]) == "" {
			sep = ""
		}
		lines[i] = l[:idx] + sep + entry + l[idx:]
		return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	}
	return fmt.Errorf("property %s not found in %s", propKey, path)
}

// removeBraceEntry is the inverse of appendBraceEntry: it removes the entry keyed
// by 'dupKey' from the { ... } map value on the line beginning with propKey. The
// map is split into top-level entries while honouring single-quoted values, so a
// SELECT column list like 'select "a","b" from t' (whose value contains commas)
// is treated as ONE entry and not split apart. It is a no-op (returns nil) when
// the property line or the entry is absent — safe to call before appendBraceEntry
// (to replace a stale column-dependent mapping) or on delete (to purge a scope).
func removeBraceEntry(path, propKey, dupKey string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || !strings.HasPrefix(t, propKey) {
			continue
		}
		openIdx := strings.Index(l, "{")
		closeIdx := strings.LastIndex(l, "}")
		if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
			return nil // not a brace-map line; nothing to remove
		}
		entries := splitTopLevelCommas(l[openIdx+1 : closeIdx])
		kept := make([]string, 0, len(entries))
		removed := false
		for _, e := range entries {
			if strings.HasPrefix(strings.TrimSpace(e), "'"+dupKey+"'") {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		if !removed {
			return nil // entry not present — idempotent
		}
		lines[i] = l[:openIdx+1] + strings.Join(kept, ",") + l[closeIdx:]
		return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	}
	return nil // property line absent — idempotent
}

// splitTopLevelCommas splits s on commas that are NOT inside a single-quoted
// segment, so a brace-map value such as 'select "a", "b" from t' stays intact.
func splitTopLevelCommas(s string) []string {
	var out []string
	inQuote, start := false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// dockerRestart restarts a sibling container via the mounted docker socket.
func dockerRestart(name string) error {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}
	cl := &http.Client{Transport: tr, Timeout: 90 * time.Second}
	resp, err := cl.Post("http://unix/containers/"+name+"/restart?t=10", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
