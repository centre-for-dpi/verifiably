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
// returning its fields as string claims. Two modes: Sunbird RC search (when p.Entity
// is set) or a plain GET-by-id (legacy / generic registries).
func fetchRegistry(ctx context.Context, p registryProvider, id string) map[string]string {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if p.Entity != "" {
		return fetchRegistrySunbird(cctx, p, id)
	}
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, p.URL+p.Path+url.PathEscape(id), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var rec map[string]any
	if json.NewDecoder(resp.Body).Decode(&rec) != nil {
		return nil
	}
	return flattenRecord(rec, false)
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
	a := buildAuthcodeArtifacts(schema)
	if err := h.Subjects.ApplyAuthcodeSchema(ctx, a.viewDDL, a.configKey, a.vcTemplateB64,
		a.credFormat, a.display, a.scope, a.displayOrder, a.sdJwtVct, a.context, a.credType, a.credsub, ownerKey); err != nil {
		return "", fmt.Errorf("DB apply failed: %w", err)
	}
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
	for _, c := range []string{"inji-certify", "injiweb-esignet"} {
		if err := dockerRestart(c); err != nil {
			return "", fmt.Errorf("restart %s failed: %w", c, err)
		}
	}
	return a.configKey, nil
}

// buildAuthcodeArtifacts maps a builder schema (any Std) to the per-credential
// auth-code artifacts, reusing injicertify's per-format credential_config logic
// (ldp_vc for W3C VCDM 1.1/2.0, vc+sd-jwt for IETF SD-JWT VC).
func buildAuthcodeArtifacts(schema vctypes.Schema) authcodeArtifacts {
	cc := injicertify.BuildAuthcodeCredConfig(schema)

	// The credential's specific type (= credential_config key, scope, view) must
	// match injicertify.credentialTypesSorted: AdditionalTypes[0] or Name-no-spaces.
	specific := strings.ReplaceAll(strings.TrimSpace(schema.Name), " ", "")
	if len(schema.AdditionalTypes) > 0 && strings.TrimSpace(schema.AdditionalTypes[0]) != "" {
		specific = strings.TrimSpace(schema.AdditionalTypes[0])
	}
	if specific == "" {
		specific = "Credential"
	}
	configKey := specific
	slug := nonAlnumRe.ReplaceAllString(strings.ToLower(configKey), "")
	if slug == "" {
		slug = "credential"
	}
	scope := slug + "_vc_ldp"
	viewName := "vc_subject_" + slug

	display, _ := json.Marshal([]any{map[string]any{
		"name": schema.Name, "locale": "en",
		"logo":             map[string]any{"url": "https://verifiably.id/static/credential-logo.svg", "alt_text": "Verifiably"},
		"background_color": "#0f172a", "text_color": "#FFFFFF",
		"background_image": map[string]any{"uri": "https://verifiably.id/static/credential-logo.svg"},
	}})

	cs := map[string]any{}
	var order, viewCols, queryCols []string
	for _, f := range schema.FieldsSpec {
		cs[f.Name] = map[string]any{"display": []any{map[string]any{"name": f.Name, "locale": "en"}}}
		order = append(order, f.Name)
		viewCols = append(viewCols, fmt.Sprintf("  claims->>'%s' AS \"%s\"", f.Name, f.Name))
		queryCols = append(queryCols, fmt.Sprintf("\"%s\"", f.Name))
	}
	// credential_subject display only for the JSON-LD formats (mirrors injicertify).
	var credsub *string
	if cc.CredFormat == "ldp_vc" || cc.CredFormat == "jwt_vc_json" {
		b, _ := json.Marshal(cs)
		s := string(b)
		credsub = &s
	}

	viewDDL := fmt.Sprintf("CREATE OR REPLACE VIEW certify.%s AS\nSELECT individual_id,\n%s\nFROM certify.vc_subject;",
		viewName, strings.Join(viewCols, ",\n"))
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
