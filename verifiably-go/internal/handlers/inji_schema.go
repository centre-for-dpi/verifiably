package handlers

import (
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

func schemaCreationEnabled(h *H) bool {
	return h.Subjects != nil && esignetScopeFile() != "" && certifyScopeQueryFile() != ""
}

// ShowCreateSchema renders the issuer schema-creation form + the existing catalog.
func (h *H) ShowCreateSchema(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	body := map[string]any{
		"Enabled": schemaCreationEnabled(h),
		"Created": r.URL.Query().Get("created"),
		"Error":   sess.SchemaError,
	}
	sess.SchemaError = ""
	if h.Subjects != nil {
		if creds, err := h.Subjects.ListCredentials(r.Context()); err == nil {
			body["Catalog"] = creds
		}
	}
	h.render(w, r, "issuer_schema", h.pageData(sess, body))
}

// CreateSchema handles the legacy /issuer/schema/inji form (W3C VCDM 2.0 only).
// The rich multi-format flow goes through the shared builder (SaveSchema).
func (h *H) CreateSchema(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	fail := func(msg string) { sess.SchemaError = msg; h.redirect(w, r, "/issuer/schema/inji") }
	if !schemaCreationEnabled(h) {
		fail("Schema creation is not enabled (INJI_CERTIFY_DATABASE_URL + scope-file mounts required).")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("Could not parse form.")
		return
	}
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if displayName == "" {
		fail("Credential name is required.")
		return
	}
	var fields []vctypes.FieldSpec
	for _, n := range r.Form["field_name"] {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !fieldNameRe.MatchString(n) {
			fail("Field name '" + n + "' must start with a letter and contain only letters, digits, or underscores.")
			return
		}
		fields = append(fields, vctypes.FieldSpec{Name: n, Datatype: "string"})
	}
	if len(fields) == 0 {
		fail("Add at least one field.")
		return
	}
	std := canonicalStd(r.FormValue("std"))
	if std == "" {
		std = "w3c_vcdm_2"
	}
	schema := vctypes.Schema{
		ID:         "custom-" + nonAlnumRe.ReplaceAllString(strings.ToLower(displayName), ""),
		Name:       displayName,
		Std:        std,
		FieldsSpec: fields,
	}
	key, err := h.applyAuthcodeSchema(r.Context(), schema, sessionOwnerKey(sess))
	if err != nil {
		fail(err.Error())
		return
	}
	h.redirect(w, r, "/issuer/schema/mine?created="+key)
}

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

// ShowProvisionSubject renders the per-credential "provide subject data" form: the
// issuer supplies a holder's AUTHORITATIVE claims for ONE credential they created.
// (Holders create their own identity + basic claims via /holder/register; this writes
// the credential-specific fields on top, keyed by the holder's eSignet PSU-token.)
func (h *H) ShowProvisionSubject(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	cred := strings.TrimSpace(r.URL.Query().Get("cred"))
	h.render(w, r, "issuer_provision", h.pageData(sess, h.provisionBody(r, sess, cred, nil)))
}

// provisionBody assembles the issuer_provision page data: the credential's display
// name (owner-scoped) + its claim fields.
func (h *H) provisionBody(r *http.Request, sess *Session, cred string, extra map[string]any) map[string]any {
	body := map[string]any{"Enabled": h.Subjects != nil, "Cred": cred}
	body["Registries"] = registryProviders() // config-driven pre-fill sources (may be empty)
	if h.Subjects != nil && cred != "" {
		if mine, err := h.Subjects.ListMyCredentials(r.Context(), sessionOwnerKey(sess)); err == nil {
			for _, c := range mine {
				if c["key"] == cred {
					body["DisplayName"] = c["displayName"]
				}
			}
		}
		if fields, err := h.Subjects.CredentialFields(r.Context(), cred); err == nil {
			body["Fields"] = fields
		}
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// ProvisionSubjectForm writes a holder's claims for one credential into certify.vc_subject.
func (h *H) ProvisionSubjectForm(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	cred := strings.TrimSpace(r.FormValue("cred"))
	render := func(extra map[string]any) {
		h.render(w, r, "issuer_provision", h.pageData(sess, h.provisionBody(r, sess, cred, extra)))
	}
	if h.Subjects == nil {
		render(map[string]any{"Error": "Subject provisioning not enabled."})
		return
	}
	id := strings.TrimSpace(r.FormValue("individual_id"))
	if id == "" {
		render(map[string]any{"Error": "Individual ID is required."})
		return
	}
	fields, err := h.Subjects.CredentialFields(r.Context(), cred)
	if err != nil || len(fields) == 0 {
		render(map[string]any{"Error": "Unknown credential (no fields)."})
		return
	}
	claims := map[string]string{}
	for _, f := range fields {
		if v := strings.TrimSpace(r.FormValue("field_" + f)); v != "" {
			claims[f] = v
		}
	}
	if len(claims) == 0 {
		render(map[string]any{"Error": "Enter at least one field value."})
		return
	}
	subjectID := esignetSubjectID(id, injiAuthcodeClientID())
	if err := h.Subjects.ProvisionSubject(r.Context(), subjectID, claims); err != nil {
		render(map[string]any{"Error": "Provision: " + err.Error()})
		return
	}
	render(map[string]any{"Success": true, "IndividualID": id})
}

// registryProvider is one configurable authoritative-data source the provisioning
// form can pre-fill from. Defined entirely by config (VERIFIABLY_REGISTRIES) so
// verifiably carries no knowledge of any specific registry.
type registryProvider struct {
	ID    string `json:"id"`    // selector value, e.g. "dad"
	Label string `json:"label"` // shown in the dropdown
	URL   string `json:"url"`   // base URL, e.g. http://dad-registry:8000
	Path  string `json:"path"`  // lookup path prefix the id is appended to, e.g. /cultivators/
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

func registryProviderByID(id string) (registryProvider, bool) {
	for _, p := range registryProviders() {
		if p.ID == id {
			return p, true
		}
	}
	return registryProvider{}, false
}

// FetchRegistryRecord proxies a lookup against a federated registry (server-side,
// internal network) so the provisioning form can pre-fill a holder's authoritative
// data by id. Forwards the registry's JSON record (or its 404), 502 if unreachable.
func (h *H) FetchRegistryRecord(w http.ResponseWriter, r *http.Request) {
	p, ok := registryProviderByID(r.URL.Query().Get("registry"))
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if !ok || id == "" {
		http.Error(w, `{"error":"unknown registry or missing id"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+p.Path+url.PathEscape(id), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, `{"error":"registry unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
