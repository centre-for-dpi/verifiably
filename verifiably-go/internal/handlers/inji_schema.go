package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
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

// CreateSchema handles the form: generate + apply all Flow B artifacts, then restart.
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
	names, labels := r.Form["field_name"], r.Form["field_label"]
	var fields []schemaField
	for i, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !fieldNameRe.MatchString(n) {
			fail("Field name '" + n + "' must start with a letter and contain only letters, digits, or underscores.")
			return
		}
		label := n
		if i < len(labels) && strings.TrimSpace(labels[i]) != "" {
			label = strings.TrimSpace(labels[i])
		}
		fields = append(fields, schemaField{Name: n, Label: label})
	}
	if len(fields) == 0 {
		fail("Add at least one field.")
		return
	}

	a := buildAuthcodeArtifacts(displayName, fields)

	// 1. DB: extraction view + credential_config (one transaction)
	if err := h.Subjects.ApplyAuthcodeSchema(r.Context(),
		a.viewDDL, a.configKey, a.ctype, a.vcTemplateB64, a.display, a.credsub, a.scope, a.displayOrder); err != nil {
		fail("DB apply failed: " + err.Error())
		return
	}
	// 2. Certify scope-query mapping (mounted file)
	if err := appendBraceEntry(certifyScopeQueryFile(),
		"mosip.certify.data-provider-plugin.postgres.scope-query-mapping", a.scope, a.scopeQuery); err != nil {
		fail("Certify scope-query write failed: " + err.Error())
		return
	}
	// 3. eSignet scope set + resource mapping (mounted file)
	if err := appendBraceEntry(esignetScopeFile(),
		"mosip.esignet.supported.credential.scopes", a.scope, "'"+a.scope+"'"); err != nil {
		fail("eSignet scope write failed: " + err.Error())
		return
	}
	if err := appendBraceEntry(esignetScopeFile(),
		"mosip.esignet.credential.scope-resource-mapping", a.scope, "'"+a.scope+"':'"+certifyResourceURL+"'"); err != nil {
		fail("eSignet resource-map write failed: " + err.Error())
		return
	}
	// 4. restart certify + esignet so they re-read the files
	for _, c := range []string{"inji-certify", "injiweb-esignet"} {
		if err := dockerRestart(c); err != nil {
			fail("restart " + c + " failed: " + err.Error())
			return
		}
	}
	h.redirect(w, r, "/issuer/schema/inji?created="+a.configKey)
}

type authcodeArtifacts struct {
	configKey, ctype, scope             string
	vcTemplateB64, display, credsub     string
	displayOrder                        []string
	viewDDL, scopeQuery                 string
}

// buildAuthcodeArtifacts is the Go port of scripts/flow-b.py's generation.
func buildAuthcodeArtifacts(displayName string, fields []schemaField) authcodeArtifacts {
	// derive identifiers from the display name
	camel := ""
	for _, word := range strings.FieldsFunc(displayName, func(r rune) bool { return !isAlnum(r) }) {
		camel += strings.ToUpper(word[:1]) + word[1:]
	}
	if camel == "" {
		camel = "Credential"
	}
	configKey := camel
	slug := nonAlnumRe.ReplaceAllString(strings.ToLower(configKey), "")
	scope := slug + "_vc_ldp"
	viewName := "vc_subject_" + slug
	types := []string{"VerifiableCredential", configKey}
	sorted := append([]string{}, types...)
	sort.Strings(sorted) // Certify's config lookup keys on alpha-sorted types

	// vc_template (@context = creds/v1 + ed25519 suite + per-field vocab terms)
	terms := map[string]any{"@vocab": vocabBase}
	for _, t := range types {
		if t != "VerifiableCredential" {
			terms[t] = vocabBase + t
		}
	}
	subj := map[string]any{"id": "${_holderId}"}
	for _, f := range fields {
		terms[f.Name] = vocabBase + f.Name
		subj[f.Name] = "${" + f.Name + "}"
	}
	template := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1", terms,
		},
		"issuer": "${_issuer}", "type": types,
		"issuanceDate": "${validFrom}", "expirationDate": "${validUntil}",
		"credentialSubject": subj,
	}
	tb, _ := json.MarshalIndent(template, "", "  ")
	b64 := base64.StdEncoding.EncodeToString(tb)

	display, _ := json.Marshal([]any{map[string]any{
		"name": displayName, "locale": "en",
		"logo":             map[string]any{"url": "https://verifiably.id/static/credential-logo.svg", "alt_text": "Verifiably"},
		"background_color": "#0f172a", "text_color": "#FFFFFF",
		"background_image": map[string]any{"uri": "https://verifiably.id/static/credential-logo.svg"},
	}})

	cs := map[string]any{}
	var order, viewCols, queryCols []string
	for _, f := range fields {
		cs[f.Name] = map[string]any{"display": []any{map[string]any{"name": f.Label, "locale": "en"}}}
		order = append(order, f.Name)
		viewCols = append(viewCols, fmt.Sprintf("  claims->>'%s' AS \"%s\"", f.Name, f.Name))
		queryCols = append(queryCols, fmt.Sprintf("\"%s\"", f.Name))
	}
	credsub, _ := json.Marshal(cs)

	viewDDL := fmt.Sprintf("CREATE OR REPLACE VIEW certify.%s AS\nSELECT individual_id,\n%s\nFROM certify.vc_subject;",
		viewName, strings.Join(viewCols, ",\n"))
	scopeQuery := fmt.Sprintf("'%s':'select %s from certify.%s where individual_id=:id'",
		scope, strings.Join(queryCols, ", "), viewName)

	return authcodeArtifacts{
		configKey: configKey, ctype: strings.Join(sorted, ","), scope: scope,
		vcTemplateB64: b64, display: string(display), credsub: string(credsub),
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
