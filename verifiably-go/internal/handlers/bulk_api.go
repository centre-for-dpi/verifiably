package handlers

// bulk_api.go — the "Bulk from API" source (key "api").
//
// Two request styles share one chip:
//
//   * get     — today's behaviour: GET <url>, decode a JSON array (or an
//               envelope), each object is one row. Optional static
//               Authorization header.
//   * sunbird — a Sunbird RC registry: POST <url>/api/v1/<entity>/search
//               {"filters":{}}; each record is one row (metadata stripped,
//               individualId back-filled from the search field).
//
// Both styles may authenticate with a static header OR an OAuth2
// client_credentials grant (tokenUrl/clientId/clientSecret/scope — the same
// fields a configured VERIFIABLY_REGISTRIES entry carries), and may opt out
// of TLS verification for demo hosts. A configured registry picked in the
// form supplies defaults; typed fields override them (entity precedence in
// buildAPISource). Registry secrets are resolved server-side only.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// apiSource is the fully resolved api mini-form.
type apiSource struct {
	registryProvider
	Mode       string // "get" | "sunbird"
	AuthHeader string // static Authorization value (api_auth)
	Limit      int    // row cap; 0 = all
}

// parseLimit reads a row limit the way the legacy form did (fmt.Sscan: leading
// integer, anything unparsable is 0); negatives are clamped to 0.
func parseLimit(s string) int {
	limit := 0
	if s = strings.TrimSpace(s); s != "" {
		_, _ = fmt.Sscan(s, &limit)
	}
	if limit < 0 {
		return 0
	}
	return limit
}

// buildAPISource reads the api mini-form (plan §6.1 field names). A missing
// api_mode means "get" so the legacy form keeps working unchanged. api_pick
// resolves a configured registry (by id) as the base; every non-empty typed
// field overrides it. Entity precedence: a configured entity beats the schema-ID
// prefill (the form's untouched default) but not a deliberately typed name.
func buildAPISource(r *http.Request, sess *Session) (apiSource, error) {
	f := func(name string) string { return strings.TrimSpace(r.FormValue(name)) }
	s := apiSource{Mode: "get"}
	switch mode := strings.ToLower(f("api_mode")); mode {
	case "", "get":
	case "sunbird":
		s.Mode = "sunbird"
	default:
		return s, fmt.Errorf("unknown request style %q", mode)
	}
	pick := f("api_pick")
	if pick != "" {
		for _, rp := range registryProviders() {
			if rp.ID == pick {
				s.registryProvider = rp
				break
			}
		}
	}
	picked := s.registryProvider
	for name, dst := range map[string]*string{
		"api_url": &s.URL, "api_search": &s.SearchField, "api_auth": &s.AuthHeader,
		"api_token_url": &s.TokenURL, "api_client_id": &s.ClientID, "api_client_secret": &s.ClientSecret, "api_scope": &s.Scope,
	} {
		if v := f(name); v != "" {
			*dst = v
		}
	}
	if v := strings.ToLower(f("api_insecure")); v != "" {
		s.InsecureSkipVerify = v == "1" || v == "on" || v == "true"
	}
	if s.SearchField == "" {
		s.SearchField = "individualId"
	}
	formEntity := f("api_entity")
	switch {
	case pick != "" && picked.Entity != "" && (formEntity == "" || formEntity == sess.SchemaID):
		s.Entity = picked.Entity
	case formEntity != "":
		s.Entity = formEntity
	default:
		s.Entity = sess.SchemaID
	}
	s.Limit = parseLimit(f("api_limit"))
	return s, nil
}

// apiAuthorization resolves the Authorization value for a fetch: the
// client_credentials token when a tokenUrl is set (falling back to the static
// header if the grant fails), else the static header.
func apiAuthorization(ctx context.Context, s apiSource) string {
	if s.TokenURL != "" {
		if tok := registryAuthHeader(ctx, s.registryProvider); tok != "" {
			return tok
		}
	}
	return s.AuthHeader
}

// fetchGETRows retrieves a JSON array from s.URL and decodes each element as a
// flat object whose string values become a row. Nested objects are serialized
// back to JSON strings for operator inspection; numeric values are stringified
// via fmt.Sprint. Limit 0 means "all rows"; the limit counts array items (a
// non-object item still consumes a slot — legacy behaviour, pinned by tests).
func fetchGETRows(ctx context.Context, s apiSource) ([]map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if auth := apiAuthorization(ctx, s); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := registryClient(s.registryProvider).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateForLogBulk(string(body), 200))
	}
	var raw any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	// Accept either a bare array or {"rows": [...]} / {"data": [...]}.
	items, ok := raw.([]any)
	if !ok {
		if obj, isObj := raw.(map[string]any); isObj {
			for _, key := range []string{"rows", "data", "items", "results"} {
				if v, has := obj[key]; has {
					if arr, isArr := v.([]any); isArr {
						items = arr
						ok = true
						break
					}
				}
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("response is not a JSON array or {rows|data|items|results:[...]}")
	}
	rows := make([]map[string]string, 0, len(items))
	for i, item := range items {
		if s.Limit > 0 && i >= s.Limit {
			break
		}
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		row := make(map[string]string, len(obj))
		for k, v := range obj {
			row[k] = stringifyAny(v)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows in response (array had %d items, none were objects)", len(items))
	}
	return rows, nil
}

// fetchJSONRows is the legacy entry point (registrar identity.go): a plain GET
// with an optional static Authorization header — a thin wrapper over
// fetchGETRows so both callers share one implementation.
func fetchJSONRows(ctx context.Context, url, authHeader, limitStr string) ([]map[string]string, error) {
	return fetchGETRows(ctx, apiSource{Mode: "get", AuthHeader: authHeader, Limit: parseLimit(limitStr), registryProvider: registryProvider{URL: url}})
}

// fetchAPIRows dispatches on the request style.
func fetchAPIRows(ctx context.Context, s apiSource) ([]map[string]string, error) {
	if s.Mode == "sunbird" {
		return fetchSunbirdRows(ctx, s)
	}
	return fetchGETRows(ctx, s)
}

// fetchSunbirdRows pulls every record of one Sunbird RC entity as rows:
// POST <url>/api/v1/<entity>/search {"filters":{}} (through the provider's
// client + token), accepting both the {"data":[...]} and {"<entity>":[...]}
// envelopes. Records are flattened with the os* metadata stripped and
// individualId back-filled from SearchField; Limit caps the rows. Unlike the
// registry chip's searchRegistryAll this surfaces errors: a non-2xx answer
// becomes "HTTP <code>: <Sunbird params.errmsg | body≤200>".
func fetchSunbirdRows(ctx context.Context, s apiSource) ([]map[string]string, error) {
	if s.URL == "" {
		return nil, fmt.Errorf("API URL is required.")
	}
	if s.Entity == "" {
		return nil, fmt.Errorf("Entity is required for Sunbird RC search.")
	}
	body, _ := json.Marshal(map[string]any{"filters": map[string]any{}})
	endpoint := strings.TrimRight(s.URL, "/") + "/api/v1/" + s.Entity + "/search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if auth := apiAuthorization(ctx, s); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := registryClient(s.registryProvider).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		msg := truncateForLogBulk(string(raw), 200)
		var env struct {
			Params struct {
				Errmsg string `json:"errmsg"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Params.Errmsg != "" {
			msg = truncateForLogBulk(env.Params.Errmsg, 200)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	hits, _ := raw["data"].([]any)
	if hits == nil {
		hits, _ = raw[s.Entity].([]any)
	}
	field := s.SearchField
	if field == "" {
		field = "individualId"
	}
	var rows []map[string]string
	for _, h := range hits {
		if s.Limit > 0 && len(rows) >= s.Limit {
			break
		}
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
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("entity '%s' has no records", s.Entity)
	}
	return rows, nil
}

// BulkAPIEntities is "Discover entities" for the api chip in Sunbird mode:
// resolves the base URL from the mini-form (api_url, or a picked configured
// registry) and lists what the registry holds (Schema/search, then Swagger).
// Renders fragment_registry_entities into #api-entities with the chips
// targeting api_entity.
func (h *H) BulkAPIEntities(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	need := map[string]any{"NeedURL": true, "Target": "api_entity"}
	if err := r.ParseForm(); err != nil {
		h.renderFragment(w, r, "fragment_registry_entities", need)
		return
	}
	s, err := buildAPISource(r, sess)
	if err != nil || s.URL == "" {
		h.renderFragment(w, r, "fragment_registry_entities", need)
		return
	}
	names, via := discoverEntities(r.Context(), s.registryProvider)
	h.renderFragment(w, r, "fragment_registry_entities", map[string]any{
		"Entities": names,
		"URL":      s.URL,
		"Via":      via,
		"Target":   "api_entity",
	})
}
