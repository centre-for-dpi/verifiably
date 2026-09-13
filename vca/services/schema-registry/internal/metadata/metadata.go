// SPDX-License-Identifier: Apache-2.0

// Package metadata builds the public documents from published schema
// versions: the OID4VCI issuer metadata with
// credential_configurations_supported (ADR-013 decision 4), the public
// schema list of GET /api/schemas, and the SD-JWT VC type metadata of one
// vct (ADR-013 decision 5). Every function is pure.
package metadata

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

// Paths of the public HTTP endpoints.
const (
	IssuerMetadataPath = "/.well-known/openid-credential-issuer"
	SchemasPath        = "/api/schemas"
	VctPrefix          = "/.well-known/vct/"
	VctAliasPrefix     = "/vct/"
	SchemaPrefix       = "/schemas/"
)

// VCDMContext is the JSON-LD context of a W3C VCDM 2.0 credential.
const VCDMContext = "https://www.w3.org/ns/credentials/v2"

// Options name the deployment values the documents carry.
type Options struct {
	// BaseURL is the public root of the registry. Schema and vct URLs start with it.
	BaseURL string
	// CredentialIssuer is the OID4VCI credential_issuer. Empty means BaseURL.
	CredentialIssuer string
	// CredentialEndpoint is the OID4VCI credential_endpoint.
	// Empty means CredentialIssuer plus /credential.
	CredentialEndpoint string
	// AuthorizationServers lists the OAuth authorization servers, when any.
	AuthorizationServers []string
	// SigningAlgs lists credential_signing_alg_values_supported.
	// Empty means ES256 and EdDSA.
	SigningAlgs []string
	// Now is the generation time. Zero omits it from the documents.
	Now time.Time
}

func (o Options) issuer() string {
	if o.CredentialIssuer != "" {
		return strings.TrimRight(o.CredentialIssuer, "/")
	}
	return strings.TrimRight(o.BaseURL, "/")
}

func (o Options) endpoint() string {
	if o.CredentialEndpoint != "" {
		return o.CredentialEndpoint
	}
	return o.issuer() + "/credential"
}

func (o Options) algs() []string {
	if len(o.SigningAlgs) > 0 {
		return append([]string(nil), o.SigningAlgs...)
	}
	return []string{"ES256", "EdDSA"}
}

// SchemaURL returns the public URL of one schema version document.
func SchemaURL(baseURL, id string, version int) string {
	return strings.TrimRight(baseURL, "/") + SchemaPrefix + url.PathEscape(id) + "/" + strconv.Itoa(version)
}

// VctURL returns the public URL of the type metadata of one vct.
func VctURL(baseURL, vct string) string {
	return strings.TrimRight(baseURL, "/") + VctPrefix + url.PathEscape(vct)
}

// Vct returns the vct of a schema: the type when it is a URL, else the
// registry URL of the type.
func Vct(baseURL string, r record.Record) string {
	if u, err := url.Parse(r.Type); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		return r.Type
	}
	return VctURL(baseURL, r.Type)
}

// Claim is one top level property with its display texts.
type Claim struct {
	Name        string
	Title       string
	Description string
	Required    bool
	SD          bool
}

// Claims lists the top level properties of the schema in document order.
// A document that does not parse gives no claims.
func Claims(r record.Record) []Claim {
	parsed, err := jsonschema.Parse([]byte(r.JSONSchema))
	if err != nil {
		return nil
	}
	required := map[string]bool{}
	for _, name := range parsed.Required() {
		required[name] = true
	}
	sd := map[string]bool{}
	for _, name := range r.SDClaims {
		sd[name] = true
	}
	var out []Claim
	for _, name := range parsed.Properties() {
		c := Claim{Name: name, Required: required[name], SD: sd[name]}
		if sub, ok := parsed.Property(name); ok {
			c.Title, _ = sub["title"].(string)
			c.Description, _ = sub["description"].(string)
		}
		if c.Title == "" {
			c.Title = name
		}
		out = append(out, c)
	}
	return out
}

// SchemaObject decodes the JSON Schema document. A document that does
// not decode becomes an empty object.
func SchemaObject(r record.Record) map[string]any {
	var obj map[string]any
	if err := json.Unmarshal([]byte(r.JSONSchema), &obj); err != nil || obj == nil {
		return map[string]any{}
	}
	return obj
}

// display renders the OID4VCI display entries of a schema.
func display(list []record.Display) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		e := map[string]any{"name": d.Name, "locale": d.Locale}
		if d.Description != "" {
			e["description"] = d.Description
		}
		if d.LogoURI != "" {
			e["logo"] = map[string]any{"uri": d.LogoURI}
		}
		if d.BackgroundColor != "" {
			e["background_color"] = d.BackgroundColor
		}
		if d.TextColor != "" {
			e["text_color"] = d.TextColor
		}
		out = append(out, e)
	}
	return out
}

// claimsMetadata renders the claims entry of a credential configuration
// per OID4VCI 1.0 section 11.2.3.
func claimsMetadata(r record.Record) []map[string]any {
	var out []map[string]any
	for _, c := range Claims(r) {
		e := map[string]any{"path": []string{c.Name}, "mandatory": c.Required}
		var texts []map[string]any
		for _, d := range r.Display {
			texts = append(texts, map[string]any{"name": c.Title, "locale": d.Locale})
		}
		if len(texts) == 0 {
			texts = []map[string]any{{"name": c.Title}}
		}
		e["display"] = texts
		out = append(out, e)
	}
	return out
}

// Configuration renders one credential_configurations_supported entry.
func Configuration(r record.Record, format string, opts Options) map[string]any {
	e := map[string]any{
		"format": format,
		"scope":  record.ConfigurationID(r.Type, format),
		"cryptographic_binding_methods_supported": []string{"jwk", "did:key", "did:jwk"},
		"credential_signing_alg_values_supported": opts.algs(),
		"display":               display(r.Display),
		"claims":                claimsMetadata(r),
		"credential_metadata":   map[string]any{"schema_uri": SchemaURL(opts.BaseURL, r.ID, r.Version)},
		"proof_types_supported": map[string]any{"jwt": map[string]any{"proof_signing_alg_values_supported": opts.algs()}},
	}
	switch format {
	case record.FormatVcSdJwt, record.FormatDcSdJwt:
		e["vct"] = Vct(opts.BaseURL, r)
	case record.FormatMsoMdoc:
		e["doctype"] = r.Type
	case record.FormatLdpVc:
		e["credential_definition"] = map[string]any{
			"@context": []string{VCDMContext},
			"type":     []string{"VerifiableCredential", r.Type},
		}
	default:
		e["credential_definition"] = map[string]any{"type": []string{"VerifiableCredential", r.Type}}
	}
	return e
}

// ConfigurationID returns the id of the entry of one format. A published
// version keeps the id the DPG returned, else the derived id.
func ConfigurationID(r record.Record, format string) string {
	if id, ok := r.ConfigurationIDs[format]; ok && id != "" {
		return id
	}
	return record.ConfigurationID(r.Type, format)
}

// Configurations renders every entry of the published versions, keyed by
// configuration id. A later version of the same type replaces an earlier one.
func Configurations(published []record.Record, opts Options) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, r := range record.Sorted(published) {
		for _, f := range r.Formats {
			out[ConfigurationID(r, f)] = Configuration(r, f, opts)
		}
	}
	return out
}

// IssuerMetadata renders the OID4VCI 1.0 issuer metadata document.
func IssuerMetadata(published []record.Record, opts Options) map[string]any {
	configs := Configurations(published, opts)
	doc := map[string]any{
		"credential_issuer":                   opts.issuer(),
		"credential_endpoint":                 opts.endpoint(),
		"credential_configurations_supported": configs,
	}
	if len(opts.AuthorizationServers) > 0 {
		doc["authorization_servers"] = append([]string(nil), opts.AuthorizationServers...)
	}
	if !opts.Now.IsZero() {
		doc["generated_at"] = opts.Now.UTC().Format(time.RFC3339)
	}
	return doc
}

// PublicSchema renders the wallet and verifier view of one version.
func PublicSchema(r record.Record, opts Options) map[string]any {
	ids := map[string]string{}
	for _, f := range r.Formats {
		ids[f] = ConfigurationID(r, f)
	}
	e := map[string]any{
		"id":                r.ID,
		"version":           r.Version,
		"type":              r.Type,
		"state":             string(r.State),
		"url":               SchemaURL(opts.BaseURL, r.ID, r.Version),
		"json_schema":       SchemaObject(r),
		"display":           display(r.Display),
		"formats":           append([]string(nil), r.Formats...),
		"sd_claims":         append([]string{}, r.SDClaims...),
		"configuration_ids": ids,
	}
	if r.Offers(record.FormatVcSdJwt) || r.Offers(record.FormatDcSdJwt) {
		e["vct"] = Vct(opts.BaseURL, r)
	}
	if !r.PublishedAt.IsZero() {
		e["published_at"] = r.PublishedAt.UTC().Format(time.RFC3339)
	}
	return e
}

// PublicList renders the GET /api/schemas document.
func PublicList(published []record.Record, opts Options) map[string]any {
	list := make([]map[string]any, 0, len(published))
	for _, r := range record.Sorted(published) {
		list = append(list, PublicSchema(r, opts))
	}
	doc := map[string]any{"schemas": list, "issuer_metadata": opts.issuer() + IssuerMetadataPath}
	if !opts.Now.IsZero() {
		doc["generated_at"] = opts.Now.UTC().Format(time.RFC3339)
	}
	return doc
}

// SchemaDocument renders the JSON Schema of one version with $id and
// the VC JSON Schema fields.
func SchemaDocument(r record.Record, opts Options) map[string]any {
	obj := SchemaObject(r)
	obj["$id"] = SchemaURL(opts.BaseURL, r.ID, r.Version)
	if _, ok := obj["$schema"]; !ok {
		obj["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	}
	if _, ok := obj["title"]; !ok {
		obj["title"] = r.Name()
	}
	return obj
}

// TypeMetadata renders the SD-JWT VC type metadata document of a version.
func TypeMetadata(r record.Record, opts Options) map[string]any {
	doc := map[string]any{
		"vct":         Vct(opts.BaseURL, r),
		"name":        r.Name(),
		"description": r.Description(),
		"schema":      SchemaDocument(r, opts),
	}
	var displays []map[string]any
	for _, d := range r.Display {
		e := map[string]any{"lang": d.Locale, "name": d.Name, "description": d.Description}
		simple := map[string]any{}
		if d.LogoURI != "" {
			simple["logo"] = map[string]any{"uri": d.LogoURI}
		}
		if d.BackgroundColor != "" {
			simple["background_color"] = d.BackgroundColor
		}
		if d.TextColor != "" {
			simple["text_color"] = d.TextColor
		}
		if len(simple) > 0 {
			e["rendering"] = map[string]any{"simple": simple}
		}
		displays = append(displays, e)
	}
	doc["display"] = displays
	var claims []map[string]any
	for _, c := range Claims(r) {
		e := map[string]any{"path": []string{c.Name}, "sd": "never"}
		if c.SD {
			e["sd"] = "allowed"
		}
		var texts []map[string]any
		for _, d := range r.Display {
			t := map[string]any{"lang": d.Locale, "label": c.Title}
			if c.Description != "" {
				t["description"] = c.Description
			}
			texts = append(texts, t)
		}
		if len(texts) == 0 {
			texts = []map[string]any{{"label": c.Title}}
		}
		e["display"] = texts
		claims = append(claims, e)
	}
	doc["claims"] = claims
	return doc
}

// FindVct returns the newest published version whose vct is vct. The
// caller can pass the type name or the full vct URL.
func FindVct(published []record.Record, vct string, opts Options) (record.Record, bool) {
	var found record.Record
	ok := false
	for _, r := range record.Sorted(published) {
		if r.Type == vct || Vct(opts.BaseURL, r) == vct {
			found, ok = r, true
		}
	}
	return found, ok
}
