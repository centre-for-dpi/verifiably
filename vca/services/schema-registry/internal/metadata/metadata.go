// SPDX-License-Identifier: Apache-2.0

// Package metadata builds the public documents from published schema
// versions: the OID4VCI issuer metadata with
// credential_configurations_supported (ADR-013 decision 4), the public
// schema list of GET /api/schemas, and the SD-JWT VC type metadata of one
// vct (ADR-013 decision 5). Every function is pure.
package metadata

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
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
			c.Title = stringField(sub, "title")
			c.Description = stringField(sub, "description")
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

// Display renders the OID4VCI display entries of a schema.
func Display(list []record.Display) []map[string]any {
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
		if m, ok := r.Mapping(c.Name); ok && len(m.Labels) > 0 {
			for _, l := range m.Labels {
				texts = append(texts, map[string]any{"name": l.Label, "locale": l.Locale})
			}
		}
		for _, d := range r.Display {
			if len(texts) > 0 {
				break
			}
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
		"display":               Display(r.Display),
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
			"@context": LdpContext(r),
			"type":     []string{"VerifiableCredential", r.Type},
		}
	default:
		e["credential_definition"] = map[string]any{"type": []string{"VerifiableCredential", r.Type}}
	}
	return e
}

// LdpContext returns the @context of an ldp_vc credential of r: the
// VCDM 2.0 context, then each context extension in order, then one
// object with the term IRI of each mapped claim, when any.
func LdpContext(r record.Record) []any {
	out := []any{VCDMContext}
	for _, c := range r.Contexts {
		out = append(out, c)
	}
	terms := map[string]any{}
	for _, m := range r.ClaimMappings {
		if m.IRI != "" {
			terms[m.Claim] = m.IRI
		}
	}
	if len(terms) > 0 {
		out = append(out, terms)
	}
	return out
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
		"display":           Display(r.Display),
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
		texts := typeLabels(r, c)
		if len(texts) == 0 {
			texts = []map[string]any{{"label": c.Title}}
		}
		e["display"] = texts
		claims = append(claims, e)
	}
	doc["claims"] = claims
	return doc
}

// typeLabels returns the display entries of one claim in the type
// metadata: the labels of the claim mapping, else the title of the
// property in each display locale.
func typeLabels(r record.Record, c Claim) []map[string]any {
	var out []map[string]any
	if m, ok := r.Mapping(c.Name); ok && len(m.Labels) > 0 {
		for _, l := range m.Labels {
			t := map[string]any{"lang": l.Locale, "label": l.Label}
			if l.Description != "" {
				t["description"] = l.Description
			}
			out = append(out, t)
		}
		return out
	}
	for _, d := range r.Display {
		t := map[string]any{"lang": d.Locale, "label": c.Title}
		if c.Description != "" {
			t["description"] = c.Description
		}
		out = append(out, t)
	}
	return out
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

// stringField returns one field as a string. A missing field, or a field
// of another type, gives an empty string.
func stringField(doc map[string]any, key string) string {
	value, ok := doc[key].(string)
	if !ok {
		return ""
	}
	return value
}

// MaxIRILength caps an IRI of a mapping.
const MaxIRILength = 2048

// Problem is one rule a mapping breaks. Field names the part of the
// mapping page that holds the value.
type Problem struct {
	Field string
	Text  string
}

// schemeRE matches the scheme of an IRI (RFC 3987 section 2.2).
var schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

// CheckIRI reports whether iri is an absolute IRI: a scheme, a colon,
// and a rest with no space and none of the characters an IRI excludes.
func CheckIRI(iri string) error {
	if iri == "" || len(iri) > MaxIRILength {
		return fmt.Errorf("metadata: an IRI has 1 to %d characters", MaxIRILength)
	}
	for _, c := range iri {
		if c <= ' ' || c == 0x7f || strings.ContainsRune("<>\"{}|\\^`", c) {
			return fmt.Errorf("metadata: the IRI %q holds the character %q", iri, c)
		}
	}
	i := strings.IndexByte(iri, ':')
	if i <= 0 || i == len(iri)-1 || !schemeRE.MatchString(iri[:i]) {
		return fmt.Errorf("metadata: the IRI %q has no scheme", iri)
	}
	return nil
}

// CheckContext reports whether iri is a context a JSON-LD processor can
// load: an absolute http or https IRI with a host.
func CheckContext(iri string) error {
	if err := CheckIRI(iri); err != nil {
		return err
	}
	u, err := url.Parse(iri)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("metadata: the context %q is not an http or https IRI with a host", iri)
	}
	return nil
}

// CheckMapping returns every rule the contexts and the claim mappings of
// r break: each context loads and appears once, after the VCDM 2.0
// context; each mapped claim is a property of the document and appears
// once; each term IRI is absolute; each label has a locale and a text,
// one per locale.
func CheckMapping(r record.Record) []Problem {
	var out []Problem
	seen := map[string]bool{}
	for _, c := range r.Contexts {
		switch {
		case c == VCDMContext:
			out = append(out, Problem{Field: "contexts", Text: msg.T("issuer.mapping.error.context_base")})
		case CheckContext(c) != nil:
			out = append(out, Problem{Field: "contexts", Text: msg.T("issuer.mapping.error.context", c)})
		case seen[c]:
			out = append(out, Problem{Field: "contexts", Text: msg.T("issuer.mapping.error.context_twice", c)})
		}
		seen[c] = true
	}
	properties := map[string]bool{}
	for _, c := range Claims(r) {
		properties[c.Name] = true
	}
	mapped := map[string]bool{}
	for _, m := range r.ClaimMappings {
		field := "claim." + m.Claim
		switch {
		case !properties[m.Claim]:
			out = append(out, Problem{Field: field, Text: msg.T("issuer.mapping.error.claim", m.Claim)})
			continue
		case mapped[m.Claim]:
			out = append(out, Problem{Field: field, Text: msg.T("issuer.mapping.error.claim_twice", m.Claim)})
			continue
		}
		mapped[m.Claim] = true
		if m.IRI != "" && CheckIRI(m.IRI) != nil {
			out = append(out, Problem{Field: field + ".iri", Text: msg.T("issuer.mapping.error.iri", m.Claim)})
		}
		if !labelsOK(m.Labels) {
			out = append(out, Problem{Field: field + ".labels", Text: msg.T("issuer.mapping.error.labels", m.Claim)})
		}
	}
	return out
}

// labelsOK reports whether every label has a locale and a text, and no
// locale appears twice.
func labelsOK(list []record.ClaimLabel) bool {
	seen := map[string]bool{}
	for _, l := range list {
		if strings.TrimSpace(l.Locale) == "" || strings.TrimSpace(l.Label) == "" || seen[l.Locale] {
			return false
		}
		seen[l.Locale] = true
	}
	return true
}
