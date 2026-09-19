// SPDX-License-Identifier: Apache-2.0

// Package preview renders what a citizen will see for a credential
// schema (ADR-014 decision 1). PreviewCredential is a pure function. It
// takes a schema and sample values and returns the three live view tabs:
// the sample credential JSON, the wallet card, and a PDF reference
// (ADR-014 decision 3). SampleData builds sample values from a schema.
// PDF renders the card as a small PDF document.
package preview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
)

// Format identifiers of OpenID for Verifiable Credential Issuance 1.0.
const (
	FormatDcSdJwt   = "dc+sd-jwt"
	FormatVcSdJwt   = "vc+sd-jwt"
	FormatJwtVcJSON = "jwt_vc_json"
	FormatLdpVc     = "ldp_vc"
	FormatMsoMdoc   = "mso_mdoc"
)

// Formats lists every format PreviewCredential can render.
var Formats = []string{FormatDcSdJwt, FormatVcSdJwt, FormatJwtVcJSON, FormatLdpVc, FormatMsoMdoc}

// DefaultIssuer is the issuer identifier of a preview when Options gives none.
const DefaultIssuer = "https://issuer.example"

// DefaultNow is the issue time of a preview when Options gives none.
var DefaultNow = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

// Validity is the validity period of a preview credential that expires.
const Validity = 365 * 24 * time.Hour

// MaxDepth bounds the nesting SampleData follows.
const MaxDepth = 8

// Display is the OID4VCI display metadata of one locale.
type Display struct {
	Name            string
	Description     string
	Locale          string
	LogoURI         string
	BackgroundColor string
	TextColor       string
}

// Schema is the part of a registry schema the preview reads.
type Schema struct {
	// Type is the VCDM type name or the SD-JWT VC vct.
	Type string
	// JSONSchema is the JSON Schema 2020-12 document.
	JSONSchema string
	// Display holds one entry per locale.
	Display []Display
	// SDClaims names the properties the holder can disclose one by one.
	SDClaims []string
	// Formats lists the wire formats the issuer offers. The first is the default.
	Formats []string
	// Expires marks a schema whose credentials carry a validity window.
	Expires bool
}

// Options select the format, the locale, and the fixed values of a preview.
type Options struct {
	// Format is one of Formats. Empty selects the first format of the schema.
	Format string
	// Locale selects the display entry. Empty selects the first entry.
	Locale string
	// Issuer is the issuer identifier. Empty means DefaultIssuer.
	Issuer string
	// Now is the issue time. Zero means DefaultNow.
	Now time.Time
	// SchemaURL is the credentialSchema id of a W3C preview. Empty omits it.
	SchemaURL string
}

// Row is one claim on the wallet card.
type Row struct {
	Label                  string
	Value                  string
	SelectivelyDisclosable bool
}

// Card is what a wallet shows for the credential.
type Card struct {
	Title           string
	Description     string
	LogoURI         string
	BackgroundColor string
	TextColor       string
	Rows            []Row
}

// Preview holds the three live view tabs.
type Preview struct {
	// Format is the format the preview used.
	Format string
	// CredentialJSON is the sample credential in the chosen format.
	CredentialJSON string
	// Card is the wallet card.
	Card Card
	// PDFRef identifies the PDF preview. It changes when the content changes.
	PDFRef string
	// Problems lists what the sample or the schema breaks.
	Problems []string
}

// PreviewCredential renders the preview of sample under schema s.
// It returns an error only when the schema document or the format is
// not usable. Sample problems go to Preview.Problems.
func PreviewCredential(s Schema, sample map[string]any, opts Options) (Preview, error) {
	parsed, err := jsonschema.Parse([]byte(s.JSONSchema))
	if err != nil {
		return Preview{}, err
	}
	format, err := pickFormat(s, opts.Format)
	if err != nil {
		return Preview{}, err
	}
	if opts.Issuer == "" {
		opts.Issuer = DefaultIssuer
	}
	if opts.Now.IsZero() {
		opts.Now = DefaultNow
	}
	if sample == nil {
		sample = map[string]any{}
	}
	p := Preview{Format: format}
	for _, problem := range parsed.Validate(sample) {
		p.Problems = append(p.Problems, problem.Error())
	}
	p.Problems = append(p.Problems, schemaProblems(s, parsed)...)
	p.Card = card(s, parsed, sample, opts.Locale)
	cred := credential(s, sample, format, opts)
	raw, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return Preview{}, fmt.Errorf("preview: encode credential: %w", err)
	}
	p.CredentialJSON = string(raw)
	sum := sha256.Sum256(append([]byte(format+"\n"), raw...))
	p.PDFRef = hex.EncodeToString(sum[:16])
	return p, nil
}

// pickFormat returns the format to render.
func pickFormat(s Schema, want string) (string, error) {
	if want == "" {
		if len(s.Formats) > 0 {
			want = s.Formats[0]
		} else {
			want = FormatDcSdJwt
		}
	}
	for _, f := range Formats {
		if f == want {
			return f, nil
		}
	}
	return "", fmt.Errorf("preview: the format %q is not supported", want)
}

// schemaProblems lists what the schema itself breaks.
func schemaProblems(s Schema, parsed jsonschema.Schema) []string {
	var out []string
	if strings.TrimSpace(s.Type) == "" {
		out = append(out, "the schema has no credential type")
	}
	if len(s.Display) == 0 {
		out = append(out, "the schema has no display metadata, the card shows the type")
	}
	for _, claim := range s.SDClaims {
		if _, ok := parsed.Property(claim); !ok {
			out = append(out, fmt.Sprintf("the selectively disclosable claim %s is not a property", claim))
		}
	}
	return out
}

// display returns the display entry of locale, or the first entry.
func display(s Schema, locale string) Display {
	for _, d := range s.Display {
		if locale != "" && d.Locale == locale {
			return d
		}
	}
	if len(s.Display) > 0 {
		return s.Display[0]
	}
	return Display{Name: s.Type}
}

// card builds the wallet card from the display entry and the sample.
func card(s Schema, parsed jsonschema.Schema, sample map[string]any, locale string) Card {
	d := display(s, locale)
	c := Card{Title: d.Name, Description: d.Description, LogoURI: d.LogoURI, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor}
	if c.Title == "" {
		c.Title = s.Type
	}
	sd := map[string]bool{}
	for _, claim := range s.SDClaims {
		sd[claim] = true
	}
	names := parsed.Properties()
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
	}
	var extra []string
	for name := range sample {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range append(names, extra...) {
		value, has := sample[name]
		if !has {
			continue
		}
		label := name
		if sub, ok := parsed.Property(name); ok {
			if t, ok := sub["title"].(string); ok && t != "" {
				label = t
			}
		}
		c.Rows = append(c.Rows, Row{Label: label, Value: Stringify(value), SelectivelyDisclosable: sd[name]})
	}
	return c
}

// Stringify renders a sample value as card text.
func Stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case bool:
		if x {
			return "yes"
		}
		return "no"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}

// credential builds the sample credential in the chosen format.
func credential(s Schema, sample map[string]any, format string, opts Options) map[string]any {
	claims := copyClaims(sample)
	issued := opts.Now.UTC()
	expires := issued.Add(Validity)
	switch format {
	case FormatMsoMdoc:
		return map[string]any{
			"docType":    s.Type,
			"namespaces": map[string]any{s.Type: claims},
			"validityInfo": map[string]any{
				"signed":     issued.Format(time.RFC3339),
				"validFrom":  issued.Format(time.RFC3339),
				"validUntil": validUntil(s, expires),
			},
		}
	case FormatJwtVcJSON, FormatLdpVc:
		vc := map[string]any{
			"@context":          []string{"https://www.w3.org/ns/credentials/v2"},
			"type":              []string{"VerifiableCredential", s.Type},
			"issuer":            opts.Issuer,
			"validFrom":         issued.Format(time.RFC3339),
			"credentialSubject": claims,
		}
		if s.Expires {
			vc["validUntil"] = expires.Format(time.RFC3339)
		}
		if opts.SchemaURL != "" {
			vc["credentialSchema"] = map[string]any{"id": opts.SchemaURL, "type": "JsonSchema"}
		}
		return vc
	}
	payload := map[string]any{"vct": s.Type, "iss": opts.Issuer, "iat": issued.Unix()}
	if s.Expires {
		payload["exp"] = expires.Unix()
	}
	for k, v := range claims {
		if _, taken := payload[k]; !taken {
			payload[k] = v
		}
	}
	if len(s.SDClaims) > 0 {
		payload["_sd_alg"] = "sha-256"
		payload["_sd_claims"] = append([]string(nil), s.SDClaims...)
	}
	return payload
}

func validUntil(s Schema, expires time.Time) any {
	if s.Expires {
		return expires.Format(time.RFC3339)
	}
	return nil
}

// copyClaims copies the sample so the credential does not share it.
func copyClaims(sample map[string]any) map[string]any {
	out := make(map[string]any, len(sample))
	for k, v := range sample {
		out[k] = v
	}
	return out
}

// SampleData builds sample values for every top level property of doc.
// It reads const, enum, examples, default, type, and format.
func SampleData(doc string) (map[string]any, error) {
	parsed, err := jsonschema.Parse([]byte(doc))
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, name := range parsed.Properties() {
		sub, ok := parsed.Property(name)
		if !ok {
			continue
		}
		out[name] = sampleValue(parsed, sub, name, 0)
	}
	return out, nil
}

// sampleValue builds one value for the sub schema of the property name.
func sampleValue(parsed jsonschema.Schema, sub map[string]any, name string, depth int) any {
	if depth > MaxDepth {
		return nil
	}
	if ref, ok := sub["$ref"].(string); ok {
		if target, err := parsed.Resolve(ref); err == nil {
			if obj, ok := target.(map[string]any); ok {
				return sampleValue(parsed, obj, name, depth+1)
			}
		}
	}
	if c, ok := sub["const"]; ok {
		return c
	}
	if e, ok := sub["enum"].([]any); ok && len(e) > 0 {
		return e[0]
	}
	if ex, ok := sub["examples"].([]any); ok && len(ex) > 0 {
		return ex[0]
	}
	if d, ok := sub["default"]; ok {
		return d
	}
	switch firstType(sub) {
	case "integer":
		if m, ok := sub["minimum"].(float64); ok {
			return m
		}
		return float64(1)
	case "number":
		if m, ok := sub["minimum"].(float64); ok {
			return m
		}
		return 1.5
	case "boolean":
		return true
	case "null":
		return nil
	case "array":
		items, ok := sub["items"].(map[string]any)
		if !ok {
			return []any{}
		}
		return []any{sampleValue(parsed, items, name, depth+1)}
	case "object":
		props := anyval.As[map[string]any](sub["properties"])
		obj := map[string]any{}
		for _, key := range sortedKeys(props) {
			if child, ok := props[key].(map[string]any); ok {
				obj[key] = sampleValue(parsed, child, key, depth+1)
			}
		}
		return obj
	}
	return sampleString(sub, name)
}

// sampleString builds a string that meets format and minLength.
func sampleString(sub map[string]any, name string) string {
	switch sub["format"] {
	case "date":
		return "1990-01-31"
	case "date-time":
		return "2024-01-31T10:00:00Z"
	case "email":
		return "citizen@example.org"
	case "uri":
		return "https://example.org/" + name
	}
	text := "Sample " + name
	if t, ok := sub["title"].(string); ok && t != "" {
		text = "Sample " + t
	}
	if m, ok := sub["minLength"].(float64); ok {
		for len([]rune(text)) < int(m) {
			text += "x"
		}
	}
	if m, ok := sub["maxLength"].(float64); ok && len([]rune(text)) > int(m) {
		text = string([]rune(text)[:int(m)])
	}
	return text
}

// firstType returns the first type name of sub.
func firstType(sub map[string]any) string {
	switch t := sub["type"].(type) {
	case string:
		return t
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "null" {
				return s
			}
		}
	}
	return "string"
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
