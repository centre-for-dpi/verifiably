// SPDX-License-Identifier: Apache-2.0

// Package draft holds the pure builder model of the schema builder
// (ADR-014 decision 2). A Draft is the editor state of one schema. Field
// types, required flags, enums, formats, and selective disclosure flags
// are first class members of a Field.
//
// Every function here is pure. Document builds a JSON Schema 2020-12
// document in field order. Parse reads a form. FromDocument imports an
// existing JSON Schema document.
package draft

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/core/preview"
)

// Dialect is the JSON Schema dialect the builder writes.
const Dialect = "https://json-schema.org/draft/2020-12/schema"

// MaxFields caps the number of fields one draft can carry.
const MaxFields = 100

// MaxEnumValues caps the number of values one enum can carry.
const MaxEnumValues = 50

// FieldTypes lists the value types the builder offers.
var FieldTypes = []string{"string", "number", "integer", "boolean"}

// FieldFormats lists the string formats the builder offers. The empty
// string means no format.
var FieldFormats = []string{"", "date", "date-time", "email", "uri"}

// Formats lists the wire formats the builder offers, in OID4VCI spelling.
var Formats = []string{preview.FormatDcSdJwt, preview.FormatVcSdJwt, preview.FormatJwtVcJSON, preview.FormatLdpVc, preview.FormatMsoMdoc}

// name is the property name rule. A property name starts with a letter.
var name = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// Field is one claim of the credential.
type Field struct {
	// Name is the JSON property name.
	Name string
	// Label is the human readable title of the property.
	Label string
	// Description is the one sentence help of the property.
	Description string
	// Type is one of FieldTypes.
	Type string
	// Format is one of FieldFormats. It applies to a string only.
	Format string
	// Enum lists the allowed values. An empty list allows any value.
	Enum []string
	// Required marks a property the credential must carry.
	Required bool
	// SelectivelyDisclosable marks a claim the holder can hide.
	SelectivelyDisclosable bool
}

// Draft is the whole editor state of one schema.
type Draft struct {
	// ID is the schema id. It is empty for a schema the registry never saw.
	ID string
	// Type is the credential type, which is the SD-JWT VC vct.
	Type string
	// Title is the display name of the credential.
	Title string
	// Description is the one sentence description of the credential.
	Description string
	// Locale is the BCP 47 tag of the display entry.
	Locale string
	// LogoURI is the logo of the wallet card.
	LogoURI string
	// BackgroundColor is the card background as a CSS hex value.
	BackgroundColor string
	// TextColor is the card text colour as a CSS hex value.
	TextColor string
	// Wire lists the wire formats the issuer offers. The first is the default.
	Wire []string
	// Expires marks a credential that carries a validity window.
	Expires bool
	// Fields lists the claims in display order.
	Fields []Field
}

// Empty returns the draft a new builder page starts from.
func Empty() Draft {
	return Draft{
		Type:  "ExampleCredential",
		Title: "Example credential",
		Wire:  []string{preview.FormatDcSdJwt},
		Fields: []Field{
			{Name: "given_name", Label: "Given name", Type: "string", Required: true, SelectivelyDisclosable: true},
		},
	}
}

// Normalize fills the defaults and drops the empty fields. It never fails.
func (d Draft) Normalize() Draft {
	d.ID = strings.TrimSpace(d.ID)
	d.Type = strings.TrimSpace(d.Type)
	d.Title = strings.TrimSpace(d.Title)
	d.Description = strings.TrimSpace(d.Description)
	d.Locale = strings.TrimSpace(d.Locale)
	if d.Locale == "" {
		d.Locale = "en"
	}
	if d.Title == "" {
		d.Title = d.Type
	}
	d.Wire = keepKnown(d.Wire, Formats)
	if len(d.Wire) == 0 {
		d.Wire = []string{preview.FormatDcSdJwt}
	}
	fields := make([]Field, 0, len(d.Fields))
	for _, f := range d.Fields {
		f.Name = strings.TrimSpace(f.Name)
		if f.Name == "" {
			continue
		}
		f.Label = strings.TrimSpace(f.Label)
		if f.Label == "" {
			f.Label = f.Name
		}
		f.Description = strings.TrimSpace(f.Description)
		if !contains(FieldTypes, f.Type) {
			f.Type = "string"
		}
		if f.Type != "string" || !contains(FieldFormats, f.Format) {
			f.Format = ""
		}
		f.Enum = trimAll(f.Enum)
		if len(f.Enum) > MaxEnumValues {
			f.Enum = f.Enum[:MaxEnumValues]
		}
		fields = append(fields, f)
		if len(fields) == MaxFields {
			break
		}
	}
	d.Fields = fields
	return d
}

// Problems lists what stops the draft from becoming a schema version.
// The sentences are for the author, in Simplified Technical English.
func (d Draft) Problems() []string {
	var out []string
	if d.Type == "" {
		out = append(out, "The credential type is empty. Give the credential a type.")
	}
	if len(d.Fields) == 0 {
		out = append(out, "The schema has no field. Add at least one field.")
	}
	seen := map[string]bool{}
	for _, f := range d.Fields {
		if !name.MatchString(f.Name) {
			out = append(out, fmt.Sprintf("The field name %q is not valid. Start with a letter and use letters, digits, and underscores.", f.Name))
			continue
		}
		if seen[f.Name] {
			out = append(out, fmt.Sprintf("The field name %q is used twice. Every field name is unique.", f.Name))
		}
		seen[f.Name] = true
	}
	return out
}

// Required returns the names of the required fields in field order.
func (d Draft) Required() []string {
	var out []string
	for _, f := range d.Fields {
		if f.Required {
			out = append(out, f.Name)
		}
	}
	return out
}

// SDClaims returns the names of the selectively disclosable fields.
func (d Draft) SDClaims() []string {
	var out []string
	for _, f := range d.Fields {
		if f.SelectivelyDisclosable {
			out = append(out, f.Name)
		}
	}
	return out
}

// Document builds the JSON Schema 2020-12 document of the draft. The
// properties keep the field order, so the preview and the pages show the
// claims the way the author sorted them.
func (d Draft) Document() string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(`  "$schema": ` + quote(Dialect) + ",\n")
	b.WriteString(`  "title": ` + quote(d.Title) + ",\n")
	if d.Description != "" {
		b.WriteString(`  "description": ` + quote(d.Description) + ",\n")
	}
	b.WriteString("  \"type\": \"object\",\n")
	b.WriteString("  \"properties\": {\n")
	for i, f := range d.Fields {
		b.WriteString("    " + quote(f.Name) + ": " + f.document())
		if i < len(d.Fields)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  },\n")
	required := make([]string, 0, len(d.Fields))
	for _, n := range d.Required() {
		required = append(required, quote(n))
	}
	b.WriteString("  \"required\": [" + strings.Join(required, ", ") + "],\n")
	b.WriteString("  \"additionalProperties\": false\n")
	b.WriteString("}")
	return b.String()
}

// document builds the sub schema of one field on one line.
func (f Field) document() string {
	parts := []string{`"type": ` + quote(f.Type), `"title": ` + quote(f.Label)}
	if f.Description != "" {
		parts = append(parts, `"description": `+quote(f.Description))
	}
	if f.Format != "" {
		parts = append(parts, `"format": `+quote(f.Format))
	}
	if len(f.Enum) > 0 {
		values := make([]string, 0, len(f.Enum))
		for _, v := range f.Enum {
			values = append(values, f.literal(v))
		}
		parts = append(parts, `"enum": [`+strings.Join(values, ", ")+`]`)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// literal renders one enum entry as a JSON value of the field type. A
// value that does not convert stays a JSON string.
func (f Field) literal(v string) string {
	switch f.Type {
	case "number":
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return strconv.FormatFloat(n, 'g', -1, 64)
		}
	case "integer":
		if n, err := strconv.Atoi(v); err == nil {
			return strconv.Itoa(n)
		}
	case "boolean":
		if b, err := strconv.ParseBool(v); err == nil {
			return strconv.FormatBool(b)
		}
	}
	return quote(v)
}

// PreviewSchema returns the preview input of the draft.
func (d Draft) PreviewSchema() preview.Schema {
	return preview.Schema{
		Type:       d.Type,
		JSONSchema: d.Document(),
		Display: []preview.Display{{
			Name: d.Title, Description: d.Description, Locale: d.Locale,
			LogoURI: d.LogoURI, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
		}},
		SDClaims: d.SDClaims(),
		Formats:  append([]string(nil), d.Wire...),
		Expires:  d.Expires,
	}
}

// Parse reads a builder form. The form carries one indexed group per
// field: field.<n>.name, .label, .description, .type, .format, .enum,
// .required, and .sd. Parse never fails. Use Problems to check the result.
func Parse(values url.Values) Draft {
	d := Draft{
		ID:              values.Get("id"),
		Type:            values.Get("type"),
		Title:           values.Get("title"),
		Description:     values.Get("description"),
		Locale:          values.Get("locale"),
		LogoURI:         values.Get("logo_uri"),
		BackgroundColor: values.Get("background_color"),
		TextColor:       values.Get("text_color"),
		Wire:            values["wire"],
		Expires:         checked(values.Get("expires")),
	}
	for _, i := range indexes(values) {
		p := "field." + strconv.Itoa(i) + "."
		d.Fields = append(d.Fields, Field{
			Name:                   values.Get(p + "name"),
			Label:                  values.Get(p + "label"),
			Description:            values.Get(p + "description"),
			Type:                   values.Get(p + "type"),
			Format:                 values.Get(p + "format"),
			Enum:                   splitEnum(values.Get(p + "enum")),
			Required:               checked(values.Get(p + "required")),
			SelectivelyDisclosable: checked(values.Get(p + "sd")),
		})
	}
	return d.Normalize()
}

// indexes returns the field indexes the form carries, in ascending order.
func indexes(values url.Values) []int {
	seen := map[int]bool{}
	for key := range values {
		rest, ok := strings.CutPrefix(key, "field.")
		if !ok {
			continue
		}
		head, _, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(head)
		if err != nil || n < 0 {
			continue
		}
		seen[n] = true
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// checked reports whether a checkbox value means on.
func checked(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}

// splitEnum cuts a comma separated enum list.
func splitEnum(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return trimAll(strings.Split(v, ","))
}

// EnumText joins an enum list back into the form value.
func EnumText(list []string) string { return strings.Join(list, ", ") }

// FromDocument imports an existing JSON Schema 2020-12 document
// (ADR-014 decision 6). It returns the draft and the parts it could not
// map. An unusable document returns an error.
func FromDocument(doc string) (Draft, []string, error) {
	parsed, err := jsonschema.Parse([]byte(doc))
	if err != nil {
		return Draft{}, nil, err
	}
	root, ok := parsed.Root().(map[string]any)
	if !ok {
		return Draft{}, nil, fmt.Errorf("draft: the document is not an object")
	}
	d := Draft{
		Title:       text(root, "title"),
		Description: text(root, "description"),
		Wire:        []string{preview.FormatDcSdJwt},
	}
	var warnings []string
	required := map[string]bool{}
	for _, n := range parsed.Required() {
		required[n] = true
	}
	for _, n := range parsed.Properties() {
		sub, ok := parsed.Property(n)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("The property %q is not an object schema. The draft drops it.", n))
			continue
		}
		f, skipped := field(n, sub, required[n])
		warnings = append(warnings, skipped...)
		d.Fields = append(d.Fields, f)
	}
	if len(d.Fields) == 0 {
		warnings = append(warnings, "The document declares no property. The draft has no field.")
	}
	return d.Normalize(), warnings, nil
}

// field maps one property sub schema to a Field.
func field(n string, sub map[string]any, required bool) (Field, []string) {
	f := Field{Name: n, Label: text(sub, "title"), Description: text(sub, "description"), Required: required}
	var warnings []string
	typ := text(sub, "type")
	if typ == "" {
		typ = "string"
	}
	if !contains(FieldTypes, typ) {
		warnings = append(warnings, fmt.Sprintf("The property %q has the type %q, which the builder does not offer. The draft uses a string.", n, typ))
		typ = "string"
	}
	f.Type = typ
	if format := text(sub, "format"); format != "" {
		if contains(FieldFormats, format) && typ == "string" {
			f.Format = format
		} else {
			warnings = append(warnings, fmt.Sprintf("The property %q has the format %q, which the builder does not offer.", n, format))
		}
	}
	if list, ok := sub["enum"].([]any); ok {
		for _, v := range list {
			f.Enum = append(f.Enum, preview.Stringify(v))
		}
	}
	for _, key := range []string{"pattern", "minLength", "maxLength", "minimum", "maximum", "items", "$ref"} {
		if _, has := sub[key]; has {
			warnings = append(warnings, fmt.Sprintf("The property %q uses %s. The builder does not keep it.", n, key))
		}
	}
	return f, warnings
}

// FromCatalog builds a draft from a DPG catalogue entry (ADR-014
// decision 6). typ overrides the credential type when it is not empty.
func FromCatalog(typ, document, display string, sdClaims []string, wire string) (Draft, []string, error) {
	d, warnings, err := FromDocument(document)
	if err != nil {
		return Draft{}, nil, err
	}
	d.Type = strings.TrimSpace(typ)
	if display != "" {
		var entries []preview.Display
		if err := json.Unmarshal([]byte(display), &entries); err != nil || len(entries) == 0 {
			warnings = append(warnings, "The display metadata of the catalogue entry did not parse. The draft keeps the schema title.")
		} else {
			e := entries[0]
			d.Title, d.Description, d.Locale = e.Name, e.Description, e.Locale
			d.LogoURI, d.BackgroundColor, d.TextColor = e.LogoURI, e.BackgroundColor, e.TextColor
		}
	}
	sd := map[string]bool{}
	for _, n := range sdClaims {
		sd[n] = true
	}
	for i := range d.Fields {
		d.Fields[i].SelectivelyDisclosable = sd[d.Fields[i].Name]
	}
	if contains(Formats, wire) {
		d.Wire = []string{wire}
	}
	return d.Normalize(), warnings, nil
}

func text(obj map[string]any, key string) string {
	if s, ok := obj[key].(string); ok {
		return s
	}
	return ""
}

// quote renders s as a JSON string, with the escapes RFC 8259 needs.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func trimAll(list []string) []string {
	var out []string
	for _, v := range list {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func keepKnown(list, known []string) []string {
	var out []string
	for _, v := range list {
		if contains(known, v) && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
