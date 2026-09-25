// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"encoding/json"
	"html/template"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/render"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// claimPrefix starts the name of every claim input, so a posted form
// keeps the claims apart from the other fields of the wizard.
const claimPrefix = "claim."

// maxDepth bounds the nesting of objects the form draws.
const maxDepth = 4

// The kinds of a claim field.
const (
	kindText    = "text"
	kindInteger = "integer"
	kindNumber  = "number"
	kindBoolean = "boolean"
	kindEnum    = "enum"
	kindList    = "list"
	kindObject  = "object"
)

// claimField is one input of the claim form, built from one property of
// the JSON Schema of the version (JSON Schema 2020-12 through
// core/jsonschema).
type claimField struct {
	// name is the input name: the claim prefix and the property path
	// joined with dots.
	name string
	// id is the element id, unique in the form.
	id string
	// pointer is the JSON Pointer of the value in the claims.
	pointer string
	// key is the property name in its parent object.
	key      string
	label    string
	hint     string
	required bool
	kind     string
	// format is the JSON Schema format of a text or of a list item.
	format string
	// item is the kind of the entries of a list.
	item     string
	enum     []any
	attrs    map[string]string
	children []claimField
}

// claimForm is the form of one schema version.
type claimForm struct {
	fields []claimField
}

// idChars matches the characters an element id cannot hold.
var idChars = regexp.MustCompile(`[^A-Za-z0-9_]`)

// newClaimForm builds the form of a schema version. A version without a
// JSON Schema gives an empty form.
func newClaimForm(s *schemav1.Schema) (claimForm, error) {
	raw := strings.TrimSpace(s.GetJsonSchema())
	if raw == "" {
		return claimForm{}, nil
	}
	parsed, err := jsonschema.Parse([]byte(raw))
	if err != nil {
		return claimForm{}, err
	}
	b := formBuilder{schema: parsed, labels: mappingLabels(s), orders: propertyOrders([]byte(raw)), ids: map[string]bool{}}
	root := anyval.As[map[string]any](parsed.Root())
	return claimForm{fields: b.object(root, nil, "/properties", 0)}, nil
}

// mappingLabels returns the English label of each top level claim from
// the claim mapping of the version (P3-05).
func mappingLabels(s *schemav1.Schema) map[string]string {
	out := map[string]string{}
	for _, m := range s.GetClaimMappings() {
		for _, l := range m.GetLabels() {
			if l.GetLabel() != "" && (l.GetLocale() == "" || strings.HasPrefix(l.GetLocale(), "en")) {
				out[m.GetClaim()] = l.GetLabel()
				break
			}
		}
	}
	return out
}

// formBuilder walks the schema once.
type formBuilder struct {
	schema jsonschema.Schema
	labels map[string]string
	orders map[string][]string
	ids    map[string]bool
}

// object returns the fields of the properties of one object schema, in
// document order. at is the location of its properties keyword in the
// document, which names its key order.
func (b *formBuilder) object(obj map[string]any, path []string, at string, depth int) []claimField {
	props := anyval.As[map[string]any](obj["properties"])
	required := map[string]bool{}
	for _, r := range anyval.As[[]any](obj["required"]) {
		if name, ok := r.(string); ok {
			required[name] = true
		}
	}
	var out []claimField
	for _, key := range ordered(props, b.orders[at]) {
		sub, subAt := b.resolve(props[key], at+"/"+escapePointer(key))
		out = append(out, b.field(sub, append(append([]string(nil), path...), key), subAt, required[key], depth))
	}
	return out
}

// resolve follows a local $ref. It returns the schema and the location
// of its properties keyword.
func (b *formBuilder) resolve(v any, at string) (map[string]any, string) {
	sub := anyval.As[map[string]any](v)
	for i := 0; i < jsonschema.MaxRefDepth; i++ {
		ref, ok := sub["$ref"].(string)
		if !ok {
			break
		}
		target, err := b.schema.Resolve(ref)
		if err != nil {
			break
		}
		sub, at = anyval.As[map[string]any](target), strings.TrimPrefix(ref, "#")
	}
	return sub, at + "/properties"
}

// field builds one input from one property.
func (b *formBuilder) field(sub map[string]any, path []string, at string, required bool, depth int) claimField {
	key := path[len(path)-1]
	f := claimField{
		name: claimPrefix + strings.Join(path, "."), id: b.id(path), key: key, required: required,
		pointer: pointerOf(path), label: b.label(sub, path), attrs: map[string]string{},
	}
	desc := stringOf(sub["description"])
	types := typeNames(sub["type"])
	enum, hasEnum := sub["enum"].([]any)
	switch {
	case hasEnum && len(enum) > 0:
		f.kind, f.enum = kindEnum, enum
	case types["object"] && depth < maxDepth:
		f.kind = kindObject
		f.children = b.object(sub, path, at, depth+1)
	case types["array"]:
		f.kind = kindList
		items := anyval.As[map[string]any](sub["items"])
		f.item, f.format = scalarKind(typeNames(items["type"])), stringOf(items["format"])
		desc = joinSentences(desc, msg.T("issuer.issue.hint.list"))
	case types["boolean"]:
		f.kind = kindBoolean
	case types["integer"]:
		f.kind = kindInteger
		f.attrs["inputmode"], f.attrs["step"] = "numeric", "1"
		desc = joinSentences(desc, numberHint(sub, "issuer.issue.hint.integer"))
	case types["number"]:
		f.kind = kindNumber
		f.attrs["inputmode"], f.attrs["step"] = "decimal", "any"
		desc = joinSentences(desc, numberHint(sub, "issuer.issue.hint.number"))
	default:
		f.kind, f.format = kindText, stringOf(sub["format"])
		if f.format == "date-time" {
			desc = joinSentences(desc, msg.T("issuer.issue.hint.date_time"))
		}
	}
	for _, k := range []string{"minimum", "maximum", "minLength", "maxLength"} {
		if n, ok := sub[k].(float64); ok {
			f.attrs[map[string]string{"minimum": "min", "maximum": "max", "minLength": "minlength", "maxLength": "maxlength"}[k]] = strconv.FormatFloat(n, 'f', -1, 64)
		}
	}
	f.hint = desc
	return f
}

// label names a field: the claim mapping, then the title, then the
// property name in words.
func (b *formBuilder) label(sub map[string]any, path []string) string {
	if len(path) == 1 {
		if l := b.labels[path[0]]; l != "" {
			return l
		}
	}
	if t, ok := sub["title"].(string); ok && strings.TrimSpace(t) != "" {
		return strings.TrimSpace(t)
	}
	return sentenceCase(render.Humanise(path[len(path)-1]))
}

// sentenceCase keeps the capital of the first word and of an acronym,
// and lowers the capital of every other word: "Date Of Birth" becomes
// "Date of birth", "Farmer ID" stays.
func sentenceCase(words string) string {
	parts := strings.Fields(words)
	for i := 1; i < len(parts); i++ {
		w := parts[i]
		if len(w) > 1 && strings.ToUpper(w[:1]) == w[:1] && strings.ToLower(w[1:]) == w[1:] {
			parts[i] = strings.ToLower(w[:1]) + w[1:]
		}
	}
	return strings.Join(parts, " ")
}

// id returns a unique element id for a property path.
func (b *formBuilder) id(path []string) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		parts = append(parts, idChars.ReplaceAllString(p, "_"))
	}
	base := "claim-" + strings.Join(parts, "-")
	id := base
	for n := 2; b.ids[id]; n++ {
		id = base + "-" + strconv.Itoa(n)
	}
	b.ids[id] = true
	return id
}

// numberHint names the range of a number field.
func numberHint(sub map[string]any, key string) string {
	lo, hasLo := sub["minimum"].(float64)
	hi, hasHi := sub["maximum"].(float64)
	text := func(n float64) string { return strconv.FormatFloat(n, 'f', -1, 64) }
	switch {
	case hasLo && hasHi:
		return msg.T(key+".between", text(lo), text(hi))
	case hasLo:
		return msg.T(key+".min", text(lo))
	case hasHi:
		return msg.T(key+".max", text(hi))
	}
	return msg.T(key)
}

// joinSentences joins two hints.
func joinSentences(a, b string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " " + b
}

// typeNames returns the type keyword as a set.
func typeNames(t any) map[string]bool {
	out := map[string]bool{}
	switch x := t.(type) {
	case string:
		out[x] = true
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// scalarKind is the kind of a list entry.
func scalarKind(types map[string]bool) string {
	switch {
	case types["integer"]:
		return kindInteger
	case types["number"]:
		return kindNumber
	case types["boolean"]:
		return kindBoolean
	}
	return kindText
}

func stringOf(v any) string { return anyval.As[string](v) }

// ordered returns the keys of props in the document order, then any
// key the order misses, sorted.
func ordered(props map[string]any, order []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range order {
		if _, ok := props[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range props {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// escapePointer encodes one JSON Pointer token (RFC 6901).
func escapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// pointerOf returns the JSON Pointer of a property path.
func pointerOf(path []string) string {
	var b strings.Builder
	for _, p := range path {
		b.WriteString("/" + escapePointer(p))
	}
	return b.String()
}

// propertyOrders reads the key order of every properties object of a
// JSON document, keyed by the JSON Pointer of that object. The decoded
// map of core/jsonschema keeps no order below the top level.
func propertyOrders(doc []byte) map[string][]string {
	out := map[string][]string{}
	dec := json.NewDecoder(strings.NewReader(string(doc)))
	var walk func(at string) bool
	walk = func(at string) bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			isProps := strings.HasSuffix(at, "/properties")
			for dec.More() {
				kt, kerr := dec.Token()
				if kerr != nil {
					return false
				}
				k := anyval.As[string](kt)
				if isProps {
					out[at] = append(out[at], k)
				}
				if !walk(at + "/" + escapePointer(k)) {
					return false
				}
			}
		case '[':
			for i := 0; dec.More(); i++ {
				if !walk(at + "/" + strconv.Itoa(i)) {
					return false
				}
			}
		}
		_, err = dec.Token()
		return err == nil
	}
	walk("")
	return out
}

// formValues is a posted claim form: the claims with their JSON types,
// the error of each field, and the errors no field shows.
type formValues struct {
	claims map[string]any
	errs   map[string]string
	other  []string
}

// ok reports whether the form passed.
func (v formValues) ok() bool { return len(v.errs) == 0 && len(v.other) == 0 }

// read reads the claims from a posted form and checks them against the
// schema. The page checks here, before the stack sees the claims, so an
// error names its field (WCAG 3.3.1).
func (c claimForm) read(form url.Values, s *schemav1.Schema) formValues {
	v := formValues{claims: map[string]any{}, errs: map[string]string{}}
	for _, f := range c.fields {
		if val, ok := f.value(form, v.errs); ok {
			v.claims[f.key] = val
		}
	}
	parsed, err := jsonschema.Parse([]byte(s.GetJsonSchema()))
	if err != nil {
		return v
	}
	byPointer := map[string]claimField{}
	walkFields(c.fields, func(f claimField) { byPointer[f.pointer] = f })
	for _, p := range parsed.Validate(v.claims) {
		f, ok := byPointer[p.Path]
		switch {
		case !ok:
			v.other = append(v.other, msg.T("issuer.issue.error.rule", p.Error()))
		case v.errs[f.id] == "":
			v.errs[f.id] = problemText(p, f)
		}
	}
	return v
}

// walkFields calls fn on every field, depth first.
func walkFields(fields []claimField, fn func(claimField)) {
	for _, f := range fields {
		fn(f)
		walkFields(f.children, fn)
	}
}

// problemText is the sentence of one broken rule.
func problemText(p jsonschema.Problem, f claimField) string {
	switch p.Keyword {
	case "required":
		return msg.T("issuer.issue.error.required")
	case "enum", "const":
		return msg.T("issuer.issue.error.enum")
	case "format":
		key := "issuer.issue.error.format." + strings.ReplaceAll(f.format, "-", "_")
		if _, ok := msg.Lookup(key); ok {
			return msg.T(key)
		}
	}
	return msg.T("issuer.issue.error.rule", p.Message)
}

// value reads one field. It returns false when the form leaves the
// field empty. A value it cannot read sets the error of the field.
func (f claimField) value(form url.Values, errs map[string]string) (any, bool) {
	if f.kind == kindObject {
		obj := map[string]any{}
		for _, c := range f.children {
			if val, ok := c.value(form, errs); ok {
				obj[c.key] = val
			}
		}
		if len(obj) == 0 && !f.required {
			return nil, false
		}
		return obj, true
	}
	raw := strings.TrimSpace(form.Get(f.name))
	if raw == "" {
		return nil, false
	}
	if f.kind == kindList {
		var list []any
		for _, line := range strings.Split(raw, "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			item, err := scalar(f.item, f.format, line)
			if err != "" {
				errs[f.id] = err
				return nil, false
			}
			list = append(list, item)
		}
		return list, true
	}
	if f.kind == kindEnum {
		for _, e := range f.enum {
			if enumText(e) == raw {
				return e, true
			}
		}
		errs[f.id] = msg.T("issuer.issue.error.enum")
		return nil, false
	}
	val, err := scalar(f.kind, f.format, raw)
	if err != "" {
		errs[f.id] = err
		return nil, false
	}
	return val, true
}

// scalar converts the text of one value to its JSON type. It returns
// the error sentence when the text does not fit.
func scalar(kind, format, raw string) (any, string) {
	switch kind {
	case kindInteger:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, msg.T("issuer.issue.error.integer")
		}
		return n, ""
	case kindNumber:
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, msg.T("issuer.issue.error.number")
		}
		return n, ""
	case kindBoolean:
		switch raw {
		case "true":
			return true, ""
		case "false":
			return false, ""
		}
		return nil, msg.T("issuer.issue.error.boolean")
	}
	if format == "date-time" {
		// A datetime-local input sends no zone and maybe no seconds. The
		// page reads the time as UTC.
		for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC().Format(time.RFC3339), ""
			}
		}
	}
	return raw, ""
}

// enumText is the text of one value of an enum.
func enumText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// html renders the fields as kit components.
func (c claimForm) html(b *blocks, form url.Values, errs map[string]string) template.HTML {
	parts := make([]template.HTML, 0, len(c.fields))
	for _, f := range c.fields {
		parts = append(parts, f.html(b, form, errs))
	}
	return components.Join(parts...)
}

// html renders one field, or one fieldset for an object.
func (f claimField) html(b *blocks, form url.Values, errs map[string]string) template.HTML {
	if f.kind == kindObject {
		inner := make([]template.HTML, 0, len(f.children))
		for _, c := range f.children {
			inner = append(inner, c.html(b, form, errs))
		}
		return b.add("fieldset", components.Fieldset{ID: f.id, Legend: f.label, Hint: f.hint, Body: components.Join(inner...)})
	}
	field := components.Field{
		ID: f.id, Name: f.name, Label: f.label, Hint: f.hint, Error: errs[f.id], Required: f.required,
		Value: form.Get(f.name), Attrs: f.attrs, Type: inputType(f),
	}
	switch f.kind {
	case kindEnum:
		field.Options = []components.Option{{Value: "", Text: msg.T("issuer.issue.select.label")}}
		for _, e := range f.enum {
			t := enumText(e)
			field.Options = append(field.Options, components.Option{Value: t, Text: t, Selected: t == field.Value})
		}
	case kindBoolean:
		field.Options = []components.Option{
			{Value: "", Text: msg.T("issuer.issue.select.label")},
			{Value: "true", Text: msg.T("issuer.issue.yes.label"), Selected: field.Value == "true"},
			{Value: "false", Text: msg.T("issuer.issue.no.label"), Selected: field.Value == "false"},
		}
	}
	return b.add("field", field)
}

// inputType is the input type of a field.
func inputType(f claimField) string {
	switch f.kind {
	case kindEnum, kindBoolean:
		return "select"
	case kindList:
		return "textarea"
	case kindInteger, kindNumber:
		return "number"
	}
	switch f.format {
	case "date":
		return "date"
	case "date-time":
		return "datetime-local"
	case "email":
		return "email"
	case "uri":
		return "url"
	}
	return "text"
}

// hidden carries the claims of a posted form to the next step.
func (c claimForm) hidden(form url.Values) template.HTML {
	var b strings.Builder
	walkFields(c.fields, func(f claimField) {
		if f.kind == kindObject {
			return
		}
		b.WriteString(hiddenInput(f.name, form.Get(f.name)))
	})
	return template.HTML(b.String()) //nolint:gosec // every name and value is escaped
}

// hiddenInput returns one escaped hidden input.
func hiddenInput(name, value string) string {
	return `<input type="hidden" name="` + template.HTMLEscapeString(name) + `" value="` + template.HTMLEscapeString(value) + `">`
}

// rows returns the review rows of the claims: the label path and the
// value as the holder gets it.
func (c claimForm) rows(claims map[string]any) []components.Row {
	var out []components.Row
	var walk func(fields []claimField, values map[string]any, prefix string)
	walk = func(fields []claimField, values map[string]any, prefix string) {
		for _, f := range fields {
			val, ok := values[f.key]
			if !ok {
				continue
			}
			label := f.label
			if prefix != "" {
				label = msg.T("issuer.issue.review.nested.label", prefix, f.label)
			}
			if f.kind == kindObject {
				walk(f.children, anyval.As[map[string]any](val), label)
				continue
			}
			out = append(out, components.Row{{Text: label}, {Text: reviewText(val)}})
		}
	}
	walk(c.fields, claims, "")
	return out
}

// reviewText is the text of one claim value on the review.
func reviewText(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return msg.T("issuer.issue.yes.label")
		}
		return msg.T("issuer.issue.no.label")
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, enumText(e))
		}
		return strings.Join(parts, ", ")
	}
	return enumText(v)
}

// errorRows returns the rows of the error summary: a link to each field
// with an error, in form order, then the errors no field shows.
func (c claimForm) errorRows(v formValues) []components.Row {
	var out []components.Row
	walkFields(c.fields, func(f claimField) {
		if e := v.errs[f.id]; e != "" {
			out = append(out, components.Row{{HTML: link("#"+f.id, f.label)}, {Text: e}})
		}
	})
	for _, e := range v.other {
		out = append(out, components.Row{{Text: msg.T("issuer.issue.errors.form.label")}, {Text: e}})
	}
	return out
}
