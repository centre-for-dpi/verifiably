// SPDX-License-Identifier: Apache-2.0

// Package jsonschema validates JSON values against the subset of JSON
// Schema 2020-12 that credential schemas use (ADR-013 decision 1).
//
// Supported keywords: type, properties, required, enum, const, format
// (date, date-time, email, uri), minLength, maxLength, minimum, maximum,
// pattern, items, additionalProperties, and $ref to a location inside
// the same document. Every other keyword is ignored.
//
// The package has no side effects. Parse reads a document once. Validate
// walks an instance and returns one Problem per broken rule. The path of
// a Problem is a JSON Pointer (RFC 6901) into the instance.
package jsonschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// MaxRefDepth bounds the number of nested $ref hops.
const MaxRefDepth = 32

// Formats lists the format values Validate checks.
var Formats = []string{"date", "date-time", "email", "uri"}

// Types lists the type names of JSON Schema.
var Types = []string{"string", "number", "integer", "boolean", "object", "array", "null"}

// Schema is a parsed document.
type Schema struct {
	root any
	// props holds the top level property names in document order.
	props []string
}

// Problem is one broken rule.
type Problem struct {
	// Path is the JSON Pointer of the value in the instance. "" is the root.
	Path string
	// Keyword is the schema keyword that failed, for example "required".
	Keyword string
	// Message says what is wrong in Simplified Technical English.
	Message string
}

// Error formats the problem as "<path>: <message>".
func (p Problem) Error() string {
	path := p.Path
	if path == "" {
		path = "/"
	}
	return path + ": " + p.Message
}

// Parse reads a JSON Schema document. The root must be a JSON object or
// a boolean. Parse also checks that every keyword it knows has the right
// shape, so Validate never meets a bad schema.
func Parse(doc []byte) (Schema, error) {
	var root any
	dec := json.NewDecoder(strings.NewReader(string(doc)))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return Schema{}, fmt.Errorf("jsonschema: parse: %w", err)
	}
	if dec.More() {
		return Schema{}, errors.New("jsonschema: parse: trailing data after the document")
	}
	root = plainNumbers(root)
	switch root.(type) {
	case map[string]any, bool:
	default:
		return Schema{}, errors.New("jsonschema: the root must be an object or a boolean")
	}
	s := Schema{root: root}
	if err := checkSchema(root, "", 0); err != nil {
		return Schema{}, err
	}
	s.props = propertyOrder(doc)
	return s, nil
}

// Root returns the decoded document.
func (s Schema) Root() any { return s.root }

// Properties returns the top level property names in document order.
func (s Schema) Properties() []string { return append([]string(nil), s.props...) }

// Property returns the sub schema of one top level property.
func (s Schema) Property(name string) (map[string]any, bool) {
	obj, ok := s.root.(map[string]any)
	if !ok {
		return nil, false
	}
	props := anyval.As[map[string]any](obj["properties"])
	sub, ok := props[name].(map[string]any)
	if !ok {
		return nil, false
	}
	if ref, ok := sub["$ref"].(string); ok {
		if r, err := s.Resolve(ref); err == nil {
			if m, ok := r.(map[string]any); ok {
				return m, true
			}
		}
	}
	return sub, true
}

// Required returns the top level required names.
func (s Schema) Required() []string {
	obj, ok := s.root.(map[string]any)
	if !ok {
		return nil
	}
	return stringList(obj["required"])
}

// plainNumbers returns a copy of v in which every number is a float64.
// It never changes v.
func plainNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, rangeErr := x.Float64()
		// A number out of range becomes an infinity, which validation reports.
		anyval.Discard(rangeErr)
		return f
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case float32:
		return float64(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = plainNumbers(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plainNumbers(e)
		}
		return out
	}
	return v
}

// propertyOrder scans the document tokens for the top level "properties"
// object and returns its keys in order.
func propertyOrder(doc []byte) []string {
	dec := json.NewDecoder(strings.NewReader(string(doc)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil
		}
		if key == "properties" {
			return readKeys(dec)
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil
		}
	}
	return nil
}

// readKeys reads one object value and returns its keys. It skips values.
func readKeys(dec *json.Decoder) []string {
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var names []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return names
		}
		names = append(names, anyval.As[string](key))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return names
		}
	}
	return names
}

// checkSchema validates the shape of the known keywords.
func checkSchema(v any, path string, depth int) error {
	if depth > MaxRefDepth {
		return fmt.Errorf("jsonschema: schema at %s is nested too deep", ptr(path))
	}
	obj, ok := v.(map[string]any)
	if !ok {
		if _, isBool := v.(bool); isBool {
			return nil
		}
		return fmt.Errorf("jsonschema: schema at %s must be an object or a boolean", ptr(path))
	}
	if t, has := obj["type"]; has {
		for _, name := range typeNames(t) {
			if !contains(Types, name) {
				return fmt.Errorf("jsonschema: schema at %s has unknown type %q", ptr(path), name)
			}
		}
		if len(typeNames(t)) == 0 {
			return fmt.Errorf("jsonschema: schema at %s has a type that is not a string or a list", ptr(path))
		}
	}
	for _, key := range []string{"minLength", "maxLength", "minimum", "maximum"} {
		if n, has := obj[key]; has {
			if _, ok := n.(float64); !ok {
				return fmt.Errorf("jsonschema: schema at %s: %s must be a number", ptr(path), key)
			}
		}
	}
	if p, has := obj["pattern"]; has {
		s, ok := p.(string)
		if !ok {
			return fmt.Errorf("jsonschema: schema at %s: pattern must be a string", ptr(path))
		}
		if _, err := regexp.Compile(s); err != nil {
			return fmt.Errorf("jsonschema: schema at %s: pattern is not valid: %w", ptr(path), err)
		}
	}
	if f, has := obj["format"]; has {
		if _, ok := f.(string); !ok {
			return fmt.Errorf("jsonschema: schema at %s: format must be a string", ptr(path))
		}
	}
	if e, has := obj["enum"]; has {
		if _, ok := e.([]any); !ok {
			return fmt.Errorf("jsonschema: schema at %s: enum must be a list", ptr(path))
		}
	}
	if r, has := obj["required"]; has {
		list, ok := r.([]any)
		if !ok {
			return fmt.Errorf("jsonschema: schema at %s: required must be a list", ptr(path))
		}
		for _, e := range list {
			if _, ok := e.(string); !ok {
				return fmt.Errorf("jsonschema: schema at %s: required must list strings", ptr(path))
			}
		}
	}
	if r, has := obj["$ref"]; has {
		s, ok := r.(string)
		if !ok || !strings.HasPrefix(s, "#") {
			return fmt.Errorf("jsonschema: schema at %s: $ref must be a string that starts with #", ptr(path))
		}
	}
	if p, has := obj["properties"]; has {
		props, ok := p.(map[string]any)
		if !ok {
			return fmt.Errorf("jsonschema: schema at %s: properties must be an object", ptr(path))
		}
		for _, name := range sortedKeys(props) {
			if err := checkSchema(props[name], path+"/properties/"+escape(name), depth+1); err != nil {
				return err
			}
		}
	}
	if d, has := obj["$defs"]; has {
		defs, ok := d.(map[string]any)
		if !ok {
			return fmt.Errorf("jsonschema: schema at %s: $defs must be an object", ptr(path))
		}
		for _, name := range sortedKeys(defs) {
			if err := checkSchema(defs[name], path+"/$defs/"+escape(name), depth+1); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"items", "additionalProperties"} {
		if sub, has := obj[key]; has {
			if err := checkSchema(sub, path+"/"+key, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate checks instance against the schema. An empty result is a pass.
// Problems come in instance order, then keyword order.
func (s Schema) Validate(instance any) []Problem {
	instance = plainNumbers(instance)
	v := validator{schema: s}
	v.walk(s.root, instance, "", 0)
	return v.problems
}

// ValidateJSON decodes raw and validates it. A decode failure is one
// Problem with the keyword "json".
func (s Schema) ValidateJSON(raw []byte) []Problem {
	var instance any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&instance); err != nil {
		return []Problem{{Keyword: "json", Message: "the value is not valid JSON"}}
	}
	return s.Validate(instance)
}

type validator struct {
	schema   Schema
	problems []Problem
}

func (v *validator) add(path, keyword, format string, args ...any) {
	v.problems = append(v.problems, Problem{Path: path, Keyword: keyword, Message: fmt.Sprintf(format, args...)})
}

// Resolve follows a local $ref such as "#/$defs/address". The fragment
// is a JSON Pointer into the document.
func (s Schema) Resolve(ref string) (any, error) {
	frag := strings.TrimPrefix(ref, "#")
	if unescaped, unescapeErr := url.PathUnescape(frag); unescapeErr == nil {
		frag = unescaped
	}
	cur := s.root
	if frag == "" {
		return cur, nil
	}
	if !strings.HasPrefix(frag, "/") {
		return nil, fmt.Errorf("jsonschema: $ref %q is not a JSON Pointer", ref)
	}
	for _, part := range strings.Split(frag[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("jsonschema: $ref %q does not resolve", ref)
		}
		cur, ok = obj[part]
		if !ok {
			return nil, fmt.Errorf("jsonschema: $ref %q does not resolve", ref)
		}
	}
	return cur, nil
}

func (v *validator) walk(schema any, instance any, path string, depth int) {
	if b, ok := schema.(bool); ok {
		if !b {
			v.add(path, "false", "no value is allowed here")
		}
		return
	}
	obj := anyval.As[map[string]any](schema)
	if ref, has := obj["$ref"].(string); has {
		if depth >= MaxRefDepth {
			v.add(path, "$ref", "the schema reference chain is too deep")
			return
		}
		target, err := v.schema.Resolve(ref)
		if err != nil {
			v.add(path, "$ref", "the schema reference %s does not resolve", ref)
			return
		}
		v.walk(target, instance, path, depth+1)
	}
	if t, has := obj["type"]; has && !typeMatches(typeNames(t), instance) {
		v.add(path, "type", "the value must have type %s", strings.Join(typeNames(t), " or "))
		return
	}
	if e, has := obj["enum"].([]any); has && !containsValue(e, instance) {
		v.add(path, "enum", "the value must be one of %s", describe(e))
	}
	if c, has := obj["const"]; has && !equal(c, instance) {
		v.add(path, "const", "the value must be %s", describe([]any{c}))
	}
	switch x := instance.(type) {
	case string:
		v.checkString(obj, x, path)
	case float64:
		v.checkNumber(obj, x, path)
	case map[string]any:
		v.checkObject(obj, x, path, depth)
	case []any:
		if items, has := obj["items"]; has {
			for i, e := range x {
				v.walk(items, e, fmt.Sprintf("%s/%d", path, i), depth+1)
			}
		}
	}
}

func (v *validator) checkString(obj map[string]any, x, path string) {
	n := float64(len([]rune(x)))
	if m, has := obj["minLength"].(float64); has && n < m {
		v.add(path, "minLength", "the text must have at least %d characters", int(m))
	}
	if m, has := obj["maxLength"].(float64); has && n > m {
		v.add(path, "maxLength", "the text must have at most %d characters", int(m))
	}
	if p, has := obj["pattern"].(string); has && !regexp.MustCompile(p).MatchString(x) {
		v.add(path, "pattern", "the text must match the pattern %s", p)
	}
	if f, has := obj["format"].(string); has {
		if err := CheckFormat(f, x); err != nil {
			v.add(path, "format", "%s", err.Error())
		}
	}
}

func (v *validator) checkNumber(obj map[string]any, x float64, path string) {
	if m, has := obj["minimum"].(float64); has && x < m {
		v.add(path, "minimum", "the number must be at least %v", m)
	}
	if m, has := obj["maximum"].(float64); has && x > m {
		v.add(path, "maximum", "the number must be at most %v", m)
	}
}

func (v *validator) checkObject(obj map[string]any, x map[string]any, path string, depth int) {
	props := anyval.As[map[string]any](obj["properties"])
	for _, name := range stringList(obj["required"]) {
		if _, has := x[name]; !has {
			v.add(path+"/"+escape(name), "required", "the property %s is required", name)
		}
	}
	for _, name := range sortedKeys(x) {
		child := path + "/" + escape(name)
		if sub, has := props[name]; has {
			v.walk(sub, x[name], child, depth+1)
			continue
		}
		if extra, has := obj["additionalProperties"]; has {
			v.walk(extra, x[name], child, depth+1)
		}
	}
}

// CheckFormat checks value against one named format. Unknown formats pass.
func CheckFormat(format, value string) error {
	switch format {
	case "date":
		if _, err := time.Parse("2006-01-02", value); err != nil {
			return errors.New("the value must be a date such as 2024-01-31")
		}
	case "date-time":
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return errors.New("the value must be a date and time such as 2024-01-31T10:00:00Z")
		}
	case "email":
		a, err := mail.ParseAddress(value)
		if err != nil || a.Address != value {
			return errors.New("the value must be an email address")
		}
	case "uri":
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" {
			return errors.New("the value must be an absolute URI")
		}
	}
	return nil
}

// typeNames returns the type keyword as a list of names.
func typeNames(t any) []string {
	switch x := t.(type) {
	case string:
		return []string{x}
	case []any:
		return stringList(x)
	}
	return nil
}

// typeMatches reports whether instance has one of the named types.
func typeMatches(names []string, instance any) bool {
	for _, name := range names {
		switch name {
		case "string":
			if _, ok := instance.(string); ok {
				return true
			}
		case "number":
			if _, ok := instance.(float64); ok {
				return true
			}
		case "integer":
			if f, ok := instance.(float64); ok && f == math.Trunc(f) && !math.IsInf(f, 0) {
				return true
			}
		case "boolean":
			if _, ok := instance.(bool); ok {
				return true
			}
		case "object":
			if _, ok := instance.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := instance.([]any); ok {
				return true
			}
		case "null":
			if instance == nil {
				return true
			}
		}
	}
	return false
}

// equal compares two decoded JSON values.
func equal(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, has := y[k]
			if !has || !equal(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return a == b
}

func containsValue(list []any, v any) bool {
	for _, e := range list {
		if equal(e, v) {
			return true
		}
	}
	return false
}

// describe renders a list of values for a message.
func describe(list []any) string {
	parts := make([]string, 0, len(list))
	for _, e := range list {
		b := anyval.OrZero(json.Marshal(e))
		parts = append(parts, string(b))
	}
	return strings.Join(parts, ", ")
}

func stringList(v any) []string {
	list := anyval.As[[]any](v)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// escape encodes one JSON Pointer token (RFC 6901).
func escape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// ptr renders a schema path for an error message.
func ptr(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
