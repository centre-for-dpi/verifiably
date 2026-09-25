// SPDX-License-Identifier: Apache-2.0

package pex

import (
	"embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// The vendored schemas. schema/SOURCE.md names the upstream commits.
//
//go:embed schema/*.json
var schemaFiles embed.FS

// Schema file names and the references the definition schema makes.
const (
	definitionFile = "schema/presentation-definition.json"
	formatFile     = "schema/claim-format-designations.json"
	extensionFile  = "schema/oid4vp-formats.json"

	formatRef = "https://identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json"
	metaRef   = "http://json-schema.org/draft-07/schema#"
)

// Keywords lists the JSON Schema keywords the validator checks. The
// vendored schemas use no other keyword; a test keeps it so.
var Keywords = []string{
	"$ref", "type", "enum", "minimum", "minItems", "items", "properties",
	"required", "additionalProperties", "patternProperties", "oneOf",
}

// Annotations lists the keywords that carry no rule.
var Annotations = []string{"$schema", "$comment", "title", "definitions"}

// schemas holds the parsed documents of one validation.
type schemas struct {
	definition map[string]any
	format     map[string]any
}

// loadSchemas parses the embedded documents. The files are part of the
// binary and a test parses them, so a failure is a build fault.
func loadSchemas() schemas {
	read := func(name string) map[string]any {
		var out map[string]any
		anyval.MustDo(json.Unmarshal(anyval.Must(schemaFiles.ReadFile(name)), &out))
		return out
	}
	format := read(formatFile)
	patterns := anyval.As[map[string]any](format["patternProperties"])
	for k, v := range anyval.As[map[string]any](read(extensionFile)["patternProperties"]) {
		patterns[k] = v
	}
	return schemas{definition: read(definitionFile), format: format}
}

// schemaProblems validates a decoded document against the definition
// schema. Numbers of the document are json.Number values.
func schemaProblems(doc any) []Problem {
	s := loadSchemas()
	v := &validator{s: s}
	v.walk(s.definition, doc, "")
	return v.problems
}

// validator walks a document against a schema and keeps the problems.
type validator struct {
	s        schemas
	problems []Problem
}

// add keeps one problem.
func (v *validator) add(path, keyword, format string, args ...any) {
	v.problems = append(v.problems, Problem{Path: path, Keyword: keyword, Message: fmt.Sprintf(format, args...)})
}

// resolve returns the schema a reference names.
func (v *validator) resolve(ref string) map[string]any {
	switch {
	case ref == formatRef:
		return v.s.format
	case ref == metaRef:
		return nil
	case strings.HasPrefix(ref, "#/definitions/"):
		defs := anyval.As[map[string]any](v.s.definition["definitions"])
		return anyval.As[map[string]any](defs[strings.TrimPrefix(ref, "#/definitions/")])
	}
	panic("pex: the vendored schema names the unknown reference " + ref)
}

// walk checks one value against one schema.
func (v *validator) walk(schema map[string]any, value any, path string) {
	if ref, ok := schema["$ref"].(string); ok {
		target := v.resolve(ref)
		if target == nil {
			v.checkMeta(value, path)
			return
		}
		v.walk(target, value, path)
		return
	}
	if name, ok := schema["type"].(string); ok && !typeMatches(name, value) {
		v.add(path, "type", "the value must be of type %s", name)
		return
	}
	if list, ok := schema["enum"].([]any); ok && !contains(list, value) {
		v.add(path, "enum", "the value must be one of %s", describe(list))
	}
	if n, ok := value.(json.Number); ok {
		if least, has := schema["minimum"].(float64); has && anyval.OrZero(n.Float64()) < least {
			v.add(path, "minimum", "the value must be %v or more", least)
		}
	}
	if list, ok := value.([]any); ok {
		v.checkArray(schema, list, path)
	}
	if obj, ok := value.(map[string]any); ok {
		v.checkObject(schema, obj, path)
	}
	if branches, ok := schema["oneOf"].([]any); ok {
		v.checkOneOf(branches, value, path)
	}
}

// checkMeta checks a filter. The draft-07 meta schema accepts an object
// or a boolean.
func (v *validator) checkMeta(value any, path string) {
	switch value.(type) {
	case map[string]any, bool:
	default:
		v.add(path, "$ref", "the filter must be a JSON Schema object or a boolean")
	}
}

// checkArray checks the item count and every item.
func (v *validator) checkArray(schema map[string]any, list []any, path string) {
	if least, ok := schema["minItems"].(float64); ok && float64(len(list)) < least {
		v.add(path, "minItems", "the list must hold at least %v items", least)
	}
	if items, ok := schema["items"].(map[string]any); ok {
		for i, item := range list {
			v.walk(items, item, fmt.Sprintf("%s/%d", path, i))
		}
	}
}

// checkObject checks the members of an object.
func (v *validator) checkObject(schema map[string]any, obj map[string]any, path string) {
	for _, name := range anyval.As[[]any](schema["required"]) {
		if _, ok := obj[anyval.As[string](name)]; !ok {
			v.add(path, "required", "the member %q is missing", name)
		}
	}
	props := anyval.As[map[string]any](schema["properties"])
	patterns := anyval.As[map[string]any](schema["patternProperties"])
	for _, name := range sortedKeys(obj) {
		at := path + "/" + escape(name)
		matched := false
		if sub, ok := props[name].(map[string]any); ok {
			matched = true
			v.walk(sub, obj[name], at)
		}
		for _, pattern := range sortedKeys(patterns) {
			if regexp.MustCompile(pattern).MatchString(name) {
				matched = true
				v.walk(anyval.As[map[string]any](patterns[pattern]), obj[name], at)
			}
		}
		if matched {
			continue
		}
		if extra, ok := schema["additionalProperties"].(bool); ok && !extra {
			v.add(at, "additionalProperties", "the member %q is not allowed here", name)
		}
	}
}

// checkOneOf checks that exactly one branch matches. When none matches,
// it keeps the problems of the closest branch, if one branch is closer
// than every other. A member the branch does not allow counts ten
// problems, because it says the value takes another form.
func (v *validator) checkOneOf(branches []any, value any, path string) {
	var matches int
	var closest []Problem
	best, tie := math.MaxInt, false
	for _, b := range branches {
		inner := &validator{s: v.s}
		inner.walk(anyval.As[map[string]any](b), value, path)
		n := cost(inner.problems)
		switch {
		case n == 0:
			matches++
		case n < best:
			best, closest, tie = n, inner.problems, false
		case n == best:
			tie = true
		}
	}
	switch {
	case matches == 1:
	case matches > 1:
		v.add(path, "oneOf", "the value matches more than one allowed form")
	default:
		v.add(path, "oneOf", "the value matches none of the allowed forms")
		if !tie {
			v.problems = append(v.problems, closest...)
		}
	}
}

// cost weighs the problems of one oneOf branch.
func cost(problems []Problem) int {
	n := 0
	for _, p := range problems {
		n++
		if p.Keyword == "additionalProperties" {
			n += 9
		}
	}
	return n
}

// typeMatches reports whether a value has the JSON Schema type.
func typeMatches(name string, value any) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && f == math.Trunc(f)
	}
	panic("pex: the vendored schema names the unknown type " + name)
}

// contains reports whether a list holds a string value. The vendored
// schemas list strings only.
func contains(list []any, value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, item := range list {
		if item == text {
			return true
		}
	}
	return false
}

// describe lists the values of an enum for a message.
func describe(list []any) string {
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("%q", item))
	}
	return strings.Join(parts, ", ")
}

// sortedKeys returns the keys of an object in order, so the problems
// come in the same order on every run.
func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// escape encodes one JSON Pointer token (RFC 6901).
func escape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}
