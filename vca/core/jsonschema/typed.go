// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// MaxLeafDepth is the depth of the deepest object whose properties
// become leaves. A deeper object is one leaf, as the claim form of the
// issue page draws it.
const MaxLeafDepth = 4

// Leaf is one value a flat row can fill: a property that is not an
// object with properties, or an object deeper than MaxLeafDepth.
type Leaf struct {
	// Path holds the property names from the root.
	Path []string
	// Type is the first type the property names that is not null, or
	// "" when it names none.
	Type string
	// Item is the type of the entries of an array.
	Item string
	// Format is the format keyword of a string.
	Format string
	// Title is the title keyword.
	Title string
	// Enum lists the allowed values.
	Enum []any
	// Required reports whether the parent object requires the property.
	Required bool
}

// Name joins the path with dots, as a field map names a claim.
func (l Leaf) Name() string { return strings.Join(l.Path, ".") }

// Leaves returns every leaf of the schema: the top level properties in
// document order, a nested object in the place of its property, and
// the properties of a nested object sorted by name.
func (s Schema) Leaves() []Leaf {
	root, ok := s.root.(map[string]any)
	if !ok {
		return nil
	}
	return s.leaves(root, nil, s.props)
}

// leaves returns the leaves of the properties of one object schema.
func (s Schema) leaves(obj map[string]any, path []string, order []string) []Leaf {
	props := anyval.As[map[string]any](obj["properties"])
	required := map[string]bool{}
	for _, name := range stringList(obj["required"]) {
		required[name] = true
	}
	var out []Leaf
	for _, key := range orderedKeys(props, order) {
		sub := s.follow(props[key])
		at := append(append([]string(nil), path...), key)
		types := typeNames(sub["type"])
		if contains(types, "object") && len(anyval.As[map[string]any](sub["properties"])) > 0 && len(path) < MaxLeafDepth {
			out = append(out, s.leaves(sub, at, nil)...)
			continue
		}
		leaf := Leaf{
			Path: at, Type: firstType(types), Format: anyval.As[string](sub["format"]),
			Title: anyval.As[string](sub["title"]), Enum: anyval.As[[]any](sub["enum"]), Required: required[key],
		}
		if leaf.Type == "array" {
			leaf.Item = firstType(typeNames(s.follow(sub["items"])["type"]))
		}
		out = append(out, leaf)
	}
	return out
}

// follow resolves a chain of local references. A reference that does
// not resolve, or a chain longer than MaxRefDepth, stops the walk.
func (s Schema) follow(v any) map[string]any {
	sub := anyval.As[map[string]any](v)
	for i := 0; i < MaxRefDepth; i++ {
		ref, ok := sub["$ref"].(string)
		if !ok {
			return sub
		}
		target, err := s.Resolve(ref)
		if err != nil {
			return sub
		}
		sub = anyval.As[map[string]any](target)
	}
	return sub
}

// orderedKeys returns the keys of props in order, then the other keys
// sorted.
func orderedKeys(props map[string]any, order []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range order {
		if _, ok := props[k]; ok {
			out = append(out, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(props))
	for k := range props {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// firstType returns the first type name that is not null.
func firstType(names []string) string {
	for _, n := range names {
		if n != "null" {
			return n
		}
	}
	return ""
}

// Typed turns a flat row of text into a claims object with JSON types.
// Each name joins a path with dots, as Leaf.Name does. An empty value
// stays out. A value takes the type of its leaf: an integer, a number,
// a boolean, an enum value, a list, or an object from its JSON text. A
// list also reads entries split by semicolons or new lines. A value
// that does not fit its type, or a name no leaf has, stays text, so the
// schema check names the claim. Typed never changes flat.
func (s Schema) Typed(flat map[string]string) map[string]any {
	byName := map[string]Leaf{}
	for _, l := range s.Leaves() {
		byName[l.Name()] = l
	}
	names := make([]string, 0, len(flat))
	for name := range flat {
		names = append(names, name)
	}
	sort.Strings(names)
	out := map[string]any{}
	for _, name := range names {
		raw := strings.TrimSpace(flat[name])
		if raw == "" {
			continue
		}
		leaf, ok := byName[name]
		if !ok {
			leaf = Leaf{Path: strings.Split(name, ".")}
		}
		put(out, leaf.Path, leaf.convert(raw))
	}
	return out
}

// put sets value at path. A part of the path that holds a value that
// is not an object keeps that value.
func put(obj map[string]any, path []string, value any) {
	for _, key := range path[:len(path)-1] {
		next, exists := obj[key]
		if !exists {
			child := map[string]any{}
			obj[key] = child
			obj = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return
		}
		obj = child
	}
	obj[path[len(path)-1]] = value
}

// convert returns the value of one leaf from its text.
func (l Leaf) convert(raw string) any {
	if len(l.Enum) > 0 {
		for _, e := range l.Enum {
			if enumText(e) == raw {
				return e
			}
		}
		return raw
	}
	switch l.Type {
	case "array":
		if list, ok := decodeJSON[[]any](raw, "["); ok {
			return list
		}
		var list []any
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == '\n' }) {
			if part = strings.TrimSpace(part); part != "" {
				list = append(list, scalarOf(l.Item, part))
			}
		}
		return list
	case "object":
		if obj, ok := decodeJSON[map[string]any](raw, "{"); ok {
			return obj
		}
		return raw
	}
	return scalarOf(l.Type, raw)
}

// decodeJSON reads raw as JSON of type T when it starts with prefix.
func decodeJSON[T any](raw, prefix string) (T, bool) {
	var v T
	if !strings.HasPrefix(raw, prefix) {
		return v, false
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil || dec.More() {
		return v, false
	}
	v, ok := plainNumbers(decoded).(T)
	return v, ok
}

// scalarOf converts one text to an integer, a number, or a boolean when
// the type asks for one and the text fits. Any other text stays text.
func scalarOf(kind, raw string) any {
	switch kind {
	case "integer":
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(raw, 64); err == nil && f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return int64(f)
		}
	case "number":
		if f, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f
		}
	case "boolean":
		switch strings.ToLower(raw) {
		case "true":
			return true
		case "false":
			return false
		}
	}
	return raw
}

// enumText is the text of one enum value: the string itself, or its
// JSON text.
func enumText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	// A value of a parsed schema always has a JSON text.
	raw, err := json.Marshal(v)
	anyval.Discard(err)
	return string(raw)
}
