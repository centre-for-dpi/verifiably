// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"strings"
	"testing"
)

const person = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Person",
  "type": "object",
  "properties": {
    "name": {"type": "string", "minLength": 1, "maxLength": 40},
    "age": {"type": "integer", "minimum": 0, "maximum": 150},
    "email": {"type": "string", "format": "email"},
    "born": {"type": "string", "format": "date"},
    "seen": {"type": "string", "format": "date-time"},
    "site": {"type": "string", "format": "uri"},
    "code": {"type": "string", "pattern": "^[A-Z]{2}$"},
    "kind": {"enum": ["a", "b", 1]},
    "flag": {"const": true},
    "tags": {"type": "array", "items": {"type": "string"}},
    "addr": {"$ref": "#/$defs/address"},
    "any": {"type": ["string", "null"]},
    "nick": true,
    "no": false
  },
  "required": ["name", "age"],
  "additionalProperties": {"type": "number"},
  "$defs": {
    "address": {"type": "object", "properties": {"street": {"type": "string"}}, "required": ["street"]}
  }
}`

func mustParse(t *testing.T, doc string) Schema {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func decode(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func paths(problems []Problem) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		parts = append(parts, p.Keyword+"@"+p.Path)
	}
	return strings.Join(parts, " ")
}

func TestParseAndAccessors(t *testing.T) {
	s := mustParse(t, person)
	if got := strings.Join(s.Properties(), ","); got != "name,age,email,born,seen,site,code,kind,flag,tags,addr,any,nick,no" {
		t.Fatalf("properties order: %s", got)
	}
	if got := strings.Join(s.Required(), ","); got != "name,age" {
		t.Fatalf("required: %s", got)
	}
	if sub, ok := s.Property("addr"); !ok || sub["type"] != "object" {
		t.Fatalf("addr not resolved: %v %v", sub, ok)
	}
	if sub, ok := s.Property("name"); !ok || sub["type"] != "string" {
		t.Fatalf("name: %v %v", sub, ok)
	}
	if _, ok := s.Property("missing"); ok {
		t.Fatal("missing property found")
	}
	if _, ok := s.Property("nick"); ok {
		t.Fatal("boolean schema property returned as object")
	}
	if s.Root() == nil {
		t.Fatal("root")
	}
	b := mustParse(t, "true")
	if _, ok := b.Property("x"); ok || b.Required() != nil || b.Properties() != nil {
		t.Fatal("boolean schema accessors")
	}
	bad := mustParse(t, `{"properties": {"a": {"$ref": "#/nope"}}}`)
	if sub, ok := bad.Property("a"); !ok || sub["$ref"] != "#/nope" {
		t.Fatal("unresolved ref should return the raw sub schema")
	}
	noObj := mustParse(t, `{"properties": {"a": {"$ref": "#/title"}}, "title": "x"}`)
	if sub, ok := noObj.Property("a"); !ok || sub["$ref"] != "#/title" {
		t.Fatal("ref to a non object should return the raw sub schema")
	}
	if got := propertyOrder([]byte(`{"title": "properties", "properties": {"z": 1, "y": 2}}`)); strings.Join(got, ",") != "z,y" {
		t.Fatalf("order with decoy: %v", got)
	}
	if got := propertyOrder([]byte(`{"properties": 3}`)); got != nil {
		t.Fatal("non object properties")
	}
	if got := propertyOrder([]byte(`{"a": {"b": 1}, "c": 2}`)); got != nil {
		t.Fatal("no properties")
	}
	if got := propertyOrder([]byte(`[1]`)); got != nil {
		t.Fatal("array root")
	}
	if got := propertyOrder([]byte(`{"a": `)); got != nil {
		t.Fatal("truncated value")
	}
	if got := propertyOrder([]byte(`{"a": 1, `)); got != nil {
		t.Fatal("truncated key")
	}
	if got := propertyOrder([]byte(`{"properties": {"a": 1, "b": `)); strings.Join(got, ",") != "a,b" {
		t.Fatalf("truncated inner value: %v", got)
	}
	if got := propertyOrder([]byte(`{"properties": {"a": 1, `)); strings.Join(got, ",") != "a" {
		t.Fatalf("truncated inner key: %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"not json":        `{`,
		"trailing":        `{} {}`,
		"root array":      `[]`,
		"root number":     `1`,
		"bad type":        `{"type": "money"}`,
		"type number":     `{"type": 1}`,
		"type list":       `{"type": [1]}`,
		"minLength":       `{"minLength": "1"}`,
		"pattern kind":    `{"pattern": 1}`,
		"pattern regexp":  `{"pattern": "("}`,
		"format":          `{"format": 1}`,
		"enum":            `{"enum": "a"}`,
		"required":        `{"required": "a"}`,
		"required item":   `{"required": [1]}`,
		"ref kind":        `{"$ref": 1}`,
		"ref remote":      `{"$ref": "https://x"}`,
		"properties":      `{"properties": []}`,
		"property schema": `{"properties": {"a": 1}}`,
		"defs":            `{"$defs": 1}`,
		"def schema":      `{"$defs": {"a": "x"}}`,
		"items":           `{"items": 1}`,
		"additional":      `{"additionalProperties": 1}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	deep := strings.Repeat(`{"items": `, MaxRefDepth+2) + `{}` + strings.Repeat(`}`, MaxRefDepth+2)
	if _, err := Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Fatalf("deep: %v", err)
	}
}

func TestValidatePasses(t *testing.T) {
	s := mustParse(t, person)
	ok := `{"name": "Ann", "age": 30, "email": "ann@example.org", "born": "1990-01-31",
	  "seen": "2024-01-31T10:00:00Z", "site": "https://example.org", "code": "KE",
	  "kind": "a", "flag": true, "tags": ["x"], "addr": {"street": "Main"}, "any": null, "nick": "A", "extra": 1.5}`
	if p := s.Validate(decode(t, ok)); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	if p := s.ValidateJSON([]byte(ok)); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	if p := s.Validate(map[string]any{"name": "Ann", "age": 30, "kind": 1, "extra": int64(2), "tags": []any{"a"}}); len(p) != 0 {
		t.Fatalf("go ints: %v", p)
	}
	if p := s.Validate(map[string]any{"name": "Ann", "age": int32(3), "extra": float32(2)}); len(p) != 0 {
		t.Fatalf("go int32: %v", p)
	}
	if p := s.Validate(map[string]any{"name": "Ann", "age": json.Number("3")}); len(p) != 0 {
		t.Fatalf("json number: %v", p)
	}
}

func TestValidateProblems(t *testing.T) {
	s := mustParse(t, person)
	bad := `{"name": "", "age": 1.5, "email": "nope", "born": "yesterday", "seen": "2024", "site": "nope",
	  "code": "ke", "kind": "z", "flag": false, "tags": [1], "addr": {}, "any": 1, "no": 1, "extra": "x"}`
	problems := s.Validate(decode(t, bad))
	got := paths(problems)
	for _, p := range []string{"required@/addr/street", "type@/age", "type@/any", "format@/born", "format@/seen", "format@/site",
		"pattern@/code", "format@/email", "type@/extra", "enum@/kind", "minLength@/name", "false@/no", "type@/tags/0", "const@/flag"} {
		if !strings.Contains(got, p) {
			t.Errorf("missing %s in %s", p, got)
		}
	}
	for _, p := range problems {
		if p.Error() == "" || p.Message == "" {
			t.Fatal("empty problem")
		}
	}
	if p := s.Validate(decode(t, `{"name": "x"}`)); paths(p) != "required@/age" {
		t.Fatalf("required: %s", paths(p))
	}
	if p := s.Validate(decode(t, `[]`)); paths(p) != "type@" || p[0].Error() != "/: the value must have type object" {
		t.Fatalf("root type: %v", p)
	}
	if p := s.ValidateJSON([]byte(`{`)); len(p) != 1 || p[0].Keyword != "json" {
		t.Fatalf("bad json: %v", p)
	}
	long := mustParse(t, `{"maxLength": 2, "maximum": 1}`)
	if p := long.Validate("abc"); paths(p) != "maxLength@" {
		t.Fatalf("maxLength: %s", paths(p))
	}
	if p := long.Validate(2); paths(p) != "maximum@" {
		t.Fatalf("maximum: %s", paths(p))
	}
	num := mustParse(t, `{"type": "integer", "minimum": 5}`)
	if p := num.Validate(4); paths(p) != "minimum@" {
		t.Fatalf("minimum: %s", paths(p))
	}
	if p := num.Validate(json.Number("1e999")); paths(p) != "type@" {
		t.Fatalf("infinite integer: %s", paths(p))
	}
	esc := mustParse(t, `{"required": ["a/b", "c~d"]}`)
	if p := esc.Validate(map[string]any{}); paths(p) != "required@/a~1b required@/c~0d" {
		t.Fatalf("escape: %s", paths(p))
	}
	if p := mustParse(t, `{"type": "null"}`).Validate(nil); len(p) != 0 {
		t.Fatal("null")
	}
	if p := mustParse(t, `{"type": ["boolean", "number"]}`).Validate("x"); paths(p) != "type@" {
		t.Fatal("type list")
	}
	if p := mustParse(t, `{"type": ["boolean", "number"]}`).Validate(true); len(p) != 0 {
		t.Fatal("boolean")
	}
	if p := mustParse(t, `{"items": {"type": "string"}}`).Validate([]any{"a", 1}); paths(p) != "type@/1" {
		t.Fatalf("items: %s", paths(p))
	}
}

func TestRefs(t *testing.T) {
	loop := mustParse(t, `{"$ref": "#"}`)
	if p := loop.Validate(1); len(p) != 1 || p[0].Keyword != "$ref" || !strings.Contains(p[0].Message, "deep") {
		t.Fatalf("loop: %v", p)
	}
	missing := mustParse(t, `{"$ref": "#/$defs/nope"}`)
	if p := missing.Validate(1); len(p) != 1 || p[0].Keyword != "$ref" {
		t.Fatalf("missing: %v", p)
	}
	viaNonObject := mustParse(t, `{"title": "t", "$ref": "#/title/x"}`)
	if p := viaNonObject.Validate(1); len(p) != 1 || p[0].Keyword != "$ref" {
		t.Fatalf("through string: %v", p)
	}
	fragment := mustParse(t, `{"$ref": "#x"}`)
	if p := fragment.Validate(1); len(p) != 1 || p[0].Keyword != "$ref" {
		t.Fatalf("anchor: %v", p)
	}
	escaped := mustParse(t, `{"$defs": {"a/b": {"type": "string"}}, "properties": {"v": {"$ref": "#/$defs/a~1b"}}}`)
	if p := escaped.Validate(map[string]any{"v": 1}); paths(p) != "type@/v" {
		t.Fatalf("escaped ref: %s", paths(p))
	}
	percent := mustParse(t, `{"$defs": {"a b": {"type": "string"}}, "properties": {"v": {"$ref": "#/$defs/a%20b"}}}`)
	if p := percent.Validate(map[string]any{"v": 1}); paths(p) != "type@/v" {
		t.Fatalf("percent ref: %s", paths(p))
	}
	sibling := mustParse(t, `{"$defs": {"s": {"type": "string"}}, "$ref": "#/$defs/s", "minLength": 3}`)
	if p := sibling.Validate("ab"); paths(p) != "minLength@" {
		t.Fatalf("sibling keywords: %s", paths(p))
	}
}

func TestCheckFormat(t *testing.T) {
	good := map[string]string{"date": "2024-02-29", "date-time": "2024-02-29T10:00:00+03:00", "email": "a@b.c", "uri": "urn:x", "other": "anything"}
	for f, v := range good {
		if err := CheckFormat(f, v); err != nil {
			t.Errorf("%s %q: %v", f, v, err)
		}
	}
	bad := map[string]string{"date": "2024-13-01", "date-time": "2024-02-29", "email": "Ann <a@b.c>", "uri": "/relative"}
	for f, v := range bad {
		if err := CheckFormat(f, v); err == nil {
			t.Errorf("%s %q: no error", f, v)
		}
	}
	if err := CheckFormat("uri", "http://[::1"); err == nil {
		t.Error("bad uri parse")
	}
}

func TestEqualAndDescribe(t *testing.T) {
	a := decode(t, `{"a": [1, {"b": null}], "c": "x"}`)
	b := decode(t, `{"a": [1, {"b": null}], "c": "x"}`)
	if !equal(a, b) {
		t.Fatal("equal")
	}
	for _, other := range []string{`{"a": [1, {"b": 1}], "c": "x"}`, `{"a": [1], "c": "x"}`, `{"a": [1, {"b": null}]}`, `{"a": [1, {"b": null}], "d": "x"}`, `[1]`, `{"a": 1, "c": "x"}`} {
		if equal(a, decode(t, other)) {
			t.Fatalf("not equal: %s", other)
		}
	}
	if describe([]any{1.0, "a", nil}) != `1, "a", null` {
		t.Fatal(describe([]any{1.0, "a", nil}))
	}
	if typeNames(1) != nil {
		t.Fatal("typeNames")
	}
	if ptr("") != "/" || ptr("/a") != "/a" {
		t.Fatal("ptr")
	}
}

func FuzzValidate(f *testing.F) {
	f.Add([]byte(person), []byte(`{"name": "Ann", "age": 3}`))
	f.Add([]byte(`{"$ref": "#"}`), []byte(`1`))
	f.Add([]byte(`{"type": "array", "items": {"enum": [1, "a"]}}`), []byte(`[1, "a", 2]`))
	f.Add([]byte(`true`), []byte(`null`))
	f.Fuzz(func(t *testing.T, doc, raw []byte) {
		s, err := Parse(doc)
		if err != nil {
			return
		}
		for _, p := range s.ValidateJSON(raw) {
			if p.Message == "" || p.Keyword == "" {
				t.Fatalf("empty problem: %+v", p)
			}
		}
		_ = s.Properties()
		_ = s.Required()
		for _, name := range s.Properties() {
			s.Property(name)
		}
	})
}
