// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// farmer is a schema with every kind of leaf a row can fill: text, a
// date, an integer, a number, a boolean, an enum of numbers, lists of
// text and of integers, a nested object through a $ref, an object
// without properties, and a type list.
const farmer = `{
  "type": "object",
  "properties": {
    "fullName": {"type": "string", "title": "Full name"},
    "dateOfBirth": {"type": "string", "format": "date"},
    "hectares": {"type": "integer", "minimum": 0},
    "yield": {"type": "number"},
    "organic": {"type": "boolean"},
    "grade": {"enum": [1, 2, 3]},
    "crops": {"type": "array", "items": {"type": "string"}},
    "plots": {"type": "array", "items": {"type": "integer"}},
    "address": {"$ref": "#/$defs/address"},
    "extra": {"type": "object"},
    "note": {"type": ["null", "string"]},
    "free": true
  },
  "required": ["fullName", "hectares"],
  "$defs": {
    "address": {"type": "object", "required": ["county"], "properties": {
      "county": {"type": "string"},
      "geo": {"type": "object", "properties": {"lat": {"type": "number"}}}
    }}
  }
}`

func TestLeavesWalkNestedObjectsInOrder(t *testing.T) {
	s := mustParse(t, farmer)
	var names []string
	byName := map[string]Leaf{}
	for _, l := range s.Leaves() {
		names = append(names, l.Name())
		byName[l.Name()] = l
	}
	want := []string{
		"fullName", "dateOfBirth", "hectares", "yield", "organic", "grade", "crops", "plots",
		"address.county", "address.geo.lat", "extra", "note", "free",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("leaves = %v, want %v", names, want)
	}
	checks := map[string]Leaf{
		"fullName":        {Path: []string{"fullName"}, Type: "string", Title: "Full name", Required: true},
		"dateOfBirth":     {Path: []string{"dateOfBirth"}, Type: "string", Format: "date"},
		"hectares":        {Path: []string{"hectares"}, Type: "integer", Required: true},
		"plots":           {Path: []string{"plots"}, Type: "array", Item: "integer"},
		"address.county":  {Path: []string{"address", "county"}, Type: "string", Required: true},
		"address.geo.lat": {Path: []string{"address", "geo", "lat"}, Type: "number"},
		"extra":           {Path: []string{"extra"}, Type: "object"},
		"note":            {Path: []string{"note"}, Type: "string"},
		"free":            {Path: []string{"free"}},
	}
	for name, w := range checks {
		if got := byName[name]; !reflect.DeepEqual(got, w) {
			t.Errorf("%s = %+v, want %+v", name, got, w)
		}
	}
	if g := byName["grade"]; len(g.Enum) != 3 || g.Enum[0] != 1.0 {
		t.Errorf("grade enum = %v", g.Enum)
	}
}

func TestLeavesOfSchemasWithoutProperties(t *testing.T) {
	for _, doc := range []string{`true`, `{"type":"object"}`} {
		if got := mustParse(t, doc).Leaves(); len(got) != 0 {
			t.Errorf("%s: leaves = %v", doc, got)
		}
	}
	// A reference that does not resolve leaves the property as it is,
	// and an object nested past MaxLeafDepth is one leaf, as the claim
	// form of the issue page draws it.
	deep := `{"type":"object","properties":{
	  "a":{"type":"object","properties":{"b":{"type":"object","properties":{"c":{"type":"object","properties":{
	    "d":{"type":"object","properties":{"e":{"type":"object","properties":{"f":{"type":"string"}}}}}}}}}}},
	  "r":{"$ref":"#/$defs/nope"},
	  "loop":{"$ref":"#/$defs/loop"}},
	  "$defs":{"loop":{"$ref":"#/$defs/loop"}}}`
	var names []string
	for _, l := range mustParse(t, deep).Leaves() {
		names = append(names, l.Name()+":"+l.Type)
	}
	if strings.Join(names, ",") != "a.b.c.d.e:object,r:,loop:" {
		t.Errorf("deep leaves = %v", names)
	}
}

// TestTypedKeepsJSONTypes proves that the text of a row reaches the
// schema check with the JSON type of each claim: "12" becomes the
// integer 12, "true" the boolean true, a list its items, and a dotted
// name a nested object.
func TestTypedKeepsJSONTypes(t *testing.T) {
	s := mustParse(t, farmer)
	got := s.Typed(map[string]string{
		"fullName":        " Wanjiku Njeri ",
		"dateOfBirth":     "1984-03-12",
		"hectares":        "12",
		"yield":           "3.5",
		"organic":         "TRUE",
		"grade":           "2",
		"crops":           "tea; maize\nbeans;",
		"plots":           "[4, 7]",
		"address.county":  "Kiambu",
		"address.geo.lat": "-1.17",
		"extra":           `{"coop":"Limuru"}`,
		"note":            "",
		"free":            "anything",
		"unknown.part":    "kept",
	})
	want := map[string]any{
		"fullName":    "Wanjiku Njeri",
		"dateOfBirth": "1984-03-12",
		"hectares":    int64(12),
		"yield":       3.5,
		"organic":     true,
		"grade":       2.0,
		"crops":       []any{"tea", "maize", "beans"},
		"plots":       []any{4.0, 7.0},
		"address":     map[string]any{"county": "Kiambu", "geo": map[string]any{"lat": -1.17}},
		"extra":       map[string]any{"coop": "Limuru"},
		"free":        "anything",
		"unknown":     map[string]any{"part": "kept"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("typed = %#v\nwant   %#v", got, want)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"hectares":12`) || !strings.Contains(string(raw), `"organic":true`) {
		t.Errorf("JSON = %s", raw)
	}
	if problems := s.Validate(got); len(problems) != 0 {
		t.Errorf("typed row fails the schema: %v", problems)
	}
}

// TestTypedLeavesBadTextForTheSchemaCheck proves that a value that does
// not fit its type stays text, so the schema check names the claim.
func TestTypedLeavesBadTextForTheSchemaCheck(t *testing.T) {
	s := mustParse(t, farmer)
	got := s.Typed(map[string]string{
		"fullName": "Amina",
		"hectares": "twelve",
		"yield":    "NaN",
		"organic":  "maybe",
		"grade":    "9",
		"plots":    "4; x",
		"extra":    "not an object",
		"crops":    "[not json",
	})
	for name, want := range map[string]any{
		"hectares": "twelve", "yield": "NaN", "organic": "maybe", "grade": "9", "extra": "not an object",
	} {
		if got[name] != want {
			t.Errorf("%s = %#v, want %#v", name, got[name], want)
		}
	}
	if !reflect.DeepEqual(got["plots"], []any{int64(4), "x"}) {
		t.Errorf("plots = %#v", got["plots"])
	}
	if !reflect.DeepEqual(got["crops"], []any{"[not json"}) {
		t.Errorf("crops = %#v", got["crops"])
	}
	paths := map[string]bool{}
	for _, p := range s.Validate(got) {
		paths[p.Path] = true
	}
	for _, want := range []string{"/hectares", "/yield", "/organic", "/grade", "/plots/1", "/extra"} {
		if !paths[want] {
			t.Errorf("the schema check does not name %s: %v", want, paths)
		}
	}
}

func TestTypedIntegerFromAWholeDecimal(t *testing.T) {
	s := mustParse(t, farmer)
	if got := s.Typed(map[string]string{"hectares": "12.0"})["hectares"]; got != int64(12) {
		t.Errorf("12.0 = %#v, want 12", got)
	}
	if got := s.Typed(map[string]string{"hectares": "12.5"})["hectares"]; got != "12.5" {
		t.Errorf("12.5 = %#v, want the text", got)
	}
}

// TestTypedNeverOverwritesAnObjectWithText keeps the first value when a
// row names an object and one of its parts.
func TestTypedNeverOverwritesAnObjectWithText(t *testing.T) {
	s := mustParse(t, `{"type":"object","properties":{"a":{"type":"string"}}}`)
	got := s.Typed(map[string]string{"a": "x", "a.b": "y"})
	if got["a"] != "x" {
		t.Errorf("a = %#v", got["a"])
	}
}

func TestTypedFalseAndTextEnum(t *testing.T) {
	s := mustParse(t, `{"type":"object","properties":{"ok":{"type":"boolean"},"crop":{"enum":["tea","maize"]}}}`)
	got := s.Typed(map[string]string{"ok": "false", "crop": "tea"})
	if got["ok"] != false || got["crop"] != "tea" {
		t.Errorf("typed = %#v", got)
	}
}
