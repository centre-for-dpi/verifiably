// SPDX-License-Identifier: Apache-2.0

package mapping

import (
	"errors"
	"reflect"
	"testing"
)

func rule(p string, t Transform, params map[string]string, fields ...string) Rule {
	return Rule{Property: p, SourceFields: fields, Transform: t, Params: params}
}

func TestApplyTable(t *testing.T) {
	row := map[string]string{
		"first": "  Grace ", "last": "Atieno", "dob": "14/03/1988", "id": "ke-1",
	}
	tests := []struct {
		name    string
		rule    Rule
		want    string
		wantErr error
	}{
		{"copy", rule("p", Copy, nil, "first"), "  Grace ", nil},
		{"trim", rule("p", Trim, nil, "first"), "Grace", nil},
		{"upper", rule("p", Upper, nil, "id"), "KE-1", nil},
		{"lower", rule("p", Lower, nil, "last"), "atieno", nil},
		{"constant", rule("p", Constant, map[string]string{ParamValue: "KE"}), "KE", nil},
		{"concat", rule("p", Concat, map[string]string{ParamSeparator: " "}, "last", "first"), "Atieno   Grace ", nil},
		{"concat no separator", rule("p", Concat, nil, "last", "id"), "Atienoke-1", nil},
		{"date", rule("p", DateFormat, map[string]string{ParamInputLayout: "02/01/2006", ParamOutputLayout: "2006-01-02"}, "dob"), "1988-03-14", nil},
		{"date bad value", rule("p", DateFormat, map[string]string{ParamInputLayout: "2006-01-02", ParamOutputLayout: "2006"}, "dob"), "", ErrBadDate},
		{"missing field", rule("p", Trim, nil, "nope"), "", ErrMissingField},
		{"missing field concat", rule("p", Concat, nil, "first", "nope"), "", ErrMissingField},
		{"empty property", rule("", Copy, nil, "first"), "", ErrEmptyProperty},
		{"no field", rule("p", Copy, nil), "", ErrNoSourceField},
		{"too many fields", rule("p", Upper, nil, "first", "last"), "", ErrTooManyFields},
		{"date no params", rule("p", DateFormat, map[string]string{ParamInputLayout: "x"}, "dob"), "", ErrMissingParam},
		{"date no field", rule("p", DateFormat, nil), "", ErrNoSourceField},
		{"constant no value", rule("p", Constant, nil), "", ErrMissingParam},
		{"concat no field", rule("p", Concat, nil), "", ErrNoSourceField},
		{"unknown", rule("p", Transform("hash"), nil, "first"), "", ErrUnknownTransform},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Apply(row, FieldMap{Rules: []Rule{tc.rule}})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got["p"] != tc.want {
				t.Fatalf("got %q, want %q", got["p"], tc.want)
			}
		})
	}
}

func TestApplyDoesNotChangeRow(t *testing.T) {
	row := map[string]string{"a": " x "}
	out, err := Apply(row, FieldMap{Rules: []Rule{rule("p", Trim, nil, "a"), rule("q", Copy, nil, "a")}})
	if err != nil || row["a"] != " x " || out["p"] != "x" || out["q"] != " x " {
		t.Fatalf("out %v err %v row %v", out, err, row)
	}
}

func TestValidateDuplicate(t *testing.T) {
	fm := FieldMap{Rules: []Rule{rule("p", Copy, nil, "a"), rule("p", Copy, nil, "b")}}
	if err := fm.Validate(); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Apply(map[string]string{}, fm); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("apply err = %v", err)
	}
}

func TestUnmappedAndSourceFields(t *testing.T) {
	fm := FieldMap{Rules: []Rule{
		rule("name", Concat, nil, "last", "first"),
		rule("dob", Copy, nil, "dob"),
		rule("country", Constant, map[string]string{ParamValue: "KE"}),
	}}
	got := Unmapped(fm, []string{"id", "name", "dob", "address", "country"})
	if !reflect.DeepEqual(got, []string{"address", "id"}) {
		t.Fatalf("unmapped %v", got)
	}
	if got := Unmapped(fm, []string{"name"}); got != nil {
		t.Fatalf("unmapped %v", got)
	}
	if got := SourceFields(fm); !reflect.DeepEqual(got, []string{"dob", "first", "last"}) {
		t.Fatalf("fields %v", got)
	}
}

// TestLenientKeepsTheSourceTextOfAFailedRule proves that a rule that
// fails on one row keeps the text of its first source field, so the
// schema check of the issuance names the claim and the other claims of
// the row still fill.
func TestLenientKeepsTheSourceTextOfAFailedRule(t *testing.T) {
	fm := FieldMap{SourceID: "s", SchemaID: "farmer", Rules: []Rule{
		rule("fullName", Trim, nil, "name"),
		rule("dateOfBirth", DateFormat, map[string]string{ParamInputLayout: "02/01/2006", ParamOutputLayout: "2006-01-02"}, "dob"),
		rule("country", Constant, map[string]string{ParamValue: "KE"}),
		rule("hectares", Copy, nil, "ha"),
	}}
	got, err := Lenient(map[string]string{"name": " Amina ", "dob": "1984-13-40"}, fm)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"fullName": "Amina", "dateOfBirth": "1984-13-40", "country": "KE"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lenient = %v, want %v", got, want)
	}
	if _, err := Lenient(nil, FieldMap{Rules: []Rule{{}}}); !errors.Is(err, ErrEmptyProperty) {
		t.Errorf("a bad map: %v", err)
	}
}
