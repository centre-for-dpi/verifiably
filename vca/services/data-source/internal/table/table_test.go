// SPDX-License-Identifier: Apache-2.0

package table

import (
	"reflect"
	"testing"
)

func TestInferType(t *testing.T) {
	tests := []struct {
		values []string
		want   Type
	}{
		{nil, String},
		{[]string{"", " "}, String},
		{[]string{"1", " 22 ", ""}, Integer},
		{[]string{"1.5", "2"}, Number},
		{[]string{"true", "FALSE"}, Boolean},
		{[]string{"1", "0"}, Integer},
		{[]string{"t"}, String},
		{[]string{"2024-01-31", "1988-03-14T00:00:00Z", "14/03/1988"}, Date},
		{[]string{"2024-01-31", "x"}, String},
		{[]string{"Grace"}, String},
	}
	for _, tc := range tests {
		if got := InferType(tc.values); got != tc.want {
			t.Errorf("%v: got %s want %s", tc.values, got, tc.want)
		}
	}
}

func TestFieldsOf(t *testing.T) {
	rows := []map[string]string{{"b": "1", "a": "2"}, {"c": "3", "a": ""}}
	if got := FieldsOf(rows, []string{"c", "zz", "c"}); !reflect.DeepEqual(got, []string{"c", "a", "b"}) {
		t.Fatalf("%v", got)
	}
	if got := FieldsOf(nil, nil); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestInferAndLimit(t *testing.T) {
	tb := Table{Fields: []string{"id", "dob", "note"}, Rows: []map[string]string{
		{"id": "1", "dob": "", "note": ""},
		{"id": "2", "dob": "2020-01-02", "note": ""},
		{"id": "x", "dob": "2020-01-03"},
	}}
	got := Infer(tb, 2, DefaultMasker)
	want := []Field{{"id", Integer, "*"}, {"dob", Date, "2********2"}, {"note", String, ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	if got := Infer(tb, 3, DefaultMasker); got[0].Type != String {
		t.Fatalf("%+v", got)
	}
	if len(Limit(tb.Rows, 0)) != 0 || len(Limit(tb.Rows, 2)) != 2 || len(Limit(tb.Rows, 9)) != 3 {
		t.Fatal("limit")
	}
}

func TestMask(t *testing.T) {
	m := DefaultMasker
	tests := map[string]string{"": "", "a": "*", "ab": "**", "abc": "a*c", "Grace Atieno": "G**********o", "éxé": "é*é"}
	for in, want := range tests {
		if got := m.Mask(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if got := (Masker{Head: 2, Tail: 0}).Mask("abcd"); got != "ab**" {
		t.Fatal(got)
	}
	if got := (Masker{}).Mask("abcd"); got != "****" {
		t.Fatal(got)
	}
	rows := []map[string]string{{"k": "secret"}}
	masked := m.MaskRows(rows)
	if masked[0]["k"] != "s****t" || rows[0]["k"] != "secret" {
		t.Fatal("mask rows")
	}
}
