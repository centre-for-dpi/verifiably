package handlers

import (
	"net/url"
	"testing"
)

func TestParseFieldLabelsFromForm(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("field_label_0_es-DO", "Apellidos")
	form.Set("field_label_0_ht", "Siyati")
	form.Set("field_name_1", "document_number")
	form.Set("field_datatype_1", "string")
	// field 1 deliberately has no label — must stay empty so Label() derives

	fields := parseFieldSpecsFromForm(form)

	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}
	if got := fields[0].Labels["en"]; got != "Family Name" {
		t.Errorf("en label = %q, want Family Name", got)
	}
	if got := fields[0].Labels["es-DO"]; got != "Apellidos" {
		t.Errorf("es-DO label = %q, want Apellidos", got)
	}
	if got := fields[0].Labels["ht"]; got != "Siyati" {
		t.Errorf("ht label = %q, want Siyati", got)
	}
	if len(fields[1].Labels) != 0 {
		t.Errorf("field with no label should have empty Labels, got %v", fields[1].Labels)
	}
}

func TestParseNewLocalePair(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("new_locale_0", "qu")
	form.Set("new_label_0", "Sutiyki")

	fields := parseFieldSpecsFromForm(form)
	if got := fields[0].Labels["qu"]; got != "Sutiyki" {
		t.Errorf("new locale qu = %q, want Sutiyki", got)
	}
}

func TestParseNewLocaleIgnoresHalfFilledPair(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("new_locale_0", "qu") // locale typed, label left blank
	fields := parseFieldSpecsFromForm(form)
	if _, exists := fields[0].Labels["qu"]; exists {
		t.Error("half-filled locale pair should be ignored")
	}
}
