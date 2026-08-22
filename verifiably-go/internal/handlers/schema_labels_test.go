package handlers

import (
	"net/url"
	"testing"
)

// The builder submits label metadata as PARALLEL indexed inputs:
// field_lang_<row>_<n> carries the locale code and field_label_<row>_<n> the
// text. The locale is a VALUE, never part of a field name — see
// parseFieldLabels for why the old field_label_<row>_<locale> scheme had to go.

func TestParseFieldLabelsFromForm(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Family Name")
	form.Set("field_lang_0_1", "es-DO")
	form.Set("field_label_0_1", "Apellidos")
	form.Set("field_lang_0_2", "ht")
	form.Set("field_label_0_2", "Siyati")
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

// TestParseFieldLabelsTrimsWhitespace kills three mutants a plain "does the
// happy path work" test wouldn't catch: dropping TrimSpace on the label,
// dropping TrimSpace on the locale, and dropping the nil-map guard before
// f.Labels is assigned. A whitespace-only label must produce no entry at all
// (not an empty-string entry — Label() treats presence, not content, as the
// derive signal), and a padded value must come out trimmed exactly.
func TestParseFieldLabelsTrimsWhitespace(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "   ") // whitespace-only label
	form.Set("field_lang_0_1", "  es  ")
	form.Set("field_label_0_1", "  Apellidos  ")

	fields := parseFieldSpecsFromForm(form)
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}
	if _, exists := fields[0].Labels["en"]; exists {
		t.Errorf("whitespace-only label should not create an en entry, got Labels=%v", fields[0].Labels)
	}
	if got := fields[0].Labels["es"]; got != "Apellidos" {
		t.Errorf("es label = %q, want exactly %q (both halves trimmed)", got, "Apellidos")
	}
}

// A locale code containing whitespace or control characters must be rejected.
// Under the index-based naming scheme this can no longer corrupt an HTML
// attribute name (the locale is a value now), but it is still not a usable
// locale code and validLocaleCode must keep rejecting it.
func TestParseFieldLabelsRejectsMalformedLocaleCodes(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Family Name")
	form.Set("field_lang_0_1", "es DO") // space in the locale code
	form.Set("field_label_0_1", "Corrupted")
	form.Set("field_lang_0_2", "es\nDO") // newline in the locale code
	form.Set("field_label_0_2", "AlsoCorrupt")

	fields := parseFieldSpecsFromForm(form)
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}
	for loc, v := range fields[0].Labels {
		if loc != "en" {
			t.Errorf("malformed locale code %q should have been rejected, got value %q", loc, v)
		}
	}
	if got := fields[0].Labels["en"]; got != "Family Name" {
		t.Errorf("en label = %q, want Family Name", got)
	}
}

// A half-filled language row — a locale typed with no label beside it, or the
// reverse — produces NO map entry. Absent means "derive from the identifier"
// downstream, and half a row is not an answer.
func TestParseFieldLabelsIgnoresHalfFilledRow(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "qu") // locale typed, label left blank
	form.Set("field_label_0_0", "")
	form.Set("field_lang_0_1", "") // label typed, locale left blank
	form.Set("field_label_0_1", "Orphaned")

	fields := parseFieldSpecsFromForm(form)
	if len(fields[0].Labels) != 0 {
		t.Errorf("half-filled language rows should be ignored, got Labels=%v", fields[0].Labels)
	}
}

// TestParseFieldLabelsStaysNilWhenNoneSubmitted guards the nil-map handling
// in parseFieldLabels: without it, a field with zero submitted labels would
// get a non-nil-but-empty map instead of a nil one. len(m) == 0 is true for
// both, so a length-only assertion can't catch that regression — this asserts
// nil-ness directly, which is what vctypes.FieldSpec.Label()'s "absent means
// derive" contract actually keys off of.
func TestParseFieldLabelsStaysNilWhenNoneSubmitted(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "document_number")
	form.Set("field_datatype_0", "string")

	fields := parseFieldSpecsFromForm(form)
	if fields[0].Labels != nil {
		t.Errorf("Labels should be nil when no labels were submitted, got %#v", fields[0].Labels)
	}
}

// TestFirstInvalidLocaleCode covers the helper SaveSchema uses to explain,
// via errorToast, why a submitted label silently didn't make it into the
// saved schema — parseFieldLabels itself just drops bad codes since it has no
// request/response to report through.
func TestFirstInvalidLocaleCode(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "all valid",
			form: url.Values{
				"field_name_0":    {"family_name"},
				"field_lang_0_0":  {"en"},
				"field_label_0_0": {"Family Name"},
				"field_lang_0_1":  {"es"},
				"field_label_0_1": {"Apellidos"},
			},
			want: "",
		},
		{
			name: "space in a locale code",
			form: url.Values{
				"field_name_0":    {"family_name"},
				"field_lang_0_0":  {"es DO"},
				"field_label_0_0": {"Corrupted"},
			},
			want: "es DO",
		},
		{
			name: "malformed code on a later row is still found",
			form: url.Values{
				"field_name_0":    {"family_name"},
				"field_lang_0_0":  {"en"},
				"field_label_0_0": {"Family Name"},
				"field_lang_0_1":  {"pt BR"},
				"field_label_0_1": {"Sobrenome"},
			},
			want: "pt BR",
		},
		{
			name: "malformed code on a later FIELD is still found",
			form: url.Values{
				"field_name_0":    {"family_name"},
				"field_lang_0_0":  {"en"},
				"field_label_0_0": {"Family Name"},
				"field_name_1":    {"given_name"},
				"field_lang_1_0":  {"ht HT"},
				"field_label_1_0": {"Non"},
			},
			want: "ht HT",
		},
		{
			name: "malformed but blank label is not reported",
			form: url.Values{
				"field_name_0":    {"family_name"},
				"field_lang_0_0":  {"es DO"},
				"field_label_0_0": {"   "},
			},
			want: "",
		},
		{
			name: "no locale fields submitted at all",
			form: url.Values{
				"field_name_0": {"family_name"},
			},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstInvalidLocaleCode(c.form); got != c.want {
				t.Errorf("firstInvalidLocaleCode = %q, want %q", got, c.want)
			}
		})
	}
}

// The first language row is FREELY EDITABLE, not locked to English: a
// deployment issuing only in Spanish sets it to "es" and carries no English
// at all. The old scheme hardcoded row 0 to the "en" key, which made that
// impossible to express.
func TestParseFieldLabelsFirstRowNeedNotBeEnglish(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "es")
	form.Set("field_label_0_0", "Apellidos")

	fields := parseFieldSpecsFromForm(form)
	if got := fields[0].Labels["es"]; got != "Apellidos" {
		t.Errorf("es label = %q, want Apellidos", got)
	}
	if _, exists := fields[0].Labels["en"]; exists {
		t.Errorf("no English was submitted, so no en entry may be synthesised; got Labels=%v", fields[0].Labels)
	}
}
