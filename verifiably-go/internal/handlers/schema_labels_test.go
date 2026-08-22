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

// TestParseFieldLabelsTrimsWhitespace kills three mutants a plain "does the
// happy path work" test wouldn't catch: dropping TrimSpace on the English
// label, dropping TrimSpace on a locale value, and dropping the
// `len(labels) > 0` guard before assigning f.Labels. A whitespace-only
// English label must produce no "en" entry at all (not an empty-string
// entry — Label() treats presence, not content, as the derive signal), and
// a locale value with surrounding whitespace must come out trimmed exactly.
func TestParseFieldLabelsTrimsWhitespace(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "   ")              // whitespace-only English label
	form.Set("field_label_0_es", "  Apellidos  ") // valid locale, padded value

	fields := parseFieldSpecsFromForm(form)
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}
	if _, exists := fields[0].Labels["en"]; exists {
		t.Errorf("whitespace-only English label should not create an en entry, got Labels=%v", fields[0].Labels)
	}
	if got := fields[0].Labels["es"]; got != "Apellidos" {
		t.Errorf("es label = %q, want exactly %q (trimmed)", got, "Apellidos")
	}
}

// TestParseFieldLabelsRejectsMalformedLocaleCodes covers Fix 1: a locale
// code containing whitespace or control characters becomes a corrupted HTML
// form field *name* on re-render (the browser truncates the attribute at the
// first space/newline), so such codes must be rejected at parse time rather
// than silently accepted and later mis-keyed.
func TestParseFieldLabelsRejectsMalformedLocaleCodes(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("field_label_0_es DO", "Corrupted")    // space in the locale code
	form.Set("field_label_0_es\nDO", "AlsoCorrupt") // newline in the locale code

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

// TestParseNewLocaleRejectsMalformedCode covers the same Fix 1 validation
// on the new_locale_N/new_label_N path.
func TestParseNewLocaleRejectsMalformedCode(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("new_locale_0", "es DO")
	form.Set("new_label_0", "Apellidos")

	fields := parseFieldSpecsFromForm(form)
	if len(fields[0].Labels) != 0 {
		t.Errorf("malformed new-locale code should be rejected, got Labels=%v", fields[0].Labels)
	}
}

// TestParseFieldLabelsStaysNilWhenNoneSubmitted guards the `len(labels) > 0`
// check before f.Labels is assigned: without it, a field with zero
// submitted labels would get a non-nil-but-empty map instead of a nil one.
// len(m) == 0 is true for both, so a length-only assertion can't catch that
// regression — this asserts nil-ness directly, which is what
// vctypes.FieldSpec.Label()'s "absent means derive" contract actually keys
// off of (a present entry with "" value would behave differently in
// principle, and only an absent key is guaranteed safe).
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
// saved schema — parseFieldSpecsFromForm itself just drops bad codes since
// it has no request/response to report through.
func TestFirstInvalidLocaleCode(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "all valid",
			form: url.Values{
				"field_name_0":     {"family_name"},
				"field_label_0":    {"Family Name"},
				"field_label_0_es": {"Apellidos"},
				"new_locale_0":     {"qu"},
				"new_label_0":      {"Sutiyki"},
			},
			want: "",
		},
		{
			name: "space in prefix-scanned locale",
			form: url.Values{
				"field_name_0":        {"family_name"},
				"field_label_0_es DO": {"Corrupted"},
			},
			want: "es DO",
		},
		{
			name: "space in new_locale",
			form: url.Values{
				"field_name_0": {"family_name"},
				"new_locale_0": {"es DO"},
				"new_label_0":  {"Apellidos"},
			},
			want: "es DO",
		},
		{
			name: "malformed but blank value is not reported",
			form: url.Values{
				"field_name_0":        {"family_name"},
				"field_label_0_es DO": {"   "},
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

// TestParseFieldLabelsPrefixScanNeverOverwritesEnglish covers Fix 4: a
// hand-crafted field_label_N_en (never produced by the template itself,
// which only renders the suffix form for non-English locales) must not
// silently clobber the base English label.
func TestParseFieldLabelsPrefixScanNeverOverwritesEnglish(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("field_label_0_en", "Should Not Win")

	fields := parseFieldSpecsFromForm(form)
	if got := fields[0].Labels["en"]; got != "Family Name" {
		t.Errorf("en label = %q, want Family Name (must not be clobbered by field_label_0_en)", got)
	}
}
