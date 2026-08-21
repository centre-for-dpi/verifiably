package vctypes

import "testing"

func TestDeriveLabel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"family_name", "Family Name"},
		{"given_name", "Given Name"},
		{"age_over_18", "Age Over 18"},
		{"portrait", "Portrait"},
		{"un_distinguishing_sign", "Un Distinguishing Sign"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := DeriveLabel(tt.in); got != tt.want {
			t.Errorf("DeriveLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFieldSpecLabelResolution(t *testing.T) {
	f := FieldSpec{
		Name: "family_name",
		Labels: map[string]string{
			"en":    "Family Name",
			"es-DO": "Apellidos",
		},
	}

	if got := f.Label("es-DO"); got != "Apellidos" {
		t.Errorf("exact locale: got %q, want Apellidos", got)
	}
	if got := f.Label("en"); got != "Family Name" {
		t.Errorf("base locale: got %q, want Family Name", got)
	}
	// An unknown locale falls back to English rather than showing nothing.
	if got := f.Label("ht"); got != "Family Name" {
		t.Errorf("unknown locale should fall back to en: got %q", got)
	}
}

func TestFieldSpecLabelFallsBackToDerived(t *testing.T) {
	// No labels at all — today's behaviour must be preserved: the wallet
	// derives a label from the identifier, so we derive the same thing.
	f := FieldSpec{Name: "document_number"}
	if got := f.Label("es-DO"); got != "Document Number" {
		t.Errorf("no labels: got %q, want Document Number", got)
	}
}
