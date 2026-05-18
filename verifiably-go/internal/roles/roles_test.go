package roles

import "testing"

func TestParse_Empty(t *testing.T) {
	if s := Parse(""); s != nil {
		t.Fatalf("empty string should return nil Set, got %v", s)
	}
}

func TestParse_Whitespace(t *testing.T) {
	if s := Parse("   "); s != nil {
		t.Fatalf("whitespace-only string should return nil Set, got %v", s)
	}
}

func TestParse_Single(t *testing.T) {
	s := Parse("issuer")
	if !s.Has(Issuer) {
		t.Error("should have issuer")
	}
	if s.Has(Holder) {
		t.Error("should not have holder")
	}
}

func TestParse_Multiple(t *testing.T) {
	s := Parse("issuer,verifier,holder")
	for _, r := range []string{Issuer, Verifier, Holder} {
		if !s.Has(r) {
			t.Errorf("should have %q", r)
		}
	}
	if s.Has(Hub) {
		t.Error("should not have hub")
	}
}

func TestParse_HubImpliesTrustAndSchemas(t *testing.T) {
	s := Parse("hub")
	for _, r := range []string{Hub, Trust, Schemas} {
		if !s.Has(r) {
			t.Errorf("hub should imply %q but does not", r)
		}
	}
	if s.Has(Issuer) {
		t.Error("hub should not imply issuer")
	}
}

func TestParse_CaseInsensitive(t *testing.T) {
	s := Parse("ISSUER,Verifier")
	if !s.Has(Issuer) {
		t.Error("should have issuer (case insensitive)")
	}
	if !s.Has(Verifier) {
		t.Error("should have verifier (case insensitive)")
	}
}

func TestParse_ExtraSpaces(t *testing.T) {
	s := Parse(" issuer , verifier ")
	if !s.Has(Issuer) {
		t.Error("should have issuer despite extra spaces")
	}
	if !s.Has(Verifier) {
		t.Error("should have verifier despite extra spaces")
	}
}

func TestSet_Has_NilMeansAll(t *testing.T) {
	var s Set // nil
	for _, r := range []string{Issuer, Holder, Verifier, Trust, Schemas, Hub} {
		if !s.Has(r) {
			t.Errorf("nil Set should return true for %q", r)
		}
	}
}

func TestSet_Has_Missing(t *testing.T) {
	s := Parse("issuer")
	if s.Has(Hub) {
		t.Error("non-nil Set missing hub should return false")
	}
}

func TestParse_EmptySegmentsIgnored(t *testing.T) {
	s := Parse(",issuer,,")
	if !s.Has(Issuer) {
		t.Error("should have issuer")
	}
	if len(s) != 1 {
		t.Errorf("expected 1 role, got %d", len(s))
	}
}
