package backend

import (
	"testing"
	"time"
)

func TestTemporalBounds(t *testing.T) {
	// W3C VCDM 2.0 RFC3339 strings.
	w3c := NormalizedCredential{Raw: map[string]any{
		"validFrom":  "2020-01-01T00:00:00Z",
		"validUntil": "2030-01-01T00:00:00Z",
	}}
	nb, na := w3c.TemporalBounds()
	if nb.Year() != 2020 || na.Year() != 2030 {
		t.Fatalf("W3C bounds wrong: nb=%v na=%v", nb, na)
	}

	// VCDM 1.1 issuanceDate/expirationDate fall back correctly.
	v1 := NormalizedCredential{Raw: map[string]any{
		"issuanceDate":   "2019-06-01T00:00:00Z",
		"expirationDate": "2025-06-01T00:00:00Z",
	}}
	nb1, na1 := v1.TemporalBounds()
	if nb1.Year() != 2019 || na1.Year() != 2025 {
		t.Fatalf("VCDM1.1 bounds wrong: nb=%v na=%v", nb1, na1)
	}

	// SD-JWT / JWT NumericDate — float64 seconds, as json.Unmarshal yields.
	nbf := float64(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	exp := float64(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	sdjwt := NormalizedCredential{Raw: map[string]any{"nbf": nbf, "exp": exp}}
	nb2, na2 := sdjwt.TemporalBounds()
	if nb2.Year() != 2021 || na2.Year() != 2029 {
		t.Fatalf("SD-JWT bounds wrong: nb=%v na=%v", nb2, na2)
	}

	// Absent → zero (no constraint).
	none := NormalizedCredential{Raw: map[string]any{}}
	nb3, na3 := none.TemporalBounds()
	if !nb3.IsZero() || !na3.IsZero() {
		t.Fatalf("expected zero bounds when no temporal fields present: nb=%v na=%v", nb3, na3)
	}
}
