package waltid

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// walt.id's validity window. This adapter was the ONLY one that honoured
// req.ValidFrom/ValidUntil — Inji Certify and CREDEBL silently dropped it, so
// every credential they issued could never expire. These tests pin walt.id's
// behaviour as the reference the others were brought up to, so a refactor
// can't quietly regress the one path that worked.
func TestBuildSDJWTCredentialData_CarriesNbfExp(t *testing.T) {
	const (
		validFrom  = "2026-07-16T17:32:00Z"
		validUntil = "2026-07-16T17:35:00Z"
	)
	raw, err := buildSDJWTCredentialData(map[string]string{"testa_id": "123456"}, nil, validFrom, validUntil)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}

	// nbf/exp are the SD-JWT VC validity slot: registered JWT claims, in the
	// plain payload. A holder cannot withhold them under selective disclosure,
	// unlike a valid_until data claim — so an expiry can't be hidden from the
	// temporal gate.
	for _, k := range []string{"nbf", "exp"} {
		if _, ok := out[k]; !ok {
			t.Errorf("SD-JWT credentialData must carry %q, got %v", k, out)
		}
	}
	if _, bad := out["valid_until"]; bad {
		t.Error("the window must be the registered nbf/exp, not a valid_until claim")
	}

	// JWT NumericDate: seconds since the epoch, as a number.
	want := func(s string) float64 {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return float64(ts.Unix())
	}
	if got, _ := out["nbf"].(float64); got != want(validFrom) {
		t.Errorf("nbf = %v, want %v (NumericDate seconds)", out["nbf"], want(validFrom))
	}
	if got, _ := out["exp"].(float64); got != want(validUntil) {
		t.Errorf("exp = %v, want %v (NumericDate seconds)", out["exp"], want(validUntil))
	}
	if _, err := strconv.ParseInt(string(mustNumber(t, raw, "exp")), 10, 64); err != nil {
		t.Errorf("exp must serialize as a JSON number, not a string: %v", err)
	}
}

// A credential with no window carries no temporal claims — it never expires,
// which is legitimate and must not be forged into a bound.
func TestBuildSDJWTCredentialData_NoWindowNoTemporalClaims(t *testing.T) {
	raw, err := buildSDJWTCredentialData(map[string]string{"testa_id": "1"}, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"nbf", "exp"} {
		if _, present := out[k]; present {
			t.Errorf("a credential with no window must not carry %q, got %v", k, out)
		}
	}
}

// An unparseable bound must be ignored rather than emitted as garbage (or a
// zero epoch, which would date the credential to 1970 and expire it instantly).
func TestBuildSDJWTCredentialData_IgnoresUnparseableBound(t *testing.T) {
	raw, err := buildSDJWTCredentialData(map[string]string{"a": "1"}, nil, "not-a-date", "2026-07-16T17:35:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if _, present := out["nbf"]; present {
		t.Errorf("an unparseable validFrom must be omitted, not emitted: %v", out["nbf"])
	}
	if _, ok := out["exp"]; !ok {
		t.Error("a valid validUntil must still be carried")
	}
}

// mustNumber extracts a raw JSON number token for the given key.
func mustNumber(t *testing.T, raw []byte, key string) []byte {
	t.Helper()
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	v, ok := probe[key]
	if !ok {
		t.Fatalf("key %q absent", key)
	}
	return v
}
