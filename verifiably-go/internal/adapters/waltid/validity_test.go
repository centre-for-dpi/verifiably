package waltid

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

func validityUnix(s string) int64 {
	tt, _ := time.Parse(time.RFC3339, s)
	return tt.Unix()
}

// B3: the walt.id credential builders write the issuance-time validity window.
func TestParseValidityRFC3339(t *testing.T) {
	if _, ok := parseValidityRFC3339(""); ok {
		t.Fatal("empty should be (zero,false)")
	}
	if _, ok := parseValidityRFC3339("not-a-time"); ok {
		t.Fatal("malformed should be (zero,false)")
	}
	got, ok := parseValidityRFC3339("2024-01-02T03:04:05Z")
	if !ok || got.Year() != 2024 || got.Month() != time.January {
		t.Fatalf("valid RFC3339 parse failed: %v ok=%v", got, ok)
	}
}

func TestBuildCredentialData_Validity(t *testing.T) {
	schema := vctypes.Schema{ID: "X", Name: "X", Custom: true, AdditionalTypes: []string{"X"}}

	b, err := buildCredentialData(schema, map[string]string{"a": "1"}, nil,
		"2024-01-02T03:04:05Z", "2030-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["validFrom"] != "2024-01-02T03:04:05Z" {
		t.Fatalf("validFrom = %v", doc["validFrom"])
	}
	if doc["validUntil"] != "2030-01-02T03:04:05Z" {
		t.Fatalf("validUntil = %v", doc["validUntil"])
	}

	// Absent window -> keys not written (backend default applies).
	b2, _ := buildCredentialData(schema, map[string]string{"a": "1"}, nil, "", "")
	var doc2 map[string]any
	_ = json.Unmarshal(b2, &doc2)
	if _, ok := doc2["validUntil"]; ok {
		t.Fatal("empty validUntil must not write the key")
	}
}

func TestBuildSDJWTCredentialData_Validity(t *testing.T) {
	b, err := buildSDJWTCredentialData(map[string]string{"a": "1"}, nil,
		"2024-01-02T03:04:05Z", "2030-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	nbf, ok := out["nbf"].(float64)
	if !ok || int64(nbf) != validityUnix("2024-01-02T03:04:05Z") {
		t.Fatalf("nbf = %v, want %d", out["nbf"], validityUnix("2024-01-02T03:04:05Z"))
	}
	exp, ok := out["exp"].(float64)
	if !ok || int64(exp) != validityUnix("2030-01-02T03:04:05Z") {
		t.Fatalf("exp = %v, want %d", out["exp"], validityUnix("2030-01-02T03:04:05Z"))
	}
}
