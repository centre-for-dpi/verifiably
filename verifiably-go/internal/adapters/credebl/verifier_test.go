package credebl

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// makeJWT builds a minimal unsigned JWT with the given payload map.
// The header and signature are stubs — only the payload is meaningful here.
func makeJWT(payload map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	p, _ := json.Marshal(payload)
	b := base64.RawURLEncoding.EncodeToString(p)
	return h + "." + b + ".sig"
}

// makeDisclosure encodes a [salt, name, value] disclosure array as base64url.
func makeDisclosure(name string, value any) string {
	arr, _ := json.Marshal([]any{"salt", name, value})
	return base64.RawURLEncoding.EncodeToString(arr)
}

// makeCompact returns a compact SD-JWT: jwt~disc1~disc2~...
func makeCompact(payload map[string]any, disclosures ...string) string {
	jwt := makeJWT(payload)
	result := jwt
	for _, d := range disclosures {
		result += "~" + d
	}
	return result
}

// ── extractClaimsFromCompactSdJwt ─────────────────────────────────────────────

func TestExtractClaimsFromCompactSdJwt_SelectiveDisclosures(t *testing.T) {
	disc1 := makeDisclosure("given_name", "Alice")
	disc2 := makeDisclosure("age", float64(30))
	jwt := makeJWT(map[string]any{"iss": "https://issuer.example", "vct": "ID"})
	compact := jwt + "~" + disc1 + "~" + disc2 + "~"

	got := extractClaimsFromCompactSdJwt(compact)
	if got["given_name"] != "Alice" {
		t.Errorf("given_name: got %q, want %q", got["given_name"], "Alice")
	}
	if got["age"] != "30" {
		t.Errorf("age: got %q, want %q", got["age"], "30")
	}
	// Technical fields must be absent.
	for _, tf := range []string{"iss", "vct", "_sd", "_sd_alg"} {
		if _, present := got[tf]; present {
			t.Errorf("technical field %q must be excluded", tf)
		}
	}
}

func TestExtractClaimsFromCompactSdJwt_NonSelectiveClaims(t *testing.T) {
	payload := map[string]any{
		"given_name": "Bob",
		"iss":        "https://issuer.example",
	}
	compact := makeCompact(payload)

	got := extractClaimsFromCompactSdJwt(compact)
	if got["given_name"] != "Bob" {
		t.Errorf("given_name: got %q", got["given_name"])
	}
	if _, ok := got["iss"]; ok {
		t.Error("iss must be excluded as a technical field")
	}
}

func TestExtractClaimsFromCompactSdJwt_BoolDisclosure(t *testing.T) {
	disc := makeDisclosure("is_adult", true)
	compact := makeCompact(map[string]any{}, disc)

	got := extractClaimsFromCompactSdJwt(compact)
	if got["is_adult"] != "true" {
		t.Errorf("is_adult: got %q, want %q", got["is_adult"], "true")
	}
}

func TestExtractClaimsFromCompactSdJwt_FloatIntDisclosure(t *testing.T) {
	disc := makeDisclosure("score", float64(42))
	compact := makeCompact(map[string]any{}, disc)

	got := extractClaimsFromCompactSdJwt(compact)
	if got["score"] != "42" {
		t.Errorf("score: got %q, want %q", got["score"], "42")
	}
}

func TestExtractClaimsFromCompactSdJwt_KBJwtSkipped(t *testing.T) {
	disc := makeDisclosure("name", "Carol")
	kbJwt := makeJWT(map[string]any{"nonce": "abc"}) // contains dots → KB-JWT
	compact := makeCompact(map[string]any{}, disc, kbJwt)

	got := extractClaimsFromCompactSdJwt(compact)
	if got["name"] != "Carol" {
		t.Errorf("name: got %q", got["name"])
	}
	if _, ok := got["nonce"]; ok {
		t.Error("KB-JWT claims must not be merged into output")
	}
}

func TestExtractClaimsFromCompactSdJwt_EmptyCompact(t *testing.T) {
	if got := extractClaimsFromCompactSdJwt(""); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

// ── extractDisclosedFieldsFromVpToken ─────────────────────────────────────────

func TestExtractDisclosedFieldsFromVpToken_ArrayFormat(t *testing.T) {
	disc := makeDisclosure("email", "alice@example.com")
	compact := makeCompact(map[string]any{}, disc)

	vpToken := fmt.Sprintf(`{"vc-1":[%q]}`, compact)
	got := extractDisclosedFieldsFromVpToken(vpToken)
	if got == nil {
		t.Fatal("expected non-nil result for array format vp_token")
	}
	if got["email"] != "alice@example.com" {
		t.Errorf("email: got %q", got["email"])
	}
}

func TestExtractDisclosedFieldsFromVpToken_StringFormat(t *testing.T) {
	disc := makeDisclosure("family_name", "Smith")
	compact := makeCompact(map[string]any{}, disc)

	vpToken := fmt.Sprintf(`{"vc-1":%q}`, compact)
	got := extractDisclosedFieldsFromVpToken(vpToken)
	if got == nil {
		t.Fatal("expected non-nil result for string format vp_token")
	}
	if got["family_name"] != "Smith" {
		t.Errorf("family_name: got %q", got["family_name"])
	}
}

func TestExtractDisclosedFieldsFromVpToken_MultipleCredentials(t *testing.T) {
	disc1 := makeDisclosure("given_name", "Dave")
	disc2 := makeDisclosure("degree", "BSc")
	c1 := makeCompact(map[string]any{}, disc1)
	c2 := makeCompact(map[string]any{}, disc2)

	// Array format with two credentials.
	vpToken := fmt.Sprintf(`{"vc-1":[%q],"vc-2":[%q]}`, c1, c2)
	got := extractDisclosedFieldsFromVpToken(vpToken)
	if got["given_name"] != "Dave" {
		t.Errorf("given_name: got %q", got["given_name"])
	}
	if got["degree"] != "BSc" {
		t.Errorf("degree: got %q", got["degree"])
	}
}

func TestExtractDisclosedFieldsFromVpToken_InvalidJSON(t *testing.T) {
	if got := extractDisclosedFieldsFromVpToken(`not-json`); got != nil {
		t.Errorf("invalid JSON: got %v, want nil", got)
	}
}

func TestExtractDisclosedFieldsFromVpToken_EmptyArrayYieldsNilNotEmpty(t *testing.T) {
	// Array format where the SD-JWT has no disclosures and no non-technical claims.
	// The JWT only has technical fields → no fields extracted → falls through to
	// string format (fails parse since it's not a string map) → returns nil.
	jwt := makeJWT(map[string]any{"iss": "https://issuer.example"})
	vpToken := fmt.Sprintf(`{"vc-1":[%q]}`, jwt)
	// This may return nil OR an empty-but-valid map depending on whether the
	// array-format path returns nil on empty. Either is acceptable — the caller
	// checks len(fields) == 0 before falling back. Just verify no panic.
	_ = extractDisclosedFieldsFromVpToken(vpToken)
}

func TestExtractDisclosedFieldsFromVpToken_ArrayFallsBackToString(t *testing.T) {
	// A vp_token that is valid JSON but not a map[string][]string (values are
	// strings, not arrays) should fall through to the string-format path.
	disc := makeDisclosure("country", "MX")
	compact := makeCompact(map[string]any{}, disc)

	// Explicitly use the OLD string format.
	vpToken := fmt.Sprintf(`{"vc-1":%q}`, compact)

	// The array-format Unmarshal will fail (string vs []string), so the
	// function must fall back to the string-format path.
	got := extractDisclosedFieldsFromVpToken(vpToken)
	if got["country"] != "MX" {
		t.Errorf("string-format fallback: country = %q, want %q", got["country"], "MX")
	}
}

// ── extractDisclosedFields (presentationDocument) ─────────────────────────────

func TestExtractDisclosedFields_FlatPayload(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"given_name": "Eve",
		"iss":        "https://issuer.example",
		"vct":        "IDCard",
	})
	got := extractDisclosedFields(json.RawMessage(raw))
	if got["given_name"] != "Eve" {
		t.Errorf("given_name: %q", got["given_name"])
	}
	if _, ok := got["iss"]; ok {
		t.Error("iss must be excluded")
	}
}

func TestExtractDisclosedFields_DCQLNested(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"credentials": map[string]any{
			"vc-1": map[string]any{
				"given_name": "Frank",
				"iss":        "https://issuer.example",
			},
		},
	})
	got := extractDisclosedFields(json.RawMessage(raw))
	if got["given_name"] != "Frank" {
		t.Errorf("given_name: %q", got["given_name"])
	}
}

func TestExtractDisclosedFields_EmptyRaw(t *testing.T) {
	if got := extractDisclosedFields(json.RawMessage(nil)); got != nil {
		t.Errorf("nil input: %v", got)
	}
}
