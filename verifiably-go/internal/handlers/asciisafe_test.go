package handlers

import (
	"encoding/json"
	"testing"
)

// TestAsciiSafeJSONEscapesNonASCII pins the fix for a real mojibake bug:
// errorToastStatus and SchemaReady put their JSON payload directly into the
// HX-Trigger response HEADER (not the body). Browsers expose response
// headers to JavaScript decoded as ISO-8859-1/Latin-1 (a fixed platform
// behavior, not a bug in htmx or in this server), so a raw UTF-8 multibyte
// sequence written straight into a header value comes back to the browser
// corrupted — observed live as "categoría" rendering as "categorÃ­a" in a
// real toast. \uXXXX escapes are pure ASCII and survive the header
// round-trip; JSON.parse (which htmx calls on this exact payload) decodes
// them back to the real character with no client-side change needed.
func TestAsciiSafeJSONEscapesNonASCII(t *testing.T) {
	in := map[string]string{"toast": "categoría de conducción — test ✓"}
	out, err := asciiSafeJSON(in)
	if err != nil {
		t.Fatalf("asciiSafeJSON: %v", err)
	}
	for i, b := range out {
		if b > 127 {
			t.Fatalf("asciiSafeJSON output contains a non-ASCII byte at index %d (0x%02x) — every byte must be ASCII to survive an HTTP header round-trip, got: %s", i, b, out)
		}
	}
	var roundtrip map[string]string
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatalf("asciiSafeJSON output is not valid JSON: %v (got: %s)", err, out)
	}
	if roundtrip["toast"] != in["toast"] {
		t.Errorf("round-tripped toast = %q, want %q", roundtrip["toast"], in["toast"])
	}
}

// TestAsciiSafeJSONPreservesASCIIOnly confirms a payload with no non-ASCII
// content is unaffected — the fix must not alter behavior for the common
// (English-only) case.
func TestAsciiSafeJSONPreservesASCIIOnly(t *testing.T) {
	in := map[string]string{"toast": "plain ascii message"}
	out, err := asciiSafeJSON(in)
	if err != nil {
		t.Fatalf("asciiSafeJSON: %v", err)
	}
	want, _ := json.Marshal(in)
	if string(out) != string(want) {
		t.Errorf("asciiSafeJSON(ascii-only) = %s, want %s (should match plain json.Marshal byte-for-byte when there's nothing to escape)", out, want)
	}
}
