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

// TestAsciiSafeJSONEscapesNonBMPAsSurrogatePair pins a real bug: %04x is a
// MINIMUM width, so a rune above U+FFFF (e.g. an emoji in an operator-typed
// schema name) produced a 5-hex-digit escape like Ὡ7 — not a valid JSON
// escape at all. JSON requires a UTF-16 surrogate pair for anything outside
// the Basic Multilingual Plane. A schema named "🚗 mDL" would have made
// SchemaReady's HX-Trigger payload fail JSON.parse client-side, silently
// dropping the "is ready to use" toast.
func TestAsciiSafeJSONEscapesNonBMPAsSurrogatePair(t *testing.T) {
	in := map[string]string{"toast": "🚗 mDL is ready to use"}
	out, err := asciiSafeJSON(in)
	if err != nil {
		t.Fatalf("asciiSafeJSON: %v", err)
	}
	for i, b := range out {
		if b > 127 {
			t.Fatalf("asciiSafeJSON output contains a non-ASCII byte at index %d (0x%02x), got: %s", i, b, out)
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

// TestAsciiSafeJSONRoundTripsAcrossPlanes is the broad guard behind the two
// specific cases above: for a spread of inputs covering ASCII, Latin-1, the
// rest of the BMP, the astral planes and the code points on either side of
// the BMP boundary, the output must be pure ASCII, parse as JSON, and decode
// back to exactly the input. A table beats hand-picking characters, because
// the defect this pins (5-hex-digit \u escapes above U+FFFF) lived in a
// range nobody had thought to test.
func TestAsciiSafeJSONRoundTripsAcrossPlanes(t *testing.T) {
	for _, s := range []string{
		"",
		"plain ascii",
		"categoría de conducción",
		"— em dash and ✓ check",
		"￿ last BMP code point",
		"\U00010000 first astral code point",
		"🚗 mDL",
		"👨‍👩‍👧‍👦 ZWJ sequence",
		"\U0010ffff last valid code point",
		"mixed 🚗 ascii ñ 漢字 end",
		`quotes " and \ backslash`,
	} {
		in := map[string]string{"toast": s}
		out, err := asciiSafeJSON(in)
		if err != nil {
			t.Errorf("%q: asciiSafeJSON: %v", s, err)
			continue
		}
		for i, b := range out {
			if b > 127 {
				t.Errorf("%q: non-ASCII byte 0x%02x at index %d: %s", s, b, i, out)
				break
			}
		}
		var got map[string]string
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("%q: output is not valid JSON: %v (got: %s)", s, err, out)
			continue
		}
		if got["toast"] != s {
			t.Errorf("%q: round-tripped to %q", s, got["toast"])
		}
	}
}
