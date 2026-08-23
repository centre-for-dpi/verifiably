package waltid

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// profilesConfPath locates the deployed issuer-api2 profile from this package.
func profilesConfPath() string {
	return filepath.Join("..", "..", "..", "deploy", "k8s", "config", "issuer2", "issuer2-profiles.conf")
}

// readProfilesConf loads the profile, skipping the test when the deploy tree is
// absent (the same posture profiledates_test.go takes).
func readProfilesConf(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(profilesConfPath())
	if err != nil {
		t.Skipf("profile not readable (%v) — this guard needs the deploy config", err)
	}
	return string(raw)
}

// expectedConversionMappings is the exact set of CBOR conversion mappings the
// profile must carry, as (field, conversionType) pairs counted with
// multiplicity. They live in mDocNameSpacesDataMappingConfig.entriesConfigMap
// blocks, NOT in credentialData.
//
// This is spelled out rather than counted because the trim these mappings sit
// next to is the thing most likely to delete them. entriesConfigMap entries are
// indented to the same depth as credentialData's sample fields and look
// interchangeable in a diff; two separate hand-trim attempts on the live VPS
// deleted from the wrong block (192 field lines instead of 144) and had to be
// restored from backup.
//
// Losing a mapping is silent. The field still gets emitted, just with the wrong
// CBOR type — a full-date becomes a text string, a portrait becomes base64 text
// instead of a byte string — and nothing in walt.id logs a complaint. The
// credential issues, the wallet stores it, and the reader rejects or
// misrenders it. A count alone would not catch a mapping that survived with
// its conversionType silently changed, so the pairs are asserted, not tallied.
var expectedConversionMappings = []struct{ field, conversion string }{
	// isoMdl / org.iso.18013.5.1
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait", "base64StringToByteString"},
	// driving_privileges is an array of two positional objects, each carrying
	// its own pair of date conversions.
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait_capture_date", "stringToFullDate"},
	{"signature_usual_mark", "base64StringToByteString"},
	// isoPhotoId / org.iso.23220.1
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait_capture_date", "stringToFullDate"},
}

// TestTrimmedProfileKeepsEveryConversionMapping is the guard that matters most
// around the credentialData trim. See expectedConversionMappings for why a
// pairwise assertion beats a field count.
func TestTrimmedProfileKeepsEveryConversionMapping(t *testing.T) {
	raw := readProfilesConf(t)

	// [^{}]*? keeps the match inside a single leaf mapping block, and the
	// conversion name must allow digits — base64StringToByteString has some.
	re := regexp.MustCompile(`"([a-z0-9_]+)"\s*=\s*\{[^{}]*?"conversionType"\s*=\s*"([A-Za-z0-9]+)"`)
	matches := re.FindAllStringSubmatch(raw, -1)

	got := make([]string, 0, len(matches))
	for _, m := range matches {
		got = append(got, m[1]+"="+m[2])
	}
	want := make([]string, 0, len(expectedConversionMappings))
	for _, m := range expectedConversionMappings {
		want = append(want, m.field+"="+m.conversion)
	}

	if len(got) != len(want) {
		t.Fatalf("profile carries %d conversion mappings, want %d\n got: %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("conversion mapping %d = %q, want %q — a trim that reaches into "+
				"entriesConfigMap changes the CBOR type of this field silently", i, got[i], want[i])
		}
	}

	// A bare occurrence count guards the same blocks against a mapping that the
	// structural regex above stops matching (e.g. reordered keys).
	if n := strings.Count(raw, "conversionType"); n != len(expectedConversionMappings) {
		t.Errorf("profile has %d conversionType occurrences, want %d", n, len(expectedConversionMappings))
	}
}

// mdlKeepList is the set of org.iso.18013.5.1 elements this deployment issues.
// Everything walt.id's sample profile declares beyond this was trimmed out.
var mdlKeepList = []string{
	"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
	"issuing_country", "issuing_authority", "document_number", "portrait",
	"driving_privileges", "un_distinguishing_sign", "portrait_capture_date",
	"issuing_jurisdiction", "age_over_18", "age_over_21",
}

// TestCredentialDataCarriesOnlyTheKeptFields pins the trim itself.
//
// issuer-api2 deep-MERGES the runtimeOverrides we POST over the profile's
// credentialData instead of replacing it, so every sample field left in the
// profile and not sent at issue time is emitted into the mdoc as a BLANK
// element. An operator who defined 15 fields saw a credential carrying 46,
// most of them empty. Restoring walt.id's full ~45-field sample set would
// bring that straight back, which is why this is asserted and not just
// commented.
func TestCredentialDataCarriesOnlyTheKeptFields(t *testing.T) {
	raw := readProfilesConf(t)

	block := namespaceBlock(t, raw, `"org.iso.18013.5.1" = {`)
	got := fieldNamesIn(block)

	want := map[string]bool{}
	for _, f := range mdlKeepList {
		want[f] = true
	}

	for _, f := range got {
		if !want[f] {
			t.Errorf("credentialData still declares %q — issuer-api2 deep-merges the "+
				"profile under our overrides, so this is emitted as a blank element in "+
				"every mdoc we issue", f)
		}
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f] = true
	}
	for _, f := range mdlKeepList {
		if !seen[f] {
			t.Errorf("credentialData is missing %q — a field absent from the profile "+
				"cannot be populated by a runtime override", f)
		}
	}
}

// namespaceBlock returns the text between `header` and its matching close
// brace, so a test can look at one credentialData namespace without matching
// the entriesConfigMap blocks that sit at the same indent elsewhere.
func namespaceBlock(t *testing.T, raw, header string) string {
	t.Helper()
	start := strings.Index(raw, header)
	if start < 0 {
		t.Fatalf("namespace header %q not found — the profile shape changed", header)
	}
	rest := raw[start+len(header):]
	depth := 1
	for i, r := range rest {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i]
			}
		}
	}
	t.Fatalf("unbalanced braces after %q", header)
	return ""
}

// fieldNamesIn extracts the direct `"name" = value` keys of a block.
func fieldNamesIn(block string) []string {
	re := regexp.MustCompile(`(?m)^\s*"([a-z0-9_]+)"\s*=`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}
