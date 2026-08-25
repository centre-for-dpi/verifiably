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
	// The committed baseline, not the gitignored runtime file, which only exists
	// after a deploy — reading that one would make these guards silently skip in
	// a fresh clone and in CI.
	return filepath.Join("..", "..", "..", "deploy", "k8s", "config", "issuer2", "issuer2-profiles.baseline.conf")
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

// expectedConversionMappings is the exact set of CBOR conversion mappings
// each profile must carry, as (field, conversionType) pairs counted with
// multiplicity within ONE profile block. isoMdl_1cat..isoMdl_4cat share
// the same fixed set (6 entries) plus 2 per driving_privileges arrayConfig
// entry (which varies 1..4 across the four profiles) — expectedMdlMappingsForProfile
// builds that per-profile list so the test does not hand-maintain a
// hardcoded total that silently drifts if a profile's category count
// changes.
//
// The split point is NOT after all 6 fixed entries: in the actual HOCON,
// entriesConfigMap declares birth_date/issue_date/expiry_date/portrait first,
// then the driving_privileges arrayConfig entries, then
// portrait_capture_date/signature_usual_mark last — so the per-profile list
// interleaves the variable-count arrayConfig pairs between the two fixed
// halves rather than appending them after all six.
var expectedMdlMappingsHead = []struct{ field, conversion string }{
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait", "base64StringToByteString"},
}

var expectedMdlMappingsTail = []struct{ field, conversion string }{
	{"portrait_capture_date", "stringToFullDate"},
	{"signature_usual_mark", "base64StringToByteString"},
}

func expectedMdlMappingsForProfile(categoryCount int) []struct{ field, conversion string } {
	out := append([]struct{ field, conversion string }{}, expectedMdlMappingsHead...)
	for i := 0; i < categoryCount; i++ {
		out = append(out,
			struct{ field, conversion string }{"issue_date", "stringToFullDate"},
			struct{ field, conversion string }{"expiry_date", "stringToFullDate"},
		)
	}
	out = append(out, expectedMdlMappingsTail...)
	return out
}

// expectedPhotoIdMappings — isoPhotoId, unchanged by this task.
var expectedPhotoIdMappings = []struct{ field, conversion string }{
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait_capture_date", "stringToFullDate"},
}

// TestTrimmedProfileKeepsEveryConversionMapping is the guard that matters most
// around the credentialData trim. See expectedMdlMappingsForProfile for why a
// pairwise assertion beats a field count, and why it is computed per profile
// rather than hand-maintained as one flat total.
func TestTrimmedProfileKeepsEveryConversionMapping(t *testing.T) {
	raw := readProfilesConf(t)

	var want []string
	for n := 1; n <= 4; n++ {
		for _, m := range expectedMdlMappingsForProfile(n) {
			want = append(want, m.field+"="+m.conversion)
		}
	}
	for _, m := range expectedPhotoIdMappings {
		want = append(want, m.field+"="+m.conversion)
	}

	re := regexp.MustCompile(`"([a-z0-9_]+)"\s*=\s*\{[^{}]*?"conversionType"\s*=\s*"([A-Za-z0-9]+)"`)
	matches := re.FindAllStringSubmatch(raw, -1)
	got := make([]string, 0, len(matches))
	for _, m := range matches {
		got = append(got, m[1]+"="+m[2])
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

	if n := strings.Count(raw, "conversionType"); n != len(want) {
		t.Errorf("profile has %d conversionType occurrences, want %d", n, len(want))
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

// TestCredentialDataCarriesOnlyTheKeptFields pins the trim itself, across
// all 4 mDL profiles independently — each isoMdl_Ncat block repeats the
// same credentialData shape, and each is an equally real risk of an
// accidental trim, so each is checked on its own rather than trusting
// that checking one implies the other three are fine.
func TestCredentialDataCarriesOnlyTheKeptFields(t *testing.T) {
	raw := readProfilesConf(t)

	want := map[string]bool{}
	for _, f := range mdlKeepList {
		want[f] = true
	}

	// The header must anchor on credentialData specifically: each isoMdl_Ncat
	// block also has an unrelated "org.iso.18013.5.1" header under
	// mDocNameSpacesDataMappingConfig.entriesConfigMap (the conversion-mapping
	// block asserted by TestTrimmedProfileKeepsEveryConversionMapping), and a
	// bare header match would double-count 8 blocks instead of the 4
	// credentialData ones this test actually pins.
	blocks := allNamespaceBlocks(t, raw, "credentialData = {\n      \"org.iso.18013.5.1\" = {")
	if len(blocks) != 4 {
		t.Fatalf("found %d \"org.iso.18013.5.1\" credentialData blocks, want 4 (one per isoMdl_Ncat profile)", len(blocks))
	}

	for i, block := range blocks {
		got := fieldNamesIn(block)
		seen := map[string]bool{}
		for _, f := range got {
			seen[f] = true
			if !want[f] {
				t.Errorf("profile block %d: credentialData still declares %q — issuer-api2 deep-merges the "+
					"profile under our overrides, so this is emitted as a blank element in every mdoc we issue", i, f)
			}
		}
		for _, f := range mdlKeepList {
			if !seen[f] {
				t.Errorf("profile block %d: credentialData is missing %q — a field absent from the profile "+
					"cannot be populated by a runtime override", i, f)
			}
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

// allNamespaceBlocks returns the text between EVERY occurrence of `header`
// and its matching close brace — unlike namespaceBlock, which only finds
// the first. Needed once a HOCON file legitimately repeats the same
// namespace header across multiple profile blocks (isoMdl_1cat..isoMdl_4cat
// each declare their own "org.iso.18013.5.1" = { ... } credentialData).
func allNamespaceBlocks(t *testing.T, raw, header string) []string {
	t.Helper()
	var blocks []string
	rest := raw
	for {
		idx := strings.Index(rest, header)
		if idx < 0 {
			break
		}
		body := rest[idx+len(header):]
		depth := 1
		end := -1
		for i, r := range body {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("unbalanced braces after %q", header)
		}
		blocks = append(blocks, body[:end])
		rest = body[end:]
	}
	if len(blocks) == 0 {
		t.Fatalf("namespace header %q not found — the profile shape changed", header)
	}
	return blocks
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
