package waltid

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEveryProfileDateFieldIsReachableFromTheForm guards a failure mode that
// has bitten a live deployment and that no test of our own code alone would
// catch: issuer-api2 deep-MERGES runtimeOverrides over its profile rather than
// replacing it, so a field we never send keeps the profile's value. Our
// profiles ship every sample value emptied — deliberately, since walt.id's
// defaults are a fictional Austrian person — and an empty string under a date
// conversion is unparseable.
//
// The offer still returns HTTP 201, so nothing fails until the citizen's
// wallet redeems it:
//
//	java.time.format.DateTimeParseException: Text '' could not be parsed
//
// portrait_capture_date was exactly this: mapped as a date in the profile,
// absent from the mDL field spec, and therefore never fillable. Any field the
// profile maps as a date must be offerable from the issue form.
func TestEveryProfileDateFieldIsReachableFromTheForm(t *testing.T) {
	// The committed baseline, not the runtime issuer2-profiles.conf: the runtime
	// file is gitignored and only exists after a deploy, so reading it would make
	// this guard silently t.Skip in a fresh clone and in CI. The date mappings
	// this test checks live in the baseline and are copied verbatim by the seed.
	path := filepath.Join("..", "..", "..", "deploy", "k8s", "config", "issuer2", "issuer2-profiles.baseline.conf")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("profile not readable (%v) — this guard needs the deploy config", err)
	}

	re := regexp.MustCompile(`"([a-z_]+)"\s*=\s*\{[^}]*?"conversionType"\s*=\s*"stringToFullDate"`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("found no stringToFullDate mappings — the regex or the profile shape changed")
	}

	offered := map[string]bool{}
	for _, fs := range fieldsForCredentialType("Iso18013DriversLicenseCredential") {
		offered[fs.Name] = true
	}

	seen := map[string]bool{}
	for _, m := range matches {
		field := m[1]
		if seen[field] {
			continue
		}
		seen[field] = true
		if !offered[field] {
			t.Errorf("profile maps %q as a date but the mDL field spec never offers it — "+
				"it reaches walt.id as the profile's empty string and kills issuance at "+
				"wallet redemption with DateTimeParseException", field)
		}
	}
	t.Logf("checked %d date-mapped profile fields", len(seen))
}
