package handlers

import (
	"strings"
	"testing"
)

// After the durable-DID fix, the external-verifier check is a PLAIN host verdict.
// It must not reintroduce the removed reconciliation language ("verifiably's
// checks are authoritative" / "can't read verifiably's status list"), which only
// ever papered over the certify-nginx DID bug — an INVALID from the external
// verifier is now a genuine failure verifiably does not override.
func TestHostVerifierCheck_PlainVerdictNoReconciliation(t *testing.T) {
	ok := hostVerifierCheck("SUCCESS")
	if ok.Status != "pass" {
		t.Errorf("SUCCESS → status %q, want pass", ok.Status)
	}
	bad := hostVerifierCheck("INVALID")
	if bad.Status != "fail" {
		t.Errorf("INVALID → status %q, want fail", bad.Status)
	}
	banned := []string{"authoritative", "can't read", "status list", "superseded", "flags"}
	for _, c := range []struct{ name, note string }{{"SUCCESS", ok.Note}, {"INVALID", bad.Note}} {
		low := strings.ToLower(c.note)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%s note reintroduces reconciliation language %q: %q", c.name, b, c.note)
			}
		}
	}
}
