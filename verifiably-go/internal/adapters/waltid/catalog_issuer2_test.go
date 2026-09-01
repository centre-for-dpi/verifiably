package waltid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// copyShippedIssuer2Metadata copies the real deploy/k8s/config/issuer2 catalog
// into a temp file. Same reasoning as the handlers-side test that also reads it:
// a hand-written miniature does not reproduce the nested display lists,
// duplicate keys, ${?VAR} substitutions or repeated docType strings that are the
// actual hazards for a byte-level editor.
func copyShippedIssuer2Metadata(t *testing.T) string {
	t.Helper()
	// internal/adapters/waltid -> repo root is three levels up.
	// The committed baseline: the runtime credential-issuer-metadata.conf beside
	// it is gitignored and only exists after a deploy, so reading that one would
	// make this test fail in a fresh clone and in CI. The baseline is the exact
	// content a deployment is seeded with, which is what this test needs.
	src := filepath.Join("..", "..", "..", "deploy", "k8s", "config", "issuer2",
		"credential-issuer-metadata.baseline.conf")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read shipped issuer2 metadata: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "credential-issuer-metadata.conf")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("copy: %v", err)
	}
	return dst
}

// TestSetIssuer2Display_ChangedGatesTheRestart asserts the RETURN VALUE, not
// just the file contents.
//
// The distinction is the whole point. `changed` is what syncIssuer2DisplayName
// uses to decide whether to restart issuer-api2 — the service mdoc issuance
// itself runs through — so a re-save of an unchanged schema must report false.
// A test that only compared the file before and after would pass even if this
// returned true every time, because rewriting identical bytes leaves the file
// identical: it would measure the artefact while the restart, the thing that
// actually costs an operator an issuance outage, went unmeasured.
func TestSetIssuer2Display_ChangedGatesTheRestart(t *testing.T) {
	path := copyShippedIssuer2Metadata(t)
	schema := vctypes.Schema{
		ID:              "custom-abc",
		Name:            "mDL",
		Std:             "mso_mdoc",
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
		Custom:          true,
	}

	changed, err := setIssuer2Display(path, "org.iso.18013.5.1.mDL", schema)
	if err != nil {
		t.Fatalf("first save: %v", err)
	}
	if !changed {
		t.Fatal("first save reported changed=false — the shipped file carries the hardcoded name, so it must have been rewritten")
	}

	changed, err = setIssuer2Display(path, "org.iso.18013.5.1.mDL", schema)
	if err != nil {
		t.Fatalf("second save: %v", err)
	}
	if changed {
		t.Error("re-saving an unchanged schema reported changed=true — issuer-api2 would be restarted for a no-op, interrupting live mdoc issuance")
	}
}

// TestSetIssuer2Display_RenameIsDetectedAsAChange is the other side of the gate:
// an actual rename must NOT be suppressed. A `changed` flag that returned false
// too eagerly would leave the wallet showing a stale name forever, which is the
// original bug wearing a different hat.
func TestSetIssuer2Display_RenameIsDetectedAsAChange(t *testing.T) {
	path := copyShippedIssuer2Metadata(t)
	base := vctypes.Schema{
		Std:             "mso_mdoc",
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
		Custom:          true,
	}
	first := base
	first.Name = "mDL"
	if _, err := setIssuer2Display(path, "org.iso.18013.5.1.mDL", first); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := base
	second.Name = "Licencia de Conducir RD"
	changed, err := setIssuer2Display(path, "org.iso.18013.5.1.mDL", second)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if !changed {
		t.Error("renaming the schema reported changed=false — issuer-api2 would never restart and the wallet would keep the old name")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `name = "Licencia de Conducir RD"`) {
		t.Error("the renamed schema's name is not in the file")
	}
}

// TestSetIssuer2Display_RejectsUnknownDocType: the function must not invent a
// configuration for a docType issuer-api2 has no profile for. Writing one would
// publish a credential the service cannot actually issue.
func TestSetIssuer2Display_RejectsUnknownDocType(t *testing.T) {
	path := copyShippedIssuer2Metadata(t)
	before, _ := os.ReadFile(path)
	_, err := setIssuer2Display(path, "com.example.NotProvisioned", vctypes.Schema{Name: "Nope"})
	if err == nil {
		t.Fatal("expected an error for a docType with no configuration in the file")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("a failed lookup still modified the file")
	}
}

// TestFindConfigBlock_IgnoresDocTypeAppearingAsAValue is the targeted guard for
// the subtlest failure mode available here. Each mdoc docType appears in its own
// configuration FOUR-plus times: once as the quoted key, and again as `scope`,
// as `doctype`, and as the first element of every claim path inside
// credential_metadata. A matcher that took the first textual occurrence would
// splice a display block into the middle of a claims array.
func TestFindConfigBlock_IgnoresDocTypeAppearingAsAValue(t *testing.T) {
	data, err := os.ReadFile(copyShippedIssuer2Metadata(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(data)
	for _, dt := range []string{"org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1"} {
		start, end, _, ok := findConfigBlock(content, dt)
		if !ok {
			t.Fatalf("%s: configuration not found", dt)
		}
		body := content[start:end]
		// The body of the right block always declares its own format and
		// doctype. A body captured from a `scope = "..."` or claim-path match
		// would be a fragment carrying neither.
		if !strings.Contains(body, `format = "mso_mdoc"`) {
			t.Errorf("%s: matched block has no format key — findConfigBlock latched onto an occurrence of the docType as a VALUE, not the configuration key", dt)
		}
		if !strings.Contains(body, `doctype = "`+dt+`"`) {
			t.Errorf("%s: matched block has no doctype key", dt)
		}
		// And the captured range must be brace-balanced.
		if d := strings.Count(body, "{") - strings.Count(body, "}"); d != 0 {
			t.Errorf("%s: captured body is not brace-balanced (delta %d)", dt, d)
		}
	}
}

// TestFindConfigBlock_SkipsValueOccurrenceBeforeTheKey is the ordering case
// the shipped file does not currently exercise, because in it every docType's
// quoted key happens to precede its own scope/doctype/claim-path repetitions —
// so a first-occurrence matcher gets the right answer there by luck.
//
// Luck is not a guarantee. Configuration order in this file is walt.id's to
// change (it is "synced from waltid-credentials"), and an entry whose
// credential_metadata references ANOTHER docType — exactly what
// org.iso.18013.5.1.mDL.aamva does today with doctype =
// "org.iso.18013.5.1.mDL" — puts a value occurrence ahead of the key. This
// pins the requirement directly instead of depending on file order.
func TestFindConfigBlock_SkipsValueOccurrenceBeforeTheKey(t *testing.T) {
	// The sibling references the target docType as a VALUE and then opens a
	// nested object — the shape credential_metadata has. A matcher that took
	// the first textual occurrence and brace-counted from the next `{` would
	// capture that nested object instead of the real configuration.
	content := `credentialConfigurations = {
  "some.other.doc" = {
    format = "mso_mdoc"
    doctype = "org.iso.18013.5.1.mDL"
    credential_metadata = {
      claims = [
        { path = ["org.iso.18013.5.1.mDL", "family_name"] }
      ]
    }
  }

  "org.iso.18013.5.1.mDL" = {
    format = "mso_mdoc"
    doctype = "org.iso.18013.5.1.mDL"
    marker = "the-real-one"
  }
}
`
	start, end, _, ok := findConfigBlock(content, "org.iso.18013.5.1.mDL")
	if !ok {
		t.Fatal("configuration not found")
	}
	body := content[start:end]
	if !strings.Contains(body, "the-real-one") {
		t.Errorf("findConfigBlock latched onto the docType where it appears as a VALUE inside a sibling configuration, not onto its own key.\n--- captured ---\n%s", body)
	}
}

// TestBuildIssuer2DisplayBlock_EscapesOperatorText: the schema name and
// description are free operator text and land inside HOCON quoted strings. An
// unescaped double quote silently truncates the value at parse time, which
// would publish a mangled credential name rather than failing loudly.
func TestBuildIssuer2DisplayBlock_EscapesOperatorText(t *testing.T) {
	got := buildIssuer2DisplayBlock("  ", vctypes.Schema{
		Name: `He said "hi"`,
		Desc: "line1\nline2",
	})
	if !strings.Contains(got, `name = "He said \"hi\""`) {
		t.Errorf("quotes in the schema name were not escaped:\n%s", got)
	}
	if strings.Contains(got, "line1\nline2") {
		t.Errorf("a raw newline survived into the HOCON string:\n%s", got)
	}
}

// TestSyncIssuer2DisplayName_SkipsNonMdoc confirms the hook is inert for every
// other format. Those schemas get their name published by appendCredentialType
// on the legacy path; touching issuer-api2 for them would restart a service
// they never use.
func TestSyncIssuer2DisplayName_SkipsNonMdoc(t *testing.T) {
	path := copyShippedIssuer2Metadata(t)
	before, _ := os.ReadFile(path)
	a := &Adapter{cfg: Config{Issuer2MetadataPath: path}}
	a.syncIssuer2DisplayName(vctypes.Schema{
		Name:   "Farmer Cred",
		Std:    "w3c_vcdm_2",
		Custom: true,
	})
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("a w3c schema save modified issuer-api2's metadata")
	}
}
