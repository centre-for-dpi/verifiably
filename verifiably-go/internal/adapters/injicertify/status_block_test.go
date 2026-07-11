package injicertify

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Part B: an auth-code W3C (ldp_vc) schema with status enabled must emit a REAL
// W3C BitstringStatusListEntry credentialStatus block (${statusUri}#${statusIdx})
// so external verifiers (Inji Verify) evaluate revocation — not just verifiably's
// own gate. Statusless when disabled.
func TestBuildAuthcodeCredConfig_W3CStatusBlock(t *testing.T) {
	w3c := vctypes.Schema{Name: "IdW3C", Std: "w3c_vcdm_2", FieldsSpec: []vctypes.FieldSpec{{Name: "givenName"}}}

	with := decodeTmpl(t, BuildAuthcodeCredConfig(w3c, true).VCTemplateB64)
	for _, want := range []string{"credentialStatus", "BitstringStatusListEntry", "statusListCredential", "${statusUri}", "${statusIdx}"} {
		if !strings.Contains(with, want) {
			t.Errorf("W3C status template missing %q\n%s", want, with)
		}
	}

	without := decodeTmpl(t, BuildAuthcodeCredConfig(w3c, false).VCTemplateB64)
	if strings.Contains(without, "credentialStatus") {
		t.Errorf("statusless W3C must NOT carry a credentialStatus block\n%s", without)
	}
}

func decodeTmpl(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode template: %v", err)
	}
	return string(raw)
}
