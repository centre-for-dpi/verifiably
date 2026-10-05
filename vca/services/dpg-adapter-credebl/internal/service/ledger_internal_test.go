// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/json"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// TestSessionTypeMatchesTheTypeName is the hint of the sync form: a
// credential type is a configuration id or the type name of the schema.
// A session of the platform names the template id and the full vct, so
// the type name matches the last segment of the vct.
func TestSessionTypeMatchesTheTypeName(t *testing.T) {
	var session credebl.IssuanceSession
	session.Metadata.Credentials = []credebl.SessionCredential{{
		SupportedID: "8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13",
		Payload: map[string]json.RawMessage{
			"vct": json.RawMessage(`"https://registry.example/vct/ProofOfResidence"`), "residentNumber": json.RawMessage(`"RES-2026-0001"`),
		},
	}}
	attrs := map[string]string{"residentNumber": "RES-2026-0001"}
	for _, typ := range []string{"ProofOfResidence", "8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13", "https://registry.example/vct/ProofOfResidence", ""} {
		if got, ok := sessionType(session, typ, attrs); !ok || got != "8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13" {
			t.Errorf("type %q: %q, %v", typ, got, ok)
		}
	}
	for _, typ := range []string{"Residence", "OfResidence", "vct"} {
		if _, ok := sessionType(session, typ, attrs); ok {
			t.Errorf("type %q matched", typ)
		}
	}
}
