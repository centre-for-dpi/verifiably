// SPDX-License-Identifier: Apache-2.0

package record

import (
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// TestAnonCredsNeedsItsLedger is P6-C2: an anoncreds format names the
// ledger its schema goes on, and no other format names one. The ledger
// survives the round trip through the message.
func TestAnonCredsNeedsItsLedger(t *testing.T) {
	r := valid()
	r.Formats = []string{FormatAnonCreds}
	if err := r.Validate(); err == nil {
		t.Error("an anoncreds format with no ledger passed")
	}
	r.Ledger = "bcovrin:testnet"
	if err := r.Validate(); err != nil {
		t.Errorf("an anoncreds format with a ledger failed: %v", err)
	}
	plain := valid()
	plain.Ledger = "bcovrin:testnet"
	if err := plain.Validate(); err == nil {
		t.Error("a ledger with no anoncreds format passed")
	}
	m := ToProto(r)
	if m.GetLedger() != "bcovrin:testnet" || len(m.GetFormats()) != 1 || m.GetFormats()[0] != commonv1.Format_FORMAT_ANONCREDS {
		t.Errorf("message = %v", m)
	}
	back, err := FromProto(&schemav1.Schema{
		Type: r.Type, JsonSchema: r.JSONSchema, Formats: []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS}, Ledger: " bcovrin:testnet ",
	})
	if err != nil || back.Ledger != "bcovrin:testnet" || !back.Offers(FormatAnonCreds) {
		t.Errorf("FromProto = %+v, %v", back, err)
	}
	if f, err := FormatFromProto(commonv1.Format_FORMAT_ANONCREDS); err != nil || f != FormatAnonCreds || FormatToProto(f) != commonv1.Format_FORMAT_ANONCREDS {
		t.Errorf("format mapping = %q, %v", f, err)
	}
}
