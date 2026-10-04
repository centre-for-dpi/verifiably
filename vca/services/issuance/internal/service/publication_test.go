// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
)

// TestConfigurationIDComesFromThePublication: the registry keeps the id
// that the adapter gave to each format at the publication. The offer
// names that id for every format, so the adapter finds its
// registration.
func TestConfigurationIDComesFromThePublication(t *testing.T) {
	for format, key := range map[commonv1.Format]string{
		commonv1.Format_FORMAT_VC_SD_JWT: "vc+sd-jwt", commonv1.Format_FORMAT_LDP_VC: "ldp_vc",
	} {
		h := newHarness(t, nil)
		h.schemas.schema.Formats = []commonv1.Format{format}
		h.schemas.schema.ConfigurationIds = map[string]string{key: "FarmerCredential_" + key}
		h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
		if got := h.adapter.lastSpec().GetConfigurationId(); got != "FarmerCredential_"+key {
			t.Errorf("%s: configuration id = %q", key, got)
		}
	}
}

// TestRecordWithoutASubjectNamesTheOffer: the issue page names no
// subject of the holder. The issued record still reaches the log
// (ADR-017 decision 1). Its subject reference is the offer, which holds
// no personal data.
func TestRecordWithoutASubjectNamesTheOffer(t *testing.T) {
	h := newHarness(t, nil)
	offer := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, func(r *issuancev1.IssueRequest) { r.Subject = nil })
	if got := h.recorder.last().GetSubject().GetRef(); got != "offer-"+offer.GetId() {
		t.Errorf("subject reference = %q, want offer-%s", got, offer.GetId())
	}
}

// TestRecordNamesTheSchema: the issued record carries the display name
// of the schema, so the issued credentials pages show a name and not
// the schema id.
func TestRecordNamesTheSchema(t *testing.T) {
	h := newHarness(t, nil)
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if got := h.recorder.last().GetSchemaName(); got != "Farmer Credential" {
		t.Errorf("schema name = %q, want the display name of the schema", got)
	}
}
