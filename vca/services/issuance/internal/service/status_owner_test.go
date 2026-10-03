// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// stackEntry is the status entry a stack with a list of its own writes
// into the credential of an offer.
func stackEntry() *backendv1.StatusListBinding {
	return &backendv1.StatusListBinding{
		Kind:       backendv1.StatusListBinding_KIND_TOKEN,
		ListId:     "6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6",
		Index:      4211,
		PublishUrl: "https://status.issuer.example.org/status-lists/6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6",
		DpgList:    true,
	}
}

// ownList is the capability answer of a stack that keeps its own status
// list: it embeds no entry of VCA and revokes through the adapter.
func ownList() *backendv1.GetCapabilitiesResponse {
	caps := allChannels()
	caps.StatusMechanisms = nil
	caps.Features = []backendv1.Feature{backendv1.Feature_FEATURE_REVOCATION}
	return caps
}

func TestAnOfferOfAStackWithItsOwnListRecordsTheStackEntry(t *testing.T) {
	h := newHarness(t, func(_ *service.Options, h *harness) {
		h.adapter.capabilities = ownList()
		h.adapter.offer.Status = stackEntry()
		h.adapter.offer.CredentialId = "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56"
	})
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if len(h.status.requests) != 0 {
		t.Fatalf("the stack embeds no entry of VCA, yet the service allocated %d index(es)", len(h.status.requests))
	}
	if spec := h.adapter.lastSpec(); spec.GetStatus() != nil {
		t.Fatalf("the spec names a VCA entry the credential never carries: %v", spec.GetStatus())
	}
	record := h.recorder.last()
	if !proto.Equal(record.GetStatusBinding(), stackEntry()) {
		t.Fatalf("the record names %v, want the entry of the stack", record.GetStatusBinding())
	}
	if record.GetDpgCredentialId() != "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56" {
		t.Fatalf("dpg_credential_id = %q, want the id the adapter revokes by", record.GetDpgCredentialId())
	}
}

func TestAnOfferDocumentOfAStackWithItsOwnListRecordsTheStackEntry(t *testing.T) {
	h := newHarness(t, func(_ *service.Options, h *harness) {
		caps := ownList()
		caps.Channels = []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH}
		h.adapter.capabilities = caps
		h.adapter.offer.Status = stackEntry()
		h.adapter.offer.CredentialId = "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56"
	})
	h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	record := h.recorder.last()
	if !proto.Equal(record.GetStatusBinding(), stackEntry()) || record.GetDpgCredentialId() == "" {
		t.Fatalf("record = %v, want the entry of the stack and its credential id", record)
	}
}

func TestAnOfferWhoseCredentialCarriesNoStatusRecordsNone(t *testing.T) {
	h := newHarness(t, func(_ *service.Options, h *harness) { h.adapter.noEcho = true })
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if record := h.recorder.last(); record.GetStatusBinding() != nil {
		t.Fatalf("the credential carries no status entry, yet the record names %v", record.GetStatusBinding())
	}
}

func TestAnOfferRecordsTheVcaEntryTheCredentialCarries(t *testing.T) {
	h := newHarness(t, nil)
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	record := h.recorder.last()
	binding := record.GetStatusBinding()
	if binding.GetListId() != "list-1" || binding.GetIndex() != 12 || binding.GetDpgList() {
		t.Fatalf("binding = %v, want the VCA entry list-1 index 12", binding)
	}
	if record.GetDpgCredentialId() != "" {
		t.Fatalf("dpg_credential_id = %q, want none for a VCA entry", record.GetDpgCredentialId())
	}
}

// TestADocumentOfAStackWithItsOwnListRecordsTheEntryOfIssue is ADR-072
// decision 2 for Issue: the answer names the entry of the list of the
// stack and the id the adapter revokes by, and the record keeps both.
func TestADocumentOfAStackWithItsOwnListRecordsTheEntryOfIssue(t *testing.T) {
	h := newHarness(t, func(_ *service.Options, h *harness) {
		h.adapter.capabilities = ownList()
		h.adapter.credential.Status = stackEntry()
		h.adapter.credential.CredentialId = "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56"
	})
	h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	if len(h.status.requests) != 0 {
		t.Fatalf("the stack embeds no entry of VCA, yet the service allocated %d index(es)", len(h.status.requests))
	}
	record := h.recorder.last()
	if !proto.Equal(record.GetStatusBinding(), stackEntry()) {
		t.Fatalf("the record names %v, want the entry of the stack", record.GetStatusBinding())
	}
	if record.GetDpgCredentialId() != "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56" {
		t.Fatalf("dpg_credential_id = %q, want the id the adapter revokes by", record.GetDpgCredentialId())
	}
}

// TestADocumentWhoseCredentialCarriesNoStatusRecordsNone: an answer of
// Issue that names no entry gives a record with no entry, on the document
// and the identity QR channels.
func TestADocumentWhoseCredentialCarriesNoStatusRecordsNone(t *testing.T) {
	for _, channel := range []backendv1.Channel{backendv1.Channel_CHANNEL_PDF, backendv1.Channel_CHANNEL_CLAIM169_QR} {
		h := newHarness(t, func(_ *service.Options, h *harness) {
			h.adapter.noEcho = true
			h.adapter.capabilities.Channels = append(h.adapter.capabilities.Channels, backendv1.Channel_CHANNEL_CLAIM169_QR)
			h.adapter.credential.Claim169Qr = identityText(t)
		})
		h.issue(t, channel, nil)
		if record := h.recorder.last(); record.GetStatusBinding() != nil {
			t.Fatalf("%v: the credential carries no status entry, yet the record names %v", channel, record.GetStatusBinding())
		}
	}
}

// TestADocumentRecordsTheVcaEntryTheAnswerNames: an adapter that embeds
// the entry of the spec names it, and the record keeps it.
func TestADocumentRecordsTheVcaEntryTheAnswerNames(t *testing.T) {
	h := newHarness(t, nil)
	h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	binding := h.recorder.last().GetStatusBinding()
	if binding.GetListId() != "list-1" || binding.GetIndex() != 12 || binding.GetDpgList() {
		t.Fatalf("binding = %v, want the VCA entry list-1 index 12", binding)
	}
}
