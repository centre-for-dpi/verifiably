// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
)

func TestFormatNames(t *testing.T) {
	for name, want := range map[string]commonv1.Format{
		"vc+sd-jwt":   commonv1.Format_FORMAT_VC_SD_JWT,
		"dc+sd-jwt":   commonv1.Format_FORMAT_DC_SD_JWT,
		"jwt_vc_json": commonv1.Format_FORMAT_JWT_VC_JSON,
		"ldp_vc":      commonv1.Format_FORMAT_LDP_VC,
		"mso_mdoc":    commonv1.Format_FORMAT_MSO_MDOC,
		"ldp_vc_bbs":  commonv1.Format_FORMAT_LDP_VC_BBS,
	} {
		if got := service.FormatEnum(name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
		if back := service.FormatName(want); back != name {
			t.Errorf("%v = %q, want %q", want, back, name)
		}
	}
	if got := service.FormatEnum("no such format"); got != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Errorf("an unknown name = %v", got)
	}
	if got := service.FormatName(commonv1.Format(99)); got != "" {
		t.Errorf("an unknown enum = %q", got)
	}
}

func TestStatusAndKindEnums(t *testing.T) {
	if got := service.StatusEnum("not a status"); got != issuedv1.Status_STATUS_UNSPECIFIED {
		t.Errorf("status = %v", got)
	}
	if got := service.StatusEnum(record.Expired); got != issuedv1.Status_STATUS_EXPIRED {
		t.Errorf("expired = %v", got)
	}
	if got := service.StatusOf(issuedv1.Status(9)); got != "" {
		t.Errorf("an unknown status = %q", got)
	}
	if got := service.KindEnum(record.KindToken); got != backendv1.StatusListBinding_KIND_TOKEN {
		t.Errorf("token = %v", got)
	}
	if got := service.KindEnum("other"); got != backendv1.StatusListBinding_KIND_UNSPECIFIED {
		t.Errorf("an unknown kind = %v", got)
	}
	if got := service.BindingOf(nil); !got.IsZero() {
		t.Errorf("a nil binding = %+v", got)
	}
}

func TestProtoRoundTrip(t *testing.T) {
	issued := time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)
	in := record.Record{
		ID: "r1", SchemaID: "diploma", SchemaVersion: 3, SubjectRef: "ref",
		Format: "ldp_vc", Status: record.Suspended, DPG: "credebl", IssuedAt: issued,
		Binding: record.Binding{Kind: record.KindToken, ListID: "v2", Index: 7, PublishURL: "https://example.org/l"},
		Hash:    "h", PreviousHash: "p", RecordHash: "rh",
		SearchableClaims: map[string]string{"name": "Wanjiru"},
		ValidFrom:        issued, ValidUntil: issued.AddDate(1, 0, 0),
		OfferID: "offer-1", StatusChangedAt: issued.Add(time.Hour), StatusReason: "review",
		RetainUntil: issued.AddDate(5, 0, 0),
	}
	back := service.FromProto(service.ToProto(in))
	// FromProto does not carry the chain hashes. The store sets them.
	in.PreviousHash, in.RecordHash = "", ""
	if back.ID != in.ID || back.Format != in.Format || back.Binding != in.Binding {
		t.Errorf("record = %+v, want %+v", back, in)
	}
	if !back.IssuedAt.Equal(in.IssuedAt) || !back.ValidUntil.Equal(in.ValidUntil) {
		t.Errorf("times = %v %v", back.IssuedAt, back.ValidUntil)
	}
	if back.Status != record.Suspended || back.StatusReason != "review" {
		t.Errorf("status = %q %q", back.Status, back.StatusReason)
	}
	if back.SearchableClaims["name"] != "Wanjiru" {
		t.Errorf("claims = %v", back.SearchableClaims)
	}
	if got := service.FromProto(nil); got.ID != "" {
		t.Errorf("a nil record = %+v", got)
	}
	if got := service.FilterOf(nil); got.SchemaID != "" {
		t.Errorf("a nil filter = %+v", got)
	}
}

func TestToProtoLeavesEmptyFieldsOut(t *testing.T) {
	p := service.ToProto(record.Record{ID: "r1"})
	if p.GetStatusBinding() != nil || p.GetValidity() != nil || p.GetIssuedAt() != nil {
		t.Errorf("record = %+v", p)
	}
}

func TestFromProtoIgnoresAnInvalidTimestamp(t *testing.T) {
	p := &issuedv1.IssuedRecord{Id: "r1", IssuedAt: &timestamppb.Timestamp{Seconds: -1 << 62}}
	if got := service.FromProto(p); !got.IssuedAt.IsZero() {
		t.Errorf("issued at = %v, want a zero time", got.IssuedAt)
	}
}

// TestDpgOfferIDRoundTrips keeps the offer id of the adapter, which the
// pages need to read the claim state of an offer.
func TestDpgOfferIDRoundTrips(t *testing.T) {
	in := &issuedv1.IssuedRecord{Id: "r1", SchemaId: "farmer", SchemaVersion: 1, OfferId: "vca-1", DpgOfferId: "dpg-7"}
	r := service.FromProto(in)
	if r.DPGOfferID != "dpg-7" || r.OfferID != "vca-1" {
		t.Fatalf("record = %+v", r)
	}
	if got := service.ToProto(r).GetDpgOfferId(); got != "dpg-7" {
		t.Fatalf("proto dpg_offer_id = %q", got)
	}
}
