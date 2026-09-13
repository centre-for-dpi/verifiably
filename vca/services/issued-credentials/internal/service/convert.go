// SPDX-License-Identifier: Apache-2.0

package service

import (
	"time"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// formatNames maps the proto enum to the OID4VCI format identifier.
var formatNames = map[commonv1.Format]string{
	commonv1.Format_FORMAT_UNSPECIFIED: "",
	commonv1.Format_FORMAT_VC_SD_JWT:   "vc+sd-jwt",
	commonv1.Format_FORMAT_DC_SD_JWT:   "dc+sd-jwt",
	commonv1.Format_FORMAT_JWT_VC_JSON: "jwt_vc_json",
	commonv1.Format_FORMAT_LDP_VC:      "ldp_vc",
	commonv1.Format_FORMAT_MSO_MDOC:    "mso_mdoc",
	commonv1.Format_FORMAT_LDP_VC_BBS:  "ldp_vc_bbs",
}

// FormatName returns the OID4VCI identifier of f. An unknown value
// returns an empty string.
func FormatName(f commonv1.Format) string { return formatNames[f] }

// FormatEnum returns the proto enum of an OID4VCI identifier. An unknown
// name returns FORMAT_UNSPECIFIED.
func FormatEnum(name string) commonv1.Format {
	for k, v := range formatNames {
		if v == name && k != commonv1.Format_FORMAT_UNSPECIFIED {
			return k
		}
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// statusNames maps the proto enum to the record status.
var statusNames = map[issuedv1.Status]record.Status{
	issuedv1.Status_STATUS_UNSPECIFIED: "",
	issuedv1.Status_STATUS_ACTIVE:      record.Active,
	issuedv1.Status_STATUS_SUSPENDED:   record.Suspended,
	issuedv1.Status_STATUS_REVOKED:     record.Revoked,
	issuedv1.Status_STATUS_EXPIRED:     record.Expired,
}

// StatusOf returns the record status of s.
func StatusOf(s issuedv1.Status) record.Status { return statusNames[s] }

// StatusEnum returns the proto enum of s.
func StatusEnum(s record.Status) issuedv1.Status {
	for k, v := range statusNames {
		if v == s && k != issuedv1.Status_STATUS_UNSPECIFIED {
			return k
		}
	}
	return issuedv1.Status_STATUS_UNSPECIFIED
}

// kindNames maps the proto enum to the status list kind.
var kindNames = map[backendv1.StatusListBinding_Kind]record.StatusKind{
	backendv1.StatusListBinding_KIND_UNSPECIFIED: "",
	backendv1.StatusListBinding_KIND_BITSTRING:   record.KindBitstring,
	backendv1.StatusListBinding_KIND_TOKEN:       record.KindToken,
}

// KindEnum returns the proto enum of k.
func KindEnum(k record.StatusKind) backendv1.StatusListBinding_Kind {
	for e, v := range kindNames {
		if v == k && e != backendv1.StatusListBinding_KIND_UNSPECIFIED {
			return e
		}
	}
	return backendv1.StatusListBinding_KIND_UNSPECIFIED
}

// BindingOf returns the record binding of p.
func BindingOf(p *backendv1.StatusListBinding) record.Binding {
	if p == nil {
		return record.Binding{}
	}
	return record.Binding{
		Kind:       kindNames[p.GetKind()],
		ListID:     p.GetListId(),
		Index:      p.GetIndex(),
		PublishURL: p.GetPublishUrl(),
	}
}

// stamp returns t as a proto timestamp. A zero time returns nil.
func stamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// timeOf returns the time of p. A nil or zero p returns a zero time.
func timeOf(p *timestamppb.Timestamp) time.Time {
	if p == nil || !p.IsValid() {
		return time.Time{}
	}
	return p.AsTime()
}

// ToProto converts one record.
func ToProto(r record.Record) *issuedv1.IssuedRecord {
	out := &issuedv1.IssuedRecord{
		Id:               r.ID,
		SchemaId:         r.SchemaID,
		SchemaVersion:    int32(r.SchemaVersion),
		Subject:          &commonv1.Subject{Ref: r.SubjectRef},
		Format:           FormatEnum(r.Format),
		Status:           StatusEnum(r.Status),
		Dpg:              r.DPG,
		IssuedAt:         stamp(r.IssuedAt),
		Hash:             r.Hash,
		PreviousHash:     r.PreviousHash,
		RecordHash:       r.RecordHash,
		SearchableClaims: r.SearchableClaims,
		OfferId:          r.OfferID,
		StatusChangedAt:  stamp(r.StatusChangedAt),
		StatusReason:     r.StatusReason,
		RetainUntil:      stamp(r.RetainUntil),
	}
	if !r.Binding.IsZero() {
		out.StatusBinding = &backendv1.StatusListBinding{
			Kind:       KindEnum(r.Binding.Kind),
			ListId:     r.Binding.ListID,
			Index:      r.Binding.Index,
			PublishUrl: r.Binding.PublishURL,
		}
	}
	if !r.ValidFrom.IsZero() || !r.ValidUntil.IsZero() {
		out.Validity = &commonv1.ValidityWindow{ValidFrom: stamp(r.ValidFrom), ValidUntil: stamp(r.ValidUntil)}
	}
	return out
}

// FromProto converts one record. The service uses it to take a record
// from the issuance service.
func FromProto(p *issuedv1.IssuedRecord) record.Record {
	if p == nil {
		return record.Record{}
	}
	return record.Record{
		ID:               p.GetId(),
		SchemaID:         p.GetSchemaId(),
		SchemaVersion:    int(p.GetSchemaVersion()),
		SubjectRef:       p.GetSubject().GetRef(),
		Format:           FormatName(p.GetFormat()),
		Binding:          BindingOf(p.GetStatusBinding()),
		Status:           StatusOf(p.GetStatus()),
		DPG:              p.GetDpg(),
		IssuedAt:         timeOf(p.GetIssuedAt()),
		Hash:             p.GetHash(),
		SearchableClaims: p.GetSearchableClaims(),
		ValidFrom:        timeOf(p.GetValidity().GetValidFrom()),
		ValidUntil:       timeOf(p.GetValidity().GetValidUntil()),
		OfferID:          p.GetOfferId(),
		StatusChangedAt:  timeOf(p.GetStatusChangedAt()),
		StatusReason:     p.GetStatusReason(),
		RetainUntil:      timeOf(p.GetRetainUntil()),
	}
}

// FilterOf converts a proto filter.
func FilterOf(p *issuedv1.Filter) record.Filter {
	if p == nil {
		return record.Filter{}
	}
	return record.Filter{
		SchemaID:   p.GetSchemaId(),
		Status:     StatusOf(p.GetStatus()),
		Format:     FormatName(p.GetFormat()),
		From:       timeOf(p.GetFrom()),
		To:         timeOf(p.GetTo()),
		SubjectRef: p.GetSubjectRef(),
	}
}

// HeadToProto converts a signed head.
func HeadToProto(h headView) *issuedv1.ChainHead {
	return &issuedv1.ChainHead{
		RecordId:   h.RecordID,
		RecordHash: h.RecordHash,
		Length:     h.Length,
		SignedAt:   stamp(h.SignedAt),
		Jws:        h.JWS,
		KeyId:      h.KeyID,
	}
}

// headView is the flat form of a signed chain head.
type headView struct {
	RecordID   string
	RecordHash string
	Length     int64
	SignedAt   time.Time
	JWS        string
	KeyID      string
}
