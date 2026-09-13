// SPDX-License-Identifier: Apache-2.0

// Package rpc implements vca.status.v1.StatusService over a list
// manager. The bitstring service and the token service share it
// (ADR-019 decision 4). The manager holds one kind of list. A request
// for the other kind fails with InvalidArgument.
//
// Allocation and the status flip are RPCs, as ADR-018 decision 4 asks.
// The public list itself is a plain HTTP GET, served by the httpapi
// package over the same manager.
package rpc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// Service is the StatusService handler.
type Service struct {
	statusv1connect.UnimplementedStatusServiceHandler
	manager     *lists.Manager
	pageSizeMax int
}

// New builds the service over m. pageSizeMax caps ListLists. Zero means
// DefaultPageSize.
func New(m *lists.Manager, pageSizeMax int) (*Service, error) {
	if m == nil {
		return nil, errors.New("rpc: a manager is required")
	}
	if pageSizeMax <= 0 {
		pageSizeMax = DefaultPageSize
	}
	return &Service{manager: m, pageSizeMax: pageSizeMax}, nil
}

// Manager returns the manager the service uses.
func (s *Service) Manager() *lists.Manager { return s.manager }

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s.manager != nil }

// AllocateIndex reserves one random index (ADR-018 decision 4).
func (s *Service) AllocateIndex(ctx context.Context, req *connect.Request[statusv1.AllocateIndexRequest]) (*connect.Response[statusv1.AllocateIndexResponse], error) {
	msg := req.Msg
	if err := s.checkKind(msg.GetKind()); err != nil {
		return nil, err
	}
	purpose, err := fromProtoPurpose(msg.GetPurpose())
	if err != nil {
		return nil, err
	}
	a, err := s.manager.Allocate(ctx, msg.GetIssuerDid(), purpose, int(msg.GetBits()))
	if err != nil {
		return nil, wrap(err)
	}
	return connect.NewResponse(&statusv1.AllocateIndexResponse{
		ListId:  a.ListID,
		Index:   int64(a.Index),
		Url:     a.URL,
		Kind:    toProtoKind(s.manager.Kind()),
		Purpose: msg.GetPurpose(),
	}), nil
}

// SetStatus writes one value and signs the list again.
func (s *Service) SetStatus(ctx context.Context, req *connect.Request[statusv1.SetStatusRequest]) (*connect.Response[statusv1.SetStatusResponse], error) {
	msg := req.Msg
	idx, err := index(msg.GetIndex())
	if err != nil {
		return nil, err
	}
	prev, signed, err := s.manager.Set(ctx, msg.GetListId(), idx, int(msg.GetValue()))
	if err != nil {
		return nil, wrap(err)
	}
	return connect.NewResponse(&statusv1.SetStatusResponse{
		PreviousValue: int32(prev),
		SignedAt:      timestamppb.New(signed.SignedAt),
	}), nil
}

// GetStatus reads one value.
func (s *Service) GetStatus(_ context.Context, req *connect.Request[statusv1.GetStatusRequest]) (*connect.Response[statusv1.GetStatusResponse], error) {
	idx, err := index(req.Msg.GetIndex())
	if err != nil {
		return nil, err
	}
	st, err := s.manager.Get(req.Msg.GetListId(), idx)
	if err != nil {
		return nil, wrap(err)
	}
	out := &statusv1.GetStatusResponse{Value: int32(st.Value), Purpose: toProtoPurpose(st.Purpose)}
	if st.Changed {
		out.ChangedAt = timestamppb.New(st.ChangedAt)
	}
	return connect.NewResponse(out), nil
}

// GetList returns the signed bytes the HTTP endpoint serves.
func (s *Service) GetList(ctx context.Context, req *connect.Request[statusv1.GetListRequest]) (*connect.Response[statusv1.GetListResponse], error) {
	rec, signed, err := s.manager.Signed(ctx, req.Msg.GetListId())
	if err != nil {
		return nil, wrap(err)
	}
	accept := req.Msg.GetAccept()
	art, ok := signed.Artifact(accept)
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("rpc: this service does not serve %q", accept))
	}
	return connect.NewResponse(&statusv1.GetListResponse{
		Body:      art.Body,
		MediaType: art.MediaType,
		Etag:      art.ETag,
		SignedAt:  timestamppb.New(signed.SignedAt),
		ExpiresAt: timestamppb.New(signed.ExpiresAt),
		List:      s.describe(rec, signed),
	}), nil
}

// ListLists returns one page of lists.
func (s *Service) ListLists(_ context.Context, req *connect.Request[statusv1.ListListsRequest]) (*connect.Response[statusv1.ListListsResponse], error) {
	msg := req.Msg
	if err := s.checkKind(msg.GetKind()); err != nil {
		return nil, err
	}
	var purpose lists.Purpose
	if msg.GetPurpose() != statusv1.Purpose_PURPOSE_UNSPECIFIED {
		p, err := fromProtoPurpose(msg.GetPurpose())
		if err != nil {
			return nil, err
		}
		purpose = p
	}
	size := int(msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	page, err := s.manager.List(purpose, size, msg.GetPage().GetPageToken())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	out := &statusv1.ListListsResponse{
		Page: &commonv1.PageResult{NextPageToken: page.NextToken, TotalSize: int64(page.Total)},
	}
	for _, e := range page.Entries {
		out.Lists = append(out.Lists, s.describe(e.Record, e.Signed))
	}
	return connect.NewResponse(out), nil
}

// RotateKey creates a new key and signs every list of the issuer again
// (ADR-018 decision 6).
func (s *Service) RotateKey(ctx context.Context, req *connect.Request[statusv1.RotateKeyRequest]) (*connect.Response[statusv1.RotateKeyResponse], error) {
	alg := jose.Algorithm(req.Msg.GetAlgorithm())
	rot, err := s.manager.Rotate(ctx, req.Msg.GetIssuerDid(), alg)
	if err != nil {
		return nil, wrap(err)
	}
	return connect.NewResponse(&statusv1.RotateKeyResponse{
		KeyId:         rot.KeyID,
		PreviousKeyId: rot.PreviousKeyID,
		ListsSigned:   int32(rot.ListsSigned),
	}), nil
}

// describe maps a record and its signature to the proto message.
func (s *Service) describe(rec lists.Record, signed lists.Signed) *statusv1.StatusList {
	out := &statusv1.StatusList{
		Id:        rec.ID,
		Kind:      toProtoKind(rec.Kind),
		Purpose:   toProtoPurpose(rec.Purpose),
		Url:       s.manager.URL(rec.ID),
		Size:      int64(rec.Size),
		Bits:      int32(rec.Bits),
		Allocated: int64(rec.AllocatedCount),
		IssuerDid: signed.IssuerDID,
		KeyId:     signed.KeyID,
		CreatedAt: timestamppb.New(rec.CreatedAt),
	}
	if !signed.SignedAt.IsZero() {
		out.SignedAt = timestamppb.New(signed.SignedAt)
		out.ExpiresAt = timestamppb.New(signed.ExpiresAt)
	}
	return out
}

// checkKind accepts the kind of this service and the unspecified kind.
func (s *Service) checkKind(k statusv1.Kind) error {
	if k == statusv1.Kind_KIND_UNSPECIFIED || k == toProtoKind(s.manager.Kind()) {
		return nil
	}
	return connect.NewError(connect.CodeInvalidArgument,
		fmt.Errorf("rpc: this service serves %s lists only", s.manager.Kind()))
}

func index(i int64) (int, error) {
	if i < 0 || i > 1<<31 {
		return 0, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("rpc: index %d is out of range", i))
	}
	return int(i), nil
}

func toProtoKind(k lists.Kind) statusv1.Kind {
	if k == lists.KindToken {
		return statusv1.Kind_KIND_TOKEN
	}
	return statusv1.Kind_KIND_BITSTRING
}

// purposeNames maps the two directions of the purpose enum.
var purposeNames = map[statusv1.Purpose]lists.Purpose{
	statusv1.Purpose_PURPOSE_REVOCATION: lists.Revocation,
	statusv1.Purpose_PURPOSE_SUSPENSION: lists.Suspension,
	statusv1.Purpose_PURPOSE_MESSAGE:    lists.Message,
}

func fromProtoPurpose(p statusv1.Purpose) (lists.Purpose, error) {
	if out, ok := purposeNames[p]; ok {
		return out, nil
	}
	return "", connect.NewError(connect.CodeInvalidArgument,
		fmt.Errorf("rpc: purpose must be revocation, suspension, or message, got %s", p))
}

func toProtoPurpose(p lists.Purpose) statusv1.Purpose {
	for k, v := range purposeNames {
		if v == p {
			return k
		}
	}
	return statusv1.Purpose_PURPOSE_UNSPECIFIED
}

// wrap maps a manager error to a Connect code.
func wrap(err error) error {
	switch {
	case errors.Is(err, lists.ErrNotFound), errors.Is(err, keys.ErrUnknownIssuer):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, lists.ErrFull):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, lists.ErrNotAllocated), errors.Is(err, lists.ErrBadPurpose),
		errors.Is(err, lists.ErrBadKind), errors.Is(err, lists.ErrBadValue),
		errors.Is(err, lists.ErrOutOfRange):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeCanceled, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}
