// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// testSecurer writes the record as JSON in two media types.
type testSecurer struct {
	kind lists.Kind
	fail error
}

func (s testSecurer) Kind() lists.Kind { return s.kind }
func (s testSecurer) MediaTypes() []string {
	return []string{"application/test+json", "application/test+cbor"}
}

func (s testSecurer) Secure(rec lists.Record, issuer keys.Issuer, url string, signedAt, expiresAt time.Time) ([]lists.Unsigned, error) {
	if s.fail != nil {
		return nil, s.fail
	}
	body, _ := json.Marshal(map[string]any{
		"url": url, "iss": issuer.DID(), "values": rec.Values, "iat": signedAt.Unix(), "exp": expiresAt.Unix(),
	})
	return []lists.Unsigned{
		{MediaType: "application/test+json", Body: body},
		{MediaType: "application/test+cbor", Body: append([]byte{0xa0}, body...)},
	}, nil
}

func newService(t *testing.T, kind lists.Kind, size, pageMax int) *Service {
	t.Helper()
	kv := store.Memory()
	is, err := keys.Open(context.Background(), kv, keys.Options{Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	m, err := lists.Open(context.Background(), lists.Options{
		Store: kv, Issuers: is, Securer: testSecurer{kind: kind},
		BaseURL: "https://status.example", Size: size, TTL: time.Hour,
		Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(m, pageMax)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewChecksManager(t *testing.T) {
	if _, err := New(nil, 0); err == nil {
		t.Fatal("expected an error")
	}
	s := newService(t, lists.KindToken, 8, 0)
	if s.pageSizeMax != DefaultPageSize || !s.Ready() || s.Manager() == nil {
		t.Fatal("defaults")
	}
}

func TestAllocateSetGet(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 8, 0)
	alloc, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{
		Purpose: statusv1.Purpose_PURPOSE_SUSPENSION, Kind: statusv1.Kind_KIND_TOKEN, Bits: 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	a := alloc.Msg
	if a.GetKind() != statusv1.Kind_KIND_TOKEN || a.GetPurpose() != statusv1.Purpose_PURPOSE_SUSPENSION {
		t.Fatalf("allocation = %+v", a)
	}
	if a.GetUrl() != "https://status.example/status/"+a.GetListId() {
		t.Fatalf("url = %s", a.GetUrl())
	}
	set, err := s.SetStatus(ctx, connect.NewRequest(&statusv1.SetStatusRequest{
		ListId: a.GetListId(), Index: a.GetIndex(), Value: 2, Reason: "suspended",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if set.Msg.GetPreviousValue() != 0 || !set.Msg.GetSignedAt().AsTime().Equal(t0) {
		t.Fatalf("set = %+v", set.Msg)
	}
	got, err := s.GetStatus(ctx, connect.NewRequest(&statusv1.GetStatusRequest{
		ListId: a.GetListId(), Index: a.GetIndex(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetValue() != 2 || got.Msg.GetPurpose() != statusv1.Purpose_PURPOSE_SUSPENSION {
		t.Fatalf("get = %+v", got.Msg)
	}
	if !got.Msg.GetChangedAt().AsTime().Equal(t0) {
		t.Fatal("changed_at")
	}
	// An index that never changed has no time.
	other := a.GetIndex() + 1
	if other >= 8 {
		other = 0
	}
	fresh, err := s.GetStatus(ctx, connect.NewRequest(&statusv1.GetStatusRequest{ListId: a.GetListId(), Index: other}))
	if err != nil || fresh.Msg.GetChangedAt() != nil {
		t.Fatalf("fresh index: %v %+v", err, fresh)
	}
}

func TestAllocateRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 8, 0)
	cases := []struct {
		name string
		req  *statusv1.AllocateIndexRequest
	}{
		{"wrong kind", &statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION, Kind: statusv1.Kind_KIND_BITSTRING}},
		{"no purpose", &statusv1.AllocateIndexRequest{Kind: statusv1.Kind_KIND_TOKEN}},
		{"bad bits", &statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_MESSAGE, Bits: 3}},
		{"unknown issuer", &statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_MESSAGE, IssuerDid: "did:web:other"}},
	}
	for _, tc := range cases {
		if _, err := s.AllocateIndex(ctx, connect.NewRequest(tc.req)); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
	// A full list reports ResourceExhausted.
	small := newService(t, lists.KindToken, 1, 0)
	req := &statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION}
	if _, err := small.AllocateIndex(ctx, connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
	// The manager makes a second list, so allocation still works.
	if _, err := small.AllocateIndex(ctx, connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
}

func TestSetAndGetErrors(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 8, 0)
	a, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION}))
	if err != nil {
		t.Fatalf("s.AllocateIndex: %v", err)
	}
	id := a.Msg.GetListId()
	unused := a.Msg.GetIndex() + 1
	if unused >= 8 {
		unused = 0
	}
	cases := []struct {
		name string
		req  *statusv1.SetStatusRequest
		code connect.Code
	}{
		{"negative index", &statusv1.SetStatusRequest{ListId: id, Index: -1}, connect.CodeInvalidArgument},
		{"huge index", &statusv1.SetStatusRequest{ListId: id, Index: 1 << 40}, connect.CodeInvalidArgument},
		{"unknown list", &statusv1.SetStatusRequest{ListId: "none", Index: 0}, connect.CodeNotFound},
		{"not allocated", &statusv1.SetStatusRequest{ListId: id, Index: unused, Value: 1}, connect.CodeInvalidArgument},
		{"value too wide", &statusv1.SetStatusRequest{ListId: id, Index: a.Msg.GetIndex(), Value: 9}, connect.CodeInvalidArgument},
	}
	for _, tc := range cases {
		_, err := s.SetStatus(ctx, connect.NewRequest(tc.req))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("%s: code = %v (%v)", tc.name, connect.CodeOf(err), err)
		}
	}
	if _, err := s.GetStatus(ctx, connect.NewRequest(&statusv1.GetStatusRequest{ListId: id, Index: -1})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Error("negative index")
	}
	if _, err := s.GetStatus(ctx, connect.NewRequest(&statusv1.GetStatusRequest{ListId: "none"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Error("unknown list")
	}
	if _, err := s.GetStatus(ctx, connect.NewRequest(&statusv1.GetStatusRequest{ListId: id, Index: 99})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Error("index past the end")
	}
}

func TestGetList(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 8, 0)
	a, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION}))
	if err != nil {
		t.Fatalf("s.AllocateIndex: %v", err)
	}
	id := a.Msg.GetListId()
	def, err := s.GetList(ctx, connect.NewRequest(&statusv1.GetListRequest{ListId: id}))
	if err != nil {
		t.Fatal(err)
	}
	if def.Msg.GetMediaType() != "application/test+json" || len(def.Msg.GetBody()) == 0 {
		t.Fatalf("default = %+v", def.Msg)
	}
	if !strings.HasPrefix(def.Msg.GetEtag(), `"`) || def.Msg.GetList().GetId() != id {
		t.Fatalf("etag or list = %+v", def.Msg)
	}
	if def.Msg.GetList().GetSize() != 8 || def.Msg.GetList().GetAllocated() != 1 {
		t.Fatalf("list = %+v", def.Msg.GetList())
	}
	if !def.Msg.GetExpiresAt().AsTime().Equal(t0.Add(time.Hour)) {
		t.Fatal("expires_at")
	}
	second, err := s.GetList(ctx, connect.NewRequest(&statusv1.GetListRequest{ListId: id, Accept: "application/test+cbor"}))
	if err != nil || second.Msg.GetMediaType() != "application/test+cbor" {
		t.Fatalf("cbor: %v", err)
	}
	if _, err := s.GetList(ctx, connect.NewRequest(&statusv1.GetListRequest{ListId: id, Accept: "text/plain"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Error("unknown media type")
	}
	if _, err := s.GetList(ctx, connect.NewRequest(&statusv1.GetListRequest{ListId: "none"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Error("unknown list")
	}
}

func TestListLists(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 1, 2)
	for i := 0; i < 3; i++ {
		if _, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_SUSPENSION})); err != nil {
		t.Fatal(err)
	}
	first, err := s.ListLists(ctx, connect.NewRequest(&statusv1.ListListsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.GetLists()) != 2 || first.Msg.GetPage().GetTotalSize() != 4 {
		t.Fatalf("page = %+v", first.Msg.GetPage())
	}
	next := first.Msg.GetPage().GetNextPageToken()
	if next == "" {
		t.Fatal("next page token")
	}
	second, err := s.ListLists(ctx, connect.NewRequest(&statusv1.ListListsRequest{
		Page: &commonv1.Pagination{PageSize: 10, PageToken: next},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetLists()) != 2 || second.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("second page = %+v", second.Msg)
	}
	filtered, err := s.ListLists(ctx, connect.NewRequest(&statusv1.ListListsRequest{
		Purpose: statusv1.Purpose_PURPOSE_SUSPENSION,
	}))
	if err != nil || len(filtered.Msg.GetLists()) != 1 {
		t.Fatalf("filter: %v", err)
	}
	bad := []*statusv1.ListListsRequest{
		{Kind: statusv1.Kind_KIND_BITSTRING},
		{Purpose: statusv1.Purpose(99)},
		{Page: &commonv1.Pagination{PageToken: "abc"}},
	}
	for i, req := range bad {
		if _, err := s.ListLists(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestRotateKey(t *testing.T) {
	ctx := context.Background()
	s := newService(t, lists.KindToken, 8, 0)
	if _, err := s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION})); err != nil {
		t.Fatal(err)
	}
	rot, err := s.RotateKey(ctx, connect.NewRequest(&statusv1.RotateKeyRequest{Algorithm: "EdDSA"}))
	if err != nil {
		t.Fatal(err)
	}
	if rot.Msg.GetListsSigned() != 1 || rot.Msg.GetKeyId() == rot.Msg.GetPreviousKeyId() {
		t.Fatalf("rotation = %+v", rot.Msg)
	}
	_, err = s.RotateKey(ctx, connect.NewRequest(&statusv1.RotateKeyRequest{IssuerDid: "did:web:other"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("err = %v", err)
	}
}

func TestWrapMapsCodes(t *testing.T) {
	cases := []struct {
		err  error
		code connect.Code
	}{
		{lists.ErrNotFound, connect.CodeNotFound},
		{keys.ErrUnknownIssuer, connect.CodeNotFound},
		{lists.ErrFull, connect.CodeResourceExhausted},
		{lists.ErrNotAllocated, connect.CodeInvalidArgument},
		{lists.ErrBadPurpose, connect.CodeInvalidArgument},
		{lists.ErrBadKind, connect.CodeInvalidArgument},
		{lists.ErrBadValue, connect.CodeInvalidArgument},
		{lists.ErrOutOfRange, connect.CodeInvalidArgument},
		{context.Canceled, connect.CodeCanceled},
		{context.DeadlineExceeded, connect.CodeCanceled},
		{errors.New("hsm down"), connect.CodeInternal},
	}
	for _, tc := range cases {
		if got := connect.CodeOf(wrap(tc.err)); got != tc.code {
			t.Errorf("%v: code = %v", tc.err, got)
		}
	}
}

func TestPurposeMapping(t *testing.T) {
	if toProtoPurpose("other") != statusv1.Purpose_PURPOSE_UNSPECIFIED {
		t.Fatal("unknown purpose")
	}
	if toProtoKind(lists.KindBitstring) != statusv1.Kind_KIND_BITSTRING {
		t.Fatal("bitstring kind")
	}
}

func TestSignerFailureIsInternal(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	is, err := keys.Open(ctx, kv, keys.Options{Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatalf("keys.Open: %v", err)
	}
	m, err := lists.Open(ctx, lists.Options{
		Store: kv, Issuers: is, Securer: testSecurer{kind: lists.KindToken, fail: errors.New("hsm down")},
		Size: 8, Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(m, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = s.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{Purpose: statusv1.Purpose_PURPOSE_REVOCATION}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("err = %v", err)
	}
}
