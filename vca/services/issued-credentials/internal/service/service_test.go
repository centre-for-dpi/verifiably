// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
)

// fakeStatus is a StatusService Connect client for the tests. Only
// SetStatus does anything.
type fakeStatus struct {
	statusv1connect.StatusServiceClient
	calls []*statusv1.SetStatusRequest
	err   error
}

func (f *fakeStatus) SetStatus(_ context.Context, req *connect.Request[statusv1.SetStatusRequest]) (*connect.Response[statusv1.SetStatusResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, req.Msg)
	return connect.NewResponse(&statusv1.SetStatusResponse{}), nil
}

var clock = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type fixture struct {
	svc    *service.Service
	status *fakeStatus
	store  *store.Store
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(store.Memory())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	key, err := head.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	signer, err := head.NewSigner(head.Options{Key: key, Issuer: "issuer.example"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	policy, err := retention.Parse("default=1y,visitor=30d")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	f := &fixture{status: &fakeStatus{}, store: st, now: clock}
	svc, err := service.New(service.Options{
		Store:     st,
		Status:    f.status,
		Head:      signer,
		Retention: policy,
		Salt:      "pepper",
		Now:       func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	f.svc = svc
	return f
}

// add appends one record with a status list binding.
func (f *fixture) add(t *testing.T, id, schema string, day int, claims map[string]string) record.Record {
	t.Helper()
	r := record.Record{
		ID: id, SchemaID: schema, SchemaVersion: 1,
		SubjectRef:       f.svc.SubjectRef("subject-" + id),
		Format:           "dc+sd-jwt",
		DPG:              "waltid",
		IssuedAt:         clock.AddDate(0, 0, day),
		Binding:          record.Binding{Kind: record.KindBitstring, ListID: "v1", Index: int64(day)},
		SearchableClaims: claims,
	}
	got, err := f.svc.AppendRecord(r)
	if err != nil {
		t.Fatalf("append %s: %v", id, err)
	}
	return got
}

func TestNewNeedsAStore(t *testing.T) {
	if _, err := service.New(service.Options{}); err == nil {
		t.Fatal("want an error without a store")
	}
}

func TestAppendFillsRetentionAndSubjectRef(t *testing.T) {
	f := newFixture(t)
	if !f.svc.Ready() {
		t.Error("the service must be ready")
	}
	got := f.add(t, "r1", "visitor", 0, map[string]string{"name": "Wanjiru"})
	want := clock.Add(30 * retention.Day)
	if !got.RetainUntil.Equal(want) {
		t.Errorf("retain until = %v, want %v", got.RetainUntil, want)
	}
	if got.SubjectRef == "subject-r1" || len(got.SubjectRef) != 64 {
		t.Errorf("the subject reference must be a salted hash, got %q", got.SubjectRef)
	}
	// An issuance without a time uses the clock.
	r := record.Record{ID: "r2", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref"}
	stored, err := f.svc.AppendRecord(r)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if !stored.IssuedAt.Equal(clock) {
		t.Errorf("issued at = %v, want %v", stored.IssuedAt, clock)
	}
	if !stored.RetainUntil.Equal(clock.Add(retention.Year)) {
		t.Errorf("retain until = %v", stored.RetainUntil)
	}
}

func TestListPagesAndFilters(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, nil)
	f.add(t, "b", "licence", 1, nil)
	f.add(t, "c", "diploma", 2, nil)
	ctx := context.Background()
	resp, err := f.svc.List(ctx, connect.NewRequest(&issuedv1.ListRequest{
		Page: &commonv1.Pagination{PageSize: 2},
	}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Msg.GetRecords()) != 2 || resp.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("page = %+v", resp.Msg.GetPage())
	}
	if resp.Msg.GetRecords()[0].GetId() != "c" {
		t.Errorf("the newest record comes first, got %q", resp.Msg.GetRecords()[0].GetId())
	}
	next := resp.Msg.GetPage().GetNextPageToken()
	if next == "" {
		t.Fatal("want a next page token")
	}
	second, err := f.svc.List(ctx, connect.NewRequest(&issuedv1.ListRequest{
		Page: &commonv1.Pagination{PageSize: 2, PageToken: next},
	}))
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Msg.GetRecords()) != 1 || second.Msg.GetPage().GetNextPageToken() != "" {
		t.Errorf("second page = %+v", second.Msg)
	}
	filtered, err := f.svc.List(ctx, connect.NewRequest(&issuedv1.ListRequest{
		Filter: &issuedv1.Filter{SchemaId: "diploma", Format: commonv1.Format_FORMAT_DC_SD_JWT},
	}))
	if err != nil {
		t.Fatalf("filtered: %v", err)
	}
	if len(filtered.Msg.GetRecords()) != 2 {
		t.Errorf("records = %d, want 2", len(filtered.Msg.GetRecords()))
	}
	if _, err := f.svc.List(ctx, connect.NewRequest(&issuedv1.ListRequest{
		Page: &commonv1.Pagination{PageToken: "no"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
}

func TestListReportsAnExpiredCredential(t *testing.T) {
	f := newFixture(t)
	r := record.Record{
		ID: "old", SchemaID: "visitor", SchemaVersion: 1, SubjectRef: "ref",
		IssuedAt: clock, ValidUntil: clock.Add(time.Hour),
	}
	if _, err := f.svc.AppendRecord(r); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.now = clock.Add(2 * time.Hour)
	resp, err := f.svc.List(context.Background(), connect.NewRequest(&issuedv1.ListRequest{
		Filter: &issuedv1.Filter{Status: issuedv1.Status_STATUS_EXPIRED},
	}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Msg.GetRecords()) != 1 {
		t.Fatalf("records = %d, want 1", len(resp.Msg.GetRecords()))
	}
	if resp.Msg.GetRecords()[0].GetStatus() != issuedv1.Status_STATUS_EXPIRED {
		t.Errorf("status = %v", resp.Msg.GetRecords()[0].GetStatus())
	}
}

func TestSearch(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, map[string]string{"name": "Wanjiru"})
	f.add(t, "b", "diploma", 1, map[string]string{"name": "Otieno"})
	ctx := context.Background()
	resp, err := f.svc.Search(ctx, connect.NewRequest(&issuedv1.SearchRequest{Query: " wanj "}))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(resp.Msg.GetRecords()) != 1 || resp.Msg.GetRecords()[0].GetId() != "a" {
		t.Errorf("records = %+v", resp.Msg.GetRecords())
	}
	all, err := f.svc.Search(ctx, connect.NewRequest(&issuedv1.SearchRequest{
		Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		t.Fatalf("search all: %v", err)
	}
	if all.Msg.GetPage().GetTotalSize() != 2 || len(all.Msg.GetRecords()) != 1 {
		t.Errorf("page = %+v", all.Msg.GetPage())
	}
	long := connect.NewRequest(&issuedv1.SearchRequest{Query: strings.Repeat("x", record.MaxQuery+1)})
	if _, err := f.svc.Search(ctx, long); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
	bad := connect.NewRequest(&issuedv1.SearchRequest{Page: &commonv1.Pagination{PageToken: "no"}})
	if _, err := f.svc.Search(ctx, bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
}

func TestGet(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, map[string]string{"name": "Wanjiru"})
	ctx := context.Background()
	resp, err := f.svc.Get(ctx, connect.NewRequest(&issuedv1.GetRequest{Id: "a"}))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got := resp.Msg.GetRecord()
	if got.GetId() != "a" || got.GetDpg() != "waltid" {
		t.Errorf("record = %+v", got)
	}
	if got.GetStatusBinding().GetKind() != backendv1.StatusListBinding_KIND_BITSTRING {
		t.Errorf("binding = %+v", got.GetStatusBinding())
	}
	if got.GetSubject().GetDid() != "" {
		t.Error("the record must never carry a subject DID")
	}
	if _, err := f.svc.Get(ctx, connect.NewRequest(&issuedv1.GetRequest{Id: "gone"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("err = %v, want not found", err)
	}
}

func TestRevokeAndReinstate(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, nil)
	ctx := context.Background()
	resp, err := f.svc.Revoke(ctx, connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "under review",
	}))
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if resp.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_SUSPENDED {
		t.Errorf("status = %v", resp.Msg.GetRecord().GetStatus())
	}
	if resp.Msg.GetRecord().GetStatusReason() != "under review" {
		t.Errorf("reason = %q", resp.Msg.GetRecord().GetStatusReason())
	}
	if len(f.status.calls) != 1 || f.status.calls[0].GetValue() != 1 || f.status.calls[0].GetListId() != "v1" {
		t.Fatalf("status calls = %+v", f.status.calls)
	}
	back, err := f.svc.Reinstate(ctx, connect.NewRequest(&issuedv1.ReinstateRequest{Id: "a", Reason: "cleared"}))
	if err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if back.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_ACTIVE {
		t.Errorf("status = %v", back.Msg.GetRecord().GetStatus())
	}
	if len(f.status.calls) != 2 || f.status.calls[1].GetValue() != 0 {
		t.Fatalf("status calls = %+v", f.status.calls)
	}
	final, err := f.svc.Revoke(ctx, connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_REVOKED, Reason: "fraud",
	}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if final.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_REVOKED {
		t.Errorf("status = %v", final.Msg.GetRecord().GetStatus())
	}
	// A revoked credential stays revoked.
	_, err = f.svc.Revoke(ctx, connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "again",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("err = %v, want failed precondition", err)
	}
}

func TestRevokeRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, nil)
	ctx := context.Background()
	cases := []struct {
		name string
		req  *issuedv1.RevokeRequest
		want connect.Code
	}{
		{"status", &issuedv1.RevokeRequest{Id: "a", Status: issuedv1.Status_STATUS_ACTIVE, Reason: "x"}, connect.CodeInvalidArgument},
		{"reason", &issuedv1.RevokeRequest{Id: "a", Status: issuedv1.Status_STATUS_REVOKED, Reason: "  "}, connect.CodeInvalidArgument},
		{"missing", &issuedv1.RevokeRequest{Id: "gone", Status: issuedv1.Status_STATUS_REVOKED, Reason: "x"}, connect.CodeNotFound},
	}
	for _, c := range cases {
		if _, err := f.svc.Revoke(ctx, connect.NewRequest(c.req)); connect.CodeOf(err) != c.want {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestRevokeNeedsAStatusListBinding(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.AppendRecord(record.Record{
		ID: "nobinding", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_, err := f.svc.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "nobinding", Status: issuedv1.Status_STATUS_REVOKED, Reason: "x",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !errors.Is(err, record.ErrNoBinding) {
		t.Errorf("err = %v, want ErrNoBinding", err)
	}
}

func TestRevokeReportsAStatusServiceFailure(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, nil)
	f.status.err = errors.New("status is down")
	_, err := f.svc.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_REVOKED, Reason: "x",
	}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) || len(cerr.Details()) != 1 {
		t.Fatalf("want one error detail, got %v", err)
	}
	if got, _ := f.svc.Get(context.Background(), connect.NewRequest(&issuedv1.GetRequest{Id: "a"})); got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_ACTIVE {
		t.Error("a failed status call must leave the record active")
	}
}

func TestRevokeWithoutAStatusClient(t *testing.T) {
	st, err := store.Open(store.Memory())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc, err := service.New(service.Options{Store: st, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := svc.AppendRecord(record.Record{
		ID: "a", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
		Binding: record.Binding{Kind: record.KindToken, ListID: "v1", Index: 1},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_, err = svc.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_REVOKED, Reason: "x",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("err = %v, want failed precondition", err)
	}
	if _, err := svc.GetChainHead(context.Background(), connect.NewRequest(&issuedv1.GetChainHeadRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("err = %v, want failed precondition without a key", err)
	}
	if _, err := svc.SignedHead(); err == nil {
		t.Error("want an error without a key")
	}
}

func TestReinstateNeedsASuspension(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, nil)
	ctx := context.Background()
	if _, err := f.svc.Reinstate(ctx, connect.NewRequest(&issuedv1.ReinstateRequest{Id: "a", Reason: "x"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("err = %v, want failed precondition", err)
	}
	if _, err := f.svc.Reinstate(ctx, connect.NewRequest(&issuedv1.ReinstateRequest{Id: "gone", Reason: "x"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("err = %v, want not found", err)
	}
	if _, err := f.svc.Revoke(ctx, connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "review",
	})); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := f.svc.Reinstate(ctx, connect.NewRequest(&issuedv1.ReinstateRequest{Id: "a", Reason: " "})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
}

// exportStream collects the chunks of one Export call.
type exportStream struct {
	chunks [][]byte
	done   []bool
	err    error
}

func (e *exportStream) Send(msg *issuedv1.ExportResponse) error {
	if e.err != nil {
		return e.err
	}
	e.chunks = append(e.chunks, msg.GetChunk())
	e.done = append(e.done, msg.GetDone())
	return nil
}

func (e *exportStream) body() string {
	var out []byte
	for _, c := range e.chunks {
		out = append(out, c...)
	}
	return string(out)
}

func TestExportEncodings(t *testing.T) {
	f := newFixture(t)
	f.add(t, "a", "diploma", 0, map[string]string{"name": "Wanjiru"})
	f.add(t, "b", "licence", 1, nil)
	ctx := context.Background()
	cases := []struct {
		name     string
		encoding issuedv1.ExportRequest_Encoding
		want     string
	}{
		{"default", issuedv1.ExportRequest_ENCODING_UNSPECIFIED, "id,schema_id,"},
		{"csv", issuedv1.ExportRequest_ENCODING_CSV, "id,schema_id,"},
		{"json", issuedv1.ExportRequest_ENCODING_JSON, `{"id":"b"`},
	}
	for _, c := range cases {
		stream := &exportStream{}
		if err := f.svc.ExportTo(ctx, &issuedv1.ExportRequest{Encoding: c.encoding}, stream); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !strings.HasPrefix(stream.body(), c.want) {
			t.Errorf("%s: body = %.40q, want the prefix %q", c.name, stream.body(), c.want)
		}
		if !stream.done[len(stream.done)-1] {
			t.Errorf("%s: the last chunk must be done", c.name)
		}
	}
	bad := &issuedv1.ExportRequest{Encoding: issuedv1.ExportRequest_Encoding(9)}
	if err := f.svc.ExportTo(ctx, bad, &exportStream{}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
	if err := f.svc.ExportTo(ctx, &issuedv1.ExportRequest{}, &exportStream{err: errors.New("gone")}); err == nil {
		t.Error("a send failure must reach the caller")
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.svc.ExportTo(stopped, &issuedv1.ExportRequest{}, &exportStream{}); err == nil {
		t.Error("a cancelled context must stop the export")
	}
}

func TestExportWritesEveryChunk(t *testing.T) {
	st, err := store.Open(store.Memory())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc, err := service.New(service.Options{
		Store:     st,
		ChunkSize: 64,
		Now:       func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := range 5 {
		if _, err := svc.AppendRecord(record.Record{
			ID: string(rune('a' + i)), SchemaID: "diploma", SchemaVersion: 1,
			SubjectRef: "ref", IssuedAt: clock,
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	stream := &exportStream{}
	if err := svc.ExportTo(context.Background(), &issuedv1.ExportRequest{}, stream); err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(stream.chunks) < 2 {
		t.Fatalf("chunks = %d, want more than one", len(stream.chunks))
	}
	if !stream.done[len(stream.done)-1] || stream.done[0] {
		t.Errorf("only the last chunk is done, got %v", stream.done)
	}
	if !strings.HasPrefix(stream.body(), "id,schema_id,") {
		t.Errorf("body = %.40q", stream.body())
	}
}

func TestChainHeadAndVerify(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.GetChainHead(ctx, connect.NewRequest(&issuedv1.GetChainHeadRequest{})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an empty log has no head, err = %v", err)
	}
	f.add(t, "a", "diploma", 0, nil)
	f.add(t, "b", "diploma", 1, nil)
	resp, err := f.svc.GetChainHead(ctx, connect.NewRequest(&issuedv1.GetChainHeadRequest{}))
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	got := resp.Msg.GetHead()
	if got.GetLength() != 2 || got.GetRecordId() != "b" || got.GetJws() == "" || got.GetKeyId() == "" {
		t.Fatalf("head = %+v", got)
	}
	flat, err := f.svc.SignedHead()
	if err != nil {
		t.Fatalf("signed head: %v", err)
	}
	if flat.GetJws() != got.GetJws() {
		t.Error("SignedHead must return the same signature")
	}
	walk, err := f.svc.VerifyChain(ctx, connect.NewRequest(&issuedv1.VerifyChainRequest{}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !walk.Msg.GetOk() || walk.Msg.GetChecked() != 2 || walk.Msg.GetHead().GetLength() != 2 {
		t.Errorf("verify = %+v", walk.Msg)
	}
	from, err := f.svc.VerifyChain(ctx, connect.NewRequest(&issuedv1.VerifyChainRequest{FromRecordId: "b"}))
	if err != nil {
		t.Fatalf("verify from b: %v", err)
	}
	if from.Msg.GetChecked() != 1 {
		t.Errorf("checked = %d, want 1", from.Msg.GetChecked())
	}
	if _, err := f.svc.VerifyChain(ctx, connect.NewRequest(&issuedv1.VerifyChainRequest{FromRecordId: "ghost"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("err = %v, want not found", err)
	}
}

func TestPrune(t *testing.T) {
	f := newFixture(t)
	f.add(t, "short", "visitor", 0, nil)
	f.add(t, "long", "diploma", 0, nil)
	if n, err := f.svc.PruneDue(); err != nil || n != 0 {
		t.Fatalf("early prune = %d %v", n, err)
	}
	f.now = clock.Add(40 * retention.Day)
	n, err := f.svc.PruneDue()
	if err != nil || n != 1 {
		t.Fatalf("prune = %d %v, want 1", n, err)
	}
	resp, err := f.svc.List(context.Background(), connect.NewRequest(&issuedv1.ListRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Msg.GetRecords()) != 1 || resp.Msg.GetRecords()[0].GetId() != "long" {
		t.Errorf("records = %+v", resp.Msg.GetRecords())
	}
}

func TestAppendRPCAssignsAnID(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	resp, err := f.svc.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{
		Record: &issuedv1.IssuedRecord{
			SchemaId:      "diploma",
			SchemaVersion: 1,
			Subject:       &commonv1.Subject{Ref: f.svc.SubjectRef("subject-a")},
			Format:        commonv1.Format_FORMAT_DC_SD_JWT,
			Hash:          "abc",
		},
	}))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(resp.Msg.GetId()) != record.IDLength || resp.Msg.GetRecordHash() == "" {
		t.Fatalf("append answer = %+v", resp.Msg)
	}
	got, err := f.svc.Get(ctx, connect.NewRequest(&issuedv1.GetRequest{Id: resp.Msg.GetId()}))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Msg.GetRecord().GetRetainUntil() == nil {
		t.Error("the service must fill the retention time")
	}
}

func TestAppendRPCRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("empty request err = %v, want invalid argument", err)
	}
	bad := &issuedv1.IssuedRecord{Id: "x", SchemaId: "diploma", SchemaVersion: 1}
	if _, err := f.svc.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{Record: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("empty subject err = %v, want invalid argument", err)
	}
	good := &issuedv1.IssuedRecord{
		Id: "twice", SchemaId: "diploma", SchemaVersion: 1,
		Subject: &commonv1.Subject{Ref: "ref"},
	}
	if _, err := f.svc.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{Record: good})); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := f.svc.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{Record: good})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("second append err = %v, want already exists", err)
	}
}

func TestPruneRPCCountsAndFilters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.add(t, "short", "visitor", 0, nil)
	f.add(t, "long", "diploma", 0, nil)
	f.now = clock.Add(40 * retention.Day)

	dry, err := f.svc.Prune(ctx, connect.NewRequest(&issuedv1.PruneRequest{DryRun: true}))
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.Msg.GetPruned() != 1 || dry.Msg.GetRemaining() != 2 {
		t.Fatalf("dry run = %+v, want 1 due and 2 kept", dry.Msg)
	}
	other, err := f.svc.Prune(ctx, connect.NewRequest(&issuedv1.PruneRequest{SchemaId: "diploma"}))
	if err != nil {
		t.Fatalf("other schema: %v", err)
	}
	if other.Msg.GetPruned() != 0 || other.Msg.GetRemaining() != 2 {
		t.Fatalf("other schema = %+v, want no change", other.Msg)
	}
	run, err := f.svc.Prune(ctx, connect.NewRequest(&issuedv1.PruneRequest{SchemaId: "visitor"}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Msg.GetPruned() != 1 || run.Msg.GetRemaining() != 1 {
		t.Fatalf("run = %+v, want one dropped and one kept", run.Msg)
	}
}
