// SPDX-License-Identifier: Apache-2.0

package clients_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"google.golang.org/protobuf/proto"
)

// fakeCapability answers as the capability RPC of a DPG adapter.
type fakeCapability struct {
	answer *backendv1.GetCapabilitiesResponse
	err    error
	calls  int
}

func (f *fakeCapability) GetCapabilities(
	context.Context, *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.answer), nil
}

// answer is the capability answer of the tests.
func answer() *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{
		Adapter:    "dpg-adapter-test",
		DpgVersion: "1.2.3",
		Formats: []commonv1.Format{
			commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_LDP_VC,
		},
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		Roles:    []commonv1.Role{commonv1.Role_ROLE_ISSUER},
	}
}

func TestCapabilitiesReportWhatTheAdapterSupports(t *testing.T) {
	c := clients.Capabilities{
		Formats:  []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT},
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_PDF},
	}
	if !c.SupportsFormat(commonv1.Format_FORMAT_VC_SD_JWT) {
		t.Fatal("the adapter issues SD-JWT VC")
	}
	if c.SupportsFormat(commonv1.Format_FORMAT_MSO_MDOC) {
		t.Fatal("the adapter does not issue mdoc")
	}
	if !c.SupportsFormat(commonv1.Format_FORMAT_UNSPECIFIED) {
		t.Fatal("an unset format leaves the choice to the schema")
	}
	if !c.SupportsChannel(backendv1.Channel_CHANNEL_PDF) {
		t.Fatal("the adapter supports the document channel")
	}
	if c.SupportsChannel(backendv1.Channel_CHANNEL_OID4VCI_PREAUTH) {
		t.Fatal("the adapter does not support the offer channel")
	}
	if c.FirstFormat() != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Fatalf("first format = %v", c.FirstFormat())
	}
	if (clients.Capabilities{}).FirstFormat() != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Fatal("an adapter without a format has no first format")
	}
}

func TestCapabilityCacheReadsTheAdapterOnce(t *testing.T) {
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	client := &fakeCapability{answer: answer()}
	cache := clients.NewCapabilityCache(client, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	first, err := cache.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if first.Adapter != "dpg-adapter-test" || first.DpgVersion != "1.2.3" {
		t.Fatalf("capabilities = %+v", first)
	}
	if len(first.Roles) != 1 {
		t.Fatalf("roles = %v", first.Roles)
	}
	if _, err := cache.Get(ctx); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("calls = %d, the cache holds the answer", client.calls)
	}
	now = now.Add(2 * time.Minute)
	if _, err := cache.Get(ctx); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("calls = %d, the cache reads again after the window", client.calls)
	}
}

func TestCapabilityCacheServesTheLastAnswerDuringAnOutage(t *testing.T) {
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	client := &fakeCapability{answer: answer()}
	cache := clients.NewCapabilityCache(client, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	if _, err := cache.Get(ctx); err != nil {
		t.Fatalf("Get: %v", err)
	}
	now = now.Add(2 * time.Minute)
	client.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	got, err := cache.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Adapter != "dpg-adapter-test" {
		t.Fatalf("capabilities = %+v", got)
	}
}

func TestCapabilityCacheReportsTheFirstFailure(t *testing.T) {
	cache := clients.NewCapabilityCache(
		&fakeCapability{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}, 0, nil)
	if _, err := cache.Get(context.Background()); err == nil {
		t.Fatal("the cache hid a failure with no earlier answer")
	}
}

func TestLogRecorderWritesTheRecord(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	id, err := clients.LogRecorder(log).Record(context.Background(),
		&issuedv1.IssuedRecord{SchemaId: "farmer", Hash: "abc"})
	if err != nil || id != "" {
		t.Fatalf("id = %q, error = %v", id, err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("farmer")) {
		t.Fatalf("the log = %s", buf.String())
	}
	if _, err := clients.LogRecorder(nil).Record(context.Background(),
		&issuedv1.IssuedRecord{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// fakeAppender answers as the Append RPC of the issued credentials
// service.
type fakeAppender struct {
	got *issuedv1.AppendRequest
	err error
}

func (f *fakeAppender) Append(_ context.Context, req *connect.Request[issuedv1.AppendRequest]) (
	*connect.Response[issuedv1.AppendResponse], error,
) {
	if f.err != nil {
		return nil, f.err
	}
	f.got = req.Msg
	return connect.NewResponse(&issuedv1.AppendResponse{Id: "record-1", RecordHash: "hash-1"}), nil
}

func TestAppendRecorderCallsTheRPC(t *testing.T) {
	fake := &fakeAppender{}
	id, err := clients.NewAppendRecorder(fake).Record(context.Background(),
		&issuedv1.IssuedRecord{SchemaId: "farmer", Hash: "abc"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id != "record-1" {
		t.Fatalf("id = %q", id)
	}
	if fake.got.GetRecord().GetSchemaId() != "farmer" {
		t.Fatalf("request = %+v", fake.got)
	}
}

func TestAppendRecorderReportsAFailure(t *testing.T) {
	ctx := context.Background()
	record := &issuedv1.IssuedRecord{SchemaId: "farmer"}
	if _, err := clients.NewConnectRecorder("", nil).Record(ctx, record); !errors.Is(
		err, clients.ErrNoRecorder) {
		t.Fatalf("error = %v, want ErrNoRecorder", err)
	}
	var missing *clients.AppendRecorder
	if _, err := missing.Record(ctx, record); !errors.Is(err, clients.ErrNoRecorder) {
		t.Fatalf("error = %v, want ErrNoRecorder", err)
	}
	fake := &fakeAppender{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}
	if _, err := clients.NewAppendRecorder(fake).Record(ctx, record); err == nil {
		t.Fatal("the recorder hid a failed call")
	}
}

func TestConnectRecorderReachesAServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/vca.issued.v1.IssuedService/Append") {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, err := proto.Marshal(&issuedv1.AppendResponse{Id: "record-2"})
		if err != nil {
			t.Errorf("marshal: %v", err)
		}
		w.Header().Set("Content-Type", "application/proto")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	id, err := clients.NewConnectRecorder(srv.URL+"/", srv.Client()).Record(context.Background(),
		&issuedv1.IssuedRecord{SchemaId: "farmer"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id != "record-2" {
		t.Fatalf("id = %q", id)
	}
	if _, err := clients.NewConnectRecorder("http://127.0.0.1:1", nil).Record(
		context.Background(), &issuedv1.IssuedRecord{}); err == nil {
		t.Fatal("the recorder passed an unreachable service")
	}
}
