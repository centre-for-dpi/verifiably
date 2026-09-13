// SPDX-License-Identifier: Apache-2.0

package clients_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
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

func TestHTTPRecorderPostsTheRecord(t *testing.T) {
	var path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		path, body = r.URL.Path, string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"record-1"}`))
	}))
	defer srv.Close()
	id, err := clients.NewHTTPRecorder(srv.URL+"/", srv.Client()).Record(context.Background(),
		&issuedv1.IssuedRecord{SchemaId: "farmer", Hash: "abc"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id != "record-1" {
		t.Fatalf("id = %q", id)
	}
	if path != clients.RecordPath {
		t.Fatalf("path = %q, want %q", path, clients.RecordPath)
	}
	if !bytes.Contains([]byte(body), []byte("farmer")) {
		t.Fatalf("body = %s", body)
	}
}

func TestHTTPRecorderAcceptsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	id, err := clients.NewHTTPRecorder(srv.URL, nil).Record(context.Background(),
		&issuedv1.IssuedRecord{SchemaId: "farmer"})
	if err != nil || id != "" {
		t.Fatalf("id = %q, error = %v", id, err)
	}
}

func TestHTTPRecorderReportsAFailure(t *testing.T) {
	ctx := context.Background()
	record := &issuedv1.IssuedRecord{SchemaId: "farmer"}
	if _, err := clients.NewHTTPRecorder("", nil).Record(ctx, record); !errors.Is(
		err, clients.ErrNoRecorder) {
		t.Fatalf("error = %v, want ErrNoRecorder", err)
	}
	var missing *clients.HTTPRecorder
	if _, err := missing.Record(ctx, record); !errors.Is(err, clients.ErrNoRecorder) {
		t.Fatalf("error = %v, want ErrNoRecorder", err)
	}
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer rejecting.Close()
	if _, err := clients.NewHTTPRecorder(rejecting.URL, nil).Record(ctx, record); err == nil {
		t.Fatal("the recorder passed a rejected record")
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer broken.Close()
	if _, err := clients.NewHTTPRecorder(broken.URL, nil).Record(ctx, record); err == nil {
		t.Fatal("the recorder read a broken answer")
	}
	if _, err := clients.NewHTTPRecorder("http://127.0.0.1:1", nil).Record(ctx, record); err == nil {
		t.Fatal("the recorder passed an unreachable service")
	}
	if _, err := clients.NewHTTPRecorder("http://%zz", nil).Record(ctx, record); err == nil {
		t.Fatal("the recorder passed a bad URL")
	}
}
