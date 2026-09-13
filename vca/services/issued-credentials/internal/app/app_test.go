// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
)

var clock = time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

// quiet drops every log line.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func load(t *testing.T, env map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(func(name string) string { return env[name] })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func build(t *testing.T, env map[string]string, deps app.Deps) *app.App {
	t.Helper()
	if deps.Log == nil {
		deps.Log = quiet()
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return clock }
	}
	a, err := app.Build(load(t, env), deps)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return a
}

func TestBuildServesTheChainHeadEndpoints(t *testing.T) {
	a := build(t, nil, app.Deps{})
	if _, err := a.Service.Append(record.Record{
		ID: "a", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + httpapi.ChainHeadPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.Count(string(body), ".") != 2 {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	keys, err := http.Get(srv.URL + httpapi.JWKSPath)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	defer keys.Body.Close()
	raw, _ := io.ReadAll(keys.Body)
	set := a.Signer.JWKS()
	if _, err := head.Verify(string(body), set); err != nil {
		t.Errorf("the head must verify with the served key: %v", err)
	}
	if !strings.Contains(string(raw), a.Signer.KeyID()) {
		t.Errorf("the key set must name the key id, got %s", raw)
	}
}

func TestBuildServesTheConnectAPI(t *testing.T) {
	a := build(t, map[string]string{"VCA_ISSUED_RETENTION": "default=1y"}, app.Deps{})
	for _, id := range []string{"a", "b"} {
		if _, err := a.Service.Append(record.Record{
			ID: id, SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref-" + id,
			IssuedAt: clock, SearchableClaims: map[string]string{"name": "Wanjiru"},
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := issuedv1connect.NewIssuedServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	list, err := client.List(ctx, connect.NewRequest(&issuedv1.ListRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Msg.GetRecords()) != 2 {
		t.Errorf("records = %d, want 2", len(list.Msg.GetRecords()))
	}
	stream, err := client.Export(ctx, connect.NewRequest(&issuedv1.ExportRequest{
		Encoding: issuedv1.ExportRequest_ENCODING_CSV,
	}))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var body []byte
	for stream.Receive() {
		body = append(body, stream.Msg().GetChunk()...)
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if !strings.HasPrefix(string(body), "id,schema_id,") {
		t.Errorf("body = %.40q", body)
	}
	head, err := client.GetChainHead(ctx, connect.NewRequest(&issuedv1.GetChainHeadRequest{}))
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if head.Msg.GetHead().GetLength() != 2 {
		t.Errorf("length = %d", head.Msg.GetHead().GetLength())
	}
}

// fakeStatus records the SetStatus calls it takes.
type fakeStatus struct {
	statusv1connect.StatusServiceClient
	calls int
}

func (f *fakeStatus) SetStatus(context.Context, *connect.Request[statusv1.SetStatusRequest]) (*connect.Response[statusv1.SetStatusResponse], error) {
	f.calls++
	return connect.NewResponse(&statusv1.SetStatusResponse{}), nil
}

func TestBuildUsesTheInjectedStatusClient(t *testing.T) {
	status := &fakeStatus{}
	a := build(t, nil, app.Deps{Status: status})
	if _, err := a.Service.Append(record.Record{
		ID: "a", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
		Binding: record.Binding{Kind: record.KindBitstring, ListID: "v1", Index: 3},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := a.Service.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_REVOKED, Reason: "fraud",
	})); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if status.calls != 1 {
		t.Errorf("status calls = %d, want 1", status.calls)
	}
}

func TestBuildMakesAStatusClientFromTheURL(t *testing.T) {
	var path string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/proto")
		// An empty SetStatusResponse is zero bytes.
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	a := build(t, map[string]string{"VCA_ISSUED_STATUS_URL": backend.URL + "/"}, app.Deps{})
	if _, err := a.Service.Append(record.Record{
		ID: "a", SchemaID: "diploma", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
		Binding: record.Binding{Kind: record.KindToken, ListID: "v1", Index: 1},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := a.Service.Revoke(context.Background(), connect.NewRequest(&issuedv1.RevokeRequest{
		Id: "a", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "review",
	})); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if path != "/vca.status.v1.StatusService/SetStatus" {
		t.Errorf("path = %q", path)
	}
}

func TestBuildReadsTheSaltAndTheKeyFile(t *testing.T) {
	dir := t.TempDir()
	key, err := head.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pem, err := head.EncodePEM(key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	keyPath := filepath.Join(dir, "head.pem")
	saltPath := filepath.Join(dir, "salt")
	if err := os.WriteFile(keyPath, pem, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(saltPath, []byte(" pepper \n"), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	a := build(t, map[string]string{
		"VCA_ISSUED_HEAD_KEY_FILE": keyPath,
		"VCA_ISSUED_SALT_FILE":     saltPath,
		"VCA_ISSUED_STORE_FILE":    filepath.Join(dir, "log.json"),
	}, app.Deps{})
	signer, err := head.NewSigner(head.Options{Key: key})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if a.Signer.KeyID() != signer.KeyID() {
		t.Errorf("key id = %q, want %q", a.Signer.KeyID(), signer.KeyID())
	}
	if got := a.Service.SubjectRef("x"); got != record.SubjectRef("pepper", "x") {
		t.Error("the salt file must key the subject reference")
	}
}

func TestBuildReportsBadFiles(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		env  map[string]string
		deps app.Deps
	}{
		{"salt file", map[string]string{"VCA_ISSUED_SALT_FILE": filepath.Join(dir, "none")}, app.Deps{}},
		{"key file", map[string]string{"VCA_ISSUED_HEAD_KEY_FILE": filepath.Join(dir, "none")}, app.Deps{}},
		{"key content", map[string]string{"VCA_ISSUED_HEAD_KEY_FILE": "any"}, app.Deps{
			ReadFile: func(string) ([]byte, error) { return []byte("not a key"), nil },
		}},
		{"store file", map[string]string{"VCA_ISSUED_STORE_FILE": dir}, app.Deps{}},
	}
	for _, c := range cases {
		deps := c.deps
		deps.Log = quiet()
		if _, err := app.Build(load(t, c.env), deps); err == nil {
			t.Errorf("%s: want an error", c.name)
		}
	}
}

func TestPruneJob(t *testing.T) {
	now := clock
	a := build(t, map[string]string{
		"VCA_ISSUED_RETENTION":      "visitor=1h",
		"VCA_ISSUED_PRUNE_INTERVAL": "1ms",
	}, app.Deps{Now: func() time.Time { return now }})
	if _, err := a.Service.Append(record.Record{
		ID: "a", SchemaID: "visitor", SchemaVersion: 1, SubjectRef: "ref", IssuedAt: clock,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	now = clock.Add(2 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.Prune(ctx, nil); close(done) }()
	deadline := time.After(3 * time.Second)
	for a.Store.Pruned() == 0 {
		select {
		case <-deadline:
			t.Fatal("the job did not prune the record")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestPruneJobStopsWithoutAnInterval(t *testing.T) {
	a := build(t, map[string]string{"VCA_ISSUED_PRUNE_INTERVAL": "0"}, app.Deps{})
	a.Prune(context.Background(), quiet())
}

func TestPruneJobLogsAFailure(t *testing.T) {
	a := build(t, map[string]string{"VCA_ISSUED_PRUNE_INTERVAL": "1ms"}, app.Deps{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	a.Prune(ctx, quiet())
	if a.Store.Pruned() != 0 {
		t.Error("nothing has a retention time, so nothing goes")
	}
}
