// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)

// registry is a trust registry that answers ExportSnapshot with text
// that is not a signed snapshot.
type registry struct {
	trustv1connect.UnimplementedTrustServiceHandler
}

func (registry) ExportSnapshot(context.Context, *connect.Request[trustv1.ExportSnapshotRequest]) (*connect.Response[trustv1.ExportSnapshotResponse], error) {
	return connect.NewResponse(&trustv1.ExportSnapshotResponse{Jws: "not a token"}), nil
}

// TestCacheReadsTheTrustRegistry wires the cache to the trust registry:
// a sync calls ExportSnapshot and refuses the answer, and the schedule
// stops with its context.
func TestCacheReadsTheTrustRegistry(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(trustv1connect.NewTrustServiceHandler(registry{}))
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			t.Error(err)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cfg := base(t)
	cfg.TrustURL = srv.URL
	a, err := Build(cfg, Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Service.SyncCache(context.Background(), connect.NewRequest(&policyv1.SyncCacheRequest{Kind: policyv1.CacheKind_CACHE_KIND_TRUST_LIST}))
	if err != nil || resp.Msg.GetFailed() != 1 || resp.Msg.GetSources()[0].GetLastError() == "" {
		t.Fatalf("SyncCache = %+v, %v", resp, err)
	}
	srv.Close()
	if _, err := snapshot(trustv1connect.NewTrustServiceClient(http.DefaultClient, srv.URL))(context.Background()); err == nil {
		t.Fatal("want an error from a closed registry")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.CacheTick = time.Hour
	a.RunCache(ctx)
	a.CacheTick = 0
	a.RunCache(ctx)
}
