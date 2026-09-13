// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
)

// client returns a Connect client that reaches the service under test.
// The batch RPC streams, and Connect has no exported constructor for a
// server stream, so the test drives the real handler.
func (h *harness) client(t *testing.T) issuancev1connect.IssuanceServiceClient {
	t.Helper()
	if h.rpc == nil {
		mux := http.NewServeMux()
		mux.Handle(issuancev1connect.NewIssuanceServiceHandler(h.service))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		h.rpc = issuancev1connect.NewIssuanceServiceClient(srv.Client(), srv.URL)
	}
	return h.rpc
}

// batch runs one batch and returns every progress message.
func (h *harness) batch(t *testing.T, req *issuancev1.IssueBatchRequest) (
	[]*issuancev1.IssueBatchResponse, error,
) {
	t.Helper()
	stream, err := h.client(t).IssueBatch(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	var out []*issuancev1.IssueBatchResponse
	for stream.Receive() {
		out = append(out, stream.Msg())
	}
	if rerr := stream.Err(); rerr != nil {
		return out, rerr
	}
	return out, stream.Close()
}
