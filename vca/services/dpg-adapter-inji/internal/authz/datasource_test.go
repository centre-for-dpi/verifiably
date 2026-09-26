// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
)

// sources answers Lookup for one value.
type sources struct {
	datasourcev1connect.UnimplementedDataSourceServiceHandler
	last *datasourcev1.LookupRequest
	auth string
}

func (s *sources) Lookup(_ context.Context, req *connect.Request[datasourcev1.LookupRequest]) (*connect.Response[datasourcev1.LookupResponse], error) {
	s.last, s.auth = req.Msg, req.Header().Get("Authorization")
	switch req.Msg.GetValue() {
	case "amina@example.org":
		return connect.NewResponse(&datasourcev1.LookupResponse{Found: true, SubjectData: `{"fullName":"Amina Njeri"}`}), nil
	case "broken":
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no issue access"))
	}
	return connect.NewResponse(&datasourcev1.LookupResponse{}), nil
}

func TestDataSourceLookup(t *testing.T) {
	h := &sources{}
	mux := http.NewServeMux()
	mux.Handle(datasourcev1connect.NewDataSourceServiceHandler(h))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	d := authz.DataSource{Client: datasourcev1connect.NewDataSourceServiceClient(srv.Client(), srv.URL), Token: "pair-token"}
	src := authz.SignInSource{ConfigID: "c", SourceID: "registry", Field: "email", TokenClaim: "email", SchemaID: "s", SchemaVersion: 3}
	row, found, err := d.Lookup(context.Background(), src, "amina@example.org")
	if err != nil || !found || row != `{"fullName":"Amina Njeri"}` {
		t.Fatalf("Lookup = %q, %v, %v", row, found, err)
	}
	if h.auth != "Bearer pair-token" {
		t.Fatalf("the lookup carried %q, want the service token of the pair", h.auth)
	}
	if h.last.GetSourceId() != "registry" || h.last.GetField() != "email" || h.last.GetSchemaId() != "s" || h.last.GetSchemaVersion() != 3 {
		t.Fatalf("request = %v", h.last)
	}
	if _, found, err = d.Lookup(context.Background(), src, "nobody@example.org"); err != nil || found {
		t.Fatalf("no row = %v, %v", found, err)
	}
	if _, _, err = d.Lookup(context.Background(), src, "broken"); err == nil {
		t.Fatal("a refusal of the source is no error")
	}
}
