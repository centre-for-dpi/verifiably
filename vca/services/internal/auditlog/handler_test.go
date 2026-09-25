// SPDX-License-Identifier: Apache-2.0

package auditlog_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// errDenied is what the test authorizer returns without the admin token.
var errDenied = errors.New("denied")

// adminOnly allows the bearer token "admin" and nothing else.
func adminOnly(_ context.Context, h http.Header) error {
	if h.Get("Authorization") != "Bearer admin" {
		return errDenied
	}
	return nil
}

// serveLog serves a log with two records over a real Connect server.
func serveLog(t *testing.T, authorize func(context.Context, http.Header) error, kv store.KeyValue) auditv1connect.AuditServiceClient {
	t.Helper()
	clock := start
	l, err := auditlog.New(kv, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := l.Append(ctx, auditlog.Entry{Actor: "alice", Action: "auth.Login", Target: "keycloak", OK: true, RequestID: "r1"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	clock = clock.Add(time.Minute)
	if _, err := l.Append(ctx, auditlog.Entry{Action: "auth.Login", Target: "keycloak", Detail: "the provider refused the code"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	mux := http.NewServeMux()
	path, h := auditlog.NewHandler(auditlog.Handler{Log: l, Service: "issuer-auth", Authorize: authorize})
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return auditv1connect.NewAuditServiceClient(srv.Client(), srv.URL)
}

func withBearer[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestHandlerQueryNeedsTheAuthorizer(t *testing.T) {
	client := serveLog(t, adminOnly, store.Memory())
	for _, token := range []string{"", "issuer-session"} {
		_, err := client.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, token))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("token %q: code = %v", token, connect.CodeOf(err))
		}
	}
	none := serveLog(t, nil, store.Memory())
	if _, err := none.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, "admin")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no authorizer: code = %v", connect.CodeOf(err))
	}
	denied := serveLog(t, func(context.Context, http.Header) error {
		return connect.NewError(connect.CodePermissionDenied, errDenied)
	}, store.Memory())
	if _, err := denied.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, "admin")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("connect error: code = %v", connect.CodeOf(err))
	}
}

func TestHandlerReturnsEventsNewestFirstWithTheSource(t *testing.T) {
	client := serveLog(t, adminOnly, store.Memory())
	res, err := client.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, "admin"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	events := res.Msg.GetEvents()
	if len(events) != 2 || res.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("events = %d", len(events))
	}
	failed, ok := events[0], events[1]
	if failed.GetOutcome() != auditv1.Outcome_OUTCOME_FAILURE || failed.GetDetail() != "the provider refused the code" {
		t.Errorf("first = %+v", failed)
	}
	if ok.GetOutcome() != auditv1.Outcome_OUTCOME_SUCCESS || ok.GetActor() != "alice" || ok.GetRequestId() != "r1" ||
		ok.GetTarget() != "keycloak" || ok.GetAction() != "auth.Login" || ok.GetId() == "" || !ok.GetTime().AsTime().Equal(start) {
		t.Errorf("second = %+v", ok)
	}
	for _, e := range events {
		if e.GetSourceService() != "issuer-auth" || e.GetPair() != "" {
			t.Errorf("source = %q pair = %q", e.GetSourceService(), e.GetPair())
		}
	}
}

func TestHandlerAppliesTheFilters(t *testing.T) {
	client := serveLog(t, adminOnly, store.Memory())
	cases := []struct {
		name string
		req  *auditv1.QueryRequest
		want int
	}{
		{"failure", &auditv1.QueryRequest{Outcome: auditv1.Outcome_OUTCOME_FAILURE}, 1},
		{"success", &auditv1.QueryRequest{Outcome: auditv1.Outcome_OUTCOME_SUCCESS}, 1},
		{"actor", &auditv1.QueryRequest{Actor: "alice"}, 1},
		{"action", &auditv1.QueryRequest{Action: "auth.Logout"}, 0},
		{"from", &auditv1.QueryRequest{From: timestamppb.New(start.Add(30 * time.Second))}, 1},
		{"to", &auditv1.QueryRequest{To: timestamppb.New(start.Add(30 * time.Second))}, 1},
		{"page", &auditv1.QueryRequest{Page: &commonv1.Pagination{PageSize: 1}}, 1},
	}
	for _, c := range cases {
		res, err := client.Query(context.Background(), withBearer(c.req, "admin"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(res.Msg.GetEvents()) != c.want {
			t.Errorf("%s: events = %d, want %d", c.name, len(res.Msg.GetEvents()), c.want)
		}
	}
	res, err := client.Query(context.Background(), withBearer(&auditv1.QueryRequest{Page: &commonv1.Pagination{PageSize: 1}}, "admin"))
	if err != nil || res.Msg.GetPage().GetNextPageToken() == "" {
		t.Fatalf("first page = %+v, %v", res, err)
	}
	next, err := client.Query(context.Background(), withBearer(&auditv1.QueryRequest{
		Page: &commonv1.Pagination{PageSize: 1, PageToken: res.Msg.GetPage().GetNextPageToken()},
	}, "admin"))
	if err != nil || len(next.Msg.GetEvents()) != 1 || next.Msg.GetEvents()[0].GetActor() != "alice" {
		t.Fatalf("second page = %+v, %v", next, err)
	}
}

func TestHandlerReportsAStoreFault(t *testing.T) {
	kv := &flaky{KeyValue: store.Memory()}
	client := serveLog(t, adminOnly, kv)
	kv.failList = true
	if _, err := client.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, "admin")); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("code = %v", connect.CodeOf(err))
	}
}

func TestHandlerStampsThePairItKnows(t *testing.T) {
	l, err := auditlog.New(store.Memory(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Write(context.Background(), auditlog.Entry{Action: "trust.Upsert", OK: true})
	h := auditlog.Handler{Log: l, Service: "trust-registry", Pair: "admin-waltid", Authorize: adminOnly}
	res, err := h.Query(context.Background(), withBearer(&auditv1.QueryRequest{}, "admin"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := res.Msg.GetEvents()[0]; got.GetPair() != "admin-waltid" || got.GetSourceService() != "trust-registry" {
		t.Fatalf("event = %+v", got)
	}
}

// flaky fails List once the test sets failList.
type flaky struct {
	store.KeyValue
	failList bool
}

func (f *flaky) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failList {
		return nil, errors.New("list failed")
	}
	return f.KeyValue.List(ctx, prefix)
}
