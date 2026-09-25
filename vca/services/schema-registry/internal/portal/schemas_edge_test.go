// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// broken wraps the service and fails the calls it names.
type broken struct {
	*service.Service
	create, publish, remove error
}

func (b broken) Create(ctx context.Context, req *connect.Request[schemav1.CreateRequest]) (*connect.Response[schemav1.CreateResponse], error) {
	if b.create != nil {
		return nil, b.create
	}
	return b.Service.Create(ctx, req)
}

func (b broken) Publish(ctx context.Context, req *connect.Request[schemav1.PublishRequest]) (*connect.Response[schemav1.PublishResponse], error) {
	if b.publish != nil {
		return nil, b.publish
	}
	return b.Service.Publish(ctx, req)
}

func (b broken) DeleteDraft(ctx context.Context, req *connect.Request[schemav1.DeleteDraftRequest]) (*connect.Response[schemav1.DeleteDraftResponse], error) {
	if b.remove != nil {
		return nil, b.remove
	}
	return b.Service.DeleteDraft(ctx, req)
}

// clientServer wires a portal over any client with a staff session.
func clientServer(t *testing.T, opts Options) http.Handler {
	t.Helper()
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	sess := staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", CSRF: "tok"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), sess)))
	})
}

// TestListEmptyState checks that a registry with no schema shows the
// empty state with the publish action, not an empty table.
func TestListEmptyState(t *testing.T) {
	st, err := store.Open(sharedstore.MemoryDoc(), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, clientServer(t, Options{Client: svc}), "/portal/")
	if !strings.Contains(body, msg.T("issuer.schemas.empty.title")) || !strings.Contains(body, `class="empty"`) || strings.Contains(body, `id="schemas"`) {
		t.Fatal("no empty state")
	}
	// Without a builder the page offers the upload only.
	if strings.Contains(body, msg.T("issuer.schemas.builder.label")) {
		t.Fatal("a builder link without a builder")
	}
}

// TestPublishFileFailures checks the answers of the upload when the
// registry refuses or fails.
func TestPublishFileFailures(t *testing.T) {
	svc, _ := registry(t)
	fields := url.Values{"formats": {"dc+sd-jwt"}, "target": {"publish"}}
	// A type the registry refuses renders the form with the reason.
	rec := postUpload(t, clientServer(t, Options{Client: svc}), farmerDoc, url.Values{"formats": {"dc+sd-jwt"}, "type": {"has space"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msg.T("issuer.schemas.upload.error.stored")) {
		t.Fatalf("refused type: %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	down := connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if got := postUpload(t, clientServer(t, Options{Client: broken{Service: svc, create: down}}), farmerDoc, fields); got.Code != http.StatusInternalServerError {
		t.Fatalf("create down: %d", got.Code)
	}
	if got := postUpload(t, clientServer(t, Options{Client: broken{Service: svc, publish: down}}), farmerDoc, fields); got.Code != http.StatusInternalServerError {
		t.Fatalf("publish down: %d", got.Code)
	}
	// A plain form post carries no file.
	req := httptest.NewRequest(http.MethodPost, "/portal/publish", strings.NewReader("formats=dc%2Bsd-jwt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	clientServer(t, Options{Client: svc}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msg.T("issuer.schemas.upload.error.file")) {
		t.Fatalf("no file: %d", rec.Code)
	}
	// A broken multipart body is a bad request.
	req = httptest.NewRequest(http.MethodPost, "/portal/publish", strings.NewReader("--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nno end"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	rec = httptest.NewRecorder()
	clientServer(t, Options{Client: svc}).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("broken body: %d", rec.Code)
	}
	// A file with a title and no name takes the title; one with neither
	// needs the type from the form.
	rec = postUpload(t, clientServer(t, Options{Client: svc}), `{"type":"object"}`, url.Values{"formats": {"dc+sd-jwt"}, "type": {"Plain"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("type from the form: %d", rec.Code)
	}
	found, err := svc.Search(context.Background(), connect.NewRequest(&schemav1.SearchRequest{Query: "Plain"}))
	if err != nil || len(found.Msg.GetSchemas()) != 1 || Name(found.Msg.GetSchemas()[0]) != "Plain" {
		t.Fatalf("name from the type: %v %v", found, err)
	}
}

// TestDeleteDraftAnswers checks the delete form over htmx and its errors.
func TestDeleteDraftAnswers(t *testing.T) {
	svc, id := registry(t)
	post := func(h http.Handler, body string, header http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/portal/schemas/"+id+"/delete", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range header {
			req.Header[k] = v
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	h := clientServer(t, Options{Client: svc})
	if rec := post(h, "version=x", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version: %d", rec.Code)
	}
	down := connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if rec := post(clientServer(t, Options{Client: broken{Service: svc, remove: down}}), "", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("down: %d", rec.Code)
	}
	rec := post(h, "", http.Header{"Hx-Request": {"true"}})
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Redirect") != "/portal/?notice=deleted" {
		t.Fatalf("htmx: %d %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

// TestPublishPageOfAStartingStack checks that a stack that is starting
// offers the draft only and says why.
func TestPublishPageOfAStartingStack(t *testing.T) {
	svc, _ := registry(t)
	body := get(t, staffServer(t, svc, shellOf(stack{dpg: configv1.Dpg_DPG_WALTID, state: topology.Starting}), nil), "/portal/publish")
	if !strings.Contains(body, msg.T("issuer.schemas.target.starting")) || strings.Contains(body, `value="publish"`) {
		t.Fatal("a starting stack offers publish")
	}
	// It knows no format, so the form has no format choice.
	if strings.Contains(body, `name="formats"`) {
		t.Fatal("a format choice without formats")
	}
}

func TestSchemaHelpers(t *testing.T) {
	if FormatLabel(commonv1.Format_FORMAT_UNSPECIFIED) != "" || FormatLabel(commonv1.Format_FORMAT_LDP_VC) != "JSON-LD" {
		t.Fatal("format labels")
	}
	for title, want := range map[string]string{"Farmer credential": "FarmerCredential", "  land-title 2 ": "LandTitle2", "Ärzte": "Rzte", "": ""} {
		if got := TypeFromTitle(title); got != want {
			t.Errorf("TypeFromTitle(%q) = %q, want %q", title, got, want)
		}
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if !Updated(&schemav1.Schema{}).IsZero() || !Updated(&schemav1.Schema{CreatedAt: timestamppb.New(at)}).Equal(at) {
		t.Fatal("updated")
	}
	if dateCell(time.Time{}).Text != "-" {
		t.Fatal("zero date")
	}
	p := &Portal{opts: Options{BuilderURL: "/builder/?tab=1"}}
	if p.builderURL("a b") != "/builder/?tab=1&id=a+b" {
		t.Fatalf("builder url %q", p.builderURL("a b"))
	}
	if (&Portal{}).builderURL("x") != "" {
		t.Fatal("no builder")
	}
	if defaultFormat(nil) != nil || defaultFormat([]commonv1.Format{commonv1.Format_FORMAT_LDP_VC})[0] != commonv1.Format_FORMAT_LDP_VC {
		t.Fatal("default format")
	}
	if message(errors.New("plain")) != "plain" {
		t.Fatal("message of a plain error")
	}
	if (&Portal{opts: Options{Prefix: "/x"}}).SignOutPath() != "/x/signout" {
		t.Fatal("sign out path")
	}
}
