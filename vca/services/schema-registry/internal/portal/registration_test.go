// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// refusingBackend refuses every registration with err, when set.
type refusingBackend struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	err error
}

func (f *refusingBackend) RegisterCredentialConfiguration(_ context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: "dpg:" + req.Msg.GetConfiguration().GetId()}), nil
}

// TestDetailPageShowsAStoppedRegistration is ADR-077 as amended on
// 2026-10-04: a registration at start that the stack refused for good
// shows on the detail page with its reason and an action that tries it
// again.
func TestDetailPageShowsAStoppedRegistration(t *testing.T) {
	backend := &refusingBackend{}
	st, err := store.Open(sharedstore.MemoryDoc(), store.Options{NewID: func(string) string { return "card" }})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := svc.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "Card", JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSchema().GetId()
	if _, perr := svc.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: id})); perr != nil {
		t.Fatal(perr)
	}
	p, err := New(Options{Client: svc, Registrations: svc})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	detail := DefaultPrefix + "/schemas/" + id
	if body := page(t, do(t, mux, http.MethodGet, detail, nil, nil)); strings.Contains(body, "registration failed") {
		t.Fatal("a registered version shows a failure")
	}
	backend.err = connect.NewError(connect.CodeAlreadyExists, errors.New("the platform holds the name Card"))
	svc.Republish(ctx, nil)
	body := page(t, do(t, mux, http.MethodGet, detail, nil, nil))
	for _, want := range []string{"registration failed: ", "the platform holds the name Card", `action="` + detail + `/register"`, msg.T("issuer.schemas.registration.retry.label")} {
		if !strings.Contains(body, want) {
			t.Errorf("the detail page has no %q", want)
		}
	}
	rec := do(t, mux, http.MethodPost, detail+"/register", url.Values{"version": {"1"}}, nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=unregistered") {
		t.Fatalf("a refused retry = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	backend.err = nil
	rec = do(t, mux, http.MethodPost, detail+"/register", url.Values{"version": {"1"}}, nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=registered") {
		t.Fatalf("a retry = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if body := page(t, do(t, mux, http.MethodGet, rec.Header().Get("Location"), nil, nil)); strings.Contains(body, "registration failed") {
		t.Error("a registered version still shows the failure")
	}
	if rec := do(t, mux, http.MethodPost, detail+"/register", url.Values{"version": {"x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a version that is not a number = %d", rec.Code)
	}
	// A portal with no registrations has no such route.
	plain := server(t, svc)
	if rec := do(t, plain, http.MethodPost, detail+"/register", url.Values{"version": {"1"}}, nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("a portal with no registrations answered %d", rec.Code)
	}
}

// TestListPageFlagsStoppedRegistrations is the follow-up of ADR-077:
// the list page counts the published versions whose registration the
// stack refused for good, flags each schema that holds one, and a
// filter shows only those schemas.
func TestListPageFlagsStoppedRegistrations(t *testing.T) {
	backend := &refusingBackend{}
	st, err := store.Open(sharedstore.MemoryDoc(), store.Options{NewID: func(typ string) string { return strings.ToLower(typ) }})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, typ := range []string{"Card", "Permit"} {
		if _, cerr := svc.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
			Type: typ, JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC},
		}})); cerr != nil {
			t.Fatal(cerr)
		}
		if _, perr := svc.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: strings.ToLower(typ)})); perr != nil {
			t.Fatal(perr)
		}
	}
	p, err := New(Options{Client: svc, Registrations: svc})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	list := DefaultPrefix + "/"
	if body := page(t, do(t, mux, http.MethodGet, list, nil, nil)); strings.Contains(body, msg.T("issuer.schemas.stopped.badge.label")) {
		t.Fatal("a list with no refusal flags a schema")
	}
	backend.err = connect.NewError(connect.CodeAlreadyExists, errors.New("the platform holds the name Card"))
	svc.Republish(ctx, []service.Key{{ID: "card", Version: 1}})
	body := page(t, do(t, mux, http.MethodGet, list, nil, nil))
	for _, want := range []string{
		msg.T("issuer.schemas.stopped.count", "1"), `href="` + list + `?registration=stopped"`,
		msg.T("issuer.schemas.stopped.badge.label"), `name="registration"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the list page has no %q", want)
		}
	}
	filtered := page(t, do(t, mux, http.MethodGet, list+"?registration=stopped", nil, nil))
	if !strings.Contains(filtered, `href="`+DefaultPrefix+`/schemas/card?`) || strings.Contains(filtered, DefaultPrefix+`/schemas/permit`) {
		t.Errorf("the filter does not keep only the stopped schema: %s", filtered)
	}
	if !strings.Contains(filtered, `<option value="stopped" selected>`) {
		t.Error("the filter does not show its choice")
	}
	a11ytest.AssertPage(t, body)
	a11ytest.AssertPage(t, filtered)
}
