// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/config"
)

// fixedTime is the clock of the tests.
var fixedTime = time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

// fakeAdapter answers as the DPG adapter.
type fakeAdapter struct{}

func (fakeAdapter) GetCapabilities(
	context.Context, *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Adapter:  "dpg-adapter-test",
		Formats:  []commonv1.Format{commonv1.Format_FORMAT_LDP_VC},
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_PDF},
		Roles:    []commonv1.Role{commonv1.Role_ROLE_ISSUER},
	}), nil
}

func (fakeAdapter) CreateOffer(
	context.Context, *connect.Request[backendv1.CreateOfferRequest],
) (*connect.Response[backendv1.CreateOfferResponse], error) {
	return connect.NewResponse(&backendv1.CreateOfferResponse{
		OfferUri: "openid-credential-offer://issuer.example.org?x=1", OfferId: "adapter-1",
	}), nil
}

func (fakeAdapter) Issue(
	context.Context, *connect.Request[backendv1.IssueRequest],
) (*connect.Response[backendv1.IssueResponse], error) {
	return connect.NewResponse(&backendv1.IssueResponse{
		Credential: &commonv1.Credential{
			Format:  commonv1.Format_FORMAT_LDP_VC,
			Payload: []byte(`{"credentialSubject":{"fullName":"Ada Lovelace"}}`),
		},
	}), nil
}

func (fakeAdapter) GetIssuanceStatus(
	context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest],
) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	return connect.NewResponse(&backendv1.GetIssuanceStatusResponse{}), nil
}

func (fakeAdapter) IssueBatch(
	context.Context, *connect.Request[backendv1.IssueBatchRequest],
) (*connect.Response[backendv1.IssueBatchResponse], error) {
	return connect.NewResponse(&backendv1.IssueBatchResponse{}), nil
}

// settings returns a configuration with the values on top of the
// smallest one.
func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	all := map[string]string{"VCA_ISSUANCE_ADAPTER_URL": "http://dpg-adapter:8080"}
	for name, value := range values {
		all[name] = value
	}
	cfg, err := config.Load(func(name string) string { return all[name] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// deps returns the wiring with the adapter fake and a log buffer.
func deps(buf *bytes.Buffer) app.Deps {
	adapter := fakeAdapter{}
	return app.Deps{
		Capability: adapter,
		Issuer:     adapter,
		Now:        func() time.Time { return fixedTime },
		Log:        slog.New(slog.NewJSONHandler(buf, nil)),
	}
}

func TestBuildServesTheRpcAndTheDocument(t *testing.T) {
	var buf bytes.Buffer
	a, err := app.Build(settings(t, map[string]string{
		"VCA_ISSUANCE_PUBLIC_URL": "https://issuance.example.org",
	}), deps(&buf))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := issuancev1connect.NewIssuanceServiceClient(srv.Client(), srv.URL)
	resp, err := client.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_PDF},
		SubjectData: `{"fullName":"Ada Lovelace"}`,
	}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	link := resp.Msg.GetOffer().GetLink()
	if link == "" {
		t.Fatalf("offer = %v", resp.Msg.GetOffer())
	}
	ref := link[strings.LastIndex(link, "/")+1:]
	doc, derr := srv.Client().Get(srv.URL + "/issuance/pdf/" + ref)
	if derr != nil {
		t.Fatalf("get the document: %v", derr)
	}
	defer func() {
		if cerr := doc.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if doc.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", doc.StatusCode)
	}
	if doc.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("content type = %q", doc.Header.Get("Content-Type"))
	}
	missing, merr := srv.Client().Get(srv.URL + "/issuance/pdf/does-not-exist")
	if merr != nil {
		t.Fatalf("get the document: %v", merr)
	}
	defer func() {
		if cerr := missing.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", missing.StatusCode)
	}
}

func TestBuildWarnsAboutTheMissingServices(t *testing.T) {
	var buf bytes.Buffer
	if _, err := app.Build(settings(t, nil), deps(&buf)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	lines := buf.String()
	if !strings.Contains(lines, "schema registry") || !strings.Contains(lines, "status service") {
		t.Fatalf("the log = %s", lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(lines, "\n", 2)[0]), &first); err != nil {
		t.Fatalf("the log is not JSON: %v", err)
	}
}

func TestBuildUsesTheConfiguredClients(t *testing.T) {
	var buf bytes.Buffer
	dir := t.TempDir()
	cfg := settings(t, map[string]string{
		"VCA_ISSUANCE_SCHEMA_URL":      "http://schema:8080",
		"VCA_ISSUANCE_STATUS_URL":      "http://status:8080",
		"VCA_ISSUANCE_ISSUED_URL":      "http://issued:8080",
		"VCA_ISSUANCE_DATA_SOURCE_URL": "http://data-source:8080",
		"VCA_ISSUANCE_DELIVERY_SENDER": "file",
		"VCA_ISSUANCE_EMAIL_SENDER":    "log",
		"VCA_ISSUANCE_SMS_SENDER":      "file",
		"VCA_ISSUANCE_DELIVERY_DIR":    dir,
		"VCA_ISSUANCE_STORE_FILE":      filepath.Join(dir, "state"),
	})
	a, err := app.Build(cfg, app.Deps{Log: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Service == nil || a.Mux == nil {
		t.Fatal("Build returned an empty app")
	}
	if strings.Contains(buf.String(), "schema registry") {
		t.Fatal("the wiring warned about a schema registry it has")
	}
}

func TestBuildReportsABadStore(t *testing.T) {
	dir := t.TempDir()
	blocking := filepath.Join(dir, "file")
	if err := os.WriteFile(blocking, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	d := deps(&buf)
	cfg := settings(t, map[string]string{
		"VCA_ISSUANCE_STORE_FILE": filepath.Join(blocking, "state"),
	})
	if _, err := app.Build(cfg, d); err == nil {
		t.Fatal("Build accepted a store inside a file")
	}
}

func TestBuildFillsTheDefaults(t *testing.T) {
	if _, err := app.Build(settings(t, nil), app.Deps{}); err != nil {
		t.Fatalf("Build: %v", err)
	}
}
