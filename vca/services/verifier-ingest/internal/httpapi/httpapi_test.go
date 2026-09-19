// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// clock is the fixed time of the tests.
var clock = time.Unix(1700000000, 0).UTC()

// query is a small DCQL query.
const query = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}`

// sdjwtSample is an SD-JWT VC with one disclosure.
const sdjwtSample = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQifQ.c2ln~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFzaGEiXQ~"

// setup wires a server over the wallet endpoints.
func setup(t *testing.T, now func() time.Time) (*httptest.Server, *service.Service, *txn.Store) {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if now == nil {
		now = func() time.Time { return clock }
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example",
		ClientID: "https://verify.example", RequestTTL: time.Minute, Now: now,
		RedirectURI: `https://verify.example/done?q="x"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	if !handler.Ready(context.Background()) {
		t.Fatal("the handler is ready")
	}
	return s, svc, store
}

// create starts one transaction.
func create(t *testing.T, svc *service.Service, store *txn.Store) txn.Transaction {
	t.Helper()
	resp, err := svc.CreateOid4VpRequest(context.Background(), connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(context.Background(), resp.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// get performs one GET.
func get(t *testing.T, s *httptest.Server, path string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body), resp.Header
}

// post performs one form post.
func post(t *testing.T, s *httptest.Server, path string, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestNewNeedsService(t *testing.T) {
	if _, err := httpapi.New(nil); err == nil {
		t.Error("the handler needs a service")
	}
}

func TestRequestObject(t *testing.T) {
	s, svc, store := setup(t, nil)
	record := create(t, svc, store)
	status, body, header := get(t, s, service.RequestPath+record.ID)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if header.Get("Content-Type") != oid4vp.MediaTypeRequestObject {
		t.Errorf("content type = %q", header.Get("Content-Type"))
	}
	if header.Get("Cache-Control") != "no-store" {
		t.Errorf("cache control = %q", header.Get("Cache-Control"))
	}
	claims, err := oid4vp.ReadRequestObject(body)
	if err != nil {
		t.Fatal(err)
	}
	if claims["nonce"] != record.Nonce {
		t.Errorf("claims = %v", claims)
	}
	missing, _, _ := get(t, s, service.RequestPath+"missing")
	if missing != http.StatusNotFound {
		t.Errorf("a missing transaction answers %d", missing)
	}
}

func TestRequestObjectSigningFailure(t *testing.T) {
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: "not a key", BaseURL: "https://verify.example",
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if serr := store.Put(context.Background(), txn.Transaction{
		ID: "abc", Nonce: "n", StateParam: "s", State: txn.StatePending,
		CreatedAt: clock, ExpiresAt: clock.Add(time.Minute),
	}); serr != nil {
		t.Fatal(serr)
	}
	handler, err := httpapi.New(svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	defer s.Close()
	status, _, _ := get(t, s, service.RequestPath+"abc")
	if status != http.StatusInternalServerError {
		t.Errorf("a key the signer refuses answers %d", status)
	}
}

func TestDirectPost(t *testing.T) {
	s, svc, store := setup(t, nil)
	record := create(t, svc, store)
	status, body := post(t, s, service.ResponsePath, url.Values{
		"state": {record.StateParam}, "vp_token": {sdjwtSample},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body %s", status, body)
	}
	if !strings.Contains(body, `"redirect_uri"`) || !strings.Contains(body, `\"x\"`) {
		t.Errorf("body = %s", body)
	}
	stored, err := store.Get(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != txn.StateReceived || stored.Presentation == nil {
		t.Errorf("transaction = %+v", stored)
	}
}

func TestDirectPostWithoutRedirect(t *testing.T) {
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example",
		RequestTTL: time.Minute, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	defer s.Close()
	record := create(t, svc, store)
	status, body := post(t, s, service.ResponsePath, url.Values{
		"state": {record.StateParam}, "vp_token": {sdjwtSample},
	})
	if status != http.StatusOK || strings.TrimSpace(body) != "{}" {
		t.Errorf("status = %d, body = %s", status, body)
	}
}

func TestDirectPostErrors(t *testing.T) {
	now := clock
	s, svc, store := setup(t, func() time.Time { return now })
	record := create(t, svc, store)
	unknown, body := post(t, s, service.ResponsePath, url.Values{"state": {"none"}, "vp_token": {sdjwtSample}})
	if unknown != http.StatusNotFound || !strings.Contains(body, "no such transaction") {
		t.Errorf("status = %d, body = %s", unknown, body)
	}
	bad, body := post(t, s, service.ResponsePath, url.Values{"state": {record.StateParam}})
	if bad != http.StatusBadRequest || !strings.Contains(body, "not valid") {
		t.Errorf("status = %d, body = %s", bad, body)
	}
	refused, _ := post(t, s, service.ResponsePath, url.Values{
		"state": {record.StateParam}, "error": {"access_denied"},
	})
	if refused != http.StatusOK {
		t.Errorf("a refusal answers %d", refused)
	}
	second := create(t, svc, store)
	now = clock.Add(2 * time.Minute)
	gone, body := post(t, s, service.ResponsePath, url.Values{
		"state": {second.StateParam}, "vp_token": {sdjwtSample},
	})
	if gone != http.StatusGone || !strings.Contains(body, "expired") {
		t.Errorf("status = %d, body = %s", gone, body)
	}
}

func TestDirectPostRejectsBadBody(t *testing.T) {
	s, _, _ := setup(t, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+service.ResponsePath, strings.NewReader("%zz"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a body that is not a form answers %d", resp.StatusCode)
	}
}

func TestDirectPostStoreFailure(t *testing.T) {
	// A transaction the store cannot write again fails with 500.
	store, err := txn.NewStore(writeOnce{KeyValue: shared.Memory()})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example",
		RequestTTL: time.Minute, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	defer s.Close()
	status, body := post(t, s, service.ResponsePath, url.Values{"state": {"s"}, "vp_token": {sdjwtSample}})
	if status != http.StatusNotFound {
		t.Errorf("status = %d, body = %s", status, body)
	}
}

// writeOnce refuses every write, so the store stays empty.
type writeOnce struct {
	shared.KeyValue
}
