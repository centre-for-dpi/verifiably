// SPDX-License-Identifier: Apache-2.0

package blobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/blobs"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// guard rejects a request without the header the test sets.
type guard struct{ reject bool }

func (g guard) Check(r *http.Request, _ session.Citizen) error {
	if g.reject || r.Header.Get("X-CSRF-Token") == "" {
		return errors.New("no token")
	}
	return nil
}

// api builds the endpoints with a session on every request.
func api(t *testing.T, st *blobs.Store, g blobs.Guard, citizen *session.Citizen) http.Handler {
	t.Helper()
	a, err := blobs.NewAPI(st, "/wallet", g)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Register(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if citizen != nil {
			r = r.WithContext(session.With(r.Context(), *citizen))
		}
		mux.ServeHTTP(w, r)
	})
}

func body(t *testing.T, e blobs.Envelope) string {
	t.Helper()
	raw, err := blobs.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAPIRoundTrip(t *testing.T) {
	st := newStore(t, 0)
	citizen := session.Citizen{Subject: "https://idp|abc", WalletID: "wallet-1"}
	h := api(t, st, guard{}, &citizen)

	put := httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1", strings.NewReader(body(t, envelope(t, "one"))))
	put.Header.Set("X-CSRF-Token", "t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/blobs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	var got struct {
		Blobs []blobs.Record `json:"blobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Blobs) != 1 || got.Blobs[0].ID != "b1" {
		t.Fatalf("blobs = %+v", got.Blobs)
	}
	del := httptest.NewRequest(http.MethodDelete, "/wallet/blobs/b1", nil)
	del.Header.Set("X-CSRF-Token", "t")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
}

func TestAPINeedsSession(t *testing.T) {
	h := api(t, newStore(t, 0), guard{}, nil)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/wallet/blobs", nil),
		httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1", strings.NewReader("{}")),
		httptest.NewRequest(http.MethodDelete, "/wallet/blobs/b1", nil),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s = %d", r.Method, rec.Code)
		}
	}
}

func TestAPIChecksToken(t *testing.T) {
	citizen := session.Citizen{Subject: "s", WalletID: "w"}
	h := api(t, newStore(t, 0), guard{reject: true}, &citizen)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1", strings.NewReader("{}")))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("put = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/blobs/b1", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete = %d", rec.Code)
	}
}

func TestAPIRejectsBadWrites(t *testing.T) {
	citizen := session.Citizen{Subject: "s", WalletID: "w"}
	st := newStore(t, 120)
	h := api(t, st, nil, &citizen)

	bad := httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1", strings.NewReader("{oops"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad envelope = %d", rec.Code)
	}
	large := httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1",
		strings.NewReader(body(t, envelope(t, strings.Repeat("a", 400)))))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, large)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large = %d", rec.Code)
	}
	full := api(t, newStore(t, 0), nil, &citizen)
	badID := httptest.NewRequest(http.MethodPut, "/wallet/blobs/%2e%2e", strings.NewReader(body(t, envelope(t, "x"))))
	rec = httptest.NewRecorder()
	full.ServeHTTP(rec, badID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	full.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/blobs/%2e%2e", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id delete = %d", rec.Code)
	}
}

// failingKV fails every call, so the endpoints report a problem.
type failingKV struct{}

func (failingKV) Get(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
func (failingKV) Put(context.Context, string, []byte) error   { return errors.New("down") }
func (failingKV) Delete(context.Context, string) error        { return errors.New("down") }
func (failingKV) List(context.Context, string) ([]string, error) {
	return nil, errors.New("down")
}
func (failingKV) CompareAndSwap(context.Context, string, []byte, []byte) error {
	return errors.New("down")
}

func TestAPIListFails(t *testing.T) {
	st, err := blobs.NewStore(failingKV{}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	citizen := session.Citizen{Subject: "s", WalletID: "w"}
	h := api(t, st, nil, &citizen)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/blobs", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list = %d", rec.Code)
	}
	put := httptest.NewRequest(http.MethodPut, "/wallet/blobs/b1", strings.NewReader(body(t, envelope(t, "x"))))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, put)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("put = %d", rec.Code)
	}
}

func TestNewAPINeedsStore(t *testing.T) {
	if _, err := blobs.NewAPI(nil, "/wallet", nil); err == nil {
		t.Fatal("want an error")
	}
}
