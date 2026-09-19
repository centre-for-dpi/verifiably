// SPDX-License-Identifier: Apache-2.0

package blobs

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// Guard checks the synchronizer token of a write.
type Guard interface {
	Check(r *http.Request, c session.Citizen) error
}

// API serves the browser storage endpoints (ADR-021 decision 4).
//
//	GET    {prefix}/blobs       every blob of the citizen
//	PUT    {prefix}/blobs/{id}  write one blob
//	DELETE {prefix}/blobs/{id}  remove one blob
//
// The endpoints are plain net/http handlers, because the browser sends
// a fetch request with the session cookie (ADR-003 decision 7).
type API struct {
	store  *Store
	prefix string
	guard  Guard
}

// NewAPI returns the endpoints. The prefix starts with a slash.
func NewAPI(st *Store, prefix string, guard Guard) (*API, error) {
	if st == nil {
		return nil, errors.New("blobs: a store is required")
	}
	prefix = "/" + strings.Trim(prefix, "/")
	return &API{store: st, prefix: prefix, guard: guard}, nil
}

// Register adds the endpoints to mux. The caller wraps mux with the
// session middleware.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+a.prefix+"/blobs", a.list)
	mux.HandleFunc("PUT "+a.prefix+"/blobs/{id}", a.put)
	mux.HandleFunc("DELETE "+a.prefix+"/blobs/{id}", a.remove)
}

// listBody is the answer of the list endpoint.
type listBody struct {
	// Blobs holds every blob of the citizen.
	Blobs []Record `json:"blobs"`
}

// list answers with every blob of the citizen.
func (a *API) list(w http.ResponseWriter, r *http.Request) {
	citizen, ok := session.From(r.Context())
	if !ok {
		fail(w, http.StatusUnauthorized, "log in first")
		return
	}
	list, err := a.store.List(r.Context(), citizen.WalletKey())
	if err != nil {
		fail(w, http.StatusInternalServerError, "the store did not answer")
		return
	}
	writeJSON(w, http.StatusOK, listBody{Blobs: list})
}

// put writes one blob.
func (a *API) put(w http.ResponseWriter, r *http.Request) {
	citizen, ok := a.writer(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, a.store.MaxBytes()+1))
	if err != nil {
		fail(w, http.StatusBadRequest, "the body did not arrive")
		return
	}
	if int64(len(raw)) > a.store.MaxBytes() {
		fail(w, http.StatusRequestEntityTooLarge, "the blob is too large")
		return
	}
	envelope, err := Parse(raw)
	if err != nil {
		fail(w, http.StatusBadRequest, "the envelope is not valid")
		return
	}
	rec, err := a.store.Put(r.Context(), citizen.WalletKey(), r.PathValue("id"), envelope)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrBadID) || errors.Is(err, ErrTooLarge) {
			status = http.StatusBadRequest
		}
		fail(w, status, "the blob was not stored")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// remove deletes one blob.
func (a *API) remove(w http.ResponseWriter, r *http.Request) {
	citizen, ok := a.writer(w, r)
	if !ok {
		return
	}
	if err := a.store.Delete(r.Context(), citizen.WalletKey(), r.PathValue("id")); err != nil {
		fail(w, http.StatusBadRequest, "the blob was not removed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writer returns the citizen of a write request. It answers the request
// itself when the session or the token is missing.
func (a *API) writer(w http.ResponseWriter, r *http.Request) (session.Citizen, bool) {
	citizen, ok := session.From(r.Context())
	if !ok {
		fail(w, http.StatusUnauthorized, "log in first")
		return session.Citizen{}, false
	}
	if a.guard != nil {
		if err := a.guard.Check(r, citizen); err != nil {
			fail(w, http.StatusForbidden, "the page token is not valid, load the page again")
			return session.Citizen{}, false
		}
	}
	return citizen, true
}

// writeJSON writes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	ignored := json.NewEncoder(w).Encode(v)
	_ = ignored
}

// fail writes one sentence as a JSON error.
func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
