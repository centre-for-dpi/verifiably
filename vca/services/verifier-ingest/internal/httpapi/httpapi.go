// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the standards defined endpoints of the
// ingestion service (ADR-003 decision 7, ADR-023 decision 5). A wallet
// is not a Connect client, so these stay plain net/http handlers.
//
// Paths:
//
//	GET  /oid4vp/request/{id}  the signed request object of one transaction
//	POST /oid4vp/response      the direct post endpoint of the wallet
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// MaxResponseBytes caps the direct post body.
const MaxResponseBytes = 8 << 20

// Handler answers the wallet endpoints.
type Handler struct {
	svc *service.Service
}

// New builds the handler.
func New(svc *service.Service) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("httpapi: an ingest service is required")
	}
	return &Handler{svc: svc}, nil
}

// Register adds the endpoints to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+service.RequestPath+"{id}", h.requestObject)
	mux.HandleFunc("POST "+service.ResponsePath, h.directPost)
}

// requestObject serves the signed request object of one transaction.
func (h *Handler) requestObject(w http.ResponseWriter, r *http.Request) {
	token, err := h.svc.RequestObject(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, txn.ErrNotFound) {
			http.Error(w, "no such request", http.StatusNotFound)
			return
		}
		http.Error(w, "the request object is not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", oid4vp.MediaTypeRequestObject)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(token))
}

// directPost takes the answer of a wallet and calls ReceiveDirectPost.
func (h *Handler) directPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxResponseBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the answer is not a form", http.StatusBadRequest)
		return
	}
	req := &ingestv1.ReceiveDirectPostRequest{
		State:                  strings.TrimSpace(r.PostForm.Get("state")),
		VpToken:                r.PostForm.Get("vp_token"),
		PresentationSubmission: r.PostForm.Get("presentation_submission"),
		ResponseJwt:            r.PostForm.Get("response"),
		Error:                  strings.TrimSpace(r.PostForm.Get("error")),
	}
	resp, err := h.svc.ReceiveDirectPost(r.Context(), connect.NewRequest(req))
	if err != nil {
		http.Error(w, reason(err), statusOf(err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if uri := resp.Msg.GetRedirectUri(); uri != "" {
		writeJSON(w, `{"redirect_uri":`+quote(uri)+`}`)
		return
	}
	writeJSON(w, `{}`)
}

// writeJSON writes one small JSON document.
func writeJSON(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body))
}

// quote writes a JSON string. The URI comes from the configuration.
func quote(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// statusOf maps a Connect code to an HTTP status.
func statusOf(err error) int {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		switch cerr.Code() {
		case connect.CodeNotFound:
			return http.StatusNotFound
		case connect.CodeInvalidArgument:
			return http.StatusBadRequest
		case connect.CodeDeadlineExceeded:
			return http.StatusGone
		}
	}
	return http.StatusInternalServerError
}

// reason returns the short sentence the wallet reads.
func reason(err error) string {
	switch statusOf(err) {
	case http.StatusNotFound:
		return "no such transaction"
	case http.StatusBadRequest:
		return "the answer is not valid"
	case http.StatusGone:
		return "the request expired"
	}
	return "the answer could not be stored"
}

// Ready reports whether the handler can take traffic. The server uses it.
func (h *Handler) Ready(_ context.Context) bool { return h.svc.Ready() }
