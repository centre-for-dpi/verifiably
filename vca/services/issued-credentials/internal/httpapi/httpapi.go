// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the standards style endpoints of the service
// (ADR-003 decision 7). An auditor reads the signed chain head and the
// public key without a Connect client.
//
//	GET /issued/chain-head serves the latest signed head as a compact JWS.
//	GET /issued/jwks.json serves the public key that signed the head.
package httpapi

import (
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
)

// Paths of the endpoints.
const (
	ChainHeadPath = "/issued/chain-head"
	JWKSPath      = "/issued/jwks.json"
)

// MediaTypeJOSE is the media type of a compact JWS.
const MediaTypeJOSE = "application/jose"

// Heads returns the latest signed chain head.
type Heads interface {
	SignedHead() (*issuedv1.ChainHead, error)
}

// Keys returns the public keys that sign the head.
type Keys interface {
	JWKS() jose.JWKS
}

// Register adds the endpoints to mux. A nil keys value turns the JWKS
// endpoint off.
func Register(mux *http.ServeMux, heads Heads, keys Keys) {
	mux.HandleFunc("GET "+ChainHeadPath, chainHead(heads))
	if keys != nil {
		mux.HandleFunc("GET "+JWKSPath, jwks(keys))
	}
}

// chainHead serves the signed head as a compact JWS.
func chainHead(heads Heads) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		head, err := heads.SignedHead()
		if err != nil {
			status(w, err)
			return
		}
		w.Header().Set("Content-Type", MediaTypeJOSE)
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("ETag", `"`+head.GetRecordHash()+`"`)
		if _, err := w.Write([]byte(head.GetJws())); err != nil {
			return
		}
	}
}

// jwks serves the public key set.
func jwks(keys Keys) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(keys.JWKS())
		if err != nil {
			http.Error(w, "the key set is not available", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if _, err := w.Write(body); err != nil {
			return
		}
	}
}

// status writes the HTTP status that matches a Connect error.
func status(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		code = http.StatusNotFound
	case connect.CodeFailedPrecondition:
		code = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), code)
}
