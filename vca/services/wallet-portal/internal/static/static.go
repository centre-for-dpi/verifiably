// SPDX-License-Identifier: Apache-2.0

// Package static serves the browser file of the wallet
// (ADR-021 decision 4). The file wallet.js creates the holder key,
// encrypts each credential, and talks to the blob endpoints.
//
// The file ships inside the binary, so the container needs no volume.
package static

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
)

// Files holds the browser files of the wallet.
//
//go:embed wallet.js
var Files embed.FS

// Name is the file name of the wallet script.
const Name = "wallet.js"

// Path is the URL path of the wallet script under the portal prefix.
const Path = "/wallet.js"

// Script returns the text of the wallet script.
func Script() ([]byte, error) { return Files.ReadFile(Name) }

// handler serves one file with an ETag and a long cache time.
type handler struct {
	body []byte
	etag string
}

// Handler returns the handler of the wallet script.
func Handler() (http.Handler, error) {
	body, err := Script()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &handler{body: body, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}, nil
}

// ServeHTTP writes the script.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("ETag", h.etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if match := r.Header.Get("If-None-Match"); strings.Contains(match, h.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := w.Write(h.body); err != nil {
		return
	}
}
