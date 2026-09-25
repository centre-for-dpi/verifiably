// SPDX-License-Identifier: Apache-2.0

// Package qrscan holds the camera QR scanner of the pages that read a
// QR code in the browser: the verifier ingestion page and the wallet
// (ADR-023 decision 6). The script reads the code on the device and
// posts only the decoded text. The camera frames never leave the device.
//
// A page that uses the scanner carries these elements:
//
//	<form id="scan-form" data-ingest="<post URL>">  with the csrf_token input
//	<button type="button" id="scan-start">           starts and stops the camera
//	<video id="scan-video" hidden>                   the camera view
//	<p id="scan-status" role="status">               the state in words
//	<div id="scan-result" role="status">             the answer of the post
//
// The script posts the text as the form field payload with the token in
// the X-CSRF-Token header. It writes the answer into scan-result. An
// answer with the header HX-Redirect sends the browser to that address.
package qrscan

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// Files holds the vendored browser assets.
//
//go:embed static
var Files embed.FS

// Names of the files a page loads, in load order.
const (
	// Reader is jsQR, the QR decoder.
	Reader = "jsqr.min.js"
	// Script is the camera scanner.
	Script = "scanner.js"
)

// static is the static directory of Files. The directory ships in the
// binary, so the sub tree always exists.
var static = anyval.Must(fs.Sub(Files, "static"))

// Handler serves the files with a long cache lifetime. Mount it under
// a prefix with http.StripPrefix.
func Handler() http.Handler {
	files := static
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.FileServerFS(files).ServeHTTP(w, r)
	})
}
