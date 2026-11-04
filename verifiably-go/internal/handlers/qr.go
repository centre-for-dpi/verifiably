package handlers

import (
	"net/http"
	"strconv"

	qr "github.com/skip2/go-qrcode"
)

// QRImage serves a QR PNG for an arbitrary text payload. Used by UI fragments
// that need to embed a scannable QR of an OID4VCI offer URI or an OID4VP
// request URI. Pure stdlib + go-qrcode; no external services involved.
//
//	GET /qr?text=<url-encoded payload>[&size=<pixels>]
func (h *H) QRImage(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		http.Error(w, "missing text", http.StatusBadRequest)
		return
	}
	size := 280
	if s := r.URL.Query().Get("size"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1024 {
			size = n
		}
	}
	png, err := qr.Encode(text, qr.Medium, size)
	if err != nil {
		http.Error(w, "qr encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_, _ = w.Write(png)
}
