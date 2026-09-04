package handlers

import (
	"bytes"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQRImage_MissingText(t *testing.T) {
	h := &H{}
	rec := httptest.NewRecorder()
	h.QRImage(rec, httptest.NewRequest(http.MethodGet, "/qr", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "missing text") {
		t.Fatalf("status = %d body = %q, want 400 missing text", rec.Code, rec.Body.String())
	}
}

func TestQRImage_RendersPNGWithSize(t *testing.T) {
	h := &H{}
	cases := []struct {
		name  string
		query string
		want  int // expected image width/height
	}{
		{"default size", "text=openid-credential-offer://x", 280},
		{"explicit size", "text=hello&size=120", 120},
		{"size out of range falls back", "text=hello&size=5000", 280},
		{"non-numeric size falls back", "text=hello&size=big", 280},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.QRImage(rec, httptest.NewRequest(http.MethodGet, "/qr?"+tc.query, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
				t.Errorf("Content-Type = %q", ct)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "private, max-age=60" {
				t.Errorf("Cache-Control = %q", cc)
			}
			img, err := png.Decode(bytes.NewReader(rec.Body.Bytes()))
			if err != nil {
				t.Fatalf("decode png: %v", err)
			}
			if b := img.Bounds(); b.Dx() != tc.want || b.Dy() != tc.want {
				t.Errorf("image size = %dx%d, want %d", b.Dx(), b.Dy(), tc.want)
			}
		})
	}
}

// qr.Encode rejects payloads beyond QR capacity (~2953 bytes at Medium).
func TestQRImage_EncodeError(t *testing.T) {
	h := &H{}
	rec := httptest.NewRecorder()
	h.QRImage(rec, httptest.NewRequest(http.MethodGet, "/qr?text="+strings.Repeat("a", 5000), nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "qr encode:") {
		t.Fatalf("status = %d body = %q, want 500 qr encode error", rec.Code, rec.Body.String())
	}
}
