package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/makiuchi-d/gozxing"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"

	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

// walletPDFQRText extracts every image from the PDF and returns the decoded
// text of the first QR found ("" when no image carries a QR).
func walletPDFQRText(t *testing.T, pdf []byte) string {
	t.Helper()
	imgs, err := extractPDFImages(pdf)
	if err != nil {
		t.Fatalf("extractPDFImages: %v", err)
	}
	for _, img := range imgs {
		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		if err != nil {
			continue
		}
		if res, err := zxqr.NewQRCodeReader().Decode(bmp, nil); err == nil {
			return res.GetText()
		}
	}
	return ""
}

// walletPDFNoise returns n deterministic pseudo-random base64url characters.
func walletPDFNoise(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, n)
	x := uint32(2463534242)
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = alphabet[x%64]
	}
	return string(out)
}

func walletPDFRequest(h *H, id string, held ...string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/holder/wallet/inji/credentials/"+id+"/pdf", nil)
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	sess := h.Sessions.MustGet(rr, req)
	sess.InjiClaimedVCs = held
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestDownloadInjiClaimedPDF(t *testing.T) {
	const w3c = `{"type":["VerifiableCredential","PersonCredential"],"issuer":"did:example:issuer","credentialSubject":{"fullName":"Ada Lovelace","dob":"1815"}}`
	// An oversized W3C VC and an oversized SD-JWT both overflow QR v40 and fall
	// back to the QR-less layout, with a format-aware note.
	// (PixelPass zlib-compresses, so the payload must be incompressible.)
	bigW3C := `{"type":["VerifiableCredential","BigCredential"],"credentialSubject":{"blob":"` + walletPDFNoise(12000) + `"}}`
	bigSDJWT := "eyJhbGciOiJFUzI1NiJ9." + walletPDFNoise(12000) + ".sig~disc~"

	t.Run("unknown id -> 404", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.DownloadInjiClaimedPDF(rr, walletPDFRequest(h, "nope", w3c))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("w3c with QR", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		id := vcID(w3c)
		rr := httptest.NewRecorder()
		h.DownloadInjiClaimedPDF(rr, walletPDFRequest(h, id, "other", w3c))
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/pdf" {
			t.Fatalf("status = %d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
		}
		if cd := rr.Header().Get("Content-Disposition"); cd != `attachment; filename="credential-`+id+`.pdf"` {
			t.Errorf("Content-Disposition = %q", cd)
		}
		if !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
			t.Fatal("body is not a PDF")
		}
		// The embedded QR is a PixelPass payload that decodes back to the VC.
		qr := walletPDFQRText(t, rr.Body.Bytes())
		if qr == "" {
			t.Fatal("QR-on-PDF layout must embed a scannable QR")
		}
		if got, ok := injicertify.DecodePixelPassQR(qr); !ok || !bytes.Contains(got, []byte(`"fullName":"Ada Lovelace"`)) {
			t.Errorf("QR payload does not decode to the credential: ok=%v %s", ok, got)
		}
	})
	t.Run("large w3c falls back without QR", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.DownloadInjiClaimedPDF(rr, walletPDFRequest(h, vcID(bigW3C), bigW3C))
		if rr.Code != http.StatusOK || !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
			t.Fatalf("status = %d", rr.Code)
		}
		if qr := walletPDFQRText(t, rr.Body.Bytes()); qr != "" {
			t.Errorf("oversized credential must render the QR-less layout, found QR %q", qr)
		}
	})
	t.Run("large sd-jwt falls back without QR", func(t *testing.T) {
		h := &H{Sessions: NewStore()}
		rr := httptest.NewRecorder()
		h.DownloadInjiClaimedPDF(rr, walletPDFRequest(h, vcID(bigSDJWT), bigSDJWT))
		if rr.Code != http.StatusOK || !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		if qr := walletPDFQRText(t, rr.Body.Bytes()); qr != "" {
			t.Errorf("oversized SD-JWT must render the QR-less layout, found QR %q", qr)
		}
	})
}
