package handlers

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/jung-kurt/gofpdf"
	qrgen "github.com/skip2/go-qrcode"

	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

func qrUploadRequest(t *testing.T, field, filename string, body []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/verifier/verify/qr", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func qrPDFWithPNG(t *testing.T, pngBytes []byte) []byte {
	t.Helper()
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.RegisterImageOptionsReader("img", gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(pngBytes))
	pdf.ImageOptions("img", 20, 20, 60, 60, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func qrBlankPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.White)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeUploadedQR(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		_, err := decodeUploadedQR(qrUploadRequest(t, "other_field", "x.png", []byte("x")))
		if err == nil || err.Error() != "no credential_image uploaded" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unreadable upload", func(t *testing.T) {
		// net/http keeps oversized parts in a temp file it reopens on FormFile.
		// Point that (unexported) tmpfile at a directory: Open succeeds, the
		// first Read fails — the only way to reach the read-error branch.
		fh := &multipart.FileHeader{Filename: "dir.png", Size: 1}
		f := reflect.ValueOf(fh).Elem().FieldByName("tmpfile")
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetString(t.TempDir())
		req := httptest.NewRequest(http.MethodPost, "/verifier/verify/qr", nil)
		req.MultipartForm = &multipart.Form{File: map[string][]*multipart.FileHeader{"credential_image": {fh}}}
		_, err := decodeUploadedQR(req)
		if err == nil || !strings.HasPrefix(err.Error(), "read dir.png:") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("undecodable raster", func(t *testing.T) {
		_, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "junk.png", []byte("not an image")))
		if err == nil || !strings.HasPrefix(err.Error(), "decode junk.png:") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("raster without a QR", func(t *testing.T) {
		_, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "blank.png", qrBlankPNG(t)))
		if err == nil || !strings.HasPrefix(err.Error(), "decode QR:") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("raw text QR", func(t *testing.T) {
		pngBytes, err := qrgen.Encode("eyJhbGciOiJFUzI1NiJ9.e30.sig", qrgen.Medium, 256)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "qr.png", pngBytes))
		if err != nil || got != "eyJhbGciOiJFUzI1NiJ9.e30.sig" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})
	t.Run("PixelPass QR is decoded to the credential", func(t *testing.T) {
		vc := `{"type":["VerifiableCredential"],"credentialSubject":{"fullName":"Ada"}}`
		payload, err := injicertify.EncodePixelPassQR([]byte(vc))
		if err != nil {
			t.Fatal(err)
		}
		pngBytes, err := qrgen.Encode(payload, qrgen.Medium, 512)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "pp.png", pngBytes))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, `"fullName"`) || !strings.Contains(got, "Ada") {
			t.Fatalf("PixelPass payload not decoded: %q", got)
		}
	})
	t.Run("PDF with QR", func(t *testing.T) {
		pngBytes, err := qrgen.Encode("IN-PDF", qrgen.Medium, 256)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "c.pdf", qrPDFWithPNG(t, pngBytes)))
		if err != nil || got != "IN-PDF" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})
	t.Run("PDF without images", func(t *testing.T) {
		pdf := gofpdf.New("P", "mm", "A4", "")
		pdf.AddPage()
		var buf bytes.Buffer
		if err := pdf.Output(&buf); err != nil {
			t.Fatal(err)
		}
		_, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "claims.pdf", buf.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "no QR image found in claims.pdf") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("corrupt PDF", func(t *testing.T) {
		_, err := decodeUploadedQR(qrUploadRequest(t, "credential_image", "bad.pdf", []byte("%PDF-1.4 garbage")))
		if err == nil || !strings.HasPrefix(err.Error(), "read images from PDF bad.pdf:") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestExtractPDFImages_SkipsUndecodableImage(t *testing.T) {
	// A hand-built PDF whose only image XObject is JPX-encoded: pdfcpu hands the
	// raw stream back and Go has no JPEG 2000 decoder, so it is skipped.
	stream := "\x00\x00\x00\x0cjP  \r\n\x87\nnot-really-jpx"
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /XObject /Subtype /Image /Width 4 /Height 4 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /JPXDecode /Length " +
			itoa(len(stream)) + " >>\nstream\n" + stream + "\nendstream",
		"<< /Length 30 >>\nstream\nq 100 0 0 100 50 50 cm /Im1 Do Q\nendstream",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = b.Len()
		b.WriteString(itoa(i+1) + " 0 obj\n" + o + "\nendobj\n")
	}
	xref := b.Len()
	b.WriteString("xref\n0 " + itoa(len(objs)+1) + "\n0000000000 65535 f \n")
	for i := 1; i <= len(objs); i++ {
		off := itoa(offsets[i])
		b.WriteString(strings.Repeat("0", 10-len(off)) + off + " 00000 n \n")
	}
	b.WriteString("trailer\n<< /Size " + itoa(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" + itoa(xref) + "\n%%EOF\n")

	imgs, err := extractPDFImages(b.Bytes())
	if err != nil {
		t.Fatalf("extractPDFImages: %v", err)
	}
	if len(imgs) != 0 {
		t.Fatalf("undecodable image must be skipped, got %d images", len(imgs))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
