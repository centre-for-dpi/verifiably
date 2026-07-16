package handlers

import (
	"bytes"
	"testing"

	"github.com/jung-kurt/gofpdf"
	"github.com/makiuchi-d/gozxing"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"
	qrgen "github.com/skip2/go-qrcode"
)

// B6: a QR embedded in a PDF (as the wallet/Inji credential PDF does) is
// extracted and decodable — the verifier can now accept PDF uploads.
func TestExtractPDFImages_QRRoundtrip(t *testing.T) {
	png, err := qrgen.Encode("HELLO-PDF-QR", qrgen.Medium, 256)
	if err != nil {
		t.Fatal(err)
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.RegisterImageOptionsReader("qr", gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(png))
	pdf.ImageOptions("qr", 20, 20, 60, 60, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatal(err)
	}

	imgs, err := extractPDFImages(buf.Bytes())
	if err != nil {
		t.Fatalf("extractPDFImages: %v", err)
	}
	if len(imgs) == 0 {
		t.Fatal("expected at least one embedded image")
	}

	found := false
	for _, img := range imgs {
		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		if err != nil {
			continue
		}
		res, err := zxqr.NewQRCodeReader().Decode(bmp, nil)
		if err == nil && res.GetText() == "HELLO-PDF-QR" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("QR text did not round-trip through PDF embed -> extract -> decode")
	}
}
