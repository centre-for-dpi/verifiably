package handlers

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder
	"io"
	"net/http"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pdfcpu/pdfcpu/pkg/api"

	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

// decodeUploadedQR reads a multipart-form file (field name "credential_image")
// and returns the payload encoded in the QR code it contains.
//
// Accepts a raster image (PNG/JPEG) OR a PDF: MOSIP Inji and the wallet's
// Download-PDF embed the credential QR as a PNG image XObject, which we extract
// and decode (B6 — matching Inji Verify, which also ingests PDFs). SD-JWT
// credential PDFs are claims-only and carry no QR, so they can't be verified
// this way. Returns an error if no file was uploaded, nothing decodes, or no QR
// is found in any frame.
func decodeUploadedQR(r *http.Request) (string, error) {
	file, header, err := r.FormFile("credential_image")
	if err != nil {
		return "", fmt.Errorf("no credential_image uploaded")
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", header.Filename, err)
	}

	// Candidate frames: for a PDF, every embedded image; otherwise the raster
	// upload itself.
	var frames []image.Image
	if bytes.HasPrefix(data, []byte("%PDF-")) {
		frames, err = extractPDFImages(data)
		if err != nil {
			return "", fmt.Errorf("read images from PDF %s: %w", header.Filename, err)
		}
		if len(frames) == 0 {
			return "", fmt.Errorf("no QR image found in %s (SD-JWT credential PDFs are claims-only and carry no QR)", header.Filename)
		}
	} else {
		img, _, derr := image.Decode(bytes.NewReader(data))
		if derr != nil {
			return "", fmt.Errorf("decode %s: %w", header.Filename, derr)
		}
		frames = []image.Image{img}
	}

	// Decode the first frame that yields a QR.
	reader := qrcode.NewQRCodeReader()
	var lastErr error
	for _, img := range frames {
		bmp, berr := gozxing.NewBinaryBitmapFromImage(img)
		if berr != nil {
			lastErr = berr
			continue
		}
		result, derr := reader.Decode(bmp, nil)
		if derr != nil {
			lastErr = derr
			continue
		}
		text := result.GetText()
		// A MOSIP PixelPass QR carries the VC as base45(zlib(cbor(json))); decode
		// it so the verifier receives the actual credential. Fall back to raw text
		// for QRs that already hold a raw credential (compact JWT, OID4VP URL, …).
		if vc, ok := injicertify.DecodePixelPassQR(text); ok {
			return string(vc), nil
		}
		return text, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no QR code found")
	}
	return "", fmt.Errorf("decode QR: %w", lastErr)
}

// extractPDFImages returns every embedded image in a PDF as a decoded
// image.Image, best-effort — images whose encoding isn't decodable (e.g. a
// format without a registered decoder) are skipped rather than failing the
// whole upload. The wallet/Inji credential PDF embeds the credential QR as a
// PNG XObject, which pdfcpu returns as PNG bytes.
func extractPDFImages(data []byte) ([]image.Image, error) {
	raw, err := api.ExtractImagesRaw(bytes.NewReader(data), nil, nil)
	if err != nil {
		return nil, err
	}
	var out []image.Image
	for _, page := range raw {
		for _, mi := range page {
			b, rerr := io.ReadAll(mi)
			if rerr != nil {
				continue
			}
			img, _, derr := image.Decode(bytes.NewReader(b))
			if derr != nil {
				continue // unsupported image encoding — skip
			}
			out = append(out, img)
		}
	}
	return out, nil
}
