// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // the upload page accepts GIF
	_ "image/jpeg" // the upload page accepts JPEG
	_ "image/png"  // the upload page accepts PNG

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// ErrNoQRCode reports that no frame held a QR code.
var ErrNoQRCode = errors.New("ingest: the upload holds no QR code")

// DecodeQRImage reads the text of the QR code of one image
// (ISO/IEC 18004, ADR-023 decision 3).
//
// The first pass stops at the first three finder patterns it confirms.
// A data shape that reads as a finder pattern can hide the real lower
// left one, so a valid symbol fails that pass. The second pass keeps
// every candidate pattern and tries each triple that forms a symbol.
func DecodeQRImage(img image.Image) (string, error) {
	// The reader builds the bitmap from the image and never fails here.
	bitmap := anyval.Must(gozxing.NewBinaryBitmapFromImage(img))
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err == nil {
		return result.GetText(), nil
	}
	results, multiErr := multiqr.NewQRCodeMultiReader().DecodeMultiple(bitmap, nil)
	if multiErr == nil && len(results) > 0 {
		return results[0].GetText(), nil
	}
	return "", fmt.Errorf("%w: %w", ErrNoQRCode, err)
}

// DecodeQRFrames returns the text of the first frame that holds a QR
// code.
func DecodeQRFrames(frames []image.Image) (string, error) {
	for _, frame := range frames {
		if text, err := DecodeQRImage(frame); err == nil {
			return text, nil
		}
	}
	return "", ErrNoQRCode
}

// DecodeImage reads the QR code of a PNG, JPEG, or GIF upload.
func DecodeImage(data []byte) (string, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("ingest: read the image: %w", err)
	}
	return DecodeQRImage(img)
}

// DecodePDF reads the QR code of the first image of a PDF that holds
// one. Credential PDFs of MOSIP Inji and of the wallet carry the
// credential QR as an image XObject.
func DecodePDF(data []byte) (string, error) {
	frames, err := ExtractPDFImages(data)
	if err != nil {
		return "", err
	}
	return DecodeQRFrames(frames)
}
