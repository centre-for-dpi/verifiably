// SPDX-License-Identifier: Apache-2.0

// Package render draws the credential document of the PDF channel
// (ADR-016 decision 3). The document is one A4 page. It carries the
// issuer line, the heading, the claims of the citizen, and a QR code.
//
// The QR payload follows ADR-016 decision 4. A credential goes in as the
// PixelPass form of the MOSIP reader: the bytes become CBOR, then zlib
// deflate, then base45. A credential offer goes in as its URI.
package render

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/pdf"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/core/qr"
)

// ErrNoPayload reports a document without a QR payload.
var ErrNoPayload = errors.New("render: the document needs a QR payload")

// Layout holds the measurements of the page in points.
const (
	// margin is the distance from the left and the right edge.
	margin = 85.0
	// issuerY is the baseline of the issuer line.
	issuerY = 800.0
	// titleY is the baseline of the heading.
	titleY = 770.0
	// ruleY is the height of the line under the heading.
	ruleY = 752.0
	// claimsY is the baseline of the first claim.
	claimsY = 728.0
	// claimStep is the distance between two claims.
	claimStep = 19.0
	// valueX is the left edge of a claim value.
	valueX = 245.0
	// qrSize is the width of the QR square.
	qrSize = 240.0
	// noteGap is the distance from the QR to the note under it.
	noteGap = 16.0
	// footerY is the baseline of the footer.
	footerY = 60.0
	// maxClaims is the number of claims one page holds.
	maxClaims = 20
)

// Document is the input of Render.
type Document struct {
	// Title is the heading of the page.
	Title string
	// Issuer is the line above the heading.
	Issuer string
	// Claims are the claims of the citizen, keyed by property name.
	Claims map[string]string
	// Order lists the claim names in display order. An empty order sorts
	// the names.
	Order []string
	// Note is the line under the QR code.
	Note string
	// Footer is the line at the foot of the page.
	Footer string
	// QRPayload is the value the QR code carries.
	QRPayload string
	// IssuedAt is the time in the footer.
	IssuedAt time.Time
}

// OfferPayload returns the QR payload of a credential offer. The wallet
// reads the URI as it is.
func OfferPayload(offerURI string) string { return strings.TrimSpace(offerURI) }

// CredentialPayload returns the QR payload of a credential. The MOSIP
// reader wants the PixelPass form. A raw JSON payload breaks its base45
// reader at the first character.
func CredentialPayload(credential []byte) (string, error) {
	payload, err := pixelpass.Encode(credential)
	if err != nil {
		return "", fmt.Errorf("render: encode the QR payload: %w", err)
	}
	return payload, nil
}

// Render returns the PDF bytes of the document.
func Render(d Document) ([]byte, error) {
	if strings.TrimSpace(d.QRPayload) == "" {
		return nil, ErrNoPayload
	}
	code, err := qr.Encode([]byte(d.QRPayload))
	if err != nil {
		return nil, fmt.Errorf("render: encode the QR code: %w", err)
	}
	// The margin of four modules is the smallest the standard allows.
	// The scale keeps the image small and the modules square.
	bitmap := code.Bitmap(scaleFor(code.Size), 4)
	title := d.Title
	if title == "" {
		title = "Credential"
	}
	doc := pdf.New(title)
	if d.Issuer != "" {
		doc.TextCentered(pdf.Helvetica, 10, issuerY, 0.45, d.Issuer)
	}
	doc.TextCentered(pdf.HelveticaBold, 22, titleY, 0.15, title)
	doc.Line(margin, ruleY, pdf.PageWidth-margin, ruleY, 0.6, 0.8)
	y := claimsY
	for _, name := range ClaimOrder(d.Claims, d.Order) {
		value := d.Claims[name]
		if value == "" {
			continue
		}
		doc.Text(pdf.HelveticaBold, 10, margin, y, 0.3, Humanise(name)+":")
		doc.Text(pdf.Helvetica, 11, valueX, y, 0.25, value)
		y -= claimStep
	}
	qrY := y - qrSize - noteGap
	if qrY < footerY+3*noteGap {
		qrY = footerY + 3*noteGap
	}
	image := pdf.Image{Width: bitmap.Width, Height: bitmap.Height, Pixels: bitmap.Pixels}
	if err := doc.Image(image, (pdf.PageWidth-qrSize)/2, qrY, qrSize); err != nil {
		return nil, fmt.Errorf("render: place the QR code: %w", err)
	}
	if d.Note != "" {
		doc.TextCentered(pdf.HelveticaOblique, 9, qrY-noteGap, 0.5, d.Note)
	}
	footer := d.Footer
	if footer == "" && !d.IssuedAt.IsZero() {
		footer = "Issued " + d.IssuedAt.UTC().Format(time.RFC3339)
	}
	if footer != "" {
		doc.TextCentered(pdf.Helvetica, 8, footerY, 0.6, footer)
	}
	return doc.Bytes(), nil
}

// scaleFor returns the pixel size of one module. A small symbol gets a
// larger scale, so every document holds a sharp image of a similar size.
func scaleFor(size int) int {
	scale := 480 / size
	if scale < 2 {
		return 2
	}
	if scale > 8 {
		return 8
	}
	return scale
}

// ClaimOrder returns the claim names in display order. The order of the
// caller comes first. Every other name follows in sorted order, so the
// document is the same on every run.
func ClaimOrder(claims map[string]string, order []string) []string {
	out := make([]string, 0, len(claims))
	seen := map[string]bool{}
	for _, name := range order {
		if _, ok := claims[name]; ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	rest := make([]string, 0, len(claims))
	for name := range claims {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	out = append(out, rest...)
	if len(out) > maxClaims {
		out = out[:maxClaims]
	}
	return out
}

// Humanise turns a property name into a label. The name full_name and
// the name fullName both become Full Name.
func Humanise(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	name = strings.ReplaceAll(name, "-", " ")
	var b strings.Builder
	previous := ' '
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' && previous >= 'a' && previous <= 'z' {
			b.WriteRune(' ')
		}
		if previous == ' ' && r >= 'a' && r <= 'z' {
			b.WriteRune(r - 32)
		} else {
			b.WriteRune(r)
		}
		previous = r
	}
	return b.String()
}
