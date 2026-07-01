package injicertify

// export.go — thin exported wrappers over the pre-auth PDF path's internal
// helpers (pdf.go / pixelpass.go), so the holder wallet (internal/handlers) can
// render a credential it already holds as the SAME QR-on-PDF the issuer's
// "As a PDF" mode produces, without duplicating the PixelPass encoder or the
// gofpdf layout. No behaviour change to the pre-auth issuance path.

// EncodePixelPassQR encodes a VC (JSON-LD object or compact string) into the
// MOSIP PixelPass QR payload (CBOR-if-JSON → zlib → base45) that Inji Verify's
// QR decoder accepts.
func EncodePixelPassQR(vc []byte) (string, error) { return encodePixelPass(vc) }

// DecodePixelPassQR reverses EncodePixelPassQR: it turns a MOSIP PixelPass QR
// payload (base45 → zlib → CBOR) back into the credential JSON. ok is false when
// s is not a well-formed PixelPass payload (e.g. a QR that already carries a raw
// JWT or JSON-LD VC), so callers can fall back to using s verbatim.
func DecodePixelPassQR(s string) ([]byte, bool) {
	js, err := decodePixelPass(s)
	if err != nil {
		return nil, false
	}
	return js, true
}

// RenderCredentialPDF lays out a one-page A4 credential — issuer line, title,
// human-readable claim rows, and a QR embedding qrPayload — and returns the PDF
// bytes. `order` fixes the claim-row order; pass nil to use map order.
func RenderCredentialPDF(title, issuer, qrPayload string, fields map[string]string, order []string) ([]byte, error) {
	return renderCredentialPDF(title, issuer, qrPayload, fields, order)
}
