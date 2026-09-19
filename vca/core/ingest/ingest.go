// SPDX-License-Identifier: Apache-2.0

// Package ingest holds the pure decoders of the verifier ingestion
// service (ADR-023 decisions 1 and 2). Every carrier decodes to one
// RawPresentation. The package performs no input or output. It takes
// bytes and returns a result.
//
// The carriers are an OID4VP request, an OID4VP response, an image
// upload, a PDF upload, an XML document, a pasted JSON document or
// token, the text of an ordinary QR code, and the text of a MOSIP
// Claim 169 QR code.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// Carrier names how a presentation arrived (ADR-023 decision 1).
type Carrier string

const (
	// CarrierUnknown means the caller gave no hint.
	CarrierUnknown Carrier = ""
	// CarrierOID4VPRequest is an OID4VP authorization request the citizen
	// pasted or scanned.
	CarrierOID4VPRequest Carrier = "oid4vp_request"
	// CarrierOID4VPResponse is the vp_token of a wallet.
	CarrierOID4VPResponse Carrier = "oid4vp_response"
	// CarrierImage is an image upload with a QR code.
	CarrierImage Carrier = "image"
	// CarrierPDF is a PDF upload with a QR code.
	CarrierPDF Carrier = "pdf"
	// CarrierXML is an XML document with an embedded credential.
	CarrierXML Carrier = "xml"
	// CarrierJSON is a pasted JSON document or a pasted compact token.
	CarrierJSON Carrier = "json"
	// CarrierQR is the text of an ordinary QR code.
	CarrierQR Carrier = "qr"
	// CarrierClaim169 is the text of a MOSIP Claim 169 QR code.
	CarrierClaim169 Carrier = "claim169_qr"
)

// Carriers lists every carrier the package decodes.
var Carriers = []Carrier{
	CarrierOID4VPRequest, CarrierOID4VPResponse, CarrierImage, CarrierPDF,
	CarrierXML, CarrierJSON, CarrierQR, CarrierClaim169,
}

// DetectedType names what the decoder found inside the carrier.
type DetectedType string

const (
	// TypeUnknown means the decoder does not understand the bytes.
	TypeUnknown DetectedType = "unknown"
	// TypeCredential means the payload holds one credential.
	TypeCredential DetectedType = "credential"
	// TypePresentation means the payload holds a presentation.
	TypePresentation DetectedType = "presentation"
	// TypeCWTClaim169 means the payload is a CWT with claim 169.
	TypeCWTClaim169 DetectedType = "cwt_claim169"
	// TypePixelPass means the payload is a legacy PixelPass QR code.
	TypePixelPass DetectedType = "pixelpass"
	// TypeRequest means the payload is an OID4VP request.
	TypeRequest DetectedType = "oid4vp_request"
)

// MaxInputBytes bounds one ingestion.
const MaxInputBytes = 16 << 20

// Credential is one credential the decoder split out of the payload.
type Credential struct {
	// Format is the wire format of the payload.
	Format vc.Format
	// Payload is the credential as the issuer produced it.
	Payload []byte
}

// Result is the normalised output of one ingestion.
type Result struct {
	// Carrier is the carrier the decoder used.
	Carrier Carrier
	// Format is the credential format, when the decoder found one.
	Format vc.Format
	// Payload is the decoded payload: a compact token, a JSON document,
	// or CBOR.
	Payload []byte
	// Detected names what the decoder found.
	Detected DetectedType
	// Credentials holds the credentials of the payload.
	Credentials []Credential
	// KeyBinding is the holder key binding JWT, when the presentation
	// carries one.
	KeyBinding string
	// Steps lists the decoder steps in order, for the operator.
	Steps []string
	// InputHash is the SHA-256 hash of the input bytes, hex encoded.
	InputHash string
}

// Options steer one ingestion.
type Options struct {
	// Carrier is the hint of the caller. CarrierUnknown detects it.
	Carrier Carrier
	// MediaType is the media type of the upload, when the caller knows
	// it.
	MediaType string
	// XML is the XML configuration, for CarrierXML.
	XML XMLConfig
	// MaxBytes bounds the input. Zero means MaxInputBytes.
	MaxBytes int
}

// Hash returns the hex SHA-256 hash of data.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Detect reads the carrier of the bytes. mediaType is a hint from the
// upload, and may be empty.
func Detect(data []byte, mediaType string) Carrier {
	switch {
	case IsPDF(data):
		return CarrierPDF
	case isImage(data):
		return CarrierImage
	}
	if strings.HasPrefix(mediaType, "image/") {
		return CarrierImage
	}
	if IsXML(data) {
		return CarrierXML
	}
	text := strings.TrimSpace(string(data))
	switch {
	case text == "":
		return CarrierUnknown
	case isRequestURL(text):
		return CarrierOID4VPRequest
	case strings.HasPrefix(text, "{"), strings.HasPrefix(text, "["):
		return CarrierJSON
	case looksBase45(text):
		return CarrierClaim169
	}
	return CarrierQR
}

// imagePrefixes are the magic bytes of the image types the page accepts.
var imagePrefixes = [][]byte{
	[]byte("\x89PNG\r\n\x1a\n"),
	[]byte("\xff\xd8\xff"),
	[]byte("GIF87a"),
	[]byte("GIF89a"),
}

// isImage reports whether the bytes start with a known image header.
func isImage(data []byte) bool {
	for _, prefix := range imagePrefixes {
		if len(data) >= len(prefix) && string(data[:len(prefix)]) == string(prefix) {
			return true
		}
	}
	return false
}

// requestSchemes are the URL schemes of an OID4VP request.
var requestSchemes = []string{"openid4vp://", "openid://", "haip://", "eudi-openid4vp://", "mdoc-openid4vp://"}

// isRequestURL reports whether the text is an OID4VP request URL.
func isRequestURL(text string) bool {
	lower := strings.ToLower(text)
	for _, scheme := range requestSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	return strings.Contains(lower, "request_uri=") || strings.Contains(lower, "presentation_definition=") ||
		strings.Contains(lower, "dcql_query=") || strings.Contains(lower, "response_uri=")
}

// looksBase45 reports whether every character is in the base45 alphabet
// of RFC 9285. A scheme prefix such as HC1: is allowed.
func looksBase45(text string) bool {
	body := text
	if cut := strings.IndexByte(text, ':'); cut > 0 && cut <= 8 {
		body = text[cut+1:]
	}
	if len(body) < 8 {
		return false
	}
	for _, r := range body {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", r) {
			return false
		}
	}
	return true
}

// Decode turns the bytes of one carrier into a result.
func Decode(data []byte, opts Options) (Result, error) {
	limit := opts.MaxBytes
	if limit <= 0 {
		limit = MaxInputBytes
	}
	if len(data) == 0 {
		return Result{}, errors.New("ingest: the input is empty")
	}
	if len(data) > limit {
		return Result{}, fmt.Errorf("ingest: the input is larger than %d bytes", limit)
	}
	carrier := opts.Carrier
	if carrier == CarrierUnknown {
		carrier = Detect(data, opts.MediaType)
	}
	res, err := decodeCarrier(data, carrier, opts)
	if err != nil {
		return Result{}, err
	}
	res.Carrier = carrier
	res.InputHash = Hash(data)
	return res, nil
}

// decodeCarrier runs the decoder of one carrier.
func decodeCarrier(data []byte, carrier Carrier, opts Options) (Result, error) {
	switch carrier {
	case CarrierImage:
		text, err := DecodeImage(data)
		if err != nil {
			return Result{}, err
		}
		res, err := DecodeText(text)
		return withSteps(res, err, "image", "qr")
	case CarrierPDF:
		text, err := DecodePDF(data)
		if err != nil {
			return Result{}, err
		}
		res, err := DecodeText(text)
		return withSteps(res, err, "pdf", "qr")
	case CarrierXML:
		text, err := DecodeXML(data, opts.XML)
		if err != nil {
			return Result{}, err
		}
		res, err := DecodeText(text)
		return withSteps(res, err, "xml")
	case CarrierClaim169:
		return decodeClaim169Text(strings.TrimSpace(string(data)))
	case CarrierOID4VPRequest:
		return decodeRequest(strings.TrimSpace(string(data)))
	case CarrierOID4VPResponse:
		res, err := DecodeVPToken(strings.TrimSpace(string(data)))
		return withSteps(res, err, "vp_token")
	case CarrierJSON, CarrierQR:
		res, err := DecodeText(strings.TrimSpace(string(data)))
		return withSteps(res, err)
	case CarrierUnknown:
		return Result{}, errors.New("ingest: the decoder cannot name the carrier of the input")
	}
	return Result{}, fmt.Errorf("ingest: the carrier %q is not known", carrier)
}

// withSteps puts the given steps in front of the steps of a result.
func withSteps(res Result, err error, steps ...string) (Result, error) {
	if err != nil {
		return Result{}, err
	}
	res.Steps = append(append([]string{}, steps...), res.Steps...)
	return res, nil
}

// decodeClaim169Text decodes a Claim 169 QR text. A legacy PixelPass
// code decodes with the same first two steps, so the decoder falls back
// to it (ADR-023 decision 3).
func decodeClaim169Text(text string) (Result, error) {
	cwt, steps, err := DecodeClaim169(text)
	if err == nil {
		payload, jsonErr := cwt.JSON()
		if jsonErr != nil {
			return Result{}, jsonErr
		}
		return Result{
			Format: vc.FormatJSON, Payload: payload, Detected: TypeCWTClaim169, Steps: steps,
			Credentials: []Credential{{Format: vc.FormatJSON, Payload: payload}},
		}, nil
	}
	raw, pixelErr := pixelpass.Decode(text)
	if pixelErr != nil {
		return Result{}, err
	}
	res, decodeErr := DecodeText(string(raw))
	if decodeErr != nil {
		return Result{}, decodeErr
	}
	if res.Detected == TypeUnknown {
		res.Detected = TypePixelPass
	}
	res.Steps = append([]string{"base45", "zlib", "pixelpass"}, res.Steps...)
	return res, nil
}

// decodeRequest reads an OID4VP request URL. The result carries the
// request parameters as a JSON document, so the caller can read the
// nonce and the query without a second parser.
func decodeRequest(text string) (Result, error) {
	u, err := url.Parse(text)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: read the OID4VP request: %w", err)
	}
	params := map[string]string{}
	for key, values := range u.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	if len(params) == 0 {
		return Result{}, errors.New("ingest: the OID4VP request has no parameter")
	}
	// A map of strings always writes.
	payload, _ := json.Marshal(params)
	return Result{Format: vc.FormatJSON, Payload: payload, Detected: TypeRequest, Steps: []string{"url"}}, nil
}
