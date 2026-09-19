// SPDX-License-Identifier: Apache-2.0

// Package detect says what a scanned or pasted text is
// (ADR-021 decision 3). The citizen scans a QR code or pastes a text.
// The wallet must know whether the text is a credential offer, a
// presentation request, or a credential.
//
// Every function here is pure. The package does no network call.
package detect

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// Kind names the type of a text.
type Kind int

// The kinds the wallet knows.
const (
	// Unknown is a text the wallet cannot use.
	Unknown Kind = iota
	// Offer is an OID4VCI credential offer.
	Offer
	// Request is an OID4VP presentation request.
	Request
	// Credential is a credential in a supported format.
	Credential
)

// SchemeOffer is the URI scheme of an OID4VCI credential offer.
const SchemeOffer = "openid-credential-offer"

// SchemeRequest is the URI scheme of an OID4VP request.
const SchemeRequest = "openid4vp"

// ErrEmpty reports a text with no content.
var ErrEmpty = errors.New("detect: the text is empty")

// ErrTooLong reports a text above the size limit.
var ErrTooLong = errors.New("detect: the text is too long")

// Result is what the wallet found in a text.
type Result struct {
	// Kind is the type of the text.
	Kind Kind
	// Offer holds the credential offer, when Kind is Offer.
	Offer Offering
	// RequestURI is the OID4VP request, when Kind is Request. It is the
	// request_uri when the text carries one, else the whole URI.
	RequestURI string
	// Credential holds the credential bytes, when Kind is Credential.
	Credential []byte
	// Format is the wire format of Credential.
	Format commonv1.Format
}

// Offering is the content of a credential offer, as OID4VCI 1.0
// section 4.1 defines it.
type Offering struct {
	// URI is the offer as the citizen scanned it. The holder backend
	// takes this value.
	URI string
	// CredentialIssuer is the issuer URL of the offer.
	CredentialIssuer string
	// ConfigurationIDs are the credential configuration ids of the offer.
	ConfigurationIDs []string
	// PreAuthorized is true when the offer carries a pre-authorized code.
	PreAuthorized bool
	// NeedsPIN is true when the offer needs a transaction code.
	NeedsPIN bool
	// ByReference is true when the offer came as credential_offer_uri.
	ByReference bool
}

// Text classifies raw text. The limit caps the size in bytes. A limit
// of zero or less applies no limit.
func Text(raw string, limit int64) (Result, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return Result{}, ErrEmpty
	}
	if limit > 0 && int64(len(text)) > limit {
		return Result{}, ErrTooLong
	}
	if r, ok := offerOf(text); ok {
		return r, nil
	}
	if r, ok := requestOf(text); ok {
		return r, nil
	}
	if r, ok := credentialOf(text); ok {
		return r, nil
	}
	return Result{Kind: Unknown}, nil
}

// offerOf reads a credential offer URI or a bare offer object.
func offerOf(text string) (Result, bool) {
	if strings.HasPrefix(text, "{") {
		var doc map[string]any
		if json.Unmarshal([]byte(text), &doc) != nil {
			return Result{}, false
		}
		if _, ok := doc["credential_issuer"]; !ok {
			return Result{}, false
		}
		return Result{Kind: Offer, Offer: fromObject(text, doc)}, true
	}
	u, err := url.Parse(text)
	if err != nil || !hasOfferScheme(u) {
		return Result{}, false
	}
	q := u.Query()
	if uri := q.Get("credential_offer_uri"); uri != "" {
		return Result{Kind: Offer, Offer: Offering{URI: text, ByReference: true}}, true
	}
	var doc map[string]any
	if json.Unmarshal([]byte(q.Get("credential_offer")), &doc) != nil {
		return Result{Kind: Offer, Offer: Offering{URI: text}}, true
	}
	return Result{Kind: Offer, Offer: fromObject(text, doc)}, true
}

// hasOfferScheme reports whether u is a credential offer URI.
func hasOfferScheme(u *url.URL) bool {
	if u.Scheme == SchemeOffer {
		return true
	}
	return u.Query().Get("credential_offer") != "" || u.Query().Get("credential_offer_uri") != ""
}

// fromObject reads the fields of a credential offer object.
func fromObject(uri string, doc map[string]any) Offering {
	out := Offering{URI: uri}
	if s, ok := doc["credential_issuer"].(string); ok {
		out.CredentialIssuer = s
	}
	if list, ok := doc["credential_configuration_ids"].([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				out.ConfigurationIDs = append(out.ConfigurationIDs, s)
			}
		}
	}
	grants, _ := doc["grants"].(map[string]any)
	for name, raw := range grants {
		if !strings.Contains(name, "pre-authorized_code") {
			continue
		}
		out.PreAuthorized = true
		grant, _ := raw.(map[string]any)
		if _, ok := grant["tx_code"]; ok {
			out.NeedsPIN = true
		}
	}
	return out
}

// requestOf reads an OID4VP request URI.
func requestOf(text string) (Result, bool) {
	u, err := url.Parse(text)
	if err != nil {
		return Result{}, false
	}
	q := u.Query()
	if u.Scheme != SchemeRequest && q.Get("request_uri") == "" && q.Get("presentation_definition") == "" &&
		q.Get("dcql_query") == "" {
		return Result{}, false
	}
	if uri := strings.TrimSpace(q.Get("request_uri")); uri != "" {
		return Result{Kind: Request, RequestURI: uri}, true
	}
	return Result{Kind: Request, RequestURI: text}, true
}

// credentialOf reads a credential in a supported format.
func credentialOf(text string) (Result, bool) {
	format := FormatOf(vc.DetectFormat([]byte(text)))
	if format == commonv1.Format_FORMAT_UNSPECIFIED {
		return Result{}, false
	}
	return Result{Kind: Credential, Credential: []byte(text), Format: format}, true
}

// FormatOf maps a core format to the proto format.
func FormatOf(f vc.Format) commonv1.Format {
	switch f {
	case vc.FormatSDJWT:
		return commonv1.Format_FORMAT_DC_SD_JWT
	case vc.FormatJWT:
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case vc.FormatJSONLD:
		return commonv1.Format_FORMAT_LDP_VC
	case vc.FormatMdoc:
		return commonv1.Format_FORMAT_MSO_MDOC
	case vc.FormatJSON, vc.FormatUnknown:
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// Explain returns one sentence that says what the wallet found. The
// citizen reads it on the scan page (ADR-028).
func Explain(r Result) string {
	switch r.Kind {
	case Offer:
		if r.Offer.NeedsPIN {
			return "This code offers you a credential. Type the code the issuer gave you."
		}
		return "This code offers you a credential. Check the issuer, then accept it."
	case Request:
		return "This code asks you to show a credential. Read the list before you agree."
	case Credential:
		return "This text holds a credential. The wallet can store it."
	case Unknown:
		return "The wallet does not know this text. Scan the code again."
	}
	return "The wallet does not know this text. Scan the code again."
}
