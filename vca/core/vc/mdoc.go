// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// errMdoc reports bytes that hold no readable mDoc.
var errMdoc = errors.New("vc: the mdoc does not decode")

// The CBOR tags an mDoc uses (ISO/IEC 18013-5 section 8.3.2.1.2.2).
const (
	tagEncoded  = 24   // encoded CBOR data item
	tagDateTime = 0    // tdate
	tagFullDate = 1004 // full-date
	x5chain     = 33   // COSE header of the certificate chain
)

// issuerSigned is the IssuerSigned structure of an mDoc.
type issuerSigned struct {
	NameSpaces map[string][]cbor.RawTag `cbor:"nameSpaces"`
	IssuerAuth cbor.RawMessage          `cbor:"issuerAuth"`
}

// signedItem is one IssuerSignedItem.
type signedItem struct {
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

// mso is the part of the mobile security object the view reads.
type mso struct {
	DocType       string `cbor:"docType"`
	DeviceKeyInfo struct {
		DeviceKey map[int]any `cbor:"deviceKey"`
	} `cbor:"deviceKeyInfo"`
	ValidityInfo map[string]any `cbor:"validityInfo"`
}

// mdocBytes returns the CBOR bytes of an mDoc, binary or base64url, and
// whether the input was base64url.
func mdocBytes(raw []byte) ([]byte, bool, error) {
	b := bytes.TrimSpace(raw)
	if len(b) > 0 && isCBORMapOrTag(b[0]) {
		return b, false, nil
	}
	dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(b), "="))
	if err != nil {
		return nil, false, errMdoc
	}
	return dec, true, nil
}

// readIssuerSigned finds the IssuerSigned structure of an mDoc: the
// structure itself, a Document, or the first document of a
// DeviceResponse. It returns the doctype a Document names.
func readIssuerSigned(raw []byte) (issuerSigned, string, error) {
	var top map[string]cbor.RawMessage
	if cbor.Unmarshal(raw, &top) != nil {
		return issuerSigned{}, "", errMdoc
	}
	if docs, ok := top["documents"]; ok {
		var list []cbor.RawMessage
		if cbor.Unmarshal(docs, &list) != nil || len(list) == 0 {
			return issuerSigned{}, "", errMdoc
		}
		return readIssuerSigned(list[0])
	}
	docType := ""
	if inner, ok := top["issuerSigned"]; ok {
		// A Document without a doctype leaves the MSO to name it.
		anyval.Discard(cbor.Unmarshal(top["docType"], &docType))
		if cbor.Unmarshal(inner, &top) != nil {
			return issuerSigned{}, "", errMdoc
		}
	}
	var out issuerSigned
	if _, ok := top["nameSpaces"]; !ok || cbor.Unmarshal(top["nameSpaces"], &out.NameSpaces) != nil {
		return issuerSigned{}, "", errMdoc
	}
	out.IssuerAuth = top["issuerAuth"]
	return out, docType, nil
}

// item decodes one IssuerSignedItem.
func item(tag cbor.RawTag) (signedItem, error) {
	var content []byte
	var it signedItem
	if cbor.Unmarshal(tag.Content, &content) != nil || cbor.Unmarshal(content, &it) != nil {
		return signedItem{}, errMdoc
	}
	return it, nil
}

// FromMdoc reads an mDoc into the format independent view: the doctype,
// each element by its identifier, the namespaces in Raw for a claim
// path, the validity window, the device key as cnf.jwk, and the subject
// of the certificate in the x5chain header as the issuer. It reads an
// IssuerSigned structure, a Document or a DeviceResponse, binary or
// base64url. It does not check the issuer signature.
func FromMdoc(raw []byte) (Credential, error) {
	b, _, err := mdocBytes(raw)
	if err != nil {
		return Credential{}, err
	}
	signed, docType, err := readIssuerSigned(b)
	if err != nil {
		return Credential{}, err
	}
	out := Credential{Format: string(FormatMdoc), Claims: map[string]string{}, Raw: map[string]any{}}
	for ns, items := range signed.NameSpaces {
		values := map[string]any{}
		for _, tag := range items {
			it, ierr := item(tag)
			if ierr != nil {
				return Credential{}, ierr
			}
			var v any
			// item decoded the value once, so it decodes again.
			anyval.Discard(cbor.Unmarshal(it.ElementValue, &v))
			v = plain(v)
			values[it.ElementIdentifier] = v
			out.Claims[it.ElementIdentifier] = claimText(v)
		}
		out.Raw[ns] = values
	}
	var auth []cbor.RawMessage
	// No issuer signature leaves the view without a type and an issuer.
	anyval.Discard(cbor.Unmarshal(signed.IssuerAuth, &auth))
	if len(auth) == 4 {
		readMSO(auth[2], &out, &docType)
		out.Issuer = certificateSubject(auth[1])
	}
	if docType != "" {
		out.Types = []string{docType}
		out.Raw["docType"] = docType
	}
	return out, nil
}

// readMSO reads the doctype, the validity and the device key of the
// mobile security object, the payload of the issuer signature.
func readMSO(payload cbor.RawMessage, out *Credential, docType *string) {
	var wrapped []byte
	var tag cbor.RawTag
	var content []byte
	var m mso
	if cbor.Unmarshal(payload, &wrapped) != nil || cbor.Unmarshal(wrapped, &tag) != nil ||
		cbor.Unmarshal(tag.Content, &content) != nil || cbor.Unmarshal(content, &m) != nil {
		return
	}
	if m.DocType != "" {
		*docType = m.DocType
	}
	for _, name := range []string{"validFrom", "validUntil"} {
		if v, ok := m.ValidityInfo[name]; ok {
			out.Raw[name] = claimText(plain(v))
		}
	}
	if jwk := coseKeyJWK(m.DeviceKeyInfo.DeviceKey); jwk != nil {
		out.Raw["cnf"] = map[string]any{"jwk": jwk}
	}
}

// coseKeyJWK turns an EC2 COSE key on P-256 into a JWK, or nil.
func coseKeyJWK(key map[int]any) map[string]any {
	x, okX := key[-2].([]byte)
	y, okY := key[-3].([]byte)
	if !okX || !okY {
		return nil
	}
	enc := base64.RawURLEncoding
	return map[string]any{"kty": "EC", "crv": "P-256", "x": enc.EncodeToString(x), "y": enc.EncodeToString(y)}
}

// certificateSubject returns the subject of the first certificate of
// the x5chain header, or the empty string.
func certificateSubject(unprotected cbor.RawMessage) string {
	var hdr map[int]cbor.RawMessage
	// A broken header names no certificate.
	anyval.Discard(cbor.Unmarshal(unprotected, &hdr))
	var der []byte
	if cbor.Unmarshal(hdr[x5chain], &der) != nil {
		var chain [][]byte
		if cbor.Unmarshal(hdr[x5chain], &chain) != nil || len(chain) == 0 {
			return ""
		}
		der = chain[0]
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return cert.Subject.String()
}

// plain turns a decoded CBOR value into a JSON value: a date tag gives
// its text, a byte string its base64url text, a map with text keys an
// object.
func plain(v any) any {
	switch t := v.(type) {
	case cbor.Tag:
		return plain(t.Content)
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	case []byte:
		return base64.RawURLEncoding.EncodeToString(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = plain(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(k)] = plain(e)
		}
		return out
	}
	return v
}

// claimText returns the display text of a claim value: a text as it
// is, anything else as JSON.
func claimText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}

// MdocElements returns the elements of an mDoc as namespace dot
// identifier, in document order, or nil for bytes that hold none.
func MdocElements(raw []byte) []string {
	b, _, err := mdocBytes(raw)
	if err != nil {
		return nil
	}
	var top struct {
		NameSpaces map[string][]cbor.RawTag `cbor:"nameSpaces"`
	}
	if cbor.Unmarshal(b, &top) != nil {
		return nil
	}
	var out []string
	for _, ns := range sortedKeys(top.NameSpaces) {
		for _, tag := range top.NameSpaces[ns] {
			if it, ierr := item(tag); ierr == nil {
				out = append(out, ns+"."+it.ElementIdentifier)
			}
		}
	}
	return out
}

// MdocDisclose returns an IssuerSigned structure with the elements that
// keep accepts, named as namespace dot identifier, in the encoding of
// the input. The issuer signature stays valid: the MSO signs a digest of
// each element, and a verifier checks the digests of the elements it
// gets.
func MdocDisclose(raw []byte, keep func(element string) bool) ([]byte, error) {
	b, wasText, err := mdocBytes(raw)
	if err != nil {
		return nil, err
	}
	var top map[string]cbor.RawMessage
	var spaces map[string][]cbor.RawTag
	if cbor.Unmarshal(b, &top) != nil || cbor.Unmarshal(top["nameSpaces"], &spaces) != nil {
		return nil, errMdoc
	}
	kept := map[string][]cbor.RawTag{}
	for ns, items := range spaces {
		for _, tag := range items {
			if it, ierr := item(tag); ierr == nil && keep(ns+"."+it.ElementIdentifier) {
				kept[ns] = append(kept[ns], tag)
			}
		}
	}
	// The values came out of a decoder, so they encode again.
	top["nameSpaces"] = anyval.Must(cbor.Marshal(kept))
	out := anyval.Must(cbor.Marshal(top))
	if wasText {
		return []byte(base64.RawURLEncoding.EncodeToString(out)), nil
	}
	return out, nil
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// MdocDeviceSigned reports whether an mDoc answer is a DeviceResponse
// whose first document carries a device signature (ISO/IEC 18013-5
// section 8.3.2.1.2.2). An IssuerSigned structure alone carries none.
func MdocDeviceSigned(raw []byte) bool {
	b, _, err := mdocBytes(raw)
	if err != nil {
		return false
	}
	var top struct {
		Documents []map[string]cbor.RawMessage `cbor:"documents"`
	}
	if cbor.Unmarshal(b, &top) != nil || len(top.Documents) == 0 {
		return false
	}
	_, ok := top.Documents[0]["deviceSigned"]
	return ok
}
