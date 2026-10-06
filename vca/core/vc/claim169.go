// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// FormatClaim169 is a CBOR Web Token (RFC 8392) with claim 169 in a
// COSE_Sign1 message (RFC 9052), the content of an identity QR code of
// the 169 QR code specification (ADR-023 decision 3). The issuer is the
// iss claim, and the issuer signs the message with a key it publishes.
const FormatClaim169 Format = "claim169"

// Claim169Type is the type of the view of a Claim 169 code. A code names
// no credential type of its own.
const Claim169Type = "Claim 169 identity"

// claim169Key is the claim of the CWT that holds the identity data.
const claim169Key = 169

// The CWT claims of RFC 8392 section 3.1 that the view reads.
const (
	cwtIss = 1
	cwtSub = 2
	cwtExp = 4
	cwtNbf = 5
	cwtIat = 6
)

// The COSE header labels of RFC 9052 section 3.1.
const (
	coseAlg = 1
	coseKid = 4
)

// The CBOR heads of a COSE_Sign1 message: tag 18, or the untagged array
// of four items.
const (
	headSign1Tag   = 0xd2
	headSign1Array = 0x84
)

// claim169Attributes names the attributes of claim 169 by their keys,
// as the attribute table of the 169 QR code specification names them.
var claim169Attributes = map[int64]string{
	1: "ID", 2: "Version", 3: "Language", 4: "Full Name", 5: "First Name",
	6: "Middle Name", 7: "Last Name", 8: "Date of Birth", 9: "Gender",
	10: "Address", 11: "Email ID", 12: "Phone Number", 13: "Nationality",
	14: "Marital Status", 15: "Guardian", 16: "Binary Image",
	17: "Binary Image Format", 18: "Best Quality Fingers",
	19: "Full Name - Secondary Language", 20: "Secondary Language",
	21: "Location Code", 22: "Legal Status", 23: "Country of Issuance",
}

// claim169Values turns the coded values of an attribute into words.
var claim169Values = map[int64]map[int64]string{
	9:  {1: "Male", 2: "Female", 3: "Others"},
	14: {1: "Unmarried", 2: "Married", 3: "Divorced"},
}

// claim169Binary reports an attribute that holds an image or a
// biometric, which the claims leave out: keys 16 and 17, and 50 to 65.
func claim169Binary(key int64) bool {
	return key == 16 || key == 17 || (key >= 50 && key <= 65)
}

// Claim169Sign1 holds what a verifier needs to check the signature of a
// Claim 169 code.
type Claim169Sign1 struct {
	// Algorithm is the COSE algorithm of the protected header, -7 for
	// ES256 and -8 for EdDSA.
	Algorithm int64
	// KeyID is the kid of the protected header as text. An issuer often
	// writes the DID URL of its key there.
	KeyID string
	// ToBeSigned is the Sig_structure of RFC 9052 section 4.4.
	ToBeSigned []byte
	// Signature is the raw signature.
	Signature []byte
}

// errClaim169 reports bytes that hold no signed CWT with claim 169.
var errClaim169 = errors.New("vc: the bytes hold no signed CWT with claim 169")

// sign1Message is the array of a COSE_Sign1 message.
type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// claim169Code is one decoded code.
type claim169Code struct {
	header map[int64]any
	msg    sign1Message
	claims map[any]any
	data   map[any]any
}

// claim169Bytes returns the CBOR of a code, binary or base64url. Binary
// bytes stay as they are: a signature can end in a byte that reads as
// white space.
func claim169Bytes(raw []byte) []byte {
	if len(raw) > 0 && (raw[0] == headSign1Tag || raw[0] == headSign1Array) {
		return raw
	}
	b := bytes.TrimSpace(raw)
	dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(b), "="))
	if err != nil || len(dec) == 0 || (dec[0] != headSign1Tag && dec[0] != headSign1Array) {
		return nil
	}
	return dec
}

// readClaim169 decodes a code: the COSE_Sign1 message, its protected
// header, the CWT claims, and claim 169.
func readClaim169(raw []byte) (claim169Code, error) {
	b := claim169Bytes(raw)
	if b == nil {
		return claim169Code{}, errClaim169
	}
	content := b
	if b[0] == headSign1Tag {
		var tag cbor.RawTag
		if cbor.Unmarshal(b, &tag) != nil {
			return claim169Code{}, errClaim169
		}
		content = tag.Content
	}
	var out claim169Code
	if cbor.Unmarshal(content, &out.msg) != nil {
		return claim169Code{}, errClaim169
	}
	// An empty protected header is a zero length byte string.
	if len(out.msg.Protected) > 0 && cbor.Unmarshal(out.msg.Protected, &out.header) != nil {
		return claim169Code{}, errClaim169
	}
	if anyMaps().Unmarshal(out.msg.Payload, &out.claims) != nil {
		return claim169Code{}, errClaim169
	}
	data, ok := out.claims[uint64(claim169Key)].(map[any]any)
	if !ok {
		return claim169Code{}, errClaim169
	}
	out.data = data
	return out, nil
}

// anyMaps decodes CBOR maps with keys of any type, so the integer keys
// of a CWT survive.
func anyMaps() cbor.DecMode {
	return anyval.Must(cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[any]any(nil))}.DecMode())
}

// isClaim169 reports whether raw holds a signed CWT with claim 169.
func isClaim169(raw []byte) bool {
	_, err := readClaim169(raw)
	return err == nil
}

// FromClaim169 reads a Claim 169 code into the format independent view:
// the issuer of the iss claim, the subject of the sub claim, each
// attribute of claim 169 by its name in the specification, and the
// validity window of the nbf and exp claims. Coded values read as words.
// An image or a biometric stays out of the claims. It does not check the
// signature; Claim169Signature gives what the check needs.
func FromClaim169(raw []byte) (Credential, error) {
	code, err := readClaim169(raw)
	if err != nil {
		return Credential{}, err
	}
	out := Credential{
		Types: []string{Claim169Type}, Format: string(FormatClaim169),
		Issuer:    anyval.As[string](code.claims[uint64(cwtIss)]),
		SubjectID: anyval.As[string](code.claims[uint64(cwtSub)]),
		Claims:    map[string]string{}, Raw: map[string]any{},
	}
	for name, key := range map[string]uint64{"iss": cwtIss, "sub": cwtSub} {
		if v := anyval.As[string](code.claims[key]); v != "" {
			out.Raw[name] = v
		}
	}
	for name, key := range map[string]uint64{"exp": cwtExp, "nbf": cwtNbf, "iat": cwtIat} {
		if n, ok := cborInt(code.claims[key]); ok {
			out.Raw[name] = float64(n)
		}
	}
	identity := map[string]any{}
	for k, v := range code.data {
		key, ok := cborInt(k)
		if !ok {
			continue
		}
		name := claim169Attributes[key]
		if name == "" {
			name = strconv.FormatInt(key, 10)
		}
		value := jsonValue(v)
		if words, coded := claim169Values[key]; coded {
			if n, isInt := cborInt(v); isInt && words[n] != "" {
				value = words[n]
			}
		}
		identity[name] = value
		if !claim169Binary(key) {
			out.Claims[name] = Stringify(value)
		}
	}
	out.Raw["claim169"] = identity
	return out, nil
}

// Claim169Signature returns the algorithm, the key id, the signed bytes
// and the signature of a Claim 169 code, for a check with the key of the
// issuer.
func Claim169Signature(raw []byte) (Claim169Sign1, error) {
	code, err := readClaim169(raw)
	if err != nil {
		return Claim169Sign1{}, err
	}
	out := Claim169Sign1{Signature: code.msg.Signature}
	out.Algorithm, _ = cborInt(code.header[coseAlg])
	switch kid := code.header[coseKid].(type) {
	case string:
		out.KeyID = kid
	case []byte:
		out.KeyID = string(kid)
	}
	// The structure holds byte strings and one text, so it always encodes.
	out.ToBeSigned = anyval.Must(cbor.Marshal([]any{"Signature1", code.msg.Protected, []byte{}, code.msg.Payload}))
	return out, nil
}

// cborInt reads a CBOR integer of either sign.
func cborInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// jsonValue turns a decoded CBOR value into one encoding/json writes:
// maps with text keys, and byte strings as base64url.
func jsonValue(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, value := range t {
			key, isText := k.(string)
			if !isText {
				if n, ok := cborInt(k); ok {
					key = strconv.FormatInt(n, 10)
				}
			}
			out[key] = jsonValue(value)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, jsonValue(item))
		}
		return out
	case []byte:
		return base64.RawURLEncoding.EncodeToString(t)
	case uint64:
		return float64(t)
	case int64:
		return float64(t)
	}
	return v
}
