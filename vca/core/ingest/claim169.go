// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
)

// Claim169 is the MOSIP QR code claim key (IANA CWT claims registry).
// The MOSIP 169 QR code specification puts the credential data there.
const Claim169 = 169

// CWT claim keys of RFC 8392 section 3.1.1.
const (
	cwtIss = 1
	cwtSub = 2
	cwtAud = 3
	cwtExp = 4
	cwtNbf = 5
	cwtIat = 6
)

// COSE header labels of RFC 9052 section 3.1.
const (
	coseAlg = 1
	coseKid = 4
)

// coseSign1Tag is the CBOR tag of a COSE_Sign1 message (RFC 9052).
const coseSign1Tag = 18

// MaxInflatedBytes bounds the size of an inflated QR payload.
const MaxInflatedBytes = 4 << 20

// ErrNotClaim169 reports that the bytes carry no claim 169.
var ErrNotClaim169 = errors.New("ingest: the CWT has no claim 169")

// Sign1 is the structure of a COSE_Sign1 message (RFC 9052 section 4.2).
// The decoder reads the structure. It never checks the signature. The
// verifier policy service checks the signature with a trusted key.
type Sign1 struct {
	// Algorithm is the COSE algorithm of the protected header, for
	// example -7 for ES256.
	Algorithm int64
	// KeyID is the kid of the protected header, when the issuer set one.
	KeyID []byte
	// Payload is the signed payload, here a CWT claim set.
	Payload []byte
	// Signature is the raw signature.
	Signature []byte
	// SigStructure is the Signature1 structure the verifier signs over.
	SigStructure []byte
}

// CWT is a decoded CBOR Web Token with the MOSIP claim 169.
type CWT struct {
	// Issuer is claim 1.
	Issuer string
	// Subject is claim 2.
	Subject string
	// Audience is claim 3.
	Audience string
	// IssuedAt is claim 6. It is the zero time when the token has none.
	IssuedAt time.Time
	// NotBefore is claim 5.
	NotBefore time.Time
	// ExpiresAt is claim 4.
	ExpiresAt time.Time
	// Data is the content of claim 169.
	Data map[string]any
	// Sign1 is the COSE_Sign1 envelope the claims came from.
	Sign1 Sign1
}

// JSON returns claim 169 as a JSON document.
func (c CWT) JSON() ([]byte, error) {
	data, err := json.Marshal(c.Data)
	if err != nil {
		return nil, fmt.Errorf("ingest: claim 169 to JSON: %w", err)
	}
	return data, nil
}

// DecodeClaim169 reads the text of a MOSIP 169 QR code (ADR-023
// decision 3). The steps are base45 decode, zlib inflate, COSE_Sign1
// parse, and CWT parse. It returns the steps it ran, so the operator
// sees where a broken code failed.
func DecodeClaim169(text string) (CWT, []string, error) {
	steps := []string{"base45"}
	raw, err := DecodeBase45Payload(text)
	if err != nil {
		return CWT{}, steps, err
	}
	steps = append(steps, "zlib")
	inflated, err := Inflate(raw)
	if err != nil {
		return CWT{}, steps, err
	}
	steps = append(steps, "cose_sign1")
	s, err := ParseSign1(inflated)
	if err != nil {
		return CWT{}, steps, err
	}
	steps = append(steps, "cwt")
	c, err := ParseCWT(s.Payload)
	if err != nil {
		return CWT{}, steps, err
	}
	c.Sign1 = s
	return c, steps, nil
}

// DecodeBase45Payload strips a scheme prefix such as HC1: and decodes the
// base45 text of RFC 9285.
func DecodeBase45Payload(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if cut := strings.IndexByte(text, ':'); cut > 0 && cut <= 8 {
		text = text[cut+1:]
	}
	if text == "" {
		return nil, errors.New("ingest: the QR text is empty")
	}
	raw, err := pixelpass.DecodeBase45(text)
	if err != nil {
		return nil, fmt.Errorf("ingest: base45: %w", err)
	}
	return raw, nil
}

// Inflate reverses a zlib stream. It bounds the result at
// MaxInflatedBytes.
func Inflate(raw []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("ingest: zlib: %w", err)
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, MaxInflatedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ingest: inflate: %w", err)
	}
	if len(out) > MaxInflatedBytes {
		return nil, fmt.Errorf("ingest: the inflated payload is larger than %d bytes", MaxInflatedBytes)
	}
	return out, nil
}

// sign1Array is the four element array of a COSE_Sign1 message.
type sign1Array struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

// ParseSign1 reads a COSE_Sign1 message. It accepts the tagged form and
// the untagged form.
func ParseSign1(raw []byte) (Sign1, error) {
	content := raw
	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err == nil {
		if tag.Number != coseSign1Tag {
			return Sign1{}, fmt.Errorf("ingest: the CBOR tag %d is not COSE_Sign1", tag.Number)
		}
		content = tag.Content
	}
	var a sign1Array
	if err := cbor.Unmarshal(content, &a); err != nil {
		return Sign1{}, fmt.Errorf("ingest: COSE_Sign1 structure: %w", err)
	}
	s := Sign1{Payload: a.Payload, Signature: a.Signature, SigStructure: sigStructure(a.Protected, a.Payload)}
	var hdr map[int64]any
	if len(a.Protected) > 0 {
		if err := cbor.Unmarshal(a.Protected, &hdr); err != nil {
			return Sign1{}, fmt.Errorf("ingest: COSE protected header: %w", err)
		}
	}
	if alg, ok := asInt(hdr[coseAlg]); ok {
		s.Algorithm = alg
	}
	s.KeyID, _ = hdr[coseKid].([]byte)
	return s, nil
}

// sigStructure builds the Signature1 structure of RFC 9052 section 4.4.
func sigStructure(protected, payload []byte) []byte {
	out, _ := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	return out
}

// ParseCWT reads a CBOR Web Token claim set and its claim 169.
func ParseCWT(raw []byte) (CWT, error) {
	var m map[int64]any
	if err := decMode().Unmarshal(raw, &m); err != nil {
		return CWT{}, fmt.Errorf("ingest: CWT claims: %w", err)
	}
	c := CWT{}
	c.Issuer, _ = m[cwtIss].(string)
	c.Subject, _ = m[cwtSub].(string)
	c.Audience, _ = m[cwtAud].(string)
	c.IssuedAt = claimTime(m, cwtIat)
	c.NotBefore = claimTime(m, cwtNbf)
	c.ExpiresAt = claimTime(m, cwtExp)
	data := m[Claim169]
	if data == nil {
		return CWT{}, ErrNotClaim169
	}
	value, ok := normaliseMap(data).(map[string]any)
	if !ok {
		return CWT{}, fmt.Errorf("ingest: claim 169 is not a map")
	}
	c.Data = value
	return c, nil
}

// claimTime reads a numeric date claim.
func claimTime(m map[int64]any, key int64) time.Time {
	if n, ok := asInt(m[key]); ok {
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

// asInt reads a CBOR integer of either sign.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// normaliseMap turns CBOR maps with any keys into maps with string keys,
// so encoding/json can write them.
func normaliseMap(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, value := range t {
			out[keyText(k)] = normaliseMap(value)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, normaliseMap(item))
		}
		return out
	case []byte:
		return string(t)
	default:
		return v
	}
}

// keyText renders a CBOR map key as text.
func keyText(k any) string {
	if s, ok := k.(string); ok {
		return s
	}
	return fmt.Sprint(k)
}

// decMode decodes CBOR maps into map[any]any, so integer keys survive.
func decMode() cbor.DecMode {
	dm, _ := cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[any]any(nil))}.DecMode()
	return dm
}
