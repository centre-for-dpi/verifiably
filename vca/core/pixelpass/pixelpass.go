// SPDX-License-Identifier: Apache-2.0

// Package pixelpass encodes and decodes the PixelPass QR payload format
// (https://github.com/mosip/pixelpass): JSON to CBOR (RFC 8949), zlib
// DEFLATE (RFC 1950), then base45 (RFC 9285).
//
// Decode reverses the pipeline. Input that is not JSON is deflated as raw
// bytes, and Decode returns such bytes unchanged.
// Lifted from the legacy internal/adapters/injicertify/pixelpass.go.
package pixelpass

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// MaxDecodedBytes bounds the inflated size Decode accepts.
const MaxDecodedBytes = 4 << 20

// alphabet is the base45 alphabet (RFC 9285 section 4).
const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// Encode returns the base45 form of the zlib deflated CBOR (when data is
// JSON) or raw bytes.
func Encode(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("pixelpass: empty input")
	}
	payload := data
	var v any
	if json.Unmarshal(data, &v) == nil {
		// JSON values always encode as CBOR.
		payload = anyval.Must(cbor.Marshal(v))
	}
	var buf bytes.Buffer
	// Writes to a bytes.Buffer cannot fail.
	w := anyval.Must(zlib.NewWriterLevel(&buf, zlib.BestCompression))
	anyval.Must(w.Write(payload))
	anyval.MustDo(w.Close())
	return EncodeBase45(buf.Bytes()), nil
}

// Decode reverses Encode: base45, inflate, CBOR to JSON. When the
// inflated bytes are not CBOR they are returned as they are.
func Decode(s string) ([]byte, error) {
	raw, err := DecodeBase45(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	// The zlib CMF byte is 0x78 for the window sizes zlib uses.
	if len(raw) < 2 || raw[0] != 0x78 {
		return nil, errors.New("pixelpass: not zlib deflated")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("pixelpass: zlib: %w", err)
	}
	inflated, err := io.ReadAll(io.LimitReader(zr, MaxDecodedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pixelpass: inflate: %w", err)
	}
	if len(inflated) > MaxDecodedBytes {
		return nil, errors.New("pixelpass: payload exceeds MaxDecodedBytes")
	}
	var v any
	if !decodesAsCBOR(inflated, &v) {
		// The payload is not CBOR. Return the inflated bytes as they are.
		return inflated, nil
	}
	js, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("pixelpass: cbor to json: %w", err)
	}
	return js, nil
}

// decodesAsCBOR reports whether raw decodes as CBOR into v.
func decodesAsCBOR(raw []byte, v any) bool {
	return decMode().Unmarshal(raw, v) == nil
}

// decMode decodes CBOR maps as map[string]any so encoding/json can
// marshal them. PixelPass payloads come from JSON, so keys are strings.
func decMode() cbor.DecMode {
	// The options are valid constants, so DecMode cannot fail.
	dm := anyval.Must(cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[string]any(nil))}.DecMode())
	return dm
}

// EncodeBase45 encodes bytes per RFC 9285: 2 bytes to 3 characters,
// a trailing byte to 2 characters.
func EncodeBase45(src []byte) string {
	out := make([]byte, 0, (len(src)/2)*3+(len(src)%2)*2)
	i := 0
	for ; i+1 < len(src); i += 2 {
		n := int(src[i])*256 + int(src[i+1])
		out = append(out, alphabet[n%45], alphabet[(n/45)%45], alphabet[n/(45*45)])
	}
	if i < len(src) {
		n := int(src[i])
		out = append(out, alphabet[n%45], alphabet[n/45])
	}
	return string(out)
}

// DecodeBase45 decodes a base45 string per RFC 9285.
func DecodeBase45(s string) ([]byte, error) {
	if len(s)%3 == 1 {
		return nil, errors.New("pixelpass: invalid base45 length")
	}
	vals := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(alphabet, s[i])
		if v < 0 {
			return nil, fmt.Errorf("pixelpass: invalid base45 character %q", s[i])
		}
		vals[i] = v
	}
	out := make([]byte, 0, (len(s)/3)*2+1)
	i := 0
	for ; i+2 < len(s); i += 3 {
		n := vals[i] + vals[i+1]*45 + vals[i+2]*45*45
		if n > 0xFFFF {
			return nil, errors.New("pixelpass: base45 group overflow")
		}
		out = append(out, byte(n>>8), byte(n&0xFF))
	}
	if i < len(s) {
		n := vals[i] + vals[i+1]*45
		if n > 0xFF {
			return nil, errors.New("pixelpass: base45 tail overflow")
		}
		out = append(out, byte(n))
	}
	return out, nil
}
