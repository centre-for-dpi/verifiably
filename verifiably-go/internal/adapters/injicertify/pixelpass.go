package injicertify

// pixelpass.go — QR payload encoder compatible with MOSIP's PixelPass
// format, the one Inji Verify's QR decoder expects.
//
// Pipeline (mirrors @mosip/pixelpass/src/index.js:generateQRData):
//   1. Parse input as JSON → CBOR-encode the parsed object. If the input
//      isn't JSON, deflate the raw bytes directly.
//   2. zlib-deflate the CBOR (or raw) bytes.
//   3. Base45-encode per RFC 9285.
//   4. Optionally prepend a header prefix (not used here — Inji Verify's
//      decoder doesn't require one for unsigned raw data).
//
// Inji Verify then runs decode: base45 → inflate → CBOR-decode → text.
// When the original was a JSON VC, the CBOR-decode step rehydrates it
// and the verifier sees a proper VC object.
//
// Why CBOR? pixelpass's encoder reaches for the smallest wire format —
// CBOR is significantly tighter than JSON for VCs with many fields. The
// zlib step then compresses the CBOR. Without CBOR the payload tends to
// exceed QR version 40's 2953-byte limit for real credentials.

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// pixelPassDecMode decodes CBOR maps into map[string]interface{} (recursively)
// rather than fxamacker's default map[interface{}]interface{}, which
// encoding/json can't marshal. PixelPass payloads originate from JSON, so every
// map key is a string.
var pixelPassDecMode, _ = cbor.DecOptions{
	DefaultMapType: reflect.TypeOf(map[string]interface{}(nil)),
}.DecMode()

// base45Alphabet per RFC 9285 §4: 0..9, A..Z, then ten specific symbols.
const base45Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// encodePixelPass returns the base45-encoded, zlib-deflated,
// CBOR-(if-JSON)-encoded form of the given VC bytes. The result is plain
// ASCII safe to embed directly into a QR payload.
func encodePixelPass(vc []byte) (string, error) {
	if len(vc) == 0 {
		return "", fmt.Errorf("empty input")
	}
	var payload []byte
	// Try JSON → CBOR. PixelPass's JS encoder uses JSON.parse, which
	// tolerates any JSON value (object, array, string). We mirror that.
	var anyVal any
	if err := json.Unmarshal(vc, &anyVal); err == nil {
		cborBytes, cerr := cbor.Marshal(anyVal)
		if cerr == nil {
			payload = cborBytes
		}
	}
	if payload == nil {
		payload = vc
	}

	// zlib-deflate at max level (pixelpass uses level 9).
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", fmt.Errorf("zlib writer: %w", err)
	}
	if _, err := zw.Write(payload); err != nil {
		return "", fmt.Errorf("zlib write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("zlib close: %w", err)
	}

	return base45Encode(buf.Bytes()), nil
}

// base45Encode maps arbitrary bytes to the base45 alphabet per RFC 9285.
// Every 2 input bytes → 3 output chars; a trailing odd byte → 2 chars.
func base45Encode(src []byte) string {
	// Preallocate: 3 chars per 2 bytes, +2 for trailing odd byte.
	out := make([]byte, 0, (len(src)/2)*3+((len(src)%2)*2))
	i := 0
	for ; i+1 < len(src); i += 2 {
		n := int(src[i])*256 + int(src[i+1])
		// n = c*45*45 + b*45 + a  →  (a, b, c)
		a := n % 45
		n /= 45
		b := n % 45
		c := n / 45
		out = append(out, base45Alphabet[a], base45Alphabet[b], base45Alphabet[c])
	}
	if i < len(src) {
		n := int(src[i])
		a := n % 45
		b := n / 45
		out = append(out, base45Alphabet[a], base45Alphabet[b])
	}
	return string(out)
}

// decodePixelPass reverses encodePixelPass: base45 → zlib-inflate → CBOR-decode
// → JSON. Returns the credential JSON bytes. Errors when the input isn't a
// well-formed PixelPass payload (bad base45, not zlib-deflated, or not CBOR),
// so a caller can fall back to treating the input as a raw credential.
func decodePixelPass(s string) ([]byte, error) {
	raw, err := base45Decode(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	// zlib CMF byte is 0x78 for the window sizes zlib uses — a cheap guard that
	// rejects most non-PixelPass QR text (raw JWT/JSON) before we try to inflate.
	if len(raw) < 2 || raw[0] != 0x78 {
		return nil, fmt.Errorf("not zlib-deflated")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("zlib reader: %w", err)
	}
	defer zr.Close()
	inflated, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("zlib inflate: %w", err)
	}
	// PixelPass CBOR-encodes JSON input; decode CBOR → value → JSON. If it isn't
	// CBOR, the encoder's raw-bytes fallback was used — the inflated bytes are
	// already the original payload.
	var v any
	if err := pixelPassDecMode.Unmarshal(inflated, &v); err != nil {
		return inflated, nil
	}
	js, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal decoded: %w", err)
	}
	return js, nil
}

// base45Decode reverses base45Encode per RFC 9285: every 3 chars → 2 bytes, a
// trailing 2 chars → 1 byte. Errors on characters outside the alphabet or a
// group whose value exceeds the byte range.
func base45Decode(s string) ([]byte, error) {
	val := func(c byte) (int, bool) {
		i := strings.IndexByte(base45Alphabet, c)
		return i, i >= 0
	}
	out := make([]byte, 0, (len(s)/3)*2+1)
	i := 0
	for ; i+2 < len(s); i += 3 {
		a, ok1 := val(s[i])
		b, ok2 := val(s[i+1])
		c, ok3 := val(s[i+2])
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("invalid base45 char")
		}
		n := a + b*45 + c*45*45
		if n > 0xFFFF {
			return nil, fmt.Errorf("base45 group overflow")
		}
		out = append(out, byte(n>>8), byte(n&0xFF))
	}
	switch len(s) - i {
	case 0:
	case 2:
		a, ok1 := val(s[i])
		b, ok2 := val(s[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid base45 char")
		}
		n := a + b*45
		if n > 0xFF {
			return nil, fmt.Errorf("base45 tail overflow")
		}
		out = append(out, byte(n))
	default:
		return nil, fmt.Errorf("invalid base45 length")
	}
	return out, nil
}
