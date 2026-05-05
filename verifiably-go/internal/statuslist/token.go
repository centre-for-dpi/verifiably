package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
)

// EncodeZlibBase64URL produces the IETF Token Status List `lst` value:
// zlib-compress the raw bytes, base64url-encode without padding. This is
// what goes into the JWT's `status_list.lst` claim.
//
// The IETF spec (draft-ietf-oauth-status-list) and the W3C BSL 2023 spec
// share the byte/bit convention (MSB-first within each byte), so the same
// Bitstring backs both. They differ only in:
//   - compression: zlib (IETF) vs gzip (W3C)
//   - envelope: JWT with status_list claim (IETF) vs VC credentialSubject
//     with encodedList field (W3C)
func (b *Bitstring) EncodeZlibBase64URL() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b.bits); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("statuslist: zlib write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("statuslist: zlib close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeZlibBase64URL is the inverse, mainly for round-trip tests. The
// resulting Bitstring uses IETF (LSB-first) bit ordering — that's the
// convention the on-the-wire bytes are meant to be interpreted with per
// draft-ietf-oauth-status-list §4.2.1.
func DecodeZlibBase64URL(s string, size int) (*Bitstring, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("statuslist: base64 decode: %w", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("statuslist: zlib reader: %w", err)
	}
	defer zr.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(zr); err != nil {
		return nil, fmt.Errorf("statuslist: zlib read: %w", err)
	}
	return FromBytesIETF(out.Bytes(), size)
}
