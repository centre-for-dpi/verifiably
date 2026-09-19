// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CWT claim keys (RFC 8392 section 4 and draft-ietf-oauth-status-list section 5.2).
const (
	cwtIss        = 1
	cwtSub        = 2
	cwtExp        = 4
	cwtIat        = 6
	cwtTTL        = 65534
	cwtStatusList = 65533
)

// COSE header labels and algorithm identifiers (RFC 9052, RFC 9053).
const (
	coseAlg = 1
	coseKid = 4
	coseTyp = 16

	// COSEAlgES256 is ECDSA with P-256 and SHA-256.
	COSEAlgES256 = -7
	// COSEAlgEdDSA is Ed25519.
	COSEAlgEdDSA = -8

	coseSign1Tag = 18
)

// ErrSignatureInvalid reports that a COSE_Sign1 signature did not verify.
var ErrSignatureInvalid = errors.New("token: COSE signature verification failed")

// CWTClaims builds the CBOR claim set of a Status List CWT (section 5.2).
func CWTClaims(c Claims, l *List) []byte {
	sl := map[string]any{"bits": l.Bits(), "lst": l.Compress()}
	if c.AggregationURI != "" {
		sl["aggregation_uri"] = c.AggregationURI
	}
	m := map[int64]any{
		cwtIss:        c.Issuer,
		cwtSub:        c.Subject,
		cwtIat:        c.IssuedAt.Unix(),
		cwtStatusList: sl,
	}
	if !c.ExpiresAt.IsZero() {
		m[cwtExp] = c.ExpiresAt.Unix()
	}
	if c.TTL > 0 {
		m[cwtTTL] = int64(c.TTL / time.Second)
	}
	// A map of scalars and byte strings always encodes.
	return bytesOrNil(cbor.Marshal(m))
}

// ParseCWTClaims reads a CBOR claim set built by CWTClaims or another issuer.
func ParseCWTClaims(raw []byte) (Claims, *List, error) {
	var m map[int64]any
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return Claims{}, nil, fmt.Errorf("token: cwt claims: %w", err)
	}
	sub := stringOf(m[cwtSub])
	if sub == "" {
		return Claims{}, nil, errors.New("token: sub claim missing")
	}
	iat, ok := asInt(m[cwtIat])
	if !ok {
		return Claims{}, nil, errors.New("token: iat claim missing")
	}
	sl, ok := m[cwtStatusList].(map[any]any)
	if !ok {
		return Claims{}, nil, errors.New("token: status_list claim missing")
	}
	bits, _ := asInt(sl["bits"])
	lst := bytesOf(sl["lst"])
	l, err := Decompress(int(bits), lst)
	if err != nil {
		return Claims{}, nil, err
	}
	c := Claims{Subject: sub, IssuedAt: time.Unix(iat, 0).UTC()}
	c.Issuer = stringOf(m[cwtIss])
	c.AggregationURI = stringOf(sl["aggregation_uri"])
	if exp, ok := asInt(m[cwtExp]); ok {
		c.ExpiresAt = time.Unix(exp, 0).UTC()
	}
	if ttl, ok := asInt(m[cwtTTL]); ok {
		c.TTL = time.Duration(ttl) * time.Second
	}
	return c, l, nil
}

func asInt(v any) (int64, bool) {
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

// bytesOrNil returns b when err is nil. It returns nil otherwise. The CBOR
// values that this package encodes always marshal, so err is always nil.
func bytesOrNil(b []byte, err error) []byte {
	if err != nil {
		return nil
	}
	return b
}

// stringOf returns the string in v. It returns "" when v is not a string.
func stringOf(v any) string {
	s, isString := v.(string)
	if !isString {
		return ""
	}
	return s
}

// bytesOf returns the byte string in v. It returns nil when v is not one.
func bytesOf(v any) []byte {
	b, isBytes := v.([]byte)
	if !isBytes {
		return nil
	}
	return b
}

// Signer signs data and returns the raw COSE signature bytes.
type Signer func(data []byte) ([]byte, error)

// Verifier checks a raw COSE signature over data for alg and kid.
type Verifier func(alg int64, kid, data, sig []byte) error

type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

func sigStructure(protected, payload []byte) []byte {
	// ["Signature1", protected, external_aad, payload] (RFC 9052 section 4.4).
	return bytesOrNil(cbor.Marshal([]any{"Signature1", protected, []byte{}, payload}))
}

// SignCWT wraps payload in a tagged COSE_Sign1 message with typ
// "statuslist+cwt" in the protected header (section 5.2).
func SignCWT(payload []byte, alg int64, kid []byte, sign Signer) ([]byte, error) {
	hdr := map[int64]any{coseAlg: alg, coseTyp: TypeCWT}
	if len(kid) > 0 {
		hdr[coseKid] = kid
	}
	protected := bytesOrNil(cbor.Marshal(hdr))
	sig, err := sign(sigStructure(protected, payload))
	if err != nil {
		return nil, fmt.Errorf("token: cose sign: %w", err)
	}
	msg := coseSign1{Protected: protected, Unprotected: map[any]any{}, Payload: payload, Signature: sig}
	return bytesOrNil(cbor.Marshal(cbor.Tag{Number: coseSign1Tag, Content: msg})), nil
}

// VerifyCWT checks a COSE_Sign1 message and returns its payload.
// The protected header must carry typ "statuslist+cwt".
func VerifyCWT(msg []byte, verify Verifier) ([]byte, error) {
	var tag cbor.RawTag
	if err := cbor.Unmarshal(msg, &tag); err != nil {
		return nil, fmt.Errorf("token: cose: %w", err)
	}
	if tag.Number != coseSign1Tag {
		return nil, fmt.Errorf("token: cose tag %d is not COSE_Sign1", tag.Number)
	}
	var s coseSign1
	if err := cbor.Unmarshal(tag.Content, &s); err != nil {
		return nil, fmt.Errorf("token: cose structure: %w", err)
	}
	var hdr map[int64]any
	if err := cbor.Unmarshal(s.Protected, &hdr); err != nil {
		return nil, fmt.Errorf("token: cose protected header: %w", err)
	}
	if typ := stringOf(hdr[coseTyp]); typ != TypeCWT {
		return nil, fmt.Errorf("token: cose typ %q is not %s", typ, TypeCWT)
	}
	alg, ok := asInt(hdr[coseAlg])
	if !ok {
		return nil, errors.New("token: cose alg missing")
	}
	kid := bytesOf(hdr[coseKid])
	if err := verify(alg, kid, sigStructure(s.Protected, s.Payload), s.Signature); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	return s.Payload, nil
}

// KeySigner returns the COSE algorithm and a Signer for an ECDSA P-256
// or Ed25519 private key.
func KeySigner(key crypto.PrivateKey) (int64, Signer, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return 0, nil, errors.New("token: ECDSA key must use P-256")
		}
		return COSEAlgES256, func(data []byte) ([]byte, error) {
			h := sha256.Sum256(data)
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			var sig []byte
			if err == nil {
				sig = make([]byte, 64)
				r.FillBytes(sig[:32])
				s.FillBytes(sig[32:])
			}
			return sig, err
		}, nil
	case ed25519.PrivateKey:
		return COSEAlgEdDSA, func(data []byte) ([]byte, error) {
			return ed25519.Sign(k, data), nil
		}, nil
	}
	return 0, nil, fmt.Errorf("token: unsupported key type %T", key)
}

// KeyVerifier returns a Verifier for one public key. It ignores kid.
func KeyVerifier(pub crypto.PublicKey) Verifier {
	return func(alg int64, _, data, sig []byte) error {
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if alg != COSEAlgES256 || len(sig) != 64 {
				return errors.New("token: alg or signature length does not match ES256")
			}
			h := sha256.Sum256(data)
			if !ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				return errors.New("token: ES256 mismatch")
			}
			return nil
		case ed25519.PublicKey:
			if alg != COSEAlgEdDSA || !ed25519.Verify(k, data, sig) {
				return errors.New("token: EdDSA mismatch")
			}
			return nil
		}
		return fmt.Errorf("token: unsupported key type %T", pub)
	}
}
