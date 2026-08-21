package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/jose"
	"github.com/verifiably/verifiably-go/internal/mdl"
)

// PossessionProof is the outcome of verifying a proof-of-possession JWT: the
// holder's public key, ready both as a raw ecdsa key (for callers that need
// it) and as the COSE_Key encoding the MSO's deviceKeyInfo requires, plus the
// nonce the proof claims — the caller decides whether that nonce was valid.
type PossessionProof struct {
	DeviceKey cbor.RawMessage
	JWK       *ecdsa.PublicKey
	Nonce     string
}

type proofHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"jwk"`
}

type proofPayload struct {
	Aud   string `json:"aud"`
	Nonce string `json:"nonce"`
	Iat   int64  `json:"iat"`
}

// VerifyPossessionProof validates an OID4VCI proof-of-possession JWT
// (Appendix F.1: proof_type "jwt") and returns the holder's device key and
// the nonce the proof claims.
//
// This function does NOT check the nonce against anything — it has no
// server-side state to check it against. The caller (mdlIssueStepTwo) MUST
// verify this function's error return first, and only then consume
// proof.Nonce against its NonceStore. Never consume a nonce before this
// function has confirmed a valid signature: doing so lets an attacker with
// any valid access_token burn a nonce that belongs to someone else's
// in-flight session by submitting a garbage-signed JWT that merely claims
// that nonce.
//
// The deviceKey this returns is the ONLY channel through which a deviceKey
// may reach mdl.Issue — never accept one via any other parameter, body field,
// or config. That is what makes the binding rule in the spec (§AD-2) hold:
// the issued MSO commits to exactly the key that proved possession of this
// nonce, for this issuer, in this request.
func VerifyPossessionProof(rawJWT, expectedAudience string) (*PossessionProof, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("mdl: proof is not a well-formed JWT (expected 3 segments)")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("mdl: decode proof signature: %w", err)
	}

	var header proofHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("mdl: parse proof header: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("mdl: unsupported proof alg %q, only ES256", header.Alg)
	}
	if header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" {
		return nil, errors.New("mdl: proof jwk must be an EC P-256 key")
	}

	var payload proofPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("mdl: parse proof payload: %w", err)
	}
	if payload.Aud != expectedAudience {
		return nil, fmt.Errorf("mdl: proof aud %q does not match issuer %q", payload.Aud, expectedAudience)
	}
	if payload.Nonce == "" {
		return nil, errors.New("mdl: proof payload has no nonce claim")
	}

	x, err := jose.DecodeBase64URLBigInt(header.JWK.X)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode jwk.x: %w", err)
	}
	y, err := jose.DecodeBase64URLBigInt(header.JWK.Y)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode jwk.y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// jose.VerifyES256 hashes signingInput itself (see internal/jose/jose.go)
	// — pass the raw bytes, NOT a pre-computed digest. Passing a digest here
	// would double-hash and reject every legitimate signature at runtime
	// without a compile error, since both are just []byte.
	signingInput := parts[0] + "." + parts[1]
	if err := jose.VerifyES256(pub, []byte(signingInput), sig); err != nil {
		return nil, fmt.Errorf("mdl: proof signature invalid: %w", err)
	}

	deviceKey, err := encodeCOSEKey(x, y)
	if err != nil {
		return nil, err
	}
	return &PossessionProof{DeviceKey: deviceKey, JWK: pub, Nonce: payload.Nonce}, nil
}

// encodeCOSEKey renders an EC2/P-256 public key as a COSE_Key (RFC 9053
// labels: 1=kty, -1=crv, -2=x, -3=y), matching the encoding mdl.LoadTestDeviceKey
// produces so both paths feed mdl.Issue the same shape.
func encodeCOSEKey(x, y *big.Int) (cbor.RawMessage, error) {
	em, err := mdl.EncMode()
	if err != nil {
		return nil, err
	}
	const fieldLen = 32
	xb := make([]byte, fieldLen)
	yb := make([]byte, fieldLen)
	x.FillBytes(xb)
	y.FillBytes(yb)
	key := map[int]any{1: 2, -1: 1, -2: xb, -3: yb} // kty=EC2(2), crv=P-256(1)
	out, err := em.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("mdl: encode device key as COSE_Key: %w", err)
	}
	return out, nil
}
