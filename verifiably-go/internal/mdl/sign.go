package mdl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// headerLabelX5Chain is the COSE header that carries the certificate chain.
const headerLabelX5Chain = int64(33)

// ValidateValidityInfo enforces the normative constraints the standard puts
// on the MSO's temporal window relative to the credential's own dates.
//
// These are easy to violate accidentally when shortening MSO lifetimes to
// approximate revocation: validUntil may not outlive the licence itself.
func ValidateValidityInfo(v ValidityInfo, issueDate, expiryDate time.Time) error {
	validFrom := time.Time(v.ValidFrom)
	validUntil := time.Time(v.ValidUntil)

	if validFrom.Before(issueDate) {
		return fmt.Errorf("mdl: validFrom (%s) precedes issue_date (%s)",
			validFrom.Format(time.RFC3339), issueDate.Format(time.RFC3339))
	}
	if validUntil.After(expiryDate) {
		return fmt.Errorf("mdl: validUntil (%s) exceeds expiry_date (%s)",
			validUntil.Format(time.RFC3339), expiryDate.Format(time.RFC3339))
	}
	if !validUntil.After(validFrom) {
		return errors.New("mdl: validUntil must be after validFrom")
	}
	return nil
}

// BuildMSO assembles the Mobile Security Object.
//
// deviceKey is mandatory: it is the holder's public key, and signing it into
// the MSO is what binds the credential to a device. Without it a copied
// credential is indistinguishable from the original.
func BuildMSO(digests map[uint][]byte, deviceKey cbor.RawMessage, v ValidityInfo) (*MobileSecurityObject, error) {
	if len(deviceKey) == 0 {
		return nil, errors.New("mdl: deviceKey is required; an MSO without it yields a clonable credential")
	}
	if len(digests) == 0 {
		return nil, errors.New("mdl: value digests must not be empty")
	}
	return &MobileSecurityObject{
		Version:         msoVersion,
		DigestAlgorithm: digestAlgorithmSHA,
		ValueDigests:    map[string]map[uint][]byte{Namespace: digests},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
		DocType:         DocType,
		ValidityInfo:    v,
	}, nil
}

// SignMSO encodes the MSO, wraps it in tag 24, and signs it as a COSE_Sign1
// carrying the issuer's certificate chain — the structure the standard calls
// IssuerAuth.
func SignMSO(ctx context.Context, s signer.Signer, mso *MobileSecurityObject) (cbor.RawMessage, error) {
	if s == nil {
		return nil, errors.New("mdl: signer is required")
	}
	if mso == nil {
		return nil, errors.New("mdl: mso is required")
	}
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	msoBytes, err := em.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal MSO: %w", err)
	}
	payload, err := em.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: msoBytes})
	if err != nil {
		return nil, fmt.Errorf("mdl: tag MSO: %w", err)
	}

	// The chain goes leaf-first (DSC, then IACA) as a CBOR array of DER
	// byte strings. A single-certificate chain may be a bare byte string,
	// but emitting an array uniformly keeps parsing simple on the verifier.
	chain := s.CertificateChain()
	if len(chain) == 0 {
		return nil, errors.New("mdl: signer exposes no certificate chain")
	}
	der := make([]any, 0, len(chain))
	for _, c := range chain {
		der = append(der, c.Raw)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(s.Algorithm())
	msg.Headers.Unprotected[headerLabelX5Chain] = der

	sig, err := signWithSigner(ctx, s, msg)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig

	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal IssuerAuth: %w", err)
	}
	return out, nil
}

// signWithSigner computes the COSE Sig_structure and hands it to the Signer.
// go-cose's Sign() wants a crypto.Signer, but our Signer interface may be
// backed by a remote KMS, so we build the to-be-signed bytes ourselves.
func signWithSigner(ctx context.Context, s signer.Signer, msg *cose.Sign1Message) ([]byte, error) {
	toBeSigned, err := sign1ToBeSigned(msg)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(ctx, toBeSigned)
	if err != nil {
		return nil, fmt.Errorf("mdl: sign: %w", err)
	}
	return sig, nil
}

// sign1ToBeSigned builds the COSE Sig_structure for a Sign1 message:
// ["Signature1", body_protected, external_aad, payload].
//
// These bytes must be identical to the ones go-cose reconstructs during
// Verify, so this mirrors Sign1Message.toBeSigned exactly:
//
//   - body_protected is the *serialized* protected header as a byte string,
//     not the header map, and it is re-encoded into a deterministic bstr.
//   - external_aad is present as an empty byte string, never absent.
//   - payload is the tag-24 wrapped MSO, carried as a byte string.
//
// It is encoded with coseEncMode rather than the mdoc EncMode(): go-cose
// marshals the Sig_structure with SortCoreDeterministic and no time tagging,
// and any divergence here yields a signature that will not verify.
func sign1ToBeSigned(msg *cose.Sign1Message) ([]byte, error) {
	rawProtected, err := msg.Headers.MarshalProtected()
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal protected headers: %w", err)
	}
	// The declared type matters: cbor.RawMessage is emitted verbatim, whereas
	// a []byte with the same contents would be encoded as a nested bstr.
	var protected cbor.RawMessage
	protected, err = deterministicByteString(rawProtected)
	if err != nil {
		return nil, fmt.Errorf("mdl: normalize protected headers: %w", err)
	}
	em, err := coseEncMode()
	if err != nil {
		return nil, err
	}
	// protected stays a cbor.RawMessage so the encoder splices its bytes in
	// verbatim. Passing a plain []byte here would wrap the already-serialized
	// bstr in a second bstr header, and the signature would not verify.
	sigStructure := []any{
		"Signature1", // context
		protected,    // body_protected
		[]byte{},     // external_aad
		msg.Payload,  // payload
	}
	out, err := em.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal Sig_structure: %w", err)
	}
	return out, nil
}

// coseEncMode mirrors go-cose's internal encoder. The mdoc EncMode() adds
// required time tagging and canonical (length-first) map sorting, neither of
// which go-cose applies when it rebuilds the Sig_structure to verify.
func coseEncMode() (cbor.EncMode, error) {
	return cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic,
		IndefLength: cbor.IndefLengthForbidden,
	}.EncMode()
}

// deterministicByteString re-encodes a CBOR byte string with the shortest
// possible length header, matching RFC 9052 §9 and go-cose's
// deterministicBinaryString. A protected header carrying only `alg` is
// already minimal, so this is a no-op today; it guards the case where future
// protected header entries grow the map past a length boundary, since a
// non-minimal length prefix there would break verification.
func deterministicByteString(data cbor.RawMessage) (cbor.RawMessage, error) {
	if len(data) == 0 {
		return nil, errors.New("mdl: empty protected header encoding")
	}
	if data[0]>>5 != 2 { // major type 2: bstr
		return nil, errors.New("mdl: protected header must encode as a byte string")
	}
	var raw []byte
	dm, err := cbor.DecOptions{IndefLength: cbor.IndefLengthForbidden}.DecMode()
	if err != nil {
		return nil, err
	}
	if err := dm.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	em, err := coseEncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(raw)
}
