package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

// SoftwareSigner holds the private key in process memory. It is meant for
// development and demos; production deployments implement Signer against a
// KMS or HSM instead.
type SoftwareSigner struct {
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

// NewSoftwareSigner validates that the key is P-256 (the curve ISO/IEC
// 18013-5 mandates for ES256) and that a non-empty chain was supplied.
func NewSoftwareSigner(key *ecdsa.PrivateKey, chain []*x509.Certificate) (*SoftwareSigner, error) {
	if key == nil {
		return nil, errors.New("signer: nil private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signer: expected P-256 key, got %s", key.Curve.Params().Name)
	}
	if len(chain) == 0 {
		return nil, errors.New("signer: certificate chain must not be empty")
	}
	return &SoftwareSigner{key: key, chain: chain}, nil
}

// Sign returns a raw (r||s) ECDSA signature, which is the encoding COSE
// expects — not the ASN.1 DER that crypto/ecdsa.SignASN1 produces.
func (s *SoftwareSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signer: ecdsa sign: %w", err)
	}
	// Left-pad each scalar to the 32-byte field size so the pair is always 64 bytes.
	const scalarLen = 32
	out := make([]byte, 2*scalarLen)
	r.FillBytes(out[:scalarLen])
	sv.FillBytes(out[scalarLen:])
	return out, nil
}

func (s *SoftwareSigner) CertificateChain() []*x509.Certificate {
	return s.chain
}

func (s *SoftwareSigner) Algorithm() cose.Algorithm {
	return cose.AlgorithmES256
}
