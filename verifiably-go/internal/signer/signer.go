// Package signer abstracts the private-key operations needed to issue
// credentials, so that the software-backed key used in demos can be swapped
// for a KMS- or HSM-backed one without touching credential-format code.
package signer

import (
	"context"
	"crypto/x509"

	"github.com/veraison/go-cose"
)

// Signer produces raw signatures over a payload and exposes the certificate
// chain that lets a verifier build a path to a trust anchor.
//
// CertificateChain returns the full chain (leaf first, e.g. DSC then IACA),
// not a single certificate: ISO/IEC 18013-5 puts an x5chain in the protected
// header of IssuerAuth, and a single certificate cannot express it.
type Signer interface {
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	CertificateChain() []*x509.Certificate
	Algorithm() cose.Algorithm
}
