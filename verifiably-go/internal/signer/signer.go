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
// not a single certificate: IssuerAuth carries an x5chain in its
// *unprotected* header per ISO/IEC 18013-5 clause 9.1.2.4 — the protected
// header holds only `alg` — and a single certificate cannot express a chain.
//
// The unprotected placement is deliberate in 18013-5 and diverges from the
// generic preference in RFC 9360; conforming readers look for the chain
// there, so moving it into the protected header would break interoperability.
// Trust is anchored by validating the X.509 chain against the IACA, not by
// COSE integrity over the certificate pointer.
type Signer interface {
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	CertificateChain() []*x509.Certificate
	Algorithm() cose.Algorithm
}
