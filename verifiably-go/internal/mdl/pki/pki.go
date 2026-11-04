// Package pki generates the certificate chain an mDL issuer needs: a
// self-signed IACA root and the Document Signer Certificates it issues,
// following the certificate profiles of ISO/IEC 18013-5 Annex B (normative).
//
// The material produced here is for proof-of-concept use only. Certificates
// carry O=POC-DO-NOT-TRUST and the IACA is deliberately short-lived so that
// leaked material expires on its own.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

const (
	// EKUDocumentSigner marks a certificate as an mDL Document Signer.
	EKUDocumentSigner = "1.0.18013.5.1.2"

	// POCOrganization is stamped into every subject so proof-of-concept
	// material is detectable if it ever shows up where it should not.
	POCOrganization = "POC-DO-NOT-TRUST"

	// maxDSCValidity is the cap Annex B puts on Document Signer certificates.
	maxDSCValidity = 457 * 24 * time.Hour
)

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// GenerateIACA creates a self-signed Issuing Authority Certificate Authority
// root and its P-256 private key.
//
// The subject carries no stateOrProvinceName. Prefer GenerateIACAWithSubject
// for anything a wallet will verify: @animo-id/mdoc cross-checks the mdoc's
// issuing_jurisdiction against that field, and a certificate without it is
// rejected at accept time.
func GenerateIACA(cn, country string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return GenerateIACAWithSubject(cn, country, "", validity)
}

// GenerateIACAWithSubject creates a self-signed IACA root and its P-256
// private key, with both subject fields a verifier cross-checks.
//
// province populates stateOrProvinceName and is omitted when empty. Wallets
// verifying with @animo-id/mdoc compare two mdoc data elements against the
// certificate subject:
//
//	issuing_country      vs  countryName          (C)
//	issuing_jurisdiction vs  stateOrProvinceName  (ST)
//
// A mismatch — or a missing ST when the credential carries an
// issuing_jurisdiction — makes the wallet refuse the credential, with nothing
// logged on the issuing side.
func GenerateIACAWithSubject(cn, country, province string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate IACA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: serial: %w", err)
	}
	now := time.Now().UTC()
	subject := pkix.Name{
		CommonName:   cn,
		Country:      []string{country},
		Organization: []string{POCOrganization},
	}
	if province != "" {
		subject.Province = []string{province}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour), // tolerate small clock skew
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create IACA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse IACA: %w", err)
	}
	return key, cert, nil
}

// GenerateDSC issues a Document Signer Certificate under the given IACA,
// generating a fresh signing key for it and returning both.
//
// Use GenerateDSCForKey instead when the signing key already exists. The key
// returned here and the certificate over it must stay together: signing mdocs
// with a key other than the one inside the x5chain leaf produces credentials
// that fail verification everywhere, silently.
func GenerateDSC(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, cn string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate DSC key: %w", err)
	}
	cert, err := GenerateDSCForKey(iacaKey, iaca, &key.PublicKey, cn, validity)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// GenerateDSCForKey issues a Document Signer Certificate over a public key the
// caller already holds, under the given IACA.
//
// This is the shape a deployment needs: the same key has to reach both the
// certificate that goes into the x5chain and the issuer's signing
// configuration. ISO 18013-5 gives a verifier no source for the signing public
// key other than the x5chain leaf, so if those two diverge every credential
// fails signature verification at every conformant reader — while issuing
// cleanly, with no error logged anywhere. Certifying a caller-supplied key
// makes them match by construction rather than by convention.
//
// Country and stateOrProvinceName are inherited from the IACA so the two ends
// of the chain cannot disagree on the fields @animo-id/mdoc cross-checks
// against the credential (see GenerateIACAWithSubject).
//
// Validity is capped twice: by the 457-day Annex B limit, and by the IACA's
// own expiry — a DSC that outlives its issuer yields a chain that fails
// verification partway through its life.
func GenerateDSCForKey(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, pub *ecdsa.PublicKey, cn string, validity time.Duration) (*x509.Certificate, error) {
	if validity > maxDSCValidity {
		return nil, fmt.Errorf("pki: DSC validity %v exceeds the Annex B cap of %v", validity, maxDSCValidity)
	}
	now := time.Now().UTC()
	notAfter := now.Add(validity)
	if notAfter.After(iaca.NotAfter) {
		return nil, fmt.Errorf("pki: DSC would outlive its IACA (%v > %v)", notAfter, iaca.NotAfter)
	}
	if pub == nil {
		return nil, fmt.Errorf("pki: DSC public key is nil")
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	eku, err := parseOID(EKUDocumentSigner)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      iaca.Subject.Country,
			Province:     iaca.Subject.Province,
			Organization: []string{POCOrganization},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iaca, pub, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("pki: create DSC: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse DSC: %w", err)
	}
	return cert, nil
}

// parseOID converts a dotted OID string into an asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i == start {
				return nil, fmt.Errorf("pki: malformed OID %q", s)
			}
			n := 0
			for _, c := range s[start:i] {
				if c < '0' || c > '9' {
					return nil, fmt.Errorf("pki: malformed OID %q", s)
				}
				n = n*10 + int(c-'0')
			}
			oid = append(oid, n)
			start = i + 1
		}
	}
	return oid, nil
}
