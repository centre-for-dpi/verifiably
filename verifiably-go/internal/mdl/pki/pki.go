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
func GenerateIACA(cn, country string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate IACA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      []string{country},
			Organization: []string{POCOrganization},
		},
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

// GenerateDSC issues a Document Signer Certificate under the given IACA.
//
// Validity is capped twice: by the 457-day Annex B limit, and by the IACA's
// own expiry — a DSC that outlives its issuer yields a chain that fails
// verification partway through its life.
func GenerateDSC(iacaKey *ecdsa.PrivateKey, iaca *x509.Certificate, cn string, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if validity > maxDSCValidity {
		return nil, nil, fmt.Errorf("pki: DSC validity %v exceeds the Annex B cap of %v", validity, maxDSCValidity)
	}
	now := time.Now().UTC()
	notAfter := now.Add(validity)
	if notAfter.After(iaca.NotAfter) {
		return nil, nil, fmt.Errorf("pki: DSC would outlive its IACA (%v > %v)", notAfter, iaca.NotAfter)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate DSC key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("pki: serial: %w", err)
	}
	eku, err := parseOID(EKUDocumentSigner)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      iaca.Subject.Country,
			Organization: []string{POCOrganization},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iaca, &key.PublicKey, iacaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create DSC: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse DSC: %w", err)
	}
	return key, cert, nil
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
