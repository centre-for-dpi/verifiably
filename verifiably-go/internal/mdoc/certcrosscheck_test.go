package mdoc

import "testing"

// TestCertificateCrossCheckedFieldsAreOffered guards the failure mode that
// reached a citizen's wallet twice: @animo-id/mdoc — the verifier inside
// cdpi-wallet — cross-checks exactly two mdoc data elements against the
// signing certificate's Subject DN.
//
//	issuing_country      must equal countryName (C)
//	issuing_jurisdiction must equal stateOrProvinceName (ST)
//
// A field absent from the mandatory list cannot be filled by the operator, so
// it arrives blank and the wallet rejects the credential ON ACCEPT with
//
//	The 'issuing_jurisdiction' () must match the 'stateOrProvinceName'
//	(DO-01) in the subject field within the issuer certificate
//
// Nothing upstream catches this: the offer returns 201 and the credential
// endpoint returns 200. It only surfaces on the phone. Both docTypes are
// checked because both are issued through the same certificate.
func TestCertificateCrossCheckedFieldsAreOffered(t *testing.T) {
	crossChecked := []string{"issuing_country", "issuing_jurisdiction"}

	for _, dt := range []string{"org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1"} {
		offered := map[string]bool{}
		for _, f := range MandatoryFields(dt) {
			offered[f.Name] = true
		}
		for _, name := range crossChecked {
			if !offered[name] {
				t.Errorf("%s: %q is cross-checked against the signing certificate but "+
					"is not offered in the mandatory list — the operator cannot fill it, "+
					"so it reaches the wallet blank and the credential is rejected on accept",
					dt, name)
			}
		}
	}
}
