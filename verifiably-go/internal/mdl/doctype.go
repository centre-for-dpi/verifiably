// Package mdl issues mobile driving licence credentials in the mdoc format
// defined by ISO/IEC 18013-5:2021.
package mdl

// Namespace and DocType identify an ISO-compliant mDL.
const (
	Namespace = "org.iso.18013.5.1"
	DocType   = "org.iso.18013.5.1.mDL"
)

// DatasetElements lists the data elements this issuer emits.
//
// Table 3 of the standard makes eleven elements mandatory. We emit ten of
// them: portrait is deferred to a later phase because the JPEG dominates the
// DeviceResponse size and stresses BLE chunking. Two optional age
// attestations are added because they let a verifier confirm a lower bound on
// age without receiving birth_date at all.
//
// A credential missing portrait is NOT a conformant mDL. It is a test mdoc.
var DatasetElements = []string{
	"family_name",
	"given_name",
	"birth_date",
	"issue_date",
	"expiry_date",
	"issuing_country",
	"issuing_authority",
	"document_number",
	"driving_privileges",
	"un_distinguishing_sign",
	"age_over_18",
	"age_over_21",
}

// containsElement reports whether name is part of the emitted dataset.
func containsElement(list []string, name string) bool {
	for _, e := range list {
		if e == name {
			return true
		}
	}
	return false
}
