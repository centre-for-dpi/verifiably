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
// Table 3 of the standard makes eleven elements mandatory, and as of C.7.5
// (docs/superpowers/plans/2026-08-17-mdl-issuer-go.md) all eleven are
// present, including portrait — deferred from C.7.1/C.7.2 because the JPEG
// dominates the DeviceResponse size and stresses BLE chunking, and Fase 0
// (docs/superpowers/plans/...) confirmed chunking with a synthetic ~20KB
// payload before this landed. Two optional age attestations are added
// because they let a verifier confirm a lower bound on age without receiving
// birth_date at all.
var DatasetElements = []string{
	"family_name",
	"given_name",
	"birth_date",
	"issue_date",
	"expiry_date",
	"issuing_country",
	"issuing_authority",
	"document_number",
	"portrait",
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
