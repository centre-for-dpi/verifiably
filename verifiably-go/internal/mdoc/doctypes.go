// Package mdoc describes the ISO document types this system can issue in the
// mso_mdoc container format.
//
// mso_mdoc is the container (CBOR, COSE, MSO, X.509 chain) defined by
// ISO/IEC 18013-5. A docType names what document travels inside it. The
// mandatory element set belongs to the DOCTYPE, not the container: mDL
// defines 11 in one namespace, Photo ID defines 9 in org.iso.23220.1 — and
// age_over_18 is mandatory for Photo ID while merely optional for mDL.
//
// Only docTypes with a profile versioned in
// deploy/k8s/config/issuer2/issuer2-profiles.conf appear here. issuer-api2
// rejects a profileId it cannot resolve, so offering an unbacked docType in
// the UI would produce a failure at issuance time, in front of a citizen.
package mdoc

import "github.com/verifiably/verifiably-go/vctypes"

// DocTypeInfo identifies a docType for display in a selector.
type DocTypeInfo struct {
	DocType string
	Name    string
}

// KnownDocTypes lists the docTypes the operator may choose, in display order.
func KnownDocTypes() []DocTypeInfo {
	return []DocTypeInfo{
		{DocType: "org.iso.18013.5.1.mDL", Name: "Mobile Driving Licence (ISO 18013-5)"},
		{DocType: "org.iso.23220.photoid.1", Name: "Photo ID (ISO 23220)"},
	}
}

func req(name, label string) vctypes.FieldSpec {
	return vctypes.FieldSpec{
		Name:     name,
		Datatype: "string",
		Required: true,
		Labels:   map[string]string{"en": label},
	}
}

// FormatDrivingPrivileges marks a field whose ISO value is an ARRAY OF
// OBJECTS, not a scalar: each entry carries a vehicle_category_code plus an
// optional issue_date / expiry_date (ISO/IEC 18013-5 §7.2.4). It is the one
// mDL element that map[string]string subject data cannot express, which is
// why it needs its own Format rather than another string field.
//
// Keying on Format rather than on the literal name "driving_privileges" is
// deliberate and matches how every other special input in the issue form is
// selected (date, uri, number). A name check would work today but would have
// to be extended by hand for the equivalent element in any other docType.
const FormatDrivingPrivileges = "driving_privileges"

// FormatImage marks a field whose ISO value is IMAGE BYTES — `portrait`,
// `signature_usual_mark`, and Photo ID's own portrait. The operator picks a
// file; the handler base64-encodes it and walt.id's profile mapping
// (conversionType = "base64StringToByteString") performs the CBOR
// byte-string conversion. We never encode CBOR ourselves.
const FormatImage = "image"

// structured returns a required field carrying a non-scalar Format. Datatype
// stays "string" because it is what every non-mdoc consumer of FieldsSpec
// (catalog claim blocks, INJI's display order, CREDEBL's attributes) reads;
// Format is the discriminator the mdoc path keys off.
func structured(name, label, format string) vctypes.FieldSpec {
	f := req(name, label)
	f.Format = format
	return f
}

// mdlMandatory is ISO/IEC 18013-5 Table 3's mandatory set — the same 11
// elements internal/mdl/doctype.go emits, kept in step with it.
var mdlMandatory = []vctypes.FieldSpec{
	req("family_name", "Family Name"),
	req("given_name", "Given Name"),
	req("birth_date", "Date of Birth"),
	req("issue_date", "Date of Issue"),
	req("expiry_date", "Date of Expiry"),
	req("issuing_country", "Issuing Country"),
	req("issuing_authority", "Issuing Authority"),
	req("document_number", "Document Number"),
	structured("portrait", "Portrait", FormatImage),
	structured("driving_privileges", "Driving Privileges", FormatDrivingPrivileges),
	req("un_distinguishing_sign", "UN Distinguishing Sign"),
}

// photoIDMandatory is ISO/IEC 23220's mandatory set in org.iso.23220.1.
// Note the differences from mDL that make this genuinely per-docType:
// age_over_18 is mandatory here, and the authority field is
// issuing_authority_unicode rather than issuing_authority.
var photoIDMandatory = []vctypes.FieldSpec{
	req("family_name", "Family Name"),
	req("given_name", "Given Name"),
	req("birth_date", "Date of Birth"),
	structured("portrait", "Portrait", FormatImage),
	req("issue_date", "Date of Issue"),
	req("expiry_date", "Date of Expiry"),
	req("issuing_authority_unicode", "Issuing Authority"),
	req("issuing_country", "Issuing Country"),
	{
		Name:     "age_over_18",
		Datatype: "boolean",
		Required: true,
		Labels:   map[string]string{"en": "Age Over 18"},
	},
}

// mandatoryByDocType keys must match KnownDocTypes' DocType values exactly.
//
// The Photo ID wire string is deliberately lowercase ("photoid", not
// "photoID") to match issuer2-profiles.conf's credentialConfigurationId and
// internal/adapters/waltid's docTypeProfiles — the routing table that
// actually reaches issuer-api2. issuer2_test.go:TestProfileIDForDocType
// asserts the capitalized form must NOT resolve there. Do not "fix" this
// back to camelCase; that would silently reintroduce a docType the builder
// offers but issuer-api2 rejects at issuance time.
var mandatoryByDocType = map[string][]vctypes.FieldSpec{
	"org.iso.18013.5.1.mDL":   mdlMandatory,
	"org.iso.23220.photoid.1": photoIDMandatory,
}

// MandatoryFields returns the elements the standard requires for a docType.
// Returns nil for an unknown docType.
//
// The result is a DEEP copy: the slice and every FieldSpec's Labels map are
// freshly allocated, so the caller may mutate what it gets back without
// touching package state. A plain copy() here would duplicate the slice but
// leave every returned FieldSpec.Labels aliasing the same map as
// mdlMandatory/photoIDMandatory — process-wide package-level vars. Callers
// DO write into these maps (the schema builder overlays the operator's
// labels onto the curated ones), so aliasing would let one request's
// Spanish label leak into every later request's defaults for the lifetime of
// the process.
func MandatoryFields(docType string) []vctypes.FieldSpec {
	src, ok := mandatoryByDocType[docType]
	if !ok {
		return nil
	}
	out := make([]vctypes.FieldSpec, len(src))
	copy(out, src)
	for i := range out {
		if out[i].Labels == nil {
			continue
		}
		labels := make(map[string]string, len(out[i].Labels))
		for k, v := range out[i].Labels {
			labels[k] = v
		}
		out[i].Labels = labels
	}
	return out
}
