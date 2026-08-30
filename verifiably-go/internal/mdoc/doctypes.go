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

// MDLDocType and PhotoIDDocType are the two ISO docType wire strings this
// deployment knows how to issue as mso_mdoc — the single source of truth so
// a call site that needs to single out "is this specifically an mDL" (e.g.
// injicertify's driving_privileges guard, which is an mDL-only element, NOT
// something every mso_mdoc docType requires) never hand-writes the literal
// and risks drifting from KnownDocTypes/mandatoryByDocType below.
const (
	MDLDocType     = "org.iso.18013.5.1.mDL"
	PhotoIDDocType = "org.iso.23220.photoid.1"
)

// KnownDocTypes lists the docTypes the operator may choose, in display order.
func KnownDocTypes() []DocTypeInfo {
	return []DocTypeInfo{
		{DocType: MDLDocType, Name: "Mobile Driving Licence (ISO 18013-5)"},
		{DocType: PhotoIDDocType, Name: "Photo ID (ISO 23220)"},
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
//
// KNOWN LIMITATION — Inji Certify v0.14.0 has no equivalent conversion at
// all: unlike walt.id, it never turns this base64 string into a real CBOR
// byte string (bstr per ISO/IEC 18013-5). Confirmed by disassembling its
// shipped io.mosip.certify.utils.MDocProcessor.class (javap -p -c):
// preprocessForCBOR (the single dispatch point deciding how each templated
// value is encoded) has exactly four branches — byte[] (passed through
// unchanged), String (checked ONLY against isDateOnlyString, for the
// full-date/tag-1004 special case — anything else stays a String), Map,
// and List. There is no fifth branch for base64/image detection, and
// convertToDataItem's own String case unconditionally wraps every String
// in a CBOR UnicodeString (tstr) — so any value that reaches Inji as a
// JSON string, however it looks, becomes tstr, never bstr. No template
// marker, field-naming convention, or Velocity trick changes this; the
// gap is in Inji Certify's own Java code, not in what this template can
// send it. Confirmed live: Inji Certify emitted `portrait` as a 300KB+
// base64 STRING claim in the final mdoc — cdpi-wallet was patched to
// tolerate this (recognizing a base64-string bstr claim value as bytes,
// alongside the ISO-conformant Uint8Array walt.id already produces) rather
// than reject the credential outright, but that wallet-side tolerance is
// a mitigation, not a fix — the correct fix is Inji Certify emitting a
// real bstr, which requires a code change upstream (MOSIP), not here.
const FormatImage = "image"

// MdocSignatureAlgo is the COSE signature algorithm every mdoc issued by
// this deployment uses: ES256 (ECDSA P-256/SHA-256). Confirmed empirically
// (header {1: -7}, IANA COSE algorithm -7 = ES256) against both walt.id
// issuer-api2 and Inji Certify v0.14.0 — the single source of truth so a
// new mdoc profile/schema config never hardcodes a different algorithm by
// accident (e.g. injicertify's Ed25519 default for its other formats).
const MdocSignatureAlgo = "ES256"

// structured returns a required field carrying a non-scalar Format. Datatype
// stays "string" because it is what every non-mdoc consumer of FieldsSpec
// (catalog claim blocks, INJI's display order, CREDEBL's attributes) reads;
// Format is the discriminator the mdoc path keys off.
// dateField is a required element whose ISO value is a full-date. Format
// "date" is what routes it to a date picker in the issue form AND what
// buildIssuer2Offer keys on to guarantee it is never sent blank — walt.id's
// profile maps these with stringToFullDate, which cannot parse "".
func dateField(name, label string) vctypes.FieldSpec {
	f := req(name, label)
	f.Format = "date"
	return f
}

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
	dateField("birth_date", "Date of Birth"),
	dateField("issue_date", "Date of Issue"),
	dateField("expiry_date", "Date of Expiry"),
	req("issuing_country", "Issuing Country"),
	// issuing_jurisdiction is OPTIONAL in ISO but required in practice here.
	// @animo-id/mdoc (the verifier inside cdpi-wallet) cross-checks exactly two
	// data elements against the signing certificate's Subject DN:
	// issuing_country must equal countryName (C), and issuing_jurisdiction must
	// equal stateOrProvinceName (ST). A blank value fails that check outright:
	//   The 'issuing_jurisdiction' () must match the 'stateOrProvinceName'
	//   (DO-01) in the subject field within the issuer certificate
	// The field was absent from this list, so the operator had no way to supply
	// it and the wallet rejected every credential on accept.
	req("issuing_jurisdiction", "Issuing Jurisdiction"),
	req("issuing_authority", "Issuing Authority"),
	req("document_number", "Document Number"),
	structured("portrait", "Portrait", FormatImage),
	// portrait_capture_date is OPTIONAL in ISO but MANDATORY here: the isoMdl
	// profile ships it as "" under a stringToFullDate mapping, and issuer-api2
	// deep-merges our data over the profile — so a field the builder never
	// offers keeps that blank and kills issuance at wallet redemption with
	// "DateTimeParseException: Text '' could not be parsed". Offering it is
	// what lets the operator (or buildIssuer2Offer's fallback) supply a value.
	dateField("portrait_capture_date", "Portrait Capture Date"),
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
	dateField("birth_date", "Date of Birth"),
	structured("portrait", "Portrait", FormatImage),
	// Same reason as mDL's: the isoPhotoId profile also ships
	// portrait_capture_date as "" under a date mapping.
	dateField("portrait_capture_date", "Portrait Capture Date"),
	dateField("issue_date", "Date of Issue"),
	dateField("expiry_date", "Date of Expiry"),
	req("issuing_authority_unicode", "Issuing Authority"),
	req("issuing_country", "Issuing Country"),
	// issuing_jurisdiction is OPTIONAL in ISO but required in practice here.
	// @animo-id/mdoc (the verifier inside cdpi-wallet) cross-checks exactly two
	// data elements against the signing certificate's Subject DN:
	// issuing_country must equal countryName (C), and issuing_jurisdiction must
	// equal stateOrProvinceName (ST). A blank value fails that check outright:
	//   The 'issuing_jurisdiction' () must match the 'stateOrProvinceName'
	//   (DO-01) in the subject field within the issuer certificate
	// The field was absent from this list, so the operator had no way to supply
	// it and the wallet rejected every credential on accept.
	req("issuing_jurisdiction", "Issuing Jurisdiction"),
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
	MDLDocType:     mdlMandatory,
	PhotoIDDocType: photoIDMandatory,
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

// IsMandatoryForAnyDocType reports whether name is a mandatory element of
// SOME known mdoc docType — not necessarily the one currently selected.
//
// Exists so the schema builder can tell apart two different reasons a
// submitted field row isn't in the CURRENT docType's mandatory set:
//   - it's a residual row left over from a docType the operator just
//     switched AWAY from (e.g. driving_privileges, still present in the
//     POST body after switching mDL -> Photo ID, because the builder form
//     re-submits every currently-rendered row on each change) — this must
//     be DROPPED, not kept as a custom field;
//   - it's a field the operator genuinely typed into an "extra field" row
//     of their own — this must be KEPT.
//
// Reproduced live: switching the docType selector from mDL to Photo ID and
// saving produced a Photo ID credential_config whose display_order still
// listed driving_privileges (confirmed directly in Inji Certify's
// credential_config table) — an ISO/IEC 23220-1 Photo ID has no such
// element, so the wallet-facing issue form (validateDrivingPrivilegesCount,
// internal/handlers/issuance.go) then refused to issue with "es
// obligatorio en ISO 18013-5", even though nothing about issuing a Photo ID
// should ever have surfaced that guard.
func IsMandatoryForAnyDocType(name string) bool {
	for _, fields := range mandatoryByDocType {
		for _, f := range fields {
			if f.Name == name {
				return true
			}
		}
	}
	return false
}
