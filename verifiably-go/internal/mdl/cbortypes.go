package mdl

import (
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CBOR tags used by the standard.
//
// The distinction matters and is easy to get wrong: every field of
// ValidityInfo is a tdate (tag 0, RFC 3339 date-time), while birth_date is a
// full-date (tag 1004, no time component). Using 1004 inside ValidityInfo
// produces an MSO no conformant verifier will accept.
const (
	TagTDate           = 0
	TagFullDate        = 1004
	TagEncodedCBOR     = 24
	fullDateLayout     = "2006-01-02"
	digestAlgorithmSHA = "SHA-256"
	msoVersion         = "1.0"
)

// FullDate is a date without a time component, encoded with CBOR tag 1004.
type FullDate time.Time

func (d FullDate) MarshalCBOR() ([]byte, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cbor.Tag{
		Number:  TagFullDate,
		Content: time.Time(d).UTC().Format(fullDateLayout),
	})
}

// TDate is an RFC 3339 date-time, encoded with CBOR tag 0.
type TDate time.Time

func (d TDate) MarshalCBOR() ([]byte, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cbor.Tag{
		Number:  TagTDate,
		Content: time.Time(d).UTC().Format(time.RFC3339),
	})
}

// DrivingPrivilege is one entry of the driving_privileges array.
//
// This is why the existing walt.id issuance path cannot carry the dataset:
// buildMdocData takes map[string]string, and this element is a nested array
// of structures.
type DrivingPrivilege struct {
	VehicleCategoryCode string    `cbor:"vehicle_category_code"`
	IssueDate           *FullDate `cbor:"issue_date,omitempty"`
	ExpiryDate          *FullDate `cbor:"expiry_date,omitempty"`
}

// IssuerSignedItem is a single disclosable data element. Random must be at
// least 16 bytes of entropy so that a digest does not leak its value.
type IssuerSignedItem struct {
	DigestID          uint   `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

// ValidityInfo carries the MSO's temporal bounds. A verifier checks these
// against its own clock on every transaction.
type ValidityInfo struct {
	Signed         TDate  `cbor:"signed"`
	ValidFrom      TDate  `cbor:"validFrom"`
	ValidUntil     TDate  `cbor:"validUntil"`
	ExpectedUpdate *TDate `cbor:"expectedUpdate,omitempty"`
}

// DeviceKeyInfo binds the credential to a key the holder controls. Without
// it the credential is clonable, so deviceKey is not optional.
type DeviceKeyInfo struct {
	DeviceKey cbor.RawMessage `cbor:"deviceKey"`
}

// MobileSecurityObject is the structure the issuer signs.
type MobileSecurityObject struct {
	Version         string                     `cbor:"version"`
	DigestAlgorithm string                     `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo              `cbor:"deviceKeyInfo"`
	DocType         string                     `cbor:"docType"`
	ValidityInfo    ValidityInfo               `cbor:"validityInfo"`
}

// IssuerSigned is what the issuer hands to the holder: the disclosable items
// plus the signed MSO.
type IssuerSigned struct {
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
}

// EncMode returns the CBOR encoder the standard requires: deterministic
// (canonical) encoding, so that digests computed over the same item are
// stable across implementations.
func EncMode() (cbor.EncMode, error) {
	return cbor.EncOptions{
		Sort:        cbor.SortCanonical,
		Time:        cbor.TimeRFC3339,
		TimeTag:     cbor.EncTagRequired,
		IndefLength: cbor.IndefLengthForbidden,
	}.EncMode()
}
