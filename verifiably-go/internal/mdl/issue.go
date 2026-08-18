package mdl

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/signer"
)

//go:embed testdata/devicekey_test.json
var testDeviceKeyJSON []byte

// LicenceData is the typed input to issuance.
//
// It deliberately does not reuse the walt.id adapter's map[string]string
// shape: driving_privileges is a nested CBOR array that a flat string map
// cannot express.
type LicenceData struct {
	FamilyName           string
	GivenName            string
	BirthDate            time.Time
	IssueDate            time.Time
	ExpiryDate           time.Time
	IssuingCountry       string
	IssuingAuthority     string
	DocumentNumber       string
	UNDistinguishingSign string
	DrivingPrivileges    []DrivingPrivilege
}

// Elements renders the licence as the element map the encoder expects.
//
// Age attestations are computed against validFrom, not against the current
// time or the issue date: the standard defines age_over_NN relative to the
// MSO's validity window, and computing it from time.Now() would make the
// output non-reproducible.
func (d LicenceData) Elements(validFrom time.Time) (map[string]any, error) {
	if d.FamilyName == "" || d.GivenName == "" {
		return nil, fmt.Errorf("mdl: family_name and given_name are required")
	}
	if d.BirthDate.IsZero() || d.IssueDate.IsZero() || d.ExpiryDate.IsZero() {
		return nil, fmt.Errorf("mdl: birth_date, issue_date and expiry_date are required")
	}
	if len(d.DrivingPrivileges) == 0 {
		return nil, fmt.Errorf("mdl: at least one driving privilege is required")
	}

	birth := FullDate(d.BirthDate)
	return map[string]any{
		"family_name":            d.FamilyName,
		"given_name":             d.GivenName,
		"birth_date":             birth,
		"issue_date":             FullDate(d.IssueDate),
		"expiry_date":            FullDate(d.ExpiryDate),
		"issuing_country":        d.IssuingCountry,
		"issuing_authority":      d.IssuingAuthority,
		"document_number":        d.DocumentNumber,
		"un_distinguishing_sign": d.UNDistinguishingSign,
		"driving_privileges":     d.DrivingPrivileges,
		"age_over_18":            ageAtLeast(d.BirthDate, validFrom, 18),
		"age_over_21":            ageAtLeast(d.BirthDate, validFrom, 21),
	}, nil
}

// ageAtLeast reports whether someone born on birth has reached n years by at.
func ageAtLeast(birth, at time.Time, n int) bool {
	return !birth.AddDate(n, 0, 0).After(at)
}

// Issue produces a complete IssuerSigned: every dataset element as a
// disclosable item, plus the signed MSO committing to their digests and to
// the holder's device key.
//
// The MSO's validity window starts at the licence's issue_date and runs
// through validUntil, which ValidateValidityInfo enforces must not exceed
// expiry_date — callers cannot silently produce a credential that outlives
// the licence it was issued from.
func Issue(ctx context.Context, s signer.Signer, d LicenceData, deviceKey cbor.RawMessage, validUntil time.Time) (*IssuerSigned, error) {
	now := time.Now().UTC()
	validFrom := d.IssueDate

	v := ValidityInfo{
		Signed:     TDate(now),
		ValidFrom:  TDate(validFrom),
		ValidUntil: TDate(validUntil),
	}
	if err := ValidateValidityInfo(v, d.IssueDate, d.ExpiryDate); err != nil {
		return nil, err
	}

	elements, err := d.Elements(validFrom)
	if err != nil {
		return nil, err
	}
	items, err := BuildIssuerSignedItems(elements)
	if err != nil {
		return nil, err
	}
	digests, err := ComputeValueDigests(items)
	if err != nil {
		return nil, err
	}
	mso, err := BuildMSO(digests, deviceKey, v)
	if err != nil {
		return nil, err
	}
	issuerAuth, err := SignMSO(ctx, s, mso)
	if err != nil {
		return nil, err
	}

	encoded := make([]cbor.RawMessage, 0, len(items))
	for _, item := range items {
		enc, err := EncodeItem(item)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, enc)
	}

	return &IssuerSigned{
		NameSpaces: map[string][]cbor.RawMessage{Namespace: encoded},
		IssuerAuth: issuerAuth,
	}, nil
}

// LoadTestDeviceKey returns a COSE_Key encoded from the embedded test JSON.
//
// This exists so issuance can be built and tested before a holder wallet
// exists. Production issuance takes the device key from the holder's proof
// of possession instead.
func LoadTestDeviceKey() (cbor.RawMessage, error) {
	var jwk struct {
		Kty int    `json:"kty"`
		Crv int    `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(testDeviceKeyJSON, &jwk); err != nil {
		return nil, fmt.Errorf("mdl: parse test device key: %w", err)
	}
	x, err := base64.StdEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode test device key x: %w", err)
	}
	y, err := base64.StdEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("mdl: decode test device key y: %w", err)
	}

	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	// COSE_Key labels: 1=kty, -1=crv, -2=x, -3=y.
	key := map[int]any{1: jwk.Kty, -1: jwk.Crv, -2: x, -3: y}
	out, err := em.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("mdl: encode test device key: %w", err)
	}
	return out, nil
}
