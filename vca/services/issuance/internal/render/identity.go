// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
)

// The identity QR channel (ADR-043 decision 1) prints the Claim 169 QR
// code a stack signs: claim 169 of a CWT in a COSE_Sign1 envelope, then
// zlib, then base45, per the MOSIP QR code specification 1.1.0. The
// document carries the text of the stack unchanged, so the MOSIP readers
// and the VCA scanner read it.

// IdentityPayload returns the QR payload of a Claim 169 code. It reports
// an error when the scanner could not read the code back.
func IdentityPayload(text string) (string, error) {
	text = strings.TrimSpace(text)
	if _, _, err := ingest.DecodeClaim169(text); err != nil {
		return "", fmt.Errorf("render: the identity QR does not decode: %w", err)
	}
	return text, nil
}

// Attribute is one attribute a Claim 169 code carries.
type Attribute struct {
	// Name is the attribute name of the QR code specification.
	Name string
	// Value is the value as a page shows it.
	Value string
}

// claim169Names are the attribute names of the QR code specification
// 1.1.0 by key.
var claim169Names = map[int]string{
	1: "ID", 2: "Version", 3: "Language", 4: "Full Name", 5: "First Name", 6: "Middle Name",
	7: "Last Name", 8: "Date of Birth", 9: "Gender", 10: "Address", 11: "Email ID", 12: "Phone Number",
	13: "Nationality", 14: "Marital Status", 15: "Guardian", 16: "Binary Image", 17: "Binary Image Format",
	18: "Best Quality Fingers", 19: "Full Name in the Secondary Language", 20: "Secondary Language",
	21: "Location Code", 22: "Legal Status", 23: "Country of Issuance",
	50: "Right Thumb", 51: "Right Pointer Finger", 52: "Right Middle Finger", 53: "Right Ring Finger",
	54: "Right Little Finger", 55: "Left Thumb", 56: "Left Pointer Finger", 57: "Left Middle Finger",
	58: "Left Ring Finger", 59: "Left Little Finger", 60: "Right Iris", 61: "Left Iris", 62: "Face",
	63: "Right Palm Print", 64: "Left Palm Print", 65: "Voice",
}

// claim169Values name the coded values of the specification.
var claim169Values = map[int]map[string]string{
	9:  {"1": "Male", "2": "Female", "3": "Others"},
	14: {"1": "Unmarried", "2": "Married", "3": "Divorced"},
}

// IdentityAttributes decodes a Claim 169 code and names what it carries,
// in the key order of the specification. A biometric or an image shows
// as included, never as its bytes.
func IdentityAttributes(text string) ([]Attribute, error) {
	cwt, _, err := ingest.DecodeClaim169(text)
	if err != nil {
		return nil, fmt.Errorf("render: the identity QR does not decode: %w", err)
	}
	keys := make([]int, 0, len(cwt.Data))
	other := make([]string, 0)
	for k := range cwt.Data {
		if n, nerr := strconv.Atoi(k); nerr == nil {
			keys = append(keys, n)
		} else {
			other = append(other, k)
		}
	}
	sort.Ints(keys)
	sort.Strings(other)
	out := make([]Attribute, 0, len(cwt.Data))
	for _, n := range keys {
		name, known := claim169Names[n]
		if !known {
			name = "Claim " + strconv.Itoa(n)
		}
		out = append(out, Attribute{Name: name, Value: attributeValue(n, cwt.Data[strconv.Itoa(n)])})
	}
	for _, k := range other {
		out = append(out, Attribute{Name: k, Value: attributeValue(0, cwt.Data[k])})
	}
	return out, nil
}

// attributeValue renders one value of the key.
func attributeValue(key int, v any) string {
	if key == 16 || key >= 50 && key <= 65 {
		return "Included"
	}
	text := fmt.Sprint(v)
	if named, ok := claim169Values[key][text]; ok {
		return named
	}
	return text
}
