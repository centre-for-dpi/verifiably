package mdoc

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdl"
)

// TestEncodeDrivingPrivilegesIsARealJSONArray is the unit-level half of the
// F4 regression. The live failure was that the value reached walt.id as the
// JSON STRING "1" rather than an array, and issuance died at wallet
// redemption with:
//
//	Expected to execute conversion from json array, but input |"1"| is not a
//	json array
//
// Asserting "the output unmarshals into []any" rather than string-matching
// the JSON is deliberate: a stringified array ("[{...}]" with quotes) would
// still CONTAIN every substring a naive Contains() check looks for, so a
// substring assertion would pass against exactly the broken shape this test
// exists to catch.
func TestEncodeDrivingPrivilegesIsARealJSONArray(t *testing.T) {
	raw, err := EncodeDrivingPrivileges([]DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2020-01-15", ExpiryDate: "2030-01-15"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}

	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("value is not a JSON array (%v) — got %s\n"+
			"this is the exact shape walt.id rejects with "+
			"\"Expected to execute conversion from json array\"", err, raw)
	}

	// Each element must itself be an OBJECT. An array of strings would
	// satisfy the check above but still fail the profile's arrayConfig,
	// which declares `type = "object"` per entry.
	for i, e := range arr {
		obj, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("entry %d is %T, want a JSON object — the profile's arrayConfig declares type=object", i, e)
		}
		if obj["vehicle_category_code"] == nil {
			t.Errorf("entry %d has no vehicle_category_code: %v", i, obj)
		}
	}
}

// TestEncodeDrivingPrivilegesNeverPads is the replacement for the old
// padding behavior: walt.id now has one profile per real category count
// (isoMdl_1cat..isoMdl_4cat), so the encoder must emit exactly what the
// operator supplied — 1, 2, 3, or 4 entries — never more.
func TestEncodeDrivingPrivilegesNeverPads(t *testing.T) {
	for n := 1; n <= DrivingPrivilegesMaxCategories; n++ {
		in := make([]DrivingPrivilege, n)
		for i := range in {
			in[i] = DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2019-03-01", ExpiryDate: "2029-03-01"}
		}
		raw, err := EncodeDrivingPrivileges(in)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}
		var arr []DrivingPrivilege
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatalf("n=%d: unmarshal: %v", n, err)
		}
		if len(arr) != n {
			t.Errorf("n=%d: encoded %d entries, want exactly %d — no padding should ever occur", n, len(arr), n)
		}
	}
}

func TestEncodeDrivingPrivilegesTruncatesOverlongInput(t *testing.T) {
	in := make([]DrivingPrivilege, DrivingPrivilegesMaxCategories+3)
	for i := range in {
		in[i] = DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2020-01-01", ExpiryDate: "2030-01-01"}
	}
	raw, err := EncodeDrivingPrivileges(in)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	var arr []DrivingPrivilege
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != DrivingPrivilegesMaxCategories {
		t.Errorf("len = %d, want %d", len(arr), DrivingPrivilegesMaxCategories)
	}
}

// A field with no category code asserts nothing, so blank repeater rows must
// vanish rather than becoming empty entries that break the size check.
func TestEncodeDrivingPrivilegesDropsBlankRows(t *testing.T) {
	raw, err := EncodeDrivingPrivileges([]DrivingPrivilege{
		{VehicleCategoryCode: "  ", IssueDate: " ", ExpiryDate: ""},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	if raw != nil {
		t.Errorf("raw = %s, want nil — an all-blank list must omit the claim entirely, "+
			"not send [] (which trips walt.id's array-size check)", raw)
	}
}

// TestDrivingPrivilegeMatchesVerifierModel pins this package's JSON-side
// struct against internal/mdl's CBOR-side one. They are separate types on
// purpose (see the doc comment on DrivingPrivilege — internal/mdl is the
// verifier and must not become an emitter), but they describe the SAME ISO
// 18013-5 element, so their field sets must not drift apart. If someone adds
// a field to one, this fails until they consider the other.
func TestDrivingPrivilegeMatchesVerifierModel(t *testing.T) {
	cborNames := map[string]bool{}
	vt := reflect.TypeOf(mdl.DrivingPrivilege{})
	for i := 0; i < vt.NumField(); i++ {
		tag := vt.Field(i).Tag.Get("cbor")
		if tag == "" {
			continue
		}
		name, _, _ := cutTag(tag)
		cborNames[name] = true
	}

	jt := reflect.TypeOf(DrivingPrivilege{})
	for i := 0; i < jt.NumField(); i++ {
		tag := jt.Field(i).Tag.Get("json")
		name, _, _ := cutTag(tag)
		if !cborNames[name] {
			t.Errorf("mdoc.DrivingPrivilege has JSON field %q with no counterpart in "+
				"mdl.DrivingPrivilege — the two models of the same ISO element have drifted", name)
		}
		delete(cborNames, name)
	}
	for name := range cborNames {
		t.Errorf("mdl.DrivingPrivilege has CBOR field %q that mdoc.DrivingPrivilege cannot carry — "+
			"the issuance path would silently drop it", name)
	}
}

// cutTag splits a struct tag value like "issue_date,omitempty" into its name
// and options.
func cutTag(tag string) (name, opts string, ok bool) {
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i], tag[i+1:], true
		}
	}
	return tag, "", false
}
