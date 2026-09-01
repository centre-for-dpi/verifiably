package backend

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestStructuredDataIsSeparateFromSubjectData pins the design decision behind
// the F4 fix: SubjectData stays map[string]string for flat claims, and
// structured claims live in a SEPARATE field.
//
// This matters because three adapters (credebl, injicertify, and the legacy
// waltid JSON-LD path) iterate SubjectData directly into their own payloads.
// Had SubjectData been widened to map[string]any instead, a driving_privileges
// array would have appeared in a W3C credential as a stringified blob with no
// compile error anywhere to catch it. Keeping the two apart means an adapter
// that does not know about structured claims simply ignores them — the correct
// behaviour for a format that cannot represent them.
//
// If someone later widens SubjectData, this test fails and points at the
// adapters that would silently start emitting stringified structures.
func TestStructuredDataIsSeparateFromSubjectData(t *testing.T) {
	rt := reflect.TypeOf(IssueRequest{})

	sd, ok := rt.FieldByName("SubjectData")
	if !ok {
		t.Fatalf("IssueRequest has no SubjectData field")
	}
	if sd.Type.String() != "map[string]string" {
		t.Errorf("SubjectData is %s, want map[string]string.\n"+
			"Widening it would make a structured claim reach credebl, injicertify and the "+
			"legacy waltid path as a stringified blob in a W3C credential, with no compile "+
			"error to catch it. Structured claims belong in StructuredData.", sd.Type)
	}

	str, ok := rt.FieldByName("StructuredData")
	if !ok {
		t.Fatalf("IssueRequest has no StructuredData field — structured claims have nowhere to travel")
	}
	if str.Type.String() != "map[string]json.RawMessage" {
		t.Errorf("StructuredData is %s, want map[string]json.RawMessage — "+
			"RawMessage is what makes the value marshal VERBATIM as a real JSON array "+
			"rather than a quoted string", str.Type)
	}
}

// The whole point of json.RawMessage here is verbatim marshalling. This
// asserts it end to end: a RawMessage array must survive marshalling as an
// array, not as a string. It is the property the F4 fix rests on.
func TestStructuredDataMarshalsVerbatim(t *testing.T) {
	req := IssueRequest{
		SubjectData: map[string]string{"family_name": "Perez"},
		StructuredData: map[string]json.RawMessage{
			"driving_privileges": json.RawMessage(`[{"vehicle_category_code":"B"}]`),
		},
	}

	raw, err := json.Marshal(req.StructuredData)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, isArray := probe["driving_privileges"].([]any); !isArray {
		t.Fatalf("driving_privileges marshalled as %T, want []any — got %s",
			probe["driving_privileges"], raw)
	}
	// And the flat map must still be strings.
	if strings.Contains(string(raw), "family_name") {
		t.Errorf("StructuredData leaked a flat field: %s", raw)
	}
}
