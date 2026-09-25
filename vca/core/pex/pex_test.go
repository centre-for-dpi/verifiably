// SPDX-License-Identifier: Apache-2.0

package pex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

// licence is a valid definition in the form walt.id 0.18 reads.
const licence = `{
  "id": "licence-check",
  "name": "Driving licence check",
  "purpose": "Check the licence class.",
  "input_descriptors": [{
    "id": "licence",
    "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
    "constraints": {
      "limit_disclosure": "required",
      "fields": [
        {"path": ["$.vct"], "filter": {"type": "string", "const": "https://ntsa.example/licence"}},
        {"path": ["$.licence_class"], "filter": {"type": "string", "enum": ["B", "C"]}},
        {"path": ["$.birth_date"]}
      ]
    }
  }]
}`

func problemText(problems []Problem) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		parts = append(parts, p.Error())
	}
	return strings.Join(parts, "\n")
}

// TestValidateDefinition accepts a valid definition and names each
// problem of a broken one with a JSON Pointer (ADR-042 decision 4).
func TestValidateDefinition(t *testing.T) {
	d, problems := Validate([]byte(licence))
	if len(problems) > 0 {
		t.Fatalf("valid definition refused:\n%s", problemText(problems))
	}
	if d.ID != "licence-check" || len(d.InputDescriptors) != 1 || len(d.InputDescriptors[0].Constraints.Fields) != 3 {
		t.Fatalf("read %+v", d)
	}
	cases := map[string]struct{ doc, want string }{
		"not json":         {`{`, "/: the text is not JSON"},
		"two values":       {`{} {}`, "/: the text holds more than one JSON value"},
		"no id":            {`{"input_descriptors": []}`, `/: the member "id" is missing`},
		"wrong type":       {`{"id": 5, "input_descriptors": []}`, "/id: the value must be of type string"},
		"extra member":     {`{"id": "a", "input_descriptors": [], "extra": 1}`, `/extra: the member "extra" is not allowed here`},
		"no descriptor":    {`{"id": "a", "input_descriptors": []}`, "/input_descriptors: the definition asks for no credential"},
		"bad disclosure":   {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"limit_disclosure": "always"}}]}`, `/input_descriptors/0/constraints/limit_disclosure: the value must be one of "required", "preferred"`},
		"no constraints":   {`{"id": "a", "input_descriptors": [{"id": "x"}]}`, `/input_descriptors/0: the member "constraints" is missing`},
		"unknown format":   {`{"id": "a", "format": {"pdf": {}}, "input_descriptors": [{"id": "x", "constraints": {}}]}`, `/format/pdf: the member "pdf" is not allowed here`},
		"empty alg":        {`{"id": "a", "format": {"jwt_vc_json": {"alg": []}}, "input_descriptors": [{"id": "x", "constraints": {}}]}`, "/format/jwt_vc_json/alg: the list must hold at least 1 items"},
		"field predicate":  {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"fields": [{"path": ["$.a"], "predicate": "required"}]}}]}`, `/input_descriptors/0/constraints/fields/0: the member "filter" is missing`},
		"field form":       {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"fields": [{"path": ["$.a"], "filter": 5}]}}]}`, "/input_descriptors/0/constraints/fields/0/filter: the filter must be a JSON Schema object or a boolean"},
		"requirement":      {`{"id": "a", "submission_requirements": [{"rule": "all"}], "input_descriptors": [{"id": "x", "constraints": {}}]}`, "/submission_requirements/0: the value matches none of the allowed forms"},
		"count":            {`{"id": "a", "submission_requirements": [{"rule": "pick", "count": 0, "from": "g"}], "input_descriptors": [{"id": "x", "group": ["g"], "constraints": {}}]}`, "/submission_requirements/0/count: the value must be 1 or more"},
		"count fraction":   {`{"id": "a", "submission_requirements": [{"rule": "pick", "count": 1.5, "from": "g"}], "input_descriptors": [{"id": "x", "group": ["g"], "constraints": {}}]}`, "/submission_requirements/0/count: the value must be of type integer"},
		"count exponent":   {`{"id": "a", "submission_requirements": [{"rule": "pick", "count": 1e0, "from": "g"}], "input_descriptors": [{"id": "x", "group": ["g"], "constraints": {}}]}`, "cannot unmarshal"},
		"unknown group":    {`{"id": "a", "submission_requirements": [{"rule": "all", "from": "g"}], "input_descriptors": [{"id": "x", "constraints": {}}]}`, `/submission_requirements/0/from: no descriptor sits in the group "g"`},
		"nested group":     {`{"id": "a", "submission_requirements": [{"rule": "all", "from_nested": [{"rule": "all", "from": "h"}]}], "input_descriptors": [{"id": "x", "group": ["g"], "constraints": {}}]}`, `/submission_requirements/0/from_nested/0/from: no descriptor sits in the group "h"`},
		"twice":            {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {}}, {"id": "x", "constraints": {}}]}`, `/input_descriptors/1/id: the descriptor id "x" is used twice`},
		"empty id":         {`{"id": "a", "input_descriptors": [{"id": "", "constraints": {}}]}`, "/input_descriptors/0/id: the descriptor id is empty"},
		"no path":          {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"fields": [{"path": []}]}}]}`, "/input_descriptors/0/constraints/fields/0/path: the field has no path"},
		"relative path":    {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"fields": [{"path": ["a.b"]}]}}]}`, `/input_descriptors/0/constraints/fields/0/path/0: the JSONPath "a.b" does not start at the root $`},
		"not an object":    {`[]`, "/: the value must be of type object"},
		"nested bad":       {`{"id": "a", "submission_requirements": [{"rule": "all", "from_nested": [{"rule": 1, "from": "g"}]}], "input_descriptors": [{"id": "x", "group": ["g"], "constraints": {}}]}`, "/submission_requirements/0/from_nested/0/rule: the value must be of type string"},
		"status directive": {`{"id": "a", "input_descriptors": [{"id": "x", "constraints": {"statuses": {"active": {"directive": "maybe"}}}}]}`, `/input_descriptors/0/constraints/statuses/active/directive: the value must be one of`},
		"escaped member":   {`{"id": "a", "input_descriptors": [], "a/b~c": 1}`, "/a~1b~0c: the member"},
	}
	for name, c := range cases {
		_, problems := Validate([]byte(c.doc))
		if got := problemText(problems); !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q in\n%s", name, c.want, got)
		}
	}
	big := `{"id": "` + strings.Repeat("a", MaxDefinitionBytes) + `", "input_descriptors": []}`
	if _, problems := Validate([]byte(big)); len(problems) != 1 || problems[0].Message != ErrTooLarge.Error() {
		t.Errorf("large definition: %v", problems)
	}
	if (Problem{Path: "/id", Message: "x"}).Error() != "/id: x" {
		t.Error("problem text")
	}
}

// sampleQuery is a DCQL query of the builder: an SD-JWT licence with
// values and a preferred claim set, a W3C farmer registration, and a
// mobile driving licence, with a required set and a pick of one.
func sampleQuery(t *testing.T) dcql.Query {
	t.Helper()
	q, err := dcql.BuildRequest(dcql.Request{
		Purpose: "Check the driver.",
		Selections: []dcql.Selection{
			{ID: "licence", Format: dcql.FormatSDJWT, Type: "https://ntsa.example/licence",
				Claims: []string{"given_name", "licence_class", "birth_date"}, Values: map[string][]any{"licence_class": {"B", "C"}},
				ClaimSets: [][]string{{"given_name", "licence_class"}, {"given_name", "licence_class", "birth_date"}}},
			{ID: "farmer", Format: dcql.FormatLDPVC, Type: "FarmerRegistration", Claims: []string{"farm_id", "address.county"}},
			{ID: "jwt", Format: dcql.FormatJWTVCJSON, Type: "EmployeeCard", Claims: []string{"employee_id"}},
			{ID: "mdl", Format: dcql.FormatMdoc, Type: "org.iso.18013.5.1.mDL", Claims: []string{"org.iso.18013.5.1.family_name", "org.iso.18013.5.1.portrait"}},
		},
		Sets: []dcql.Set{
			{Options: [][]string{{"licence"}}, Required: true, Purpose: "Check the driver."},
			{Options: [][]string{{"farmer"}, {"jwt"}, {"mdl"}}, Required: true, Purpose: "Check the work."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestConvertDcqlToPexAndBack converts a builder query to a definition
// and back without a loss, and the result equals the query. The
// definition passes the vendored schema.
func TestConvertDcqlToPexAndBack(t *testing.T) {
	q := sampleQuery(t)
	d, report, err := FromDCQL(q, "driver-check", "Driver check", "Check the driver.")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Lossless() {
		t.Fatalf("DCQL to PE lost %+v", report.Losses)
	}
	raw := Marshal(d)
	again, problems := Validate(raw)
	if len(problems) > 0 {
		t.Fatalf("the generated definition fails the schema:\n%s\n%s", problemText(problems), raw)
	}
	back, report, err := ToDCQL(again)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Lossless() {
		t.Fatalf("PE to DCQL lost %+v", report.Losses)
	}
	if back.Name != "Driver check" || back.Purpose != "Check the driver." {
		t.Errorf("name %q purpose %q", back.Name, back.Purpose)
	}
	want, got := string(must(dcql.Marshal(q))), string(must(dcql.Marshal(back.Query)))
	if want != got {
		t.Errorf("round trip differs\nwant %s\ngot  %s", want, got)
	}
	// And from PE: the definition survives PE to DCQL to PE.
	d2, report, err := FromDCQL(back.Query, again.ID, again.Name, again.Purpose)
	if err != nil || !report.Lossless() {
		t.Fatalf("second pass: %v %+v", err, report.Losses)
	}
	if !reflect.DeepEqual(d2, again) {
		t.Errorf("definition differs\nwant %s\ngot  %s", raw, Marshal(d2))
	}
	// A query without credential sets asks for every credential.
	plain := dcql.Query{Credentials: q.Credentials[:1]}
	d3, _, err := FromDCQL(plain, "plain", "", "")
	if err != nil {
		t.Fatal(err)
	}
	back3, report, err := ToDCQL(d3)
	if err != nil || !report.Lossless() || len(back3.Query.CredentialSets) != 0 {
		t.Errorf("plain: %v %+v %+v", err, report, back3.Query.CredentialSets)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func codes(r Report) []string {
	out := make([]string, 0, len(r.Losses))
	for _, l := range r.Losses {
		out = append(out, l.Code+"@"+l.Where+"="+l.Detail)
	}
	return out
}

// TestLossyConversionReported names every part the other language
// cannot hold, in both directions.
func TestLossyConversionReported(t *testing.T) {
	no := false
	q := sampleQuery(t)
	q.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthority{{Type: dcql.AuthorityETSITrustedList, Values: []string{"https://ntsa.example"}}}
	q.Credentials[0].Multiple = true
	q.Credentials[0].RequireCryptographicHolderBinding = &no
	q.Credentials[1].ClaimSets = [][]string{{"farm_id"}}
	q.Credentials[1].Meta.TypeValues = [][]string{{"VerifiableCredential", "Registration", "FarmerRegistration"}}
	q.Credentials[3].Claims = append(q.Credentials[3].Claims, dcql.ClaimQuery{ID: "deep", Path: dcql.Path{dcql.Name("ns"), dcql.Index(0)}})
	q.CredentialSets = append(q.CredentialSets, dcql.CredentialSetQuery{Options: [][]string{{"licence", "farmer"}, {"mdl"}}},
		dcql.CredentialSetQuery{Options: [][]string{{"jwt"}}, Required: &no})
	_, report, err := FromDCQL(q, "x", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"issuers@licence=", "multiple@licence=", "holder_binding@licence=",
		"claim_sets@farmer=", "type_values@farmer=VerifiableCredential, Registration, FarmerRegistration",
		"mdoc_path@mdl=ns[0]", "set_options@credential_sets/2=", "optional_set@credential_sets/3=",
	}
	if got := codes(report); !reflect.DeepEqual(got, want) {
		t.Errorf("DCQL to PE losses\nwant %v\ngot  %v", want, got)
	}
	for _, c := range []dcql.CredentialQuery{
		{ID: "a", Claims: []dcql.ClaimQuery{{ID: "x"}, {ID: "y"}}, ClaimSets: [][]string{{"x"}, {"y"}, {"x", "y"}}},
		{ID: "b", Claims: []dcql.ClaimQuery{{ID: "x"}, {ID: "y"}}, ClaimSets: [][]string{{"x"}, {"y"}}},
		{ID: "c", Claims: []dcql.ClaimQuery{{ID: "x"}, {ID: "y"}}, ClaimSets: [][]string{{"x", "z"}}},
	} {
		if claimSetsKept(c) {
			t.Errorf("%s: claim sets kept", c.ID)
		}
	}
	if _, _, idErr := FromDCQL(q, "", "", ""); idErr == nil {
		t.Error("want an error without an id")
	}

	lossy := `{
	  "id": "old", "frame": {"@context": "x"}, "format": {"jwt_vc_json": {"alg": ["ES256"]}},
	  "submission_requirements": [
	    {"name": "Work", "rule": "pick", "count": 2, "from": "work"},
	    {"rule": "all", "from_nested": [{"rule": "pick", "min": 0, "max": 1, "from": "id"}]},
	    {"rule": "pick", "count": 5, "from": "work"}
	  ],
	  "input_descriptors": [
	    {"id": "badge", "name": "Badge", "group": ["work"], "format": {"ldp_vc": {"proof_type": ["Ed25519Signature2020"]}, "jwt_vc_json": {}, "ac_vc": {}},
	     "constraints": {"limit_disclosure": "required", "statuses": {"active": {"directive": "required"}}, "subject_is_issuer": "preferred",
	       "fields": [
	         {"path": ["$.type"], "filter": {"type": "array", "contains": {"type": "string", "pattern": "EmployeeBadge"}, "minItems": 1}},
	         {"path": ["$.type"], "filter": {"type": "array"}},
	         {"id": "n", "name": "Name", "path": ["$.credentialSubject.name", "$.vc.credentialSubject.name", "$..name"], "purpose": "We greet you."},
	         {"path": ["$.credentialSubject.age"], "filter": {"type": "integer", "minimum": 18}, "predicate": "required"},
	         {"path": ["$.credentialSubject.name"]},
	         {"path": ["$.issuer"]},
	         {"path": ["$.credentialSubject.role"], "filter": {"type": "string", "enum": ["lead"], "pattern": "l.*"}, "intent_to_retain": true},
	         {"path": ["$.credentialSubject.level"], "filter": {"const": 2, "enum": [1, 2]}},
	         {"path": ["$.credentialSubject.flag"], "filter": false},
	         {"path": ["$.credentialSubject.obj"], "filter": {"const": {"a": 1}}}
	       ]}},
	    {"id": "desk", "group": ["work"], "constraints": {"fields": [
	      {"path": ["$.vc.type"], "filter": true},
	      {"path": ["$.vc.credentialSubject.desk"], "optional": true}]}},
	    {"id": "mdl", "group": ["id"], "format": {"mso_mdoc": {}}, "constraints": {"fields": [
	      {"path": ["$.docType"], "filter": {"type": "string", "enum": ["org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1"]}},
	      {"path": ["$['org.iso.18013.5.1']['family_name']"]},
	      {"path": ["$['org.iso.18013.5.1']"]}]}},
	    {"id": "loose", "format": {"vc+sd-jwt": {}}, "constraints": {"fields": [{"path": ["$.vct"]}, {"path": ["$.x"], "optional": true}]}}
	  ]
	}`
	d, problems := Validate([]byte(lossy))
	if len(problems) > 0 {
		t.Fatalf("lossy definition refused:\n%s", problemText(problems))
	}
	got, report, err := ToDCQL(d)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"frame@/frame=", "format_limits@/format=",
		"format_limits@/input_descriptors/0/format=", "format@/input_descriptors/0/format=jwt_vc_json",
		"text@/input_descriptors/0=", "statuses@/input_descriptors/0/constraints/statuses=",
		"holder_rules@/input_descriptors/0/constraints=", "limit_disclosure@/input_descriptors/0/constraints/limit_disclosure=",
		"type_filter@/input_descriptors/0/constraints/fields/0=pattern, minItems",
		"duplicate@/input_descriptors/0/constraints/fields/1=$.type",
		"alt_paths@/input_descriptors/0/constraints/fields/2=$.vc.credentialSubject.name",
		"text@/input_descriptors/0/constraints/fields/2=",
		"predicate@/input_descriptors/0/constraints/fields/3=",
		"filter@/input_descriptors/0/constraints/fields/3=minimum, type",
		"duplicate@/input_descriptors/0/constraints/fields/4=name",
		"path@/input_descriptors/0/constraints/fields/5=$.issuer",
		"retain@/input_descriptors/0/constraints/fields/6=",
		"filter@/input_descriptors/0/constraints/fields/6=pattern",
		"filter@/input_descriptors/0/constraints/fields/7=enum",
		"filter@/input_descriptors/0/constraints/fields/8=boolean",
		"filter@/input_descriptors/0/constraints/fields/9=const",
		"type_filter@/input_descriptors/1/constraints/fields/0=filter, type",
		"all_optional@/input_descriptors/1=",
		"type_filter@/input_descriptors/2/constraints/fields/0=org.iso.18013.5.1.mDL",
		"path@/input_descriptors/2/constraints/fields/2=$['org.iso.18013.5.1']",
		"type_filter@/input_descriptors/3/constraints/fields/0=filter, type",
		"all_optional@/input_descriptors/3=",
		"text@/submission_requirements/0=",
		"nested@/submission_requirements/1=",
		"pick@/submission_requirements/2=",
	}
	if g := codes(report); !reflect.DeepEqual(g, want) {
		t.Errorf("PE to DCQL losses\nwant %v\ngot  %v", want, g)
	}
	q2 := got.Query
	if q2.Credentials[0].Format != dcql.FormatJWTVCJSON || !reflect.DeepEqual(q2.Credentials[0].Meta.TypeValues, [][]string{{"VerifiableCredential", "EmployeeBadge"}}) {
		t.Errorf("badge %+v", q2.Credentials[0])
	}
	if q2.Credentials[2].Meta.DoctypeValue != "org.iso.18013.5.1.mDL" || q2.Credentials[2].Claims[0].Path.String() != "org.iso.18013.5.1.family_name" {
		t.Errorf("mdl %+v", q2.Credentials[2])
	}
	sets := must(json.Marshal(q2.CredentialSets))
	if string(sets) != `[{"options":[["badge","desk"]]},{"options":[["mdl"]],"required":false},{"options":[["badge","desk"]]},{"options":[["loose"]],"required":false}]` {
		t.Errorf("sets %s", sets)
	}
}

// TestToDcqlRefusesWhatNoQueryHolds covers the definitions no DCQL
// query can stand for.
func TestToDcqlRefusesWhatNoQueryHolds(t *testing.T) {
	for name, doc := range map[string]string{
		"no format":     `{"id": "a", "input_descriptors": [{"id": "x", "constraints": {}}]}`,
		"only anoncred": `{"id": "a", "input_descriptors": [{"id": "x", "format": {"ac_vc": {}}, "constraints": {}}]}`,
		"empty group":   `{"id": "a", "format": {"ldp_vc": {}}, "submission_requirements": [{"rule": "all", "from": "g"}], "input_descriptors": [{"id": "x", "constraints": {}}]}`,
	} {
		var d Definition
		if err := json.Unmarshal([]byte(doc), &d); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ToDCQL(d); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestToDcqlIDsAndPicks cleans descriptor ids, keeps them unique, and
// lists the combinations of a pick rule.
func TestToDcqlIDsAndPicks(t *testing.T) {
	doc := `{"id": "a", "format": {"dc+sd-jwt": {}}, "submission_requirements": [{"rule": "pick", "min": 1, "max": 2, "from": "g"}],
	  "input_descriptors": [
	    {"id": "a b", "group": ["g"], "constraints": {"fields": [{"path": ["$.vct"], "filter": {"type": "string", "enum": ["T1", "T2"]}}, {"path": ["$.x"], "filter": {"type": "string", "enum": []}}]}},
	    {"id": "a_b", "group": ["g"], "format": {"ldp_vc": {}}, "constraints": {"fields": [
	      {"path": ["$.type"], "filter": {"type": "array", "contains": {"const": "VerifiableCredential"}}},
	      {"path": ["$.credentialSubject.a", "$.credentialSubject.b"]}]}},
	    {"id": "!!", "group": ["g"], "constraints": {"fields": [{"path": ["$.n"], "filter": {"type": "number", "enum": [1, 2]}}, {"path": ["$.b"], "filter": {"type": "boolean", "const": true}}]}}
	  ]}`
	d, problems := Validate([]byte(doc))
	if len(problems) > 0 {
		t.Fatal(problemText(problems))
	}
	got, report, err := ToDCQL(d)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{got.Query.Credentials[0].ID, got.Query.Credentials[1].ID, got.Query.Credentials[2].ID}
	if !reflect.DeepEqual(ids, []string{"a_b", "a_b_2", "credential3"}) {
		t.Errorf("ids %v", ids)
	}
	if !reflect.DeepEqual(got.Query.Credentials[0].Meta.VctValues, []string{"T1", "T2"}) {
		t.Errorf("vct %v", got.Query.Credentials[0].Meta)
	}
	if !reflect.DeepEqual(got.Query.Credentials[1].Meta.TypeValues, [][]string{{"VerifiableCredential"}}) {
		t.Errorf("type %v", got.Query.Credentials[1].Meta)
	}
	if !reflect.DeepEqual(codes(report), []string{"filter@/input_descriptors/0/constraints/fields/1=enum, type",
		"alt_paths@/input_descriptors/1/constraints/fields/1=$.credentialSubject.a"}) {
		t.Errorf("losses %v", codes(report))
	}
	if n := len(got.Query.CredentialSets[0].Options); n != 6 {
		t.Errorf("pick of 1 or 2 of 3 gives %d options", n)
	}
	if many := combinations([]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, 5); len(many) <= MaxOptions {
		t.Errorf("combinations stop late: %d", len(many))
	}
}

// TestParseJSONPath reads the plain forms and refuses the rest.
func TestParseJSONPath(t *testing.T) {
	for in, want := range map[string]string{
		"$.a.b":         "a.b",
		"$['a']['b c']": "a.b c",
		`$["a"][0]`:     "a[0]",
		"$.a[*].b":      "a[].b",
	} {
		p, err := ParseJSONPath(in)
		if err != nil || p.String() != want {
			t.Errorf("%s: %v %v", in, p, err)
		}
	}
	for _, in := range []string{"a", "$", "$..a", "$.", "$.*", "$x", "$[?(@.a)]", "$['a'", "$['a',", "$[0", "$[-1]"} {
		if _, err := ParseJSONPath(in); err == nil {
			t.Errorf("%s: want an error", in)
		}
	}
}

// TestVendoredSchemasMatchSource checks the hashes of SOURCE.md and that
// the schemas use only the keywords the validator knows.
func TestVendoredSchemasMatchSource(t *testing.T) {
	source, err := os.ReadFile("schema/SOURCE.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("\\| `([a-z-]+\\.json)` \\|[^|]+\\| `[0-9a-f]{40}` \\| `([0-9a-f]{64})` \\|")
	rows := row.FindAllStringSubmatch(string(source), -1)
	if len(rows) != 2 {
		t.Fatalf("SOURCE.md lists %d files", len(rows))
	}
	for _, m := range rows {
		data, err := schemaFiles.ReadFile("schema/" + m[1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != m[2] {
			t.Errorf("%s does not match its hash", m[1])
		}
	}
	s := loadSchemas()
	allowed := append(slices.Clone(Keywords), Annotations...)
	var walk func(v any, schemaPos bool)
	walk = func(v any, schemaPos bool) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		for k, sub := range m {
			if schemaPos && !slices.Contains(allowed, k) {
				t.Errorf("the vendored schema uses the unknown keyword %q", k)
			}
			switch k {
			case "properties", "patternProperties", "definitions":
				for _, inner := range anyval.As[map[string]any](sub) {
					walk(inner, true)
				}
			case "items":
				walk(sub, true)
			case "oneOf":
				for _, inner := range anyval.As[[]any](sub) {
					walk(inner, true)
				}
			}
		}
	}
	walk(s.definition, true)
	walk(s.format, true)
}

// TestValidatorEdges covers the branches the vendored schemas never
// reach: two matching branches, a tie, and the build faults.
func TestValidatorEdges(t *testing.T) {
	v := &validator{s: loadSchemas()}
	both := map[string]any{"oneOf": []any{map[string]any{"type": "string"}, map[string]any{"type": "string"}}}
	v.walk(both, "x", "/a")
	if len(v.problems) != 1 || v.problems[0].Keyword != "oneOf" || v.problems[0].Message != "the value matches more than one allowed form" {
		t.Errorf("two branches: %v", v.problems)
	}
	if typeMatches("integer", "1") || contains([]any{"1"}, 1) {
		t.Error("type or enum of a string")
	}
	for name, fn := range map[string]func(){
		"type": func() { typeMatches("number", 1) },
		"ref":  func() { v.resolve("https://example.com/other.json") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: want a panic", name)
				}
			}()
			fn()
		}()
	}
	if everyOfType([]any{"x"}, "integer") || !scalar(true) || scalar(1.5) || scalar(nil) {
		t.Error("value checks")
	}
}
