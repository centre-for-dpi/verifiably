// SPDX-License-Identifier: Apache-2.0

package dcql_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

func TestParsePath(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		jsonp  string
		length int
	}{
		{in: "given_name", want: "given_name", jsonp: "$.given_name", length: 1},
		{in: "address.street", want: "address.street", jsonp: "$.address.street", length: 2},
		{in: "list[0].name", want: "list[0].name", jsonp: "$.list[0].name", length: 3},
		{in: "list[].name", want: "list[].name", jsonp: "$.list[*].name", length: 3},
		{in: " degrees[2] ", want: "degrees[2]", jsonp: "$.degrees[2]", length: 2},
	}
	for _, c := range cases {
		got, err := dcql.ParsePath(c.in)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", c.in, err)
		}
		if len(got) != c.length {
			t.Errorf("ParsePath(%q) has %d segments, want %d", c.in, len(got), c.length)
		}
		if got.String() != c.want {
			t.Errorf("ParsePath(%q).String() = %q, want %q", c.in, got.String(), c.want)
		}
		if got.JSONPath("") != c.jsonp {
			t.Errorf("ParsePath(%q).JSONPath() = %q, want %q", c.in, got.JSONPath(""), c.jsonp)
		}
	}
}

func TestParsePathPrefix(t *testing.T) {
	p, err := dcql.ParsePath("given_name")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.JSONPath("vc.credentialSubject"); got != "$.vc.credentialSubject.given_name" {
		t.Errorf("JSONPath with prefix = %q", got)
	}
}

func TestParsePathErrors(t *testing.T) {
	for _, in := range []string{"", "  ", "a]b", "list[", "list[x]", "list[-1]", "list]0[", "list[0]b"} {
		if _, err := dcql.ParsePath(in); err == nil {
			t.Errorf("ParsePath(%q) wants an error", in)
		}
	}
	if _, err := dcql.ParsePath("."); err == nil {
		t.Error("ParsePath(\".\") wants an error")
	}
}

func TestSegmentJSON(t *testing.T) {
	p := dcql.Path{dcql.Name("a"), dcql.Index(3), dcql.All()}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `["a",3,null]` {
		t.Fatalf("marshal = %s", data)
	}
	var back dcql.Path
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.String() != "a[3][]" {
		t.Errorf("round trip = %q", back.String())
	}
	var bad dcql.Path
	if err := json.Unmarshal([]byte(`[true]`), &bad); err == nil {
		t.Error("a boolean segment wants an error")
	}
}

// sample is a valid two credential query.
const sample = `{
  "credentials": [
    {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://example.test/pid"]},
     "claims": [{"id": "given_name", "path": ["given_name"]}, {"id": "street", "path": ["address", "street"]}],
     "claim_sets": [["given_name"], ["given_name", "street"]]},
    {"id": "licence", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
     "claims": [{"path": ["org.iso.18013.5.1", "portrait"]}]}
  ],
  "credential_sets": [{"options": [["pid"], ["pid", "licence"]], "purpose": "Prove your age"}]
}`

func TestParseAndMarshal(t *testing.T) {
	q, err := dcql.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if got := q.IDs(); len(got) != 2 || got[0] != "pid" {
		t.Fatalf("IDs = %v", got)
	}
	c, ok := q.Find("pid")
	if !ok {
		t.Fatal("Find(pid) found nothing")
	}
	if c.Type() != "https://example.test/pid" {
		t.Errorf("Type = %q", c.Type())
	}
	if paths := c.ClaimPaths(); len(paths) != 2 || paths[1] != "address.street" {
		t.Errorf("ClaimPaths = %v", paths)
	}
	if _, ok := q.Find("missing"); ok {
		t.Error("Find(missing) found something")
	}
	data, err := dcql.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	again, err := dcql.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Credentials) != 2 {
		t.Errorf("round trip lost a credential query")
	}
	if _, err := dcql.Parse([]byte("{")); err == nil {
		t.Error("broken JSON wants an error")
	}
	if _, err := dcql.Parse([]byte(`{"credentials": []}`)); err == nil {
		t.Error("an empty query wants an error")
	}
	if _, err := dcql.Marshal(dcql.Query{}); err == nil {
		t.Error("Marshal of an empty query wants an error")
	}
}

func TestTypeVariants(t *testing.T) {
	w3c := dcql.CredentialQuery{Meta: &dcql.Meta{TypeValues: [][]string{{"VerifiableCredential", "DegreeCredential"}}}}
	if w3c.Type() != "DegreeCredential" {
		t.Errorf("W3C type = %q", w3c.Type())
	}
	empty := dcql.CredentialQuery{Meta: &dcql.Meta{TypeValues: [][]string{{}}}}
	if empty.Type() != "" {
		t.Errorf("empty type list = %q", empty.Type())
	}
	none := dcql.CredentialQuery{}
	if none.Type() != "" {
		t.Errorf("no metadata type = %q", none.Type())
	}
	mdoc := dcql.CredentialQuery{Meta: &dcql.Meta{DoctypeValue: "org.iso.18013.5.1.mDL"}}
	if mdoc.Type() != "org.iso.18013.5.1.mDL" {
		t.Errorf("mdoc type = %q", mdoc.Type())
	}
	if !(&dcql.Meta{}).Empty() || !(*dcql.Meta)(nil).Empty() {
		t.Error("an empty metadata must report Empty")
	}
}

func TestIsRequired(t *testing.T) {
	no := false
	if (dcql.CredentialSetQuery{}).IsRequired() != true {
		t.Error("a set without the field is required")
	}
	if (dcql.CredentialSetQuery{Required: &no}).IsRequired() {
		t.Error("a set with required false is not required")
	}
}

func TestBuild(t *testing.T) {
	q, err := dcql.Build([]dcql.Selection{
		{ID: "Person ID", Format: dcql.FormatSDJWT, Type: "https://example.test/pid", Claims: []string{"given_name", "address.street"}, Issuers: []string{"did:web:issuer.test"}},
		{Format: dcql.FormatJWTVCJSON, Type: "DegreeCredential", Claims: []string{"degree"}},
		{Format: dcql.FormatMdoc, Type: "org.iso.18013.5.1.mDL", Claims: []string{"org.iso.18013.5.1.portrait"}, Optional: true},
	}, "Prove your identity")
	if err != nil {
		t.Fatal(err)
	}
	if got := q.IDs(); len(got) != 3 || got[0] != "Person_ID" || got[1] != "DegreeCredential" {
		t.Fatalf("IDs = %v", got)
	}
	if len(q.CredentialSets) != 2 {
		t.Fatalf("credential sets = %d, want 2", len(q.CredentialSets))
	}
	if q.CredentialSets[1].IsRequired() {
		t.Error("the optional credential must sit in a set that is not required")
	}
	pid, _ := q.Find("Person_ID")
	if len(pid.TrustedAuthorities) != 1 || pid.TrustedAuthorities[0].Type != dcql.AuthorityETSITrustedList {
		t.Errorf("trusted authorities = %v", pid.TrustedAuthorities)
	}
	if pid.Meta.VctValues[0] != "https://example.test/pid" {
		t.Errorf("vct values = %v", pid.Meta.VctValues)
	}
	degree, _ := q.Find("DegreeCredential")
	if degree.Meta.TypeValues[0][1] != "DegreeCredential" {
		t.Errorf("type values = %v", degree.Meta.TypeValues)
	}
	licence, _ := q.Find("org_iso_18013_5_1_mDL")
	if licence.Meta.DoctypeValue != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q", licence.Meta.DoctypeValue)
	}
}

func TestBuildNamesUnnamedSelections(t *testing.T) {
	q, err := dcql.Build([]dcql.Selection{{Format: dcql.FormatLDPVC, Claims: []string{"name"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if q.Credentials[0].ID != "credential1" {
		t.Errorf("id = %q", q.Credentials[0].ID)
	}
	if q.Credentials[0].Meta != nil {
		t.Errorf("a selection without a type needs no metadata")
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := dcql.Build(nil, ""); err == nil {
		t.Error("no selection wants an error")
	}
	if _, err := dcql.Build([]dcql.Selection{{Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"a["}}}, ""); err == nil {
		t.Error("a broken claim path wants an error")
	}
	if _, err := dcql.Build([]dcql.Selection{{Format: "bogus", Type: "t"}}, ""); err == nil {
		t.Error("an unknown format wants an error")
	}
	if _, err := dcql.Build([]dcql.Selection{{ID: "a", Format: dcql.FormatMdoc, Type: "t", Claims: []string{"name."}}}, ""); err == nil {
		t.Error("an mdoc claim without a name wants an error")
	}
	q, err := dcql.Build([]dcql.Selection{{ID: "a", Format: dcql.FormatMdoc, Type: "t", Claims: []string{"portrait"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := q.Credentials[0].Claims[0].Path.String(); got != dcql.MdocNamespace+".portrait" {
		t.Errorf("a bare mdoc claim takes the default namespace, got %q", got)
	}
}

func TestCleanID(t *testing.T) {
	if got := dcql.CleanID("Person ID/2"); got != "Person_ID_2" {
		t.Errorf("CleanID = %q", got)
	}
	if got := dcql.CleanID("///"); got != "" {
		t.Errorf("CleanID of punctuation = %q", got)
	}
}

func TestSelectiveDisclosureAndPrefix(t *testing.T) {
	cases := []struct {
		format    string
		selective bool
		prefix    string
		typePath  string
	}{
		{dcql.FormatSDJWT, true, "", "$.vct"},
		{dcql.FormatSDJWTLegacy, true, "", "$.vct"},
		{dcql.FormatMdoc, true, "", "$.docType"},
		{dcql.FormatLDPVC, false, "credentialSubject", "$.type"},
		{dcql.FormatJWTVCJSON, false, "vc.credentialSubject", "$.vc.type"},
	}
	for _, c := range cases {
		if dcql.SelectiveDisclosure(c.format) != c.selective {
			t.Errorf("SelectiveDisclosure(%q) = %v", c.format, !c.selective)
		}
		if dcql.ClaimPrefix(c.format) != c.prefix {
			t.Errorf("ClaimPrefix(%q) = %q", c.format, dcql.ClaimPrefix(c.format))
		}
		if dcql.TypePath(c.format) != c.typePath {
			t.Errorf("TypePath(%q) = %q", c.format, dcql.TypePath(c.format))
		}
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() dcql.Query {
		q, err := dcql.Parse([]byte(sample))
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	cases := []struct {
		name string
		fix  func(*dcql.Query)
		want string
	}{
		{"no credential", func(q *dcql.Query) { q.Credentials = nil }, "no credential query"},
		{"too many", func(q *dcql.Query) {
			for i := 0; i < dcql.MaxCredentials+1; i++ {
				q.Credentials = append(q.Credentials, q.Credentials[0])
			}
		}, "the limit is"},
		{"empty id", func(q *dcql.Query) { q.Credentials[0].ID = "" }, "is empty"},
		{"bad id", func(q *dcql.Query) { q.Credentials[0].ID = "a b" }, "has the character"},
		{"duplicate id", func(q *dcql.Query) { q.Credentials[1].ID = q.Credentials[0].ID }, "used twice"},
		{"bad format", func(q *dcql.Query) { q.Credentials[0].Format = "jwt" }, "unknown format"},
		{"sd-jwt without vct", func(q *dcql.Query) { q.Credentials[0].Meta = &dcql.Meta{DoctypeValue: "x"} }, "meta.vct_values"},
		{"mdoc without doctype", func(q *dcql.Query) { q.Credentials[1].Meta = &dcql.Meta{VctValues: []string{"x"}} }, "meta.doctype_value"},
		{"w3c without types", func(q *dcql.Query) {
			q.Credentials[0].Format = dcql.FormatJWTVCJSON
		}, "meta.type_values"},
		{"w3c empty type set", func(q *dcql.Query) {
			q.Credentials[0].Format = dcql.FormatLDPVC
			q.Credentials[0].Meta = &dcql.Meta{TypeValues: [][]string{{}}}
		}, "entry of"},
		{"authority without type", func(q *dcql.Query) {
			q.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthority{{Values: []string{"a"}}}
		}, "no type"},
		{"authority without values", func(q *dcql.Query) {
			q.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthority{{Type: dcql.AuthorityAKI}}
		}, "no value"},
		{"too many claims", func(q *dcql.Query) {
			for i := 0; i <= dcql.MaxClaims; i++ {
				q.Credentials[0].Claims = append(q.Credentials[0].Claims, q.Credentials[0].Claims[0])
			}
		}, "the limit is"},
		{"empty path", func(q *dcql.Query) { q.Credentials[0].Claims[0].Path = nil }, "empty path"},
		{"empty name segment", func(q *dcql.Query) {
			q.Credentials[0].Claims[0].Path = dcql.Path{dcql.Name("")}
		}, "empty name segment"},
		{"negative index", func(q *dcql.Query) {
			q.Credentials[0].Claims[0].Path = dcql.Path{dcql.Name("a"), {Kind: dcql.KindIndex, Index: -2}}
		}, "negative array index"},
		{"mdoc path length", func(q *dcql.Query) {
			q.Credentials[1].Claims[0].Path = dcql.Path{dcql.Name("portrait")}
		}, "two segments"},
		{"bad claim id", func(q *dcql.Query) { q.Credentials[0].Claims[0].ID = "a b" }, "claim id"},
		{"duplicate claim id", func(q *dcql.Query) {
			q.Credentials[0].Claims[1].ID = q.Credentials[0].Claims[0].ID
		}, "used twice"},
		{"claim sets without claims", func(q *dcql.Query) {
			q.Credentials[1].Claims = nil
			q.Credentials[1].ClaimSets = [][]string{{"x"}}
		}, "no claim"},
		{"empty claim set", func(q *dcql.Query) { q.Credentials[0].ClaimSets = [][]string{{}} }, "claim set of"},
		{"unknown claim id", func(q *dcql.Query) { q.Credentials[0].ClaimSets = [][]string{{"nope"}} }, "unknown claim id"},
		{"credential set without options", func(q *dcql.Query) { q.CredentialSets[0].Options = nil }, "no option"},
		{"empty option", func(q *dcql.Query) { q.CredentialSets[0].Options = [][]string{{}} }, "option of credential set"},
		{"unknown credential id", func(q *dcql.Query) { q.CredentialSets[0].Options = [][]string{{"nope"}} }, "unknown credential query id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := base()
			c.fix(&q)
			err := dcql.Validate(q)
			if err == nil {
				t.Fatalf("want an error that names %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name %q", err, c.want)
			}
		})
	}
}

func TestValidateAcceptsClaimWithoutID(t *testing.T) {
	q := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "a", Format: dcql.FormatLDPVC, Claims: []dcql.ClaimQuery{{Path: dcql.Path{dcql.Name("name")}}},
	}}}
	if err := dcql.Validate(q); err != nil {
		t.Fatal(err)
	}
}
