package handlers

import (
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The generated extraction view must read each claim from the per-slug-namespaced
// JSONB key (subjectClaimKey) while keeping the column ALIAS the plain field name,
// so two schemas that reuse a field name don't collide in the shared vc_subject
// blob yet the scope-query + ${field} template markers stay unchanged.
func TestBuildAuthcodeArtifacts_NamespacedView(t *testing.T) {
	// W3C (ldp_vc): plain claim fields.
	w3c := buildAuthcodeArtifacts(vctypes.Schema{
		Name:            "Testa Delegate A",
		AdditionalTypes: []string{"TestaDelegateA"},
		Std:             "w3c_vcdm_2",
		FieldsSpec:      []vctypes.FieldSpec{{Name: "onBehalfOf"}, {Name: "role"}},
	}, "")
	// slug = lower-alnum("TestaDelegateA")
	for _, want := range []string{
		`claims->>'testadelegatea.onBehalfOf' AS "onBehalfOf"`,
		`claims->>'testadelegatea.role' AS "role"`,
		`certify.vc_subject_testadelegatea`,
	} {
		if !strings.Contains(w3c.viewDDL, want) {
			t.Errorf("view DDL missing %q\ngot: %s", want, w3c.viewDDL)
		}
	}
	// The scope-query still selects the PLAIN aliases (unchanged contract).
	if !strings.Contains(w3c.scopeQuery, `"onBehalfOf", "role"`) {
		t.Errorf("scope-query should select plain aliases, got: %s", w3c.scopeQuery)
	}
	// The bare (un-namespaced) key must NOT appear as a read.
	if strings.Contains(w3c.viewDDL, `claims->>'onBehalfOf'`) {
		t.Errorf("view DDL still reads the un-namespaced key: %s", w3c.viewDDL)
	}

	// SD-JWT with token status: the statusIdx column keeps its own per-slug key
	// (statusIdx_<slug>) and statusUri stays a literal.
	sd := buildAuthcodeArtifacts(vctypes.Schema{
		Name:            "Testa Delegate B",
		AdditionalTypes: []string{"TestaDelegateB"},
		Std:             "sd_jwt_vc (IETF)",
		FieldsSpec:      []vctypes.FieldSpec{{Name: "onBehalfOf"}},
	}, "https://verifiably.example/tokenstatus")
	for _, want := range []string{
		`claims->>'testadelegateb.onBehalfOf' AS "onBehalfOf"`,
		`coalesce(claims->>'statusIdx_testadelegateb','0') AS "statusIdx"`,
		`'https://verifiably.example/tokenstatus' AS "statusUri"`,
	} {
		if !strings.Contains(sd.viewDDL, want) {
			t.Errorf("SD-JWT view DDL missing %q\ngot: %s", want, sd.viewDDL)
		}
	}
}

// authcodeViewDDL is the single source of truth for the view shape; the migration
// reconcile rebuilds views straight from credential_config through it.
func TestAuthcodeViewDDL(t *testing.T) {
	if got := subjectClaimKey("myslug", "role"); got != "myslug.role" {
		t.Errorf("subjectClaimKey = %q, want myslug.role", got)
	}
	ddl := authcodeViewDDL("myslug", []string{"a", "b", "statusIdx", "statusUri"}, true, "https://ts")
	// statusIdx/statusUri passed as fields are skipped (auto-added), so exactly one
	// namespaced statusIdx column with the per-slug key, plus the literal statusUri.
	for _, want := range []string{
		`claims->>'myslug.a' AS "a"`,
		`claims->>'myslug.b' AS "b"`,
		`coalesce(claims->>'statusIdx_myslug','0') AS "statusIdx"`,
		`'https://ts' AS "statusUri"`,
		`DROP VIEW IF EXISTS certify.vc_subject_myslug`,
		`CREATE VIEW certify.vc_subject_myslug`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("authcodeViewDDL missing %q\ngot: %s", want, ddl)
		}
	}
	// DROP+CREATE, never CREATE OR REPLACE (which 42P16s on a column-set change).
	if strings.Contains(ddl, "CREATE OR REPLACE") {
		t.Errorf("view DDL must not use CREATE OR REPLACE: %s", ddl)
	}
	if strings.Contains(ddl, `claims->>'myslug.statusIdx'`) {
		t.Errorf("statusIdx field should be auto-added, not read as a namespaced claim: %s", ddl)
	}
	// Without token status, no statusIdx/statusUri columns.
	plain := authcodeViewDDL("s", []string{"x"}, false, "")
	if strings.Contains(plain, "statusIdx") || strings.Contains(plain, "statusUri") {
		t.Errorf("non-token view must not add status columns: %s", plain)
	}
}

// slugForEntity resolves a Sunbird entity to the view slug: exact match against a
// known schema's configKey/Name, else the lower-alnum convention.
func TestSlugForEntity(t *testing.T) {
	schemas := []vctypes.Schema{
		{Name: "Testa Delegate A", AdditionalTypes: []string{"TestaDelegateA"}},
	}
	if got := slugForEntity(schemas, "TestaDelegateA"); got != "testadelegatea" {
		t.Errorf("configKey match = %q, want testadelegatea", got)
	}
	if got := slugForEntity(schemas, "Testa Delegate A"); got != "testadelegatea" {
		t.Errorf("display-name match = %q, want testadelegatea", got)
	}
	// Unknown entity → convention fallback lower-alnum(entity).
	if got := slugForEntity(schemas, "WakaWakaV3"); got != "wakawakav3" {
		t.Errorf("fallback = %q, want wakawakav3", got)
	}
}
