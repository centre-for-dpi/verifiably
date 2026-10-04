// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anoncreds"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

const farmerSchema = "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0"

// farmerCredDef is the credential definition of the farmer schema.
const farmerCredDef = "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/CLAIM_DEF/2107/default" //nolint:gosec // G101: a credential definition id, not a credential.

// farmerRequest reveals the name and proves at least 10 acres, both
// from the one credential definition of the schema.
func farmerRequest() *anoncreds.Request {
	bound := anoncreds.Restriction{SchemaID: farmerSchema, CredDefID: farmerCredDef}
	return &anoncreds.Request{
		Attributes: []anoncreds.Attribute{{Names: []string{"fullName"}, Restriction: bound}},
		Predicates: []anoncreds.Predicate{{Name: "acres", Op: ">=", Value: 10, Restriction: bound}},
	}
}

// TestTrustedAnonCredsTemplateNeedsACredentialDefinition is finding 3.2
// of the CREDEBL review: a template that asks for a trusted issuer binds
// every part to a credential definition. A template open to any issuer
// may restrict a schema alone.
func TestTrustedAnonCredsTemplateNeedsACredentialDefinition(t *testing.T) {
	open := farmerRequest()
	open.Predicates[0].Restriction.CredDefID = ""
	_, err := template.Build(template.Template{DisplayName: "Farmer check", Kind: template.KindNative, AnonCreds: open, RequireTrustedIssuer: true})
	if err == nil || !strings.Contains(err.Error(), "credential definition") {
		t.Fatalf("a trusted template on a schema alone: %v", err)
	}
	if _, err := template.Build(template.Template{DisplayName: "Farmer check", Kind: template.KindNative, AnonCreds: open}); err != nil {
		t.Fatalf("a template open to any issuer: %v", err)
	}
}

// TestBuildNativeAnonCreds is ADR-061 decision 4: a native template
// holds an AnonCreds proof request. It has no DCQL and no PE form, and
// its queries name each schema with the attributes the request asks for.
func TestBuildNativeAnonCreds(t *testing.T) {
	out, err := template.Build(template.Template{DisplayName: "Farmer check", Kind: template.KindNative, AnonCreds: farmerRequest(),
		RequireTrustedIssuer: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if out.DCQL != "" || out.PresentationDefinition != "" || out.AnonCreds.Version != "1.0" || out.AnonCreds.Name != "Farmer check" {
		t.Errorf("template = %+v", out)
	}
	if len(out.Queries) != 1 || out.Queries[0].Type != farmerSchema || out.Queries[0].Format != "anoncreds" ||
		strings.Join(out.Queries[0].Claims, ",") != "fullName,acres" {
		t.Errorf("queries = %+v", out.Queries)
	}
	if !out.HasRules() {
		t.Error("the trust rule needs a policy set")
	}
	if _, peErr := out.PresentationExchange(); peErr == nil {
		t.Error("an AnonCreds template has no PE form")
	}
	unrestricted, err := template.Build(template.Template{DisplayName: "Any", Kind: template.KindNative,
		AnonCreds: &anoncreds.Request{Attributes: []anoncreds.Attribute{{Names: []string{"a"}}}}})
	if err != nil || len(unrestricted.Queries) != 1 || unrestricted.Queries[0].Type != "" {
		t.Errorf("unrestricted = %+v, %v", unrestricted.Queries, err)
	}
}

// TestAnonCredsTemplateWithoutTheTrustRuleSkipsTheTrustCheck: an
// AnonCreds template that admits any issuer gets a policy set of its own
// without the trust check, so the built in set, which holds that check,
// never runs on its answer. With the rule the set holds the check.
func TestAnonCredsTemplateWithoutTheTrustRuleSkipsTheTrustCheck(t *testing.T) {
	open, err := template.Build(template.Template{DisplayName: "Any farmer", Kind: template.KindNative, AnonCreds: farmerRequest()})
	if err != nil {
		t.Fatal(err)
	}
	if !open.HasRules() {
		t.Fatal("an AnonCreds template without the trust rule falls back to the built in set, which checks the trust list")
	}
	for _, c := range open.PolicyChecks() {
		if c.GetName() == policy.NameTrustChain {
			t.Errorf("the set of a template open to any issuer checks the trust list: %v", open.PolicyChecks())
		}
	}
	trusted, err := template.Build(template.Template{DisplayName: "Farmer", Kind: template.KindNative, AnonCreds: farmerRequest(), RequireTrustedIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	if checks := trusted.PolicyChecks(); len(checks) == 0 || checks[0].GetName() != policy.NameTrustChain {
		t.Errorf("a trusted template: %v", checks)
	}
}

// TestBuildNativeRefuses: a native template needs a valid AnonCreds
// request, and a DCQL template holds none. The date rules of DCQL do not
// apply to a native template, which has predicates of its own.
func TestBuildNativeRefuses(t *testing.T) {
	for name, tm := range map[string]template.Template{
		"no request":  {DisplayName: "x", Kind: template.KindNative},
		"bad request": {DisplayName: "x", Kind: template.KindNative, AnonCreds: &anoncreds.Request{}},
		"date rule": {DisplayName: "x", Kind: template.KindNative, AnonCreds: farmerRequest(),
			Predicates: []template.Predicate{{QueryID: "anoncreds-1", Path: "fullName", Op: template.OpAtLeastYears, Value: "18"}}},
		"no name": {Kind: template.KindNative, AnonCreds: farmerRequest()},
		"dcql with anoncreds": {DisplayName: "x", Kind: template.KindDCQL, AnonCreds: farmerRequest(),
			Queries: []template.Query{{QueryID: "a", Type: "T", Claims: []string{"a"}}}},
	} {
		if _, err := template.Build(tm); err == nil {
			t.Errorf("%s passed", name)
		}
	}
}

// TestAnonCredsProtoRoundTrip: the proto message carries the request
// and the AnonCreds format.
func TestAnonCredsProtoRoundTrip(t *testing.T) {
	built, err := template.Build(template.Template{DisplayName: "Farmer check", Kind: template.KindNative, AnonCreds: farmerRequest()})
	if err != nil {
		t.Fatal(err)
	}
	m := built.ToProto()
	if m.GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE || len(m.GetAnoncreds().GetPredicates()) != 1 ||
		m.GetQueries()[0].GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Fatalf("proto = %v", m)
	}
	back := template.FromProto(m)
	if back.AnonCreds == nil || string(back.AnonCreds.JSON()) != string(built.AnonCreds.JSON()) || back.Queries[0].Format != "anoncreds" {
		t.Errorf("back = %+v", back)
	}
	if plain := template.FromProto(&discoveryv1.PresentationTemplate{Dcql: "{}"}); plain.AnonCreds != nil {
		t.Errorf("a DCQL message has a request: %+v", plain.AnonCreds)
	}
}
