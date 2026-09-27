// SPDX-License-Identifier: Apache-2.0

package anoncreds_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anoncreds"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
)

const (
	schemaID = "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0"
	credDef  = "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/CLAIM_DEF/2107/default" //nolint:gosec // G101: a credential definition id, not a credential.
)

// farmerCheck asks for the name of the farmer and proves that the farm
// has at least 10 acres.
func farmerCheck() anoncreds.Request {
	return anoncreds.Request{
		Name: " Farmer check ",
		Attributes: []anoncreds.Attribute{{
			Names: []string{" fullName "}, Restriction: anoncreds.Restriction{SchemaID: schemaID, CredDefID: credDef},
		}},
		Predicates: []anoncreds.Predicate{{Name: "acres", Op: ">=", Value: 10, Restriction: anoncreds.Restriction{SchemaID: schemaID}}},
	}
}

// TestJSONIsTheProofRequestOfTheSpecification: the request names each
// attribute group attr1 and on, and each predicate pred1 and on. A group
// of one name uses name, a larger group uses names, and an empty
// restriction leaves the restrictions out.
func TestJSONIsTheProofRequestOfTheSpecification(t *testing.T) {
	r := farmerCheck().Normal()
	r.Attributes = append(r.Attributes, anoncreds.Attribute{Names: []string{"village", "district"}})
	var got struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Attributes map[string]struct {
			Name         string              `json:"name"`
			Names        []string            `json:"names"`
			Restrictions []map[string]string `json:"restrictions"`
		} `json:"requested_attributes"`
		Predicates map[string]struct {
			Name         string              `json:"name"`
			Type         string              `json:"p_type"`
			Value        int64               `json:"p_value"`
			Restrictions []map[string]string `json:"restrictions"`
		} `json:"requested_predicates"`
	}
	if err := json.Unmarshal(r.JSON(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "Farmer check" || got.Version != "1.0" || len(got.Attributes) != 2 || len(got.Predicates) != 1 {
		t.Fatalf("request = %+v", got)
	}
	a1 := got.Attributes["attr1"]
	if a1.Name != "fullName" || len(a1.Names) != 0 || len(a1.Restrictions) != 1 ||
		a1.Restrictions[0]["schema_id"] != schemaID || a1.Restrictions[0]["cred_def_id"] != credDef {
		t.Errorf("attr1 = %+v", a1)
	}
	if a2 := got.Attributes["attr2"]; a2.Name != "" || len(a2.Names) != 2 || a2.Restrictions != nil {
		t.Errorf("attr2 = %+v", a2)
	}
	p1 := got.Predicates["pred1"]
	if p1.Name != "acres" || p1.Type != ">=" || p1.Value != 10 || len(p1.Restrictions) != 1 || p1.Restrictions[0]["cred_def_id"] != "" {
		t.Errorf("pred1 = %+v", p1)
	}
	if !strings.Contains(string(r.JSON()), `"requested_predicates"`) {
		t.Errorf("json = %s", r.JSON())
	}
}

// TestNormalFillsTheDefaults: the name and the version get a default,
// and every value loses its spaces.
func TestNormalFillsTheDefaults(t *testing.T) {
	r := anoncreds.Request{Version: " 2.0 ", Predicates: []anoncreds.Predicate{{Name: " acres ", Op: " > ",
		Restriction: anoncreds.Restriction{SchemaID: " s ", CredDefID: " c "}}}}.Normal()
	if r.Name != anoncreds.DefaultName || r.Version != "2.0" || r.Predicates[0].Name != "acres" || r.Predicates[0].Op != ">" ||
		r.Predicates[0].Restriction.SchemaID != "s" || r.Predicates[0].Restriction.CredDefID != "c" {
		t.Errorf("normal = %+v", r)
	}
}

// TestCheckRefusesWhatAWalletRefuses: a request asks for something, a
// group names each attribute, a predicate has a known operator, and a
// name appears once, because an agent refuses a name in both lists.
func TestCheckRefusesWhatAWalletRefuses(t *testing.T) {
	if err := farmerCheck().Normal().Check(); err != nil {
		t.Fatalf("the farmer check: %v", err)
	}
	long := farmerCheck()
	long.Name = strings.Repeat("x", anoncreds.MaxNameLength+1)
	for name, r := range map[string]anoncreds.Request{
		"nothing":      {},
		"long name":    long,
		"empty group":  {Attributes: []anoncreds.Attribute{{}}},
		"blank name":   {Attributes: []anoncreds.Attribute{{Names: []string{" "}}}},
		"no predicate": {Predicates: []anoncreds.Predicate{{Op: ">="}}},
		"bad operator": {Predicates: []anoncreds.Predicate{{Name: "acres", Op: "=="}}},
		"twice": {Attributes: []anoncreds.Attribute{{Names: []string{"acres"}}},
			Predicates: []anoncreds.Predicate{{Name: "acres", Op: ">="}}},
	} {
		if err := r.Normal().Check(); err == nil {
			t.Errorf("%s passed", name)
		}
	}
}

// TestProtoRoundTrip: the proto message of a template holds the whole
// request, and a nil message is an empty request.
func TestProtoRoundTrip(t *testing.T) {
	r := farmerCheck().Normal()
	back := anoncreds.FromProto(r.ToProto())
	if string(back.JSON()) != string(r.JSON()) {
		t.Errorf("round trip = %s, want %s", back.JSON(), r.JSON())
	}
	var none *discoveryv1.AnonCredsRequest
	if got := anoncreds.FromProto(none); !got.Empty() || !(anoncreds.Request{}).Empty() || r.Empty() {
		t.Errorf("empty = %+v", got)
	}
	if names := r.Names(); len(names) != 2 || names[0] != "fullName" || names[1] != "acres" {
		t.Errorf("names = %v", names)
	}
	if schemas := r.Schemas(); len(schemas) != 1 || schemas[0] != schemaID {
		t.Errorf("schemas = %v", schemas)
	}
	if len(anoncreds.Ops) != 4 {
		t.Errorf("ops = %v", anoncreds.Ops)
	}
}
