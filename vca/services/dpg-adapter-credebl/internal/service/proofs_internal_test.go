// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// TestProofHelpers pins the pure helpers of the DIDComm proof requests:
// the names of schemas and issuers in both id forms, the page token, and
// the attribute list of a request over a connection.
func TestProofHelpers(t *testing.T) {
	for id, want := range map[string]string{
		"did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0": "Farmer",
		"Ra8F:2:Farmer:1.0":              "Farmer",
		"https://schemas.example/farmer": "https://schemas.example/farmer",
	} {
		if got := schemaName(id); got != want {
			t.Errorf("schemaName(%q) = %q", id, got)
		}
	}
	if got := issuerOf("Ra8F:3:CL:12:default"); got != "Ra8F" {
		t.Errorf("issuerOf = %q", got)
	}
	if nextToken(2, 10, 20) != "" || nextToken(1, 10, 20) != "2" {
		t.Error("nextToken")
	}
	if text(3) != "" || text("a") != "a" {
		t.Error("text")
	}
	req, err := parseAnonCreds(`{"requested_attributes":{"a":{"names":["x","y"]}}}`)
	if err != nil || req.Name == "" || req.Version != "1.0" || req.Predicates == nil {
		t.Fatalf("request = %+v, %v", req, err)
	}
	lines := req.attributes()
	if len(lines) != 1 || lines[0].Name != "" || len(lines[0].Names) != 2 || lines[0].SchemaID != "" {
		t.Errorf("lines = %+v", lines)
	}
	if _, perr := proofRequestOf(&backendv1.CreateRequestRequest{AnoncredsRequest: `{"requested_predicates":{"p":{"name":"a","p_type":">","p_value":1}}}`}, false); perr != nil {
		t.Errorf("a request with a predicate alone: %v", perr)
	}
	if _, derr := platformDefinition(`{"id":"x","input_descriptors":[1]}`); derr == nil {
		t.Error("a descriptor that is no object passed")
	}
	def, err := platformDefinition(`{"id":"x","input_descriptors":[{"id":"a","schema":[{"uri":"u"}]},` +
		`{"id":"b","constraints":{"fields":[{"path":["$.vc.type"],"filter":{"const":"T"}}]}}]}`)
	if err != nil || string(def) != `{"id":"x","input_descriptors":[{"id":"a","schema":[{"uri":"u"}]},`+
		`{"constraints":{"fields":[{"filter":{"const":"T"},"path":["$.vc.type"]}]},"id":"b","schema":[{"uri":"T"}]}]}` {
		t.Errorf("definition = %s, %v", def, err)
	}
}
