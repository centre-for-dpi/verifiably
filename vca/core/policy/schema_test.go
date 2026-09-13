// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

const schemaURLValue = "https://issuer.example/schema/1"

// schemaCred returns a credential that declares a schema.
func schemaCred(declared any, extra map[string]any) Credential {
	obj := map[string]any{"issuer": "did:web:issuer"}
	for k, v := range extra {
		obj[k] = v
	}
	if declared != nil {
		obj["credentialSchema"] = declared
	}
	return objectCred(vc.FormatJSONLD, obj)
}

var schemaDoc = []byte(`{"type":"object","required":["issuer","name"],
"properties":{"issuer":{"type":"string"},"name":{"type":"string"}}}`)

func TestSchemaNoCredentials(t *testing.T) {
	wantOutcome(t, only(t, schema(context.Background(), Presentation{}, base())), Skip)
}

func TestSchemaNotDeclared(t *testing.T) {
	wantOutcome(t, only(t, schema(context.Background(), pres(schemaCred(nil, nil)), base())), Skip)
	declared := []any{"text", map[string]any{"type": "JsonSchema"}}
	wantOutcome(t, only(t, schema(context.Background(), pres(schemaCred(declared, nil)), base())), Skip)
}

func TestSchemaPass(t *testing.T) {
	pc := base()
	pc.Schemas = bytesFetch(schemaDoc)
	c := schemaCred(map[string]any{"id": schemaURLValue}, map[string]any{"name": "Ada"})
	got := only(t, schema(context.Background(), pres(c), pc))
	wantOutcome(t, got, Pass)
	if got.Evidence["schema"] != schemaURLValue {
		t.Fatalf("want the schema url as evidence, got %v", got.Evidence)
	}
}

func TestSchemaFail(t *testing.T) {
	pc := base()
	pc.Schemas = bytesFetch(schemaDoc)
	c := schemaCred(map[string]any{"id": schemaURLValue}, nil)
	got := only(t, schema(context.Background(), pres(c), pc))
	wantOutcome(t, got, Fail)
	if got.Evidence["problems"] != "1" || got.Evidence["first"] != "required" {
		t.Fatalf("want one required problem, got %v", got.Evidence)
	}
}

func TestSchemaProblemPath(t *testing.T) {
	pc := base()
	pc.Schemas = bytesFetch([]byte(`{"type":"object","properties":{"name":{"type":"number"}}}`))
	c := schemaCred(map[string]any{"id": schemaURLValue}, map[string]any{"name": "Ada"})
	got := only(t, schema(context.Background(), pres(c), pc))
	wantOutcome(t, got, Fail)
	if got.Evidence["path"] == "" {
		t.Fatalf("want a problem path, got %v", got.Evidence)
	}
}

func TestSchemaErrors(t *testing.T) {
	c := schemaCred(map[string]any{"id": schemaURLValue}, nil)
	wantOutcome(t, only(t, schema(context.Background(), pres(c), base())), Error)

	offline := base()
	offline.Schemas = failFetch
	wantOutcome(t, only(t, schema(context.Background(), pres(c), offline)), Error)

	broken := base()
	broken.Schemas = bytesFetch([]byte("{oops"))
	wantOutcome(t, only(t, schema(context.Background(), pres(c), broken)), Error)
}
