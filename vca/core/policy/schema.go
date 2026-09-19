// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strconv"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// schema checks every credential against the JSON Schema it declares
// (ADR-024 decision 5, W3C VC JSON Schema).
func schema(ctx context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameSchema)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, schemaOf(ctx, i, c, pc))
	}
	return out
}

func schemaOf(ctx context.Context, index int, c Credential, pc Context) CheckResult {
	url := schemaURL(c.VC)
	if url == "" {
		return result(NameSchema, Skip, index, "the credential declares no schema", nil)
	}
	ev := map[string]string{"schema": url}
	if pc.Schemas == nil {
		return result(NameSchema, Error, index, "the service has no schema fetcher", ev)
	}
	raw, err := pc.Schemas(ctx, url)
	if err != nil {
		return result(NameSchema, Error, index, "the schema is not reachable", ev)
	}
	doc, err := jsonschema.Parse(raw)
	if err != nil {
		return result(NameSchema, Error, index, "the schema document does not parse", ev)
	}
	problems := doc.Validate(c.VC.Raw)
	if len(problems) == 0 {
		return result(NameSchema, Pass, index, "the credential matches its schema", ev)
	}
	ev["problems"] = strconv.Itoa(len(problems))
	ev["first"] = problems[0].Keyword
	if problems[0].Path != "" {
		ev["path"] = problems[0].Path
	}
	return result(NameSchema, Fail, index, "the credential does not match its schema", ev)
}

// schemaURL returns the id of the declared JSON Schema. It reads the
// credentialSchema entry of a W3C credential. The entry is an object or
// a list of objects.
func schemaURL(c vc.Credential) string {
	for _, item := range asSlice(c.Raw["credentialSchema"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id := anyval.As[string](m["id"]); id != "" {
			return id
		}
	}
	return ""
}
