// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// ParamRequireChain makes a presentation without a chain link fail.
const ParamRequireChain = "require_chain"

// trustChain checks that every issuer is on an enabled trust list, and
// that a chained presentation links up (ADR-024 decision 4).
func trustChain(ctx context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameTrustChain)
	}
	out := make([]CheckResult, 0, len(p.Credentials)+1)
	for i, c := range p.Credentials {
		out = append(out, issuerTrust(ctx, i, c, pc))
	}
	return append(out, chainLink(p, pc))
}

func issuerTrust(ctx context.Context, index int, c Credential, pc Context) CheckResult {
	ev := map[string]string{"issuer": c.VC.Issuer, "type": c.VC.PrimaryType()}
	if pc.Trust == nil {
		return result(NameTrustChain, Error, index, "the service has no trust list lookup", ev)
	}
	t, err := pc.Trust(ctx, c.VC.Issuer, c.VC.PrimaryType())
	if err != nil {
		return result(NameTrustChain, Error, index, "the trust registry is not reachable", ev)
	}
	if t.ListURL != "" {
		ev["list"] = t.ListURL
	}
	if t.DisplayName != "" {
		ev["issuer_name"] = t.DisplayName
	}
	if !t.Trusted {
		if t.Reason != "" {
			ev["reason"] = t.Reason
		}
		return result(NameTrustChain, Fail, index, "the issuer is not on an enabled trust list", ev)
	}
	return result(NameTrustChain, Pass, index, "the issuer is on an enabled trust list", ev)
}

// chainLink checks that each link of a credential chain references
// another credential of the same presentation by id.
func chainLink(p Presentation, pc Context) CheckResult {
	ids := map[string]bool{}
	for _, c := range p.Credentials {
		if id := refID(c.VC.Raw["id"]); id != "" {
			ids[id] = true
		}
	}
	links, broken := 0, ""
	for _, c := range p.Credentials {
		ref := chainRef(c.VC)
		if ref == "" {
			continue
		}
		links++
		if !ids[ref] {
			broken = ref
		}
	}
	switch {
	case links == 0 && strings.EqualFold(pc.Param(ParamRequireChain, "false"), "true"):
		return result(NameTrustChain, Fail, WholePresentation, "the presentation carries no credential chain", nil)
	case links == 0:
		return result(NameTrustChain, Skip, WholePresentation, "the presentation carries no credential chain", nil)
	case broken != "":
		return result(NameTrustChain, Fail, WholePresentation, "a chain link names a credential that is not present",
			map[string]string{"missing": broken})
	default:
		return result(NameTrustChain, Pass, WholePresentation, "every chain link names a credential of the presentation", nil)
	}
}

// chainRef returns the id of the credential that c chains to.
func chainRef(c vc.Credential) string {
	if id := refID(c.Raw["parentCredential"]); id != "" {
		return id
	}
	if cs, ok := c.Raw["credentialSubject"].(map[string]any); ok {
		if id := refID(cs["parentCredential"]); id != "" {
			return id
		}
	}
	if d, ok := c.Raw["delegation"].(map[string]any); ok {
		if id := refID(d["parent_capability"]); id != "" {
			return id
		}
	}
	for _, item := range asSlice(c.Raw["termsOfUse"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id := refID(m["parentCapability"]); id != "" {
			return id
		}
	}
	return ""
}

// refID reads an identifier that is a string or an object with an id.
func refID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		id := anyval.As[string](t["id"])
		return id
	}
	return ""
}

// asSlice returns v as a slice. A single value becomes a slice of one.
func asSlice(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	default:
		return []any{t}
	}
}
