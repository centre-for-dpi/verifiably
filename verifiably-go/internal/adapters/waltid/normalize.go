package waltid

import (
	"encoding/json"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// normalizePresentedCredentials produces a per-credential, format-agnostic view
// of a verified presentation for cross-credential policies (e.g. delegated
// access). Unlike extractPresentedCredential — which returns only the first
// credential's flat claims for the result card — this returns EVERY presented
// credential plus the holder binding, reusing the shared internal/vp parser.
// Best-effort: returns (nil, nil) when nothing parses.
func normalizePresentedCredentials(raw json.RawMessage) ([]backend.NormalizedCredential, *backend.HolderBinding) {
	if len(raw) == 0 {
		return nil, nil
	}
	var env struct {
		VPToken any `json:"vp_token"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil
	}
	var tokens []string
	switch v := env.VPToken.(type) {
	case string:
		tokens = []string{v}
	case []any:
		for _, t := range v {
			if s, ok := t.(string); ok {
				tokens = append(tokens, s)
			}
		}
	}

	var creds []backend.NormalizedCredential
	var holder *backend.HolderBinding
	for _, tok := range tokens {
		if strings.Contains(tok, "~") {
			if nc, ok := vp.FromCompactSDJWT(tok); ok {
				creds = append(creds, nc)
				// SD-JWT presenter binding is proven by the KB-JWT, which the
				// host verifier checks; mark it confirmed without an identifier
				// so the evaluator's invocation check stays lenient.
				if holder == nil {
					holder = &backend.HolderBinding{Confirmed: true}
				}
			}
			continue
		}
		ncs, hb := normalizeVPJWT(tok)
		creds = append(creds, ncs...)
		if hb != nil {
			holder = hb
		}
	}
	return creds, holder
}

// normalizeVPJWT decodes a VP-JWT (W3C VCDM 1.1/2.0 presentation), returning a
// normalized credential for EVERY embedded VC plus the VP holder binding.
func normalizeVPJWT(tok string) ([]backend.NormalizedCredential, *backend.HolderBinding) {
	payload := vp.DecodeJWTPayload(tok)
	if payload == nil {
		return nil, nil
	}
	vpObj, _ := payload["vp"].(map[string]any)
	if vpObj == nil {
		vpObj = payload
	}
	var holder *backend.HolderBinding
	if hid := firstHolderID(payload["holder"], vpObj["holder"], payload["iss"]); hid != "" {
		holder = &backend.HolderBinding{ID: hid, Confirmed: true}
	}
	vcList, _ := vpObj["verifiableCredential"].([]any)
	var out []backend.NormalizedCredential
	for _, item := range vcList {
		var obj map[string]any
		switch v := item.(type) {
		case string:
			obj = vp.DecodeJWTPayload(v)
		case map[string]any:
			obj = v
		}
		if obj == nil {
			continue
		}
		out = append(out, vp.FromVCObject(obj))
	}
	return out, holder
}

func firstHolderID(vs ...any) string {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
