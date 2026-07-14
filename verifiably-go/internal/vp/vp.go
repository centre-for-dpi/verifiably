// Package vp turns individual presented credentials — JSON-LD VC objects or
// compact SD-JWT VCs — into the format-agnostic backend.NormalizedCredential
// shape consumed by cross-credential policies (e.g. internal/delegation). It is
// the single per-credential parser shared by the verifier adapters so the
// normalization has one implementation, not one per DPG (ADR D5).
//
// It does NOT verify signatures or holder binding — that is the host verifier's
// job; these helpers only decode what the host already verified.
package vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
)

// reserved JWT/SD-JWT control claims that should not appear as display claims.
var reserved = map[string]bool{
	"_sd": true, "_sd_alg": true, "cnf": true, "iss": true, "iat": true,
	"exp": true, "nbf": true, "sub": true, "vct": true, "status": true,
}

// FromVCObject normalizes a decoded JSON-LD VC object (optionally wrapped in a
// JWT `vc` claim) into a NormalizedCredential. Raw is the VC object itself, so
// the evaluator can read termsOfUse / credentialStatus / nested onBehalfOf.
func FromVCObject(vc map[string]any) backend.NormalizedCredential {
	inner, _ := vc["vc"].(map[string]any)
	if inner == nil {
		inner = vc
	}
	cs, _ := inner["credentialSubject"].(map[string]any)
	claims := map[string]string{}
	subject := ""
	if cs != nil {
		subject, _ = cs["id"].(string)
		for k, v := range cs {
			if k != "id" {
				claims[k] = Stringify(v)
			}
		}
	}
	if subject == "" {
		subject = str(vc, "sub")
	}
	// issuer: prefer vc.issuer; fall back to the JWT-level `iss` (VC-JWT /
	// jwt_vc_json carries the issuer there, not inside the vc object).
	issuer := IssuerID(inner["issuer"])
	if issuer == "" {
		issuer = str(vc, "iss")
	}
	return backend.NormalizedCredential{
		Types:     AsStringSlice(inner["type"]),
		SubjectID: subject,
		Issuer:    issuer,
		Format:    vcdmFormat(inner),
		Claims:    claims,
		Raw:       inner,
	}
}

// FromCompactSDJWT normalizes a compact SD-JWT VC presentation
// (<issuer-jwt>~<disclosure>~…[~<kb-jwt>]) into a NormalizedCredential. Raw is
// the issuer payload merged with the disclosed claims, so the delegation /
// status claims survive for the evaluator.
func FromCompactSDJWT(tok string) (backend.NormalizedCredential, bool) {
	parts := strings.Split(tok, "~")
	payload := DecodeJWTPayload(parts[0])
	if payload == nil {
		return backend.NormalizedCredential{}, false
	}
	raw := make(map[string]any, len(payload))
	claims := map[string]string{}
	for k, v := range payload {
		raw[k] = v
		if !reserved[k] {
			claims[k] = Stringify(v)
		}
	}
	for _, seg := range parts[1:] {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		d, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			continue
		}
		var arr []any
		if json.Unmarshal(d, &arr) != nil || len(arr) != 3 {
			continue
		}
		if name, ok := arr[1].(string); ok {
			claims[name] = Stringify(arr[2])
			raw[name] = arr[2]
		}
	}
	vct, _ := payload["vct"].(string)
	return backend.NormalizedCredential{
		Types:     []string{vct},
		SubjectID: str(payload, "sub"),
		Issuer:    str(payload, "iss"),
		Format:    "vc+sd-jwt",
		Claims:    claims,
		Raw:       raw,
	}, true
}

// DecodeJWTPayload base64url-decodes and JSON-parses the payload of a compact
// JWS. Returns nil on any malformation.
func DecodeJWTPayload(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// IssuerID returns the issuer identifier whether it is a bare string or an
// object {"id": "..."}.
func IssuerID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		return str(t, "id")
	}
	return ""
}

// AsStringSlice coerces a JSON value that may be a string, []any of strings, or
// []string into a []string.
func AsStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}

// Stringify renders a claim value for display: scalars as text, structured
// values as compact JSON.
func Stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func vcdmFormat(vc map[string]any) string {
	for _, c := range AsStringSlice(vc["@context"]) {
		if strings.Contains(c, "/ns/credentials/v2") {
			return "w3c_vcdm_2"
		}
	}
	return "jwt_vc_json"
}
