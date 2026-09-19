// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// MaxCredentials bounds the credentials of one presentation.
const MaxCredentials = 64

// DecodeText reads decoded text: a compact token, a JSON document, or a
// base45 QR payload. It names what it found and splits the credentials
// out of a presentation.
func DecodeText(text string) (Result, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Result{}, errors.New("ingest: the decoded text is empty")
	}
	switch format := vc.DetectFormat([]byte(text)); format {
	case vc.FormatSDJWT:
		return sdjwtResult(text)
	case vc.FormatJWT:
		return jwtResult(text)
	case vc.FormatJSONLD, vc.FormatJSON:
		return jsonResult(text, format), nil
	case vc.FormatMdoc:
		return Result{Format: vc.FormatMdoc, Payload: []byte(text), Detected: TypeCredential,
			Credentials: []Credential{{Format: vc.FormatMdoc, Payload: []byte(text)}}, Steps: []string{"mdoc"}}, nil
	}
	// The text is no known credential. It may still be a QR payload.
	if looksBase45(text) {
		if res, err := decodeClaim169Text(text); err == nil {
			return res, nil
		}
	}
	return Result{Payload: []byte(text), Detected: TypeUnknown, Steps: []string{"text"}}, nil
}

// sdjwtResult reads an SD-JWT VC presentation.
func sdjwtResult(text string) (Result, error) {
	p, err := sdjwt.Parse(text)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Format: vc.FormatSDJWT, Payload: []byte(text), Detected: TypeCredential,
		Credentials: []Credential{{Format: vc.FormatSDJWT, Payload: []byte(text)}},
		Steps:       []string{"sd-jwt"},
	}
	if p.KeyBindingJWT != "" {
		res.KeyBinding = p.KeyBindingJWT
		res.Detected = TypePresentation
	}
	return res, nil
}

// jwtResult reads a compact JWS. A vp claim makes it a presentation.
func jwtResult(text string) (Result, error) {
	payload, err := jose.PeekPayload(text)
	if err != nil {
		return Result{}, err
	}
	res := Result{Format: vc.FormatJWT, Payload: []byte(text), Detected: TypeCredential, Steps: []string{"jwt"}}
	vp, ok := payload["vp"].(map[string]any)
	if !ok {
		res.Credentials = []Credential{{Format: vc.FormatJWT, Payload: []byte(text)}}
		return res, nil
	}
	res.Detected = TypePresentation
	res.Credentials = credentialsOf(vp["verifiableCredential"])
	return res, nil
}

// jsonResult reads a JSON document. A verifiableCredential member or a
// VerifiablePresentation type makes it a presentation. DetectFormat has
// already read the document, so the reader cannot fail here.
func jsonResult(text string, format vc.Format) Result {
	var doc map[string]any
	anyval.MustDo(json.Unmarshal([]byte(text), &doc))
	res := Result{Format: format, Payload: []byte(text), Detected: TypeCredential, Steps: []string{"json"}}
	inner, hasInner := doc["verifiableCredential"]
	if !hasInner && !hasType(doc, "VerifiablePresentation") {
		res.Credentials = []Credential{{Format: format, Payload: []byte(text)}}
		return res
	}
	res.Detected = TypePresentation
	res.Credentials = credentialsOf(inner)
	if proof, ok := doc["proof"].(map[string]any); ok {
		res.KeyBinding = anyval.As[string](proof["jwt"])
	}
	return res
}

// hasType reports whether the type member of a document holds name.
func hasType(doc map[string]any, name string) bool {
	for _, t := range vc.AsStringSlice(doc["type"]) {
		if t == name {
			return true
		}
	}
	return false
}

// credentialsOf splits the verifiableCredential member of a presentation.
func credentialsOf(value any) []Credential {
	var out []Credential
	for _, item := range listOf(value) {
		if len(out) >= MaxCredentials {
			break
		}
		if c, ok := credentialOf(item); ok {
			out = append(out, c)
		}
	}
	return out
}

// listOf turns a single value or a list into a list.
func listOf(value any) []any {
	switch t := value.(type) {
	case nil:
		return nil
	case []any:
		return t
	default:
		return []any{t}
	}
}

// credentialOf turns one entry of a presentation into a credential.
func credentialOf(item any) (Credential, bool) {
	switch t := item.(type) {
	case string:
		return Credential{Format: vc.DetectFormat([]byte(t)), Payload: []byte(t)}, true
	case map[string]any:
		// The value came from a JSON document, so it always writes.
		raw := anyval.Must(json.Marshal(t))
		return Credential{Format: vc.DetectFormat(raw), Payload: raw}, true
	}
	return Credential{}, false
}

// DecodeVPToken reads the vp_token parameter of an OID4VP response. The
// value is one token, a JSON array of tokens, or a JSON object that maps
// a DCQL credential query id to its tokens.
func DecodeVPToken(text string) (Result, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Result{}, errors.New("ingest: the vp_token is empty")
	}
	if !strings.HasPrefix(text, "[") && !strings.HasPrefix(text, "{") {
		res, err := DecodeText(text)
		if err != nil {
			return Result{}, err
		}
		res.Detected = TypePresentation
		return res, nil
	}
	tokens, ok := vpTokenList(text)
	if !ok {
		return DecodeText(text)
	}
	res := Result{Format: vc.FormatJSON, Payload: []byte(text), Detected: TypePresentation, Steps: []string{"vp_token", "json"}}
	for _, token := range tokens {
		if len(res.Credentials) >= MaxCredentials {
			break
		}
		part, err := DecodeText(token)
		if err != nil {
			continue
		}
		res.Credentials = append(res.Credentials, part.Credentials...)
		if res.KeyBinding == "" {
			res.KeyBinding = part.KeyBinding
		}
	}
	if len(res.Credentials) == 0 {
		return DecodeText(text)
	}
	return res, nil
}

// vpTokenList reads the tokens of an array or of a query id map.
func vpTokenList(text string) ([]string, bool) {
	var list []any
	if json.Unmarshal([]byte(text), &list) == nil {
		return stringsOf(list), true
	}
	var byQuery map[string]any
	if json.Unmarshal([]byte(text), &byQuery) != nil {
		return nil, false
	}
	var out []string
	for _, value := range byQuery {
		out = append(out, stringsOf(listOf(value))...)
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

// stringsOf keeps the string entries of a list.
func stringsOf(list []any) []string {
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
