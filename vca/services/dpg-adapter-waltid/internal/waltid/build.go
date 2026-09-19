// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Format names one OID4VCI wire format walt.id knows.
type Format string

// The wire formats of walt.id 0.18.2.
const (
	FormatJwtVcJSON Format = "jwt_vc_json"
	FormatVcSdJwt   Format = "vc+sd-jwt"
	FormatDcSdJwt   Format = "dc+sd-jwt"
	FormatLdpVc     Format = "ldp_vc"
	FormatMsoMdoc   Format = "mso_mdoc"
)

// IssuePath returns the issue endpoint of the format. walt.id 0.18.2
// routes the JWT, the SD-JWT, and the mdoc issuers to three paths.
func IssuePath(f Format) (string, error) {
	switch f {
	case FormatJwtVcJSON, FormatLdpVc:
		return "/openid4vc/jwt/issue", nil
	case FormatVcSdJwt, FormatDcSdJwt:
		return "/openid4vc/sdjwt/issue", nil
	case FormatMsoMdoc:
		return "/openid4vc/mdoc/issue", nil
	default:
		return "", fmt.Errorf("waltid: the format %q has no issue endpoint", f)
	}
}

// IsSdJwt reports whether the format is an SD-JWT VC format.
func IsSdJwt(f Format) bool { return f == FormatVcSdJwt || f == FormatDcSdJwt }

// AuthenticationMethod maps a delivery flow onto the walt.id value.
// PRE_AUTHORIZED makes walt.id put a pre-authorized code in the offer.
// NONE makes walt.id use the authorization code flow.
func AuthenticationMethod(preAuthorized bool) string {
	if preAuthorized {
		return "PRE_AUTHORIZED"
	}
	return "NONE"
}

// StatusEntry points at the status list entry of one credential.
type StatusEntry struct {
	// Bitstring selects the W3C Bitstring Status List shape.
	Bitstring bool
	// Token selects the IETF Token Status List shape.
	Token bool
	// Index is the position of the credential in the list.
	Index int64
	// URL is the public address of the list.
	URL string
}

// Validity is the window a credential is valid in.
type Validity struct {
	// From is the start. A zero time leaves the start open.
	From time.Time
	// Until is the end. A zero time leaves the end open.
	Until time.Time
}

// BuildVcdmCredential returns the VCDM body walt.id signs. The subject
// claims go under credentialSubject. A Bitstring status entry becomes a
// credentialStatus member.
//
// The statusListIndex value is a string. A verifier rejects a number
// here with a validation error, although the value is numeric.
func BuildVcdmCredential(types []string, subject map[string]any, status StatusEntry, v Validity) ([]byte, error) {
	all := append([]string{"VerifiableCredential"}, types...)
	doc := map[string]any{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/ns/credentials/examples/v1",
		},
		"type":              dedupe(all),
		"credentialSubject": subject,
	}
	if !v.From.IsZero() {
		doc["validFrom"] = v.From.UTC().Format(time.RFC3339)
	}
	if !v.Until.IsZero() {
		doc["validUntil"] = v.Until.UTC().Format(time.RFC3339)
	}
	if status.Bitstring {
		doc["credentialStatus"] = map[string]any{
			"id":                   fmt.Sprintf("%s#%d", status.URL, status.Index),
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":        "revocation",
			"statusListIndex":      fmt.Sprintf("%d", status.Index),
			"statusListCredential": status.URL,
		}
	}
	return json.Marshal(doc)
}

// BuildSdJwtCredential returns the SD-JWT VC body. Every claim sits at
// the payload root, which is where the walt.id SDMap looks for it. A
// VCDM shaped body would make only credentialSubject disclosable.
func BuildSdJwtCredential(subject map[string]any, status StatusEntry, v Validity) ([]byte, error) {
	out := make(map[string]any, len(subject)+3)
	for k, val := range subject {
		out[k] = val
	}
	if !v.From.IsZero() {
		out["nbf"] = v.From.Unix()
	}
	if !v.Until.IsZero() {
		out["exp"] = v.Until.Unix()
	}
	if status.Token {
		out["status"] = map[string]any{
			"status_list": map[string]any{"idx": status.Index, "uri": status.URL},
		}
	}
	return json.Marshal(out)
}

// BuildMdocData returns the namespace keyed body the mdoc issuer wants.
// The namespace is the doctype without its last dot part, so the
// doctype org.iso.18013.5.1.mDL uses the namespace org.iso.18013.5.1.
func BuildMdocData(doctype string, subject map[string]any) ([]byte, error) {
	if strings.TrimSpace(doctype) == "" {
		return nil, fmt.Errorf("waltid: an mdoc needs a doctype")
	}
	namespace := doctype
	if i := strings.LastIndex(doctype, "."); i > 0 {
		namespace = doctype[:i]
	}
	return json.Marshal(map[string]any{namespace: subject})
}

// BuildSelectiveDisclosure returns the walt.id SDMap. Every top level
// claim becomes a disclosure, so the holder can reveal the claims one by
// one. The decoy mode stays off to keep the output the same every time.
func BuildSelectiveDisclosure(subject map[string]any) []byte {
	fields := make(map[string]any, len(subject))
	for k := range subject {
		fields[k] = map[string]any{"sd": true}
	}
	// The map holds strings and numbers only, so Marshal cannot fail.
	raw, ignored := json.Marshal(map[string]any{
		"fields": fields, "decoyMode": "NONE", "decoys": 0,
	})
	_ = ignored
	return raw
}

// BorrowConfigurationID returns a configuration id the walt.id catalog
// advertises for the format. The adapter cannot add an entry to the
// catalog over the HTTP API, so a credential of a new type is signed
// through a configuration of the same format. The signed credential
// carries the type of the credential body, not of the configuration.
func BorrowConfigurationID(meta IssuerMetadata, f Format) (string, error) {
	ids := make([]string, 0, len(meta.CredentialConfigurationsSupported))
	for id, entry := range meta.CredentialConfigurationsSupported {
		if Format(entry.Format) == f {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("waltid: the issuer advertises no configuration of the format %q", f)
	}
	sort.Strings(ids)
	return ids[0], nil
}

// dedupe returns the values without repeats and in the input order.
func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
