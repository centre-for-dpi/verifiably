package delegation

import (
	"encoding/json"
	"fmt"
)

// This file is the issuance-side counterpart to the evaluator: it constructs the
// two credentials of a delegated-access relation — a subject identity credential
// and an issuer-signed delegation credential carrying the capability. The bodies
// are handed to a DPG issuer adapter to SIGN (the adapter never signs here —
// invariant I1). The shapes are exactly what the evaluator (via internal/vp
// normalization) reads back at verification, so issuance and verification share
// one contract.
//
// Two encodings are produced, selected by data-model tier:
//   - JSON-LD (W3C VCDM 1.1 / 2.0): BuildSubjectCredential / BuildDelegationCredential —
//     the capability lives in termsOfUse, status in credentialStatus (Bitstring).
//   - SD-JWT VC: SubjectClaims / DelegationClaims — flat claims; the capability is
//     the top-level `delegation` claim, status the IETF Token Status List entry.

const (
	// ContextVCDM2 / ContextVCDM1 are the W3C VC Data Model base contexts.
	ContextVCDM2 = "https://www.w3.org/ns/credentials/v2"
	ContextVCDM1 = "https://www.w3.org/2018/credentials/v1"
)

// StatusEntry is an allocated revocation slot (W3C Bitstring or IETF Token list).
type StatusEntry struct {
	PublishURL string // absolute, verifier-dereferenceable status list URL
	Index      int    // the allocated bit index
}

func (s *StatusEntry) bitstring() map[string]any {
	return map[string]any{
		"id":                   fmt.Sprintf("%s#%d", s.PublishURL, s.Index),
		"type":                 "BitstringStatusListEntry",
		"statusPurpose":        "revocation",
		"statusListIndex":      fmt.Sprintf("%d", s.Index), // spec requires a string
		"statusListCredential": s.PublishURL,
	}
}

// SubjectCredentialSpec describes a subject identity credential (e.g. a birth
// certificate). The stable, non-pairwise SubjectRef is the linkage anchor the
// delegation credential's onBehalfOf must match (ADR Q6).
type SubjectCredentialSpec struct {
	DataModel  string            // "w3c_vcdm_1" | "w3c_vcdm_2" (default v2)
	ContextURL string            // hosted delegated-access @context URL (for subjectRef term)
	Issuer     string            // issuer DID — the signer
	SubjectDID string            // credentialSubject.id (optional; bearer when empty)
	SubjectRef string            // stable registry id — the linkage anchor
	Type       string            // credential type, e.g. "BirthCertificate"
	Claims     map[string]string // additional subject claims
	ValidFrom  string            // RFC3339 (optional)
	ValidUntil string            // RFC3339 (optional)
	Status     *StatusEntry      // revocation slot (optional)
}

// BuildSubjectCredential constructs the JSON-LD subject identity credential body.
func BuildSubjectCredential(s SubjectCredentialSpec) map[string]any {
	cs := map[string]any{}
	if s.SubjectDID != "" {
		cs["id"] = s.SubjectDID
	}
	if s.SubjectRef != "" {
		cs["subjectRef"] = s.SubjectRef
	}
	for k, v := range s.Claims {
		cs[k] = v
	}
	typ := s.Type
	if typ == "" {
		typ = "IdentityCredential"
	}
	doc := map[string]any{
		"@context":          contextArr(s.DataModel, s.ContextURL),
		"type":              []string{"VerifiableCredential", typ},
		"credentialSubject": cs,
	}
	// Omit issuer when unset so the signing DPG injects its own signing DID
	// (avoids an issuer↔signing-key mismatch). The evaluator reads the issuer
	// back from the signed VC.
	if s.Issuer != "" {
		doc["issuer"] = s.Issuer
	}
	addValidity(doc, s.DataModel, s.ValidFrom, s.ValidUntil)
	if s.Status != nil {
		doc["credentialStatus"] = s.Status.bitstring()
	}
	return doc
}

// DelegationCredentialSpec describes the issuer-issued (Type I) delegation
// credential: the delegate is the credential subject (holder-bound → the
// invoker), acting onBehalfOf the subject. The capability is carried in
// termsOfUse (ADR D2/D3/§6).
type DelegationCredentialSpec struct {
	DataModel              string
	ContextURL             string
	Issuer                 string   // root authority + signer; becomes the capability controller
	DelegateID             string   // credentialSubject.id — the delegate (holder-bound)
	OnBehalfOf             string   // the subject's SubjectRef — the linkage anchor
	Role                   string   // e.g. "Mother" (optional)
	AllowedAction          []string // e.g. ["present", "consent:disclose"]
	ValidFrom              string
	ValidUntil             string // = transition point (e.g. age of majority)
	AllowFurtherDelegation bool
	Status                 *StatusEntry
}

// BuildDelegationCredential constructs the JSON-LD DelegatedAccessCredential body.
func BuildDelegationCredential(d DelegationCredentialSpec) map[string]any {
	cs := map[string]any{
		"onBehalfOf": map[string]any{"id": d.OnBehalfOf},
	}
	if d.DelegateID != "" {
		cs["id"] = d.DelegateID
	}
	if d.Role != "" {
		cs["role"] = d.Role
	}
	capability := map[string]any{
		"type":                   "DelegationCapability",
		"invocationTarget":       d.OnBehalfOf,
		"allowFurtherDelegation": d.AllowFurtherDelegation,
	}
	// delegate is the holder-bound credentialSubject.id; omit when unset so the
	// evaluator defaults it to the (OID4VCI-bound) credential subject.
	if d.DelegateID != "" {
		capability["delegate"] = d.DelegateID
	}
	// controller = the root authority = the issuer. Omit when unset so the
	// evaluator defaults it to the signed VC's issuer (DPG-injected DID).
	if d.Issuer != "" {
		capability["controller"] = d.Issuer
	}
	if len(d.AllowedAction) > 0 {
		capability["allowedAction"] = d.AllowedAction
	}
	if d.ValidUntil != "" {
		capability["caveat"] = []any{map[string]any{"type": "ValidWhile", "validUntil": d.ValidUntil}}
	}
	doc := map[string]any{
		"@context":          contextArr(d.DataModel, d.ContextURL),
		"type":              []string{"VerifiableCredential", "DelegatedAccessCredential"},
		"credentialSubject": cs,
		"termsOfUse":        []any{capability},
	}
	if d.Issuer != "" {
		doc["issuer"] = d.Issuer
	}
	addValidity(doc, d.DataModel, d.ValidFrom, d.ValidUntil)
	if d.Status != nil {
		doc["credentialStatus"] = d.Status.bitstring()
	}
	return doc
}

// SubjectClaims returns the FLAT claim set for an SD-JWT subject identity
// credential (no JSON-LD wrapping). The capability is absent; this is the
// identity half. Values are strings (the SD-JWT issuance path is map-based).
func SubjectClaims(s SubjectCredentialSpec) map[string]string {
	out := map[string]string{}
	if s.SubjectRef != "" {
		out["subjectRef"] = s.SubjectRef
	}
	for k, v := range s.Claims {
		out[k] = v
	}
	return out
}

// DelegationClaims returns the FLAT claim set for an SD-JWT delegation
// credential: the capability is the top-level `delegation` claim (JSON-encoded,
// per ADR §12.3), plus onBehalfOf/role for display. The evaluator parses the
// `delegation` claim (object or JSON string). Status is injected separately by
// the SD-JWT issuance path (IETF Token Status List).
func DelegationClaims(d DelegationCredentialSpec) map[string]string {
	deleg := map[string]any{
		"on_behalf_of":             d.OnBehalfOf,
		"allow_further_delegation": d.AllowFurtherDelegation,
	}
	if len(d.AllowedAction) > 0 {
		deleg["allowed_action"] = d.AllowedAction
	}
	if d.ValidUntil != "" {
		deleg["valid_until"] = d.ValidUntil
	}
	if d.DelegateID != "" {
		deleg["delegate"] = d.DelegateID
	}
	if d.Issuer != "" {
		deleg["controller"] = d.Issuer
	}
	b, _ := json.Marshal(deleg)
	out := map[string]string{
		"onBehalfOf": d.OnBehalfOf,
		"delegation": string(b),
	}
	if d.Role != "" {
		out["role"] = d.Role
	}
	return out
}

func baseContext(dataModel string) string {
	if dataModel == "w3c_vcdm_1" {
		return ContextVCDM1
	}
	return ContextVCDM2
}

func contextArr(dataModel, ctxURL string) []string {
	arr := []string{baseContext(dataModel)}
	if ctxURL != "" {
		arr = append(arr, ctxURL)
	}
	return arr
}

func addValidity(doc map[string]any, dataModel, from, until string) {
	fromKey, untilKey := "validFrom", "validUntil"
	if dataModel == "w3c_vcdm_1" {
		fromKey, untilKey = "issuanceDate", "expirationDate"
	}
	if from != "" {
		doc[fromKey] = from
	}
	if until != "" {
		doc[untilKey] = until
	}
}
