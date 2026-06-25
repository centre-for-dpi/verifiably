package delegation

import "fmt"

// This file is the issuance-side counterpart to the evaluator: it constructs the
// two credentials of a delegated-access relation as W3C VCDM 2.0 JSON-LD bodies
// (ADR §6) — a subject identity credential and an issuer-signed delegation
// credential carrying the capability in termsOfUse. The bodies are handed to a
// DPG issuer adapter to SIGN (the adapter never signs here — invariant I1). The
// shapes are exactly what the evaluator (via internal/vp normalization) reads
// back at verification, so issuance and verification share one contract.

// ContextVCDM2 is the W3C VC Data Model 2.0 base context.
const ContextVCDM2 = "https://www.w3.org/ns/credentials/v2"

// StatusEntry is an allocated W3C Bitstring Status List 2023 revocation slot.
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

// BuildSubjectCredential constructs the VCDM 2.0 subject identity credential body.
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
		"@context":          contextArr(s.ContextURL),
		"type":              []string{"VerifiableCredential", typ},
		"issuer":            s.Issuer,
		"credentialSubject": cs,
	}
	addValidity(doc, s.ValidFrom, s.ValidUntil)
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

// BuildDelegationCredential constructs the VCDM 2.0 DelegatedAccessCredential body.
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
		"controller":             d.Issuer,
		"invocationTarget":       d.OnBehalfOf,
		"delegate":               d.DelegateID,
		"allowFurtherDelegation": d.AllowFurtherDelegation,
	}
	if len(d.AllowedAction) > 0 {
		capability["allowedAction"] = d.AllowedAction
	}
	if d.ValidUntil != "" {
		capability["caveat"] = []any{map[string]any{"type": "ValidWhile", "validUntil": d.ValidUntil}}
	}
	doc := map[string]any{
		"@context":          contextArr(d.ContextURL),
		"type":              []string{"VerifiableCredential", "DelegatedAccessCredential"},
		"issuer":            d.Issuer,
		"credentialSubject": cs,
		"termsOfUse":        []any{capability},
	}
	addValidity(doc, d.ValidFrom, d.ValidUntil)
	if d.Status != nil {
		doc["credentialStatus"] = d.Status.bitstring()
	}
	return doc
}

func contextArr(ctxURL string) []string {
	arr := []string{ContextVCDM2}
	if ctxURL != "" {
		arr = append(arr, ctxURL)
	}
	return arr
}

func addValidity(doc map[string]any, from, until string) {
	if from != "" {
		doc["validFrom"] = from
	}
	if until != "" {
		doc["validUntil"] = until
	}
}
