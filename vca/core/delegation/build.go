// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"encoding/json"

	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// This file is the issuance side of the evaluator. It builds the bodies
// of the subject identity credential and the delegation credential. A
// backend signs them. The shapes are what the evaluator reads back.

// Context URLs of the W3C VC Data Model.
const (
	ContextVCDM2 = "https://www.w3.org/ns/credentials/v2"
	ContextVCDM1 = "https://www.w3.org/2018/credentials/v1"
)

// StatusEntry is an allocated status list slot.
type StatusEntry struct {
	PublishURL string // status list URL a verifier can dereference
	Index      int
}

// SubjectSpec describes a subject identity credential.
type SubjectSpec struct {
	DataModel  string // vc.ModelVCDM1 or vc.ModelVCDM2 (default)
	ContextURL string // hosted delegated access context URL
	Issuer     string // issuer DID, empty lets the backend inject its own
	SubjectDID string // credentialSubject.id, optional
	SubjectRef string // stable registry id, the linkage anchor
	Type       string // credential type, default IdentityCredential
	Claims     map[string]string
	ValidFrom  string // RFC 3339, optional
	ValidUntil string // RFC 3339, optional
	Status     *StatusEntry
}

// BuildSubjectCredential builds the JSON-LD subject identity credential.
func BuildSubjectCredential(s SubjectSpec) map[string]any {
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
	if s.Issuer != "" {
		doc["issuer"] = s.Issuer
	}
	addValidity(doc, s.DataModel, s.ValidFrom, s.ValidUntil)
	if s.Status != nil {
		doc["credentialStatus"] = bitstring.Entry(s.Status.PublishURL, s.Status.Index, bitstring.Revocation)
	}
	return doc
}

// DelegationSpec describes the delegation credential: the delegate is the
// subject and acts on behalf of the principal named by OnBehalfOf.
type DelegationSpec struct {
	DataModel              string
	ContextURL             string
	Type                   string // scenario type, added next to DelegatedAccessCredential
	Issuer                 string // root authority and signer, the capability controller
	DelegateID             string // credentialSubject.id
	OnBehalfOf             string // the subject's SubjectRef
	Role                   string
	AllowedAction          []string
	ValidFrom              string
	ValidUntil             string
	AllowFurtherDelegation bool
	Status                 *StatusEntry
}

// BuildDelegationCredential builds the JSON-LD DelegatedAccessCredential.
func BuildDelegationCredential(d DelegationSpec) map[string]any {
	cs := map[string]any{"onBehalfOf": map[string]any{"id": d.OnBehalfOf}}
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
	if d.DelegateID != "" {
		capability["delegate"] = d.DelegateID
	}
	if d.Issuer != "" {
		capability["controller"] = d.Issuer
	}
	if len(d.AllowedAction) > 0 {
		capability["allowedAction"] = d.AllowedAction
	}
	if d.ValidUntil != "" {
		capability["caveat"] = []any{map[string]any{"type": "ValidWhile", "validUntil": d.ValidUntil}}
	}
	types := []string{"VerifiableCredential", "DelegatedAccessCredential"}
	if d.Type != "" && d.Type != "DelegatedAccessCredential" {
		types = append(types, d.Type)
	}
	doc := map[string]any{
		"@context":          contextArr(d.DataModel, d.ContextURL),
		"type":              types,
		"credentialSubject": cs,
		"termsOfUse":        []any{capability},
	}
	if d.Issuer != "" {
		doc["issuer"] = d.Issuer
	}
	addValidity(doc, d.DataModel, d.ValidFrom, d.ValidUntil)
	if d.Status != nil {
		doc["credentialStatus"] = bitstring.Entry(d.Status.PublishURL, d.Status.Index, bitstring.Revocation)
	}
	return doc
}

// SubjectClaims returns the flat claim set of an SD-JWT subject credential.
func SubjectClaims(s SubjectSpec) map[string]string {
	out := map[string]string{}
	if s.SubjectRef != "" {
		out["subjectRef"] = s.SubjectRef
	}
	for k, v := range s.Claims {
		out[k] = v
	}
	return out
}

// DelegationClaims returns the flat claim set of an SD-JWT delegation
// credential. The capability is the JSON encoded "delegation" claim.
func DelegationClaims(d DelegationSpec) map[string]string {
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
	// A map of strings, bools and string lists always encodes.
	b, _ := json.Marshal(deleg)
	out := map[string]string{"onBehalfOf": d.OnBehalfOf, "delegation": string(b)}
	if d.Role != "" {
		out["role"] = d.Role
	}
	return out
}

func contextArr(dataModel, ctxURL string) []string {
	arr := []string{ContextVCDM2}
	if dataModel == vc.ModelVCDM1 {
		arr[0] = ContextVCDM1
	}
	if ctxURL != "" {
		arr = append(arr, ctxURL)
	}
	return arr
}

func addValidity(doc map[string]any, dataModel, from, until string) {
	fromKey, untilKey := "validFrom", "validUntil"
	if dataModel == vc.ModelVCDM1 {
		fromKey, untilKey = "issuanceDate", "expirationDate"
	}
	if from != "" {
		doc[fromKey] = from
	}
	if until != "" {
		doc[untilKey] = until
	}
}
