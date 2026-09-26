// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

// A DIDComm invitation (P6-C3). An issuer that issues over DIDComm
// shows an out of band invitation (Aries RFC 0434) in the query
// parameter oob, or a connection invitation (Aries RFC 0160) in c_i. The
// value is base64url of the invitation JSON. The attachments of an out
// of band invitation can carry a credential offer (Aries RFC 0453).

// SchemeDidcomm is the URI scheme that a DIDComm wallet opens.
const SchemeDidcomm = "didcomm"

// invitationParams are the query parameters that hold an invitation.
var invitationParams = []string{"oob", "c_i", "d_m"}

// DidcommInvitation is what the wallet reads in an invitation.
type DidcommInvitation struct {
	// URI is the invitation as the holder scanned it.
	URI string
	// Label is the name the issuer gave its agent.
	Label string
	// CarriesOffer is true when the invitation carries a credential
	// offer.
	CarriesOffer bool
}

// invitationOf reads a DIDComm invitation URI.
func invitationOf(text string) (Result, bool) {
	u, err := url.Parse(text)
	if err != nil {
		return Result{}, false
	}
	q := u.Query()
	for _, name := range invitationParams {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		doc, ok := decodeInvitation(raw)
		if !ok {
			continue
		}
		return Result{Kind: Invitation, Invitation: DidcommInvitation{
			URI: text, Label: str(doc["label"]), CarriesOffer: carriesOffer(doc),
		}}, true
	}
	return Result{}, false
}

// decodeInvitation reads base64url JSON, padded or not, and checks that
// it names a DIDComm invitation type.
func decodeInvitation(raw string) (map[string]any, bool) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		return nil, false
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil, false
	}
	typ := str(doc["@type"])
	if !strings.Contains(typ, "/out-of-band/") && !strings.Contains(typ, "/connections/") {
		return nil, false
	}
	return doc, true
}

// carriesOffer reports whether an attachment of an out of band
// invitation is a credential offer.
func carriesOffer(doc map[string]any) bool {
	attachments, ok := doc["requests~attach"].([]any)
	if !ok {
		return false
	}
	for _, item := range attachments {
		encoded := str(obj(obj(item)["data"])["base64"])
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		var message map[string]any
		if json.Unmarshal(raw, &message) != nil {
			continue
		}
		if typ := str(message["@type"]); strings.Contains(typ, "/issue-credential/") && strings.Contains(typ, "offer-credential") {
			return true
		}
	}
	return false
}

// str returns a JSON string, or empty for any other value.
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// obj returns a JSON object, or nil for any other value.
func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}
