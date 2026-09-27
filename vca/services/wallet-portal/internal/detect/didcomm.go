// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
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
	// CarriesRequest is true when the invitation carries a proof request
	// (Aries RFC 0454).
	CarriesRequest bool
	// Name is the name of the credential or of the proof request, when
	// the message names one.
	Name string
	// Offered are the values of an offer.
	Offered []NamedValue
	// Requested is what a proof request asks for, as plain text.
	Requested []string
}

// NamedValue is one name and its value.
type NamedValue struct {
	// Name is the attribute name.
	Name string
	// Value is the value as text.
	Value string
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
		inv := DidcommInvitation{URI: text, Label: str(doc["label"])}
		readMessages(doc, &inv)
		return Result{Kind: Invitation, Invitation: inv}, true
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

// attachmentData returns the JSON of an attachment: its json member, or
// its base64 member decoded.
func attachmentData(item any) (map[string]any, bool) {
	data := obj(obj(item)["data"])
	if doc := obj(data["json"]); doc != nil {
		return doc, true
	}
	raw, err := base64.StdEncoding.DecodeString(str(data["base64"]))
	if err != nil {
		return nil, false
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	return doc, true
}

// readMessages reads the messages that the attachments of an out of
// band invitation carry: a credential offer (Aries RFC 0453) or a proof
// request (Aries RFC 0454).
func readMessages(doc map[string]any, inv *DidcommInvitation) {
	attachments, ok := doc["requests~attach"].([]any)
	if !ok {
		return
	}
	for _, item := range attachments {
		message, ok := attachmentData(item)
		if !ok {
			continue
		}
		typ := str(message["@type"])
		switch {
		case strings.Contains(typ, "/issue-credential/") && strings.Contains(typ, "offer-credential"):
			inv.CarriesOffer = true
			readOffer(message, inv)
		case strings.Contains(typ, "/present-proof/") && strings.Contains(typ, "request-presentation"):
			inv.CarriesRequest = true
			readRequest(message, inv)
		}
	}
}

// readOffer reads the preview of an offer and the format it carries:
// the schema of an AnonCreds offer, or the unsigned credential of a
// JSON-LD offer.
func readOffer(message map[string]any, inv *DidcommInvitation) {
	if list, ok := obj(message["credential_preview"])["attributes"].([]any); ok {
		for _, a := range list {
			inv.Offered = append(inv.Offered, NamedValue{Name: str(obj(a)["name"]), Value: str(obj(a)["value"])})
		}
	}
	offers := anyval.As[[]any](message["offers~attach"])
	for _, item := range offers {
		offer, ok := attachmentData(item)
		if !ok {
			continue
		}
		if schema := str(offer["schema_id"]); schema != "" {
			inv.Name = schemaName(schema)
		}
		credential := obj(offer["credential"])
		if credential == nil {
			continue
		}
		if types, ok := credential["type"].([]any); ok && len(types) > 0 {
			inv.Name = str(types[len(types)-1])
		}
		if len(inv.Offered) == 0 {
			subject := obj(credential["credentialSubject"])
			for _, name := range sortedKeys(subject) {
				if name != "id" {
					inv.Offered = append(inv.Offered, NamedValue{Name: name, Value: text(subject[name])})
				}
			}
		}
	}
}

// readRequest reads what a proof request asks for: the attributes and
// the predicates of an AnonCreds request, or the fields of a DIF PE
// request.
func readRequest(message map[string]any, inv *DidcommInvitation) {
	requests := anyval.As[[]any](message["request_presentations~attach"])
	for _, item := range requests {
		req, ok := attachmentData(item)
		if !ok {
			continue
		}
		if definition := obj(req["presentation_definition"]); definition != nil {
			inv.Name = str(definition["name"])
			inv.Requested = append(inv.Requested, peFields(definition)...)
			continue
		}
		inv.Name = str(req["name"])
		attributes := obj(req["requested_attributes"])
		for _, ref := range sortedKeys(attributes) {
			a := obj(attributes[ref])
			if name := str(a["name"]); name != "" {
				inv.Requested = append(inv.Requested, name)
			}
			names := anyval.As[[]any](a["names"])
			for _, n := range names {
				inv.Requested = append(inv.Requested, str(n))
			}
		}
		predicates := obj(req["requested_predicates"])
		for _, ref := range sortedKeys(predicates) {
			p := obj(predicates[ref])
			inv.Requested = append(inv.Requested, str(p["name"])+" "+str(p["p_type"])+" "+text(p["p_value"]))
		}
	}
}

// peFields returns the claim name of each field of a presentation
// definition, or the name of a descriptor without fields.
func peFields(definition map[string]any) []string {
	var out []string
	descriptors := anyval.As[[]any](definition["input_descriptors"])
	for _, d := range descriptors {
		fields := anyval.As[[]any](obj(obj(d)["constraints"])["fields"])
		if len(fields) == 0 {
			out = append(out, str(obj(d)["name"]))
			continue
		}
		for _, f := range fields {
			if paths, ok := obj(f)["path"].([]any); ok && len(paths) > 0 {
				path := str(paths[0])
				out = append(out, path[strings.LastIndexAny(path, ".'\"[")+1:])
			}
		}
	}
	return out
}

// schemaName returns the name part of an AnonCreds schema id.
func schemaName(id string) string {
	if i := strings.Index(id, "/SCHEMA/"); i >= 0 {
		return strings.Split(id[i+len("/SCHEMA/"):], "/")[0]
	}
	if parts := strings.Split(id, ":"); len(parts) == 4 {
		return parts[2]
	}
	return id
}

// sortedKeys returns the keys of an object in order.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// text returns a JSON value as text.
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
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
