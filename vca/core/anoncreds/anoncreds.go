// SPDX-License-Identifier: Apache-2.0

// Package anoncreds holds the AnonCreds proof request of a native
// presentation template (ADR-061 decision 4). A request names the
// attributes a holder reveals and the predicates a holder proves
// without the value. A schema id and a credential definition id
// restrict the credential that answers each part.
//
// The package is pure. It checks a request and writes the proof request
// of the AnonCreds specification that an agent sends to a wallet.
package anoncreds

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
)

// MaxNameLength caps the name of a request.
const MaxNameLength = 200

// DefaultName is the name of a request that names none.
const DefaultName = "Proof request"

// DefaultVersion is the version of a request that names none.
const DefaultVersion = "1.0"

// Ops are the operators of a predicate, in the order of a select.
var Ops = []string{">=", ">", "<=", "<"}

// Restriction limits the credential that answers a part of a request.
// An empty field accepts every value.
type Restriction struct {
	// SchemaID is the id of the schema on its ledger.
	SchemaID string `json:"schema_id,omitempty"`
	// CredDefID is the id of the credential definition.
	CredDefID string `json:"cred_def_id,omitempty"`
}

// empty reports whether the restriction accepts every credential.
func (r Restriction) empty() bool { return r.SchemaID == "" && r.CredDefID == "" }

// list returns the restrictions of the specification: none for an empty
// restriction.
func (r Restriction) list() []Restriction {
	if r.empty() {
		return nil
	}
	return []Restriction{r}
}

// Attribute is one group of attributes that one credential reveals.
type Attribute struct {
	// Names are the attribute names.
	Names []string `json:"names"`
	// Restriction limits the credential that answers.
	Restriction Restriction `json:"restriction"`
}

// Predicate is one comparison of a whole number attribute.
type Predicate struct {
	// Name is the attribute name.
	Name string `json:"name"`
	// Op is one of Ops.
	Op string `json:"op"`
	// Value is the number to compare with.
	Value int64 `json:"value"`
	// Restriction limits the credential that answers.
	Restriction Restriction `json:"restriction"`
}

// Request is one AnonCreds proof request.
type Request struct {
	// Name is the name the wallet shows.
	Name string `json:"name"`
	// Version is the version of the request.
	Version string `json:"version"`
	// Attributes are the attributes to reveal.
	Attributes []Attribute `json:"attributes,omitempty"`
	// Predicates are the predicates to prove.
	Predicates []Predicate `json:"predicates,omitempty"`
}

// Empty reports whether the request asks for nothing and names nothing.
func (r Request) Empty() bool {
	return r.Name == "" && r.Version == "" && len(r.Attributes) == 0 && len(r.Predicates) == 0
}

// trimmed returns the restriction without spaces around its values.
func (r Restriction) trimmed() Restriction {
	return Restriction{SchemaID: strings.TrimSpace(r.SchemaID), CredDefID: strings.TrimSpace(r.CredDefID)}
}

// Normal returns the request without spaces around its values, with the
// default name and version when it names none.
func (r Request) Normal() Request {
	out := Request{Name: strings.TrimSpace(r.Name), Version: strings.TrimSpace(r.Version)}
	if out.Name == "" {
		out.Name = DefaultName
	}
	if out.Version == "" {
		out.Version = DefaultVersion
	}
	for _, a := range r.Attributes {
		group := Attribute{Restriction: a.Restriction.trimmed()}
		for _, n := range a.Names {
			group.Names = append(group.Names, strings.TrimSpace(n))
		}
		out.Attributes = append(out.Attributes, group)
	}
	for _, p := range r.Predicates {
		out.Predicates = append(out.Predicates, Predicate{
			Name: strings.TrimSpace(p.Name), Op: strings.TrimSpace(p.Op), Value: p.Value, Restriction: p.Restriction.trimmed(),
		})
	}
	return out
}

// Check reports the first part of a normal request that a wallet would
// refuse. A name appears once in the whole request, because an agent
// refuses a name in the attributes and in the predicates.
func (r Request) Check() error {
	if len(r.Name) > MaxNameLength {
		return fmt.Errorf("anoncreds: the name is longer than %d characters", MaxNameLength)
	}
	if len(r.Attributes)+len(r.Predicates) == 0 {
		return errors.New("anoncreds: the request asks for no attribute and no predicate")
	}
	seen := map[string]bool{}
	use := func(name string) error {
		if name == "" {
			return errors.New("anoncreds: a part of the request names no attribute")
		}
		if seen[name] {
			return fmt.Errorf("anoncreds: the request names the attribute %q twice", name)
		}
		seen[name] = true
		return nil
	}
	for _, a := range r.Attributes {
		if len(a.Names) == 0 {
			return errors.New("anoncreds: an attribute group names no attribute")
		}
		for _, n := range a.Names {
			if err := use(n); err != nil {
				return err
			}
		}
	}
	for _, p := range r.Predicates {
		if err := use(p.Name); err != nil {
			return err
		}
		if !slices.Contains(Ops, p.Op) {
			return fmt.Errorf("anoncreds: the predicate on %q needs one of %s", p.Name, strings.Join(Ops, ", "))
		}
	}
	return nil
}

// specAttribute is one requested attribute of the specification.
type specAttribute struct {
	Name         string        `json:"name,omitempty"`
	Names        []string      `json:"names,omitempty"`
	Restrictions []Restriction `json:"restrictions,omitempty"`
}

// specPredicate is one requested predicate of the specification.
type specPredicate struct {
	Name         string        `json:"name"`
	Type         string        `json:"p_type"`
	Value        int64         `json:"p_value"`
	Restrictions []Restriction `json:"restrictions,omitempty"`
}

// JSON returns the proof request of the AnonCreds specification: the
// name, the version, requested_attributes with the referents attr1 and
// on, and requested_predicates with the referents pred1 and on.
func (r Request) JSON() []byte {
	attributes := map[string]specAttribute{}
	for i, a := range r.Attributes {
		item := specAttribute{Restrictions: a.Restriction.list()}
		if len(a.Names) == 1 {
			item.Name = a.Names[0]
		} else {
			item.Names = a.Names
		}
		attributes["attr"+strconv.Itoa(i+1)] = item
	}
	predicates := map[string]specPredicate{}
	for i, p := range r.Predicates {
		predicates["pred"+strconv.Itoa(i+1)] = specPredicate{Name: p.Name, Type: p.Op, Value: p.Value, Restrictions: p.Restriction.list()}
	}
	// Maps of plain structs always encode.
	return anyval.Must(json.Marshal(map[string]any{
		"name": r.Name, "version": r.Version, "requested_attributes": attributes, "requested_predicates": predicates,
	}))
}

// Names returns every attribute name of the request in order: the
// attributes, then the predicates.
func (r Request) Names() []string {
	var out []string
	for _, a := range r.Attributes {
		out = append(out, a.Names...)
	}
	for _, p := range r.Predicates {
		out = append(out, p.Name)
	}
	return out
}

// Schemas returns the schema ids the request names, each once, in order.
func (r Request) Schemas() []string {
	var out []string
	add := func(id string) {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, a := range r.Attributes {
		add(a.Restriction.SchemaID)
	}
	for _, p := range r.Predicates {
		add(p.Restriction.SchemaID)
	}
	return out
}

// restrictionOf reads a proto restriction.
func restrictionOf(m *discoveryv1.AnonCredsRequest_Restriction) Restriction {
	return Restriction{SchemaID: m.GetSchemaId(), CredDefID: m.GetCredDefId()}
}

// toProto returns the proto restriction.
func (r Restriction) toProto() *discoveryv1.AnonCredsRequest_Restriction {
	return &discoveryv1.AnonCredsRequest_Restriction{SchemaId: r.SchemaID, CredDefId: r.CredDefID}
}

// FromProto reads the request of a template message. A nil message is
// an empty request.
func FromProto(m *discoveryv1.AnonCredsRequest) Request {
	out := Request{Name: m.GetName(), Version: m.GetVersion()}
	for _, a := range m.GetAttributes() {
		out.Attributes = append(out.Attributes, Attribute{Names: a.GetNames(), Restriction: restrictionOf(a.GetRestriction())})
	}
	for _, p := range m.GetPredicates() {
		out.Predicates = append(out.Predicates, Predicate{Name: p.GetName(), Op: p.GetOp(), Value: p.GetValue(), Restriction: restrictionOf(p.GetRestriction())})
	}
	return out
}

// ToProto returns the proto message of the request.
func (r Request) ToProto() *discoveryv1.AnonCredsRequest {
	out := &discoveryv1.AnonCredsRequest{Name: r.Name, Version: r.Version}
	for _, a := range r.Attributes {
		out.Attributes = append(out.Attributes, &discoveryv1.AnonCredsRequest_Attribute{Names: a.Names, Restriction: a.Restriction.toProto()})
	}
	for _, p := range r.Predicates {
		out.Predicates = append(out.Predicates, &discoveryv1.AnonCredsRequest_Predicate{
			Name: p.Name, Op: p.Op, Value: p.Value, Restriction: p.Restriction.toProto(),
		})
	}
	return out
}
