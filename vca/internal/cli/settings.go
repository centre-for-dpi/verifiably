// SPDX-License-Identifier: Apache-2.0

// Package cli holds the pure logic of the vca command line tool.
// The commands under cmd/vca are thin wrappers over this package
// (ADR-007, ADR-008, ADR-009).
//
// The setup questions come from one place only: the setting option on
// each field of the vca.config.v1.Config message. Settings walks the
// generated descriptor and returns one Setting per leaf field. Nothing
// in this package holds a hard coded question (ADR-007 decision 6).
package cli

import (
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Kind is the value shape of one setting.
type Kind int

const (
	// KindString is a free text value.
	KindString Kind = iota
	// KindInt is a whole number value.
	KindInt
	// KindList is a comma separated list of text values.
	KindList
	// KindEnum is one name out of a closed set.
	KindEnum
	// KindSecretRef points at a generated or supplied secret.
	KindSecretRef
	// KindPortMap is the port of each remaining service.
	// The CLI assigns these ports, so it asks no question.
	KindPortMap
)

// Setting is one setup variable of the Config message.
type Setting struct {
	// Path is the dotted field path, for example secrets.session_key.
	Path string
	// Env is the environment variable name.
	Env string
	// Description is the one sentence help text.
	Description string
	// Default is the value the CLI offers. Empty means no default.
	Default string
	// Secret reports whether the value must stay out of the terminal.
	Secret bool
	// Required reports whether a missing value is an error.
	Required bool
	// Validation is the rule in plain words.
	Validation string
	// Roles lists the roles that need the setting. Empty means every role.
	Roles []commonv1.Role
	// Dpgs lists the DPGs that need the setting. Empty means every DPG.
	Dpgs []configv1.Dpg
	// Kind is the value shape.
	Kind Kind
	// Choices lists the valid names when Kind is KindEnum.
	Choices []string
}

// Asks reports whether the CLI asks a question for the setting.
// The role and the DPG fields come from the flags, and the CLI assigns
// the service port map, so none of those three needs a question.
func (s Setting) Asks() bool {
	if s.Kind == KindPortMap {
		return false
	}
	return s.Path != "role" && s.Path != "dpg"
}

// Settings returns every leaf setting of the Config message in field order.
func Settings() []Setting {
	var out []Setting
	walk((&configv1.Config{}).ProtoReflect().Descriptor(), "", nil, nil, &out)
	return out
}

// walk appends one Setting per leaf field of md. The prefix is the dotted
// path of the parent. A child with no roles or DPGs inherits the ones of
// its parent, so a nested field of an issuer only message stays issuer only.
func walk(md protoreflect.MessageDescriptor, prefix string, roles []commonv1.Role, dpgs []configv1.Dpg, out *[]Setting) {
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		opt, _ := proto.GetExtension(fd.Options(), configv1.E_Setting).(*configv1.Setting)
		if opt == nil {
			continue
		}
		childRoles := roles
		if len(opt.GetRoles()) > 0 {
			childRoles = opt.GetRoles()
		}
		childDpgs := dpgs
		if len(opt.GetDpgs()) > 0 {
			childDpgs = opt.GetDpgs()
		}
		path := fd.TextName()
		if prefix != "" {
			path = prefix + "." + path
		}
		if nested, ok := nestedMessage(fd); ok {
			walk(nested, path, childRoles, childDpgs, out)
			continue
		}
		*out = append(*out, Setting{
			Path:        path,
			Env:         opt.GetEnv(),
			Description: opt.GetDescription(),
			Default:     opt.GetDefault(),
			Secret:      opt.GetSecret(),
			Required:    opt.GetRequired(),
			Validation:  opt.GetValidation(),
			Roles:       childRoles,
			Dpgs:        childDpgs,
			Kind:        kindOf(fd),
			Choices:     choicesOf(fd),
		})
	}
}

// nestedMessage returns the message to walk into, and true when the field
// groups other settings. A SecretRef is a leaf, not a group.
func nestedMessage(fd protoreflect.FieldDescriptor) (protoreflect.MessageDescriptor, bool) {
	if fd.Kind() != protoreflect.MessageKind || fd.IsMap() {
		return nil, false
	}
	md := fd.Message()
	if md.FullName() == "vca.common.v1.SecretRef" {
		return nil, false
	}
	return md, true
}

// kindOf maps a field descriptor to a value shape.
func kindOf(fd protoreflect.FieldDescriptor) Kind {
	switch {
	case fd.IsMap():
		return KindPortMap
	case fd.IsList():
		return KindList
	case fd.Kind() == protoreflect.MessageKind:
		return KindSecretRef
	case fd.Kind() == protoreflect.EnumKind:
		return KindEnum
	case fd.Kind() == protoreflect.Int32Kind || fd.Kind() == protoreflect.Int64Kind:
		return KindInt
	default:
		return KindString
	}
}

// choicesOf returns the short lower case names of an enum field.
// The zero value, which every proto3 enum reserves for "unspecified",
// is not a choice.
func choicesOf(fd protoreflect.FieldDescriptor) []string {
	if fd.Kind() != protoreflect.EnumKind {
		return nil
	}
	values := fd.Enum().Values()
	out := make([]string, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		v := values.Get(i)
		if v.Number() == 0 {
			continue
		}
		out = append(out, ShortName(string(v.Name())))
	}
	return out
}

// ShortName turns an enum value name into the name the CLI uses.
// ROLE_ISSUER becomes issuer. DPG_WALTID becomes waltid.
func ShortName(name string) string {
	if i := strings.Index(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}

// Filter returns the settings that the role and the DPG need,
// in the order Settings returns them (ADR-007 decision 2).
func Filter(all []Setting, role commonv1.Role, dpg configv1.Dpg) []Setting {
	out := make([]Setting, 0, len(all))
	for _, s := range all {
		if !wantsRole(s.Roles, role) || !wantsDpg(s.Dpgs, dpg) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func wantsRole(list []commonv1.Role, role commonv1.Role) bool {
	if len(list) == 0 {
		return true
	}
	for _, r := range list {
		if r == role {
			return true
		}
	}
	return false
}

func wantsDpg(list []configv1.Dpg, dpg configv1.Dpg) bool {
	if len(list) == 0 {
		return true
	}
	for _, d := range list {
		if d == dpg {
			return true
		}
	}
	return false
}

// Roles lists the roles the CLI accepts, in enum order.
func Roles() []commonv1.Role {
	return []commonv1.Role{
		commonv1.Role_ROLE_ISSUER,
		commonv1.Role_ROLE_HOLDER,
		commonv1.Role_ROLE_VERIFIER,
		commonv1.Role_ROLE_ADMIN,
	}
}

// Dpgs lists the DPGs the CLI accepts, in enum order.
func Dpgs() []configv1.Dpg {
	return []configv1.Dpg{
		configv1.Dpg_DPG_WALTID,
		configv1.Dpg_DPG_INJI,
		configv1.Dpg_DPG_CREDEBL,
	}
}

// ParseRole turns a CLI name into a role. It reports an error for an
// unknown name and lists the names it accepts.
func ParseRole(name string) (commonv1.Role, error) {
	for _, r := range Roles() {
		if ShortName(r.String()) == name {
			return r, nil
		}
	}
	return commonv1.Role_ROLE_UNSPECIFIED, &InvalidChoiceError{Field: "role", Value: name, Choices: RoleNames()}
}

// ParseDpg turns a CLI name into a DPG. It reports an error for an
// unknown name and lists the names it accepts.
func ParseDpg(name string) (configv1.Dpg, error) {
	for _, d := range Dpgs() {
		if ShortName(d.String()) == name {
			return d, nil
		}
	}
	return configv1.Dpg_DPG_UNSPECIFIED, &InvalidChoiceError{Field: "dpg", Value: name, Choices: DpgNames()}
}

// RoleNames lists the role names the CLI accepts.
func RoleNames() []string {
	out := make([]string, 0, 4)
	for _, r := range Roles() {
		out = append(out, ShortName(r.String()))
	}
	return out
}

// DpgNames lists the DPG names the CLI accepts.
func DpgNames() []string {
	out := make([]string, 0, 3)
	for _, d := range Dpgs() {
		out = append(out, ShortName(d.String()))
	}
	return out
}

// Pair names one role and DPG combination.
type Pair struct {
	Role commonv1.Role
	Dpg  configv1.Dpg
}

// Name is the directory and compose profile name, for example issuer-waltid.
func (p Pair) Name() string {
	return ShortName(p.Role.String()) + "-" + ShortName(p.Dpg.String())
}

// AllPairs lists every role and DPG combination in a stable order.
// The admin role runs with each DPG as well, so an operator can put the
// admin portal next to any stack (ADR-007 decision 7).
func AllPairs() []Pair {
	var out []Pair
	for _, r := range Roles() {
		for _, d := range Dpgs() {
			out = append(out, Pair{Role: r, Dpg: d})
		}
	}
	return out
}

// InvalidChoiceError reports a value outside a closed set.
type InvalidChoiceError struct {
	Field   string
	Value   string
	Choices []string
}

func (e *InvalidChoiceError) Error() string {
	return e.Field + " " + quote(e.Value) + " is not valid; use one of " + strings.Join(e.Choices, ", ")
}

func quote(s string) string { return "\"" + s + "\"" }
