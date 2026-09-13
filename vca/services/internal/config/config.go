// SPDX-License-Identifier: Apache-2.0

// Package config reads service settings from environment variables into
// a tagged struct. Every service shares it (ADR-005, ADR-028).
//
// A field carries these tags:
//
//	env:"NAME"       the variable name without the service prefix (required)
//	default:"value"  the value when the variable is empty
//	required:"true"  the variable must be set and not empty
//	secret:"true"    the value never appears in logs or in Describe
//
// Supported field types: string, []string (comma separated), bool, int,
// int64, and time.Duration. Load reports every missing or invalid
// variable at once, so an operator fixes the deployment in one pass.
//
// The package is pure. Callers pass the lookup function, for example
// os.Getenv, so tests need no process state.
package config

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Variable describes one setting of a service.
type Variable struct {
	// Name is the full variable name with the prefix.
	Name string
	// Default is the value when the variable is empty.
	Default string
	// Required reports whether the variable must be set.
	Required bool
	// Secret reports whether the value must stay out of logs.
	Secret bool
}

// Load fills dst, a pointer to a struct, from getenv with prefix.
// It returns one error that names every problem.
func Load(prefix string, dst any, getenv func(string) string) error {
	fields, err := describe(prefix, dst)
	if err != nil {
		return err
	}
	var problems []string
	v := reflect.ValueOf(dst).Elem()
	for _, f := range fields {
		raw := strings.TrimSpace(getenv(f.variable.Name))
		if raw == "" {
			if f.variable.Required {
				problems = append(problems, fmt.Sprintf("%s is required", f.variable.Name))
				continue
			}
			raw = f.variable.Default
		}
		if err := set(v.Field(f.index), raw); err != nil {
			problems = append(problems, fmt.Sprintf("%s %s", f.variable.Name, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Describe lists the variables of dst in field order. Documentation and
// start logs use it.
func Describe(prefix string, dst any) ([]Variable, error) {
	fields, err := describe(prefix, dst)
	if err != nil {
		return nil, err
	}
	out := make([]Variable, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.variable)
	}
	return out, nil
}

// Redact returns the loaded values of dst by variable name with secrets
// replaced by "[redacted]". Start logs use it.
func Redact(prefix string, dst any) (map[string]string, error) {
	fields, err := describe(prefix, dst)
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(dst).Elem()
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		if f.variable.Secret {
			out[f.variable.Name] = "[redacted]"
			continue
		}
		out[f.variable.Name] = format(v.Field(f.index))
	}
	return out, nil
}

type field struct {
	index    int
	variable Variable
}

func describe(prefix string, dst any) ([]field, error) {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return nil, errors.New("config: dst must be a non-nil pointer to a struct")
	}
	rt := rv.Elem().Type()
	var out []field
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		name, ok := sf.Tag.Lookup("env")
		if !ok {
			continue
		}
		if name == "" || !sf.IsExported() {
			return nil, fmt.Errorf("config: field %s.%s needs a non-empty env tag on an exported field", rt.Name(), sf.Name)
		}
		if !supported(sf.Type) {
			return nil, fmt.Errorf("config: field %s.%s has unsupported type %s", rt.Name(), sf.Name, sf.Type)
		}
		out = append(out, field{index: i, variable: Variable{
			Name:     prefix + name,
			Default:  sf.Tag.Get("default"),
			Required: sf.Tag.Get("required") == "true",
			Secret:   sf.Tag.Get("secret") == "true",
		}})
	}
	return out, nil
}

var durationType = reflect.TypeOf(time.Duration(0))

func supported(t reflect.Type) bool {
	if t == durationType {
		return true
	}
	switch t.Kind() {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int64:
		return true
	case reflect.Slice:
		return t.Elem().Kind() == reflect.String
	}
	return false
}

func set(v reflect.Value, raw string) error {
	if v.Type() == durationType {
		if raw == "" {
			v.SetInt(0)
			return nil
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("must be a duration such as 30s or 24h, got %q", raw)
		}
		v.SetInt(int64(d))
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(raw)
	case reflect.Bool:
		if raw == "" {
			v.SetBool(false)
			return nil
		}
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("must be true or false, got %q", raw)
		}
		v.SetBool(b)
	case reflect.Int, reflect.Int64:
		if raw == "" {
			v.SetInt(0)
			return nil
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("must be a whole number, got %q", raw)
		}
		v.SetInt(n)
	default:
		v.Set(reflect.ValueOf(splitList(raw)))
	}
	return nil
}

// splitList splits a comma separated value. It drops empty items.
func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func format(v reflect.Value) string {
	if v.Type() == durationType {
		return time.Duration(v.Int()).String()
	}
	switch v.Kind() {
	case reflect.Slice:
		return strings.Join(v.Interface().([]string), ",")
	default:
		return fmt.Sprint(v.Interface())
	}
}
