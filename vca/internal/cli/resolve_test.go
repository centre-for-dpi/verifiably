// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	s := Setting{Env: "VCA_X", Default: "from-default"}
	src := Sources{
		Flags:   map[string]string{"VCA_X": "from-flag"},
		Env:     func(string) string { return "from-env" },
		File:    map[string]string{"VCA_X": "from-file"},
		Answers: map[string]string{"VCA_X": "from-answer"},
	}
	steps := []struct {
		drop   func(*Sources)
		value  string
		origin Origin
	}{
		{func(*Sources) {}, "from-flag", OriginFlag},
		{func(s *Sources) { s.Flags = nil }, "from-env", OriginEnv},
		{func(s *Sources) { s.Env = nil }, "from-file", OriginFile},
		{func(s *Sources) { s.File = nil }, "from-answer", OriginAnswer},
		{func(s *Sources) { s.Answers = nil }, "from-default", OriginDefault},
	}
	for _, step := range steps {
		step.drop(&src)
		got, origin := Resolve(s, src)
		if got != step.value || origin != step.origin {
			t.Errorf("got %q from %v, want %q from %v", got, origin, step.value, step.origin)
		}
	}
	s.Default = ""
	if got, origin := Resolve(s, src); got != "" || origin != OriginNone {
		t.Errorf("got %q from %v, want no value", got, origin)
	}
}

func TestResolveSkipsBlankValues(t *testing.T) {
	s := Setting{Env: "VCA_X", Default: "d"}
	src := Sources{
		Flags: map[string]string{"VCA_X": "  "},
		Env:   func(string) string { return "\t" },
		File:  map[string]string{"VCA_X": ""},
	}
	got, origin := Resolve(s, src)
	if got != "d" || origin != OriginDefault {
		t.Errorf("got %q from %v", got, origin)
	}
}

func TestResolveKeepsExistingSecret(t *testing.T) {
	secret := Setting{Env: "VCA_S", Secret: true}
	plain := Setting{Env: "VCA_P"}
	src := Sources{Existing: map[string]string{"VCA_S": "kept", "VCA_P": "ignored"}}
	if got, origin := Resolve(secret, src); got != "kept" || origin != OriginExisting {
		t.Errorf("secret: got %q from %v", got, origin)
	}
	if got, _ := Resolve(plain, src); got != "" {
		t.Errorf("a plain setting read the existing file: %q", got)
	}
}

func TestOriginString(t *testing.T) {
	want := map[Origin]string{
		OriginFlag: "flag", OriginEnv: "environment", OriginFile: "env file",
		OriginAnswer: "answer", OriginExisting: "existing file",
		OriginDefault: "default", OriginNone: "missing",
	}
	for o, name := range want {
		if o.String() != name {
			t.Errorf("Origin(%d) = %q, want %q", o, o.String(), name)
		}
	}
}

func TestResolveAllAndValues(t *testing.T) {
	settings := []Setting{
		{Env: "VCA_A", Default: "a"},
		{Env: "VCA_B", Required: true},
		{Env: "VCA_C", Required: true},
	}
	list := ResolveAll(settings, Sources{Flags: map[string]string{"VCA_B": "b"}})
	if len(list) != 3 {
		t.Fatalf("got %d resolutions", len(list))
	}
	values := Values(list)
	if values["VCA_A"] != "a" || values["VCA_B"] != "b" {
		t.Errorf("values = %v", values)
	}
	if _, ok := values["VCA_C"]; ok {
		t.Error("an empty value reached the map")
	}
	missing := Missing(list)
	if len(missing) != 1 || missing[0].Env != "VCA_C" {
		t.Errorf("missing = %v", missing)
	}
}

func TestMissingNamesEveryValue(t *testing.T) {
	settings := []Setting{
		{Env: "VCA_A", Required: true},
		{Env: "VCA_B", Required: true},
		{Env: "VCA_C"},
	}
	missing := Missing(ResolveAll(settings, Sources{}))
	var names []string
	for _, s := range missing {
		names = append(names, s.Env)
	}
	if strings.Join(names, ",") != "VCA_A,VCA_B" {
		t.Errorf("missing = %v", names)
	}
}
