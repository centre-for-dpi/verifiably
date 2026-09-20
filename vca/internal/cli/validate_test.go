// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestValidateRequired(t *testing.T) {
	s := Setting{Env: "VCA_X", Required: true}
	err := Validate(s, "  ")
	if err == nil {
		t.Fatal("an empty required value passed")
	}
	if !strings.Contains(err.Error(), "VCA_X") {
		t.Errorf("error does not name the variable: %v", err)
	}
	if Validate(Setting{Env: "VCA_X"}, "") != nil {
		t.Error("an empty optional value failed")
	}
}

func TestValidatePublicURL(t *testing.T) {
	s := find(t, Settings(), "public_url")
	good := []string{"https://issuer.example", "https://issuer.example:8443"}
	bad := []string{"http://issuer.example", "https://issuer.example/", "https://issuer.example/api", "not a url", "https://"}
	for _, v := range good {
		if err := Validate(s, v); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range bad {
		if Validate(s, v) == nil {
			t.Errorf("Validate(%q) passed", v)
		}
	}
}

func TestValidateInternalURL(t *testing.T) {
	s := find(t, Settings(), "internal_url")
	for _, v := range []string{"http://issuer:8080", "https://issuer/api"} {
		if err := Validate(s, v); err != nil {
			t.Errorf("Validate(%q) = %v", v, err)
		}
	}
	for _, v := range []string{"ftp://issuer", "issuer:8080"} {
		if Validate(s, v) == nil {
			t.Errorf("Validate(%q) passed", v)
		}
	}
}

func TestValidatePrefixRules(t *testing.T) {
	db := find(t, Settings(), "database_url")
	if err := Validate(db, "postgres://u:p@h/d"); err != nil {
		t.Errorf("postgres URL failed: %v", err)
	}
	if err := Validate(db, "postgresql://u:p@h/d"); err != nil {
		t.Errorf("postgresql URL failed: %v", err)
	}
	if Validate(db, "mysql://h/d") == nil {
		t.Error("a MySQL URL passed")
	}
	redis := find(t, Settings(), "redis_url")
	if err := Validate(redis, "rediss://h:6379"); err != nil {
		t.Errorf("rediss URL failed: %v", err)
	}
	if Validate(redis, "http://h:6379") == nil {
		t.Error("an HTTP URL passed as Redis")
	}
}

func TestValidateOneOf(t *testing.T) {
	level := find(t, Settings(), "log_level")
	for _, v := range []string{"debug", "info", "warn", "error"} {
		if err := Validate(level, v); err != nil {
			t.Errorf("Validate(%q) = %v", v, err)
		}
	}
	err := Validate(level, "trace")
	if err == nil {
		t.Fatal("an unknown log level passed")
	}
	if !strings.Contains(err.Error(), "warn") {
		t.Errorf("error does not list the choices: %v", err)
	}
}

func TestValidateEnum(t *testing.T) {
	role := find(t, Settings(), "role")
	if err := Validate(role, "issuer"); err != nil {
		t.Errorf("issuer failed: %v", err)
	}
	if Validate(role, "mayor") == nil {
		t.Error("an unknown role passed")
	}
}

func TestValidateList(t *testing.T) {
	methods := find(t, Settings(), "trust_methods")
	if err := Validate(methods, "etsi,dedi"); err != nil {
		t.Errorf("etsi,dedi failed: %v", err)
	}
	if err := Validate(methods, " etsi , dedi "); err != nil {
		t.Errorf("spaced list failed: %v", err)
	}
	if Validate(methods, "etsi,other") == nil {
		t.Error("an unknown method passed")
	}
}

func TestValidatePortRange(t *testing.T) {
	portal := find(t, Settings(), "ports.portal")
	if err := Validate(portal, "8080"); err != nil {
		t.Errorf("8080 failed: %v", err)
	}
	for _, v := range []string{"80", "70000", "eighty"} {
		if Validate(portal, v) == nil {
			t.Errorf("Validate(%q) passed", v)
		}
	}
}

func TestValidateHostPortOrURL(t *testing.T) {
	otlp := find(t, Settings(), "otlp_endpoint")
	for _, v := range []string{"collector:4317", "http://collector:4318"} {
		if err := Validate(otlp, v); err != nil {
			t.Errorf("Validate(%q) = %v", v, err)
		}
	}
	for _, v := range []string{"collector", "collector:grpc", "http://"} {
		if Validate(otlp, v) == nil {
			t.Errorf("Validate(%q) passed", v)
		}
	}
	if err := Validate(otlp, ""); err != nil {
		t.Errorf("an empty OTLP endpoint failed: %v", err)
	}
}

func TestValidateFreeText(t *testing.T) {
	// A setting with no machine rule accepts any text.
	s := find(t, Settings(), "oidc.roles_claim_path")
	if err := Validate(s, "resource_access.vca.roles"); err != nil {
		t.Errorf("free text failed: %v", err)
	}
}

func TestValidateWholeNumberKind(t *testing.T) {
	s := Setting{Env: "VCA_N", Kind: KindInt}
	if Validate(s, "12") != nil {
		t.Error("a number failed")
	}
	if Validate(s, "twelve") == nil {
		t.Error("a word passed as a number")
	}
}

func TestValidateAllListsEveryProblem(t *testing.T) {
	all := Settings()
	settings := []Setting{
		find(t, all, "public_url"),
		find(t, all, "log_level"),
		find(t, all, "database_url"),
	}
	problems := ValidateAll(settings, map[string]string{
		"VCA_PUBLIC_URL":   "http://x",
		"VCA_LOG_LEVEL":    "trace",
		"VCA_DATABASE_URL": "mysql://x/y",
	})
	if len(problems) != 3 {
		t.Fatalf("got %d problems, want 3: %v", len(problems), problems)
	}
	if !strings.Contains(problems[2].Error(), "VCA_DATABASE_URL") {
		t.Errorf("third problem = %v", problems[2])
	}
	if ValidateAll(settings, map[string]string{
		"VCA_PUBLIC_URL":   "https://x.example",
		"VCA_LOG_LEVEL":    "info",
		"VCA_DATABASE_URL": "postgres://x/y",
	}) != nil {
		t.Error("a good set reported a problem")
	}
}

func TestSplitNames(t *testing.T) {
	got := splitNames("etsi and dedi")
	if strings.Join(got, "|") != "etsi|dedi" {
		t.Errorf("got %v", got)
	}
	got = splitNames("a, b , c,")
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("got %v", got)
	}
}
