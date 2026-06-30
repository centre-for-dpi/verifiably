package handlers

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestDetectColumns(t *testing.T) {
	rows := []map[string]string{
		{"last_name": "Hopper", "reg_id": "1", "extra": "x"},
		{"last_name": "Lovelace", "reg_id": "2"},
	}
	// preferred (CSV header) order honored first; remaining keys sorted.
	got := detectColumns(rows, []string{"reg_id", "last_name"})
	want := []string{"reg_id", "last_name", "extra"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detectColumns = %v, want %v", got, want)
	}
	// No header → all keys sorted, deterministic.
	got2 := detectColumns(rows, nil)
	want2 := []string{"extra", "last_name", "reg_id"}
	if !reflect.DeepEqual(got2, want2) {
		t.Errorf("detectColumns(no header) = %v, want %v", got2, want2)
	}
}

func TestDefaultColumnFor(t *testing.T) {
	cols := []string{"lastName", "reg_id"}
	if got := defaultColumnFor("lastName", cols); got != "lastName" {
		t.Errorf("exact match = %q, want lastName", got)
	}
	if got := defaultColumnFor("last_name", cols); got != "" {
		t.Errorf("no match (case/shape differs) = %q, want empty", got)
	}
}

func TestIdentityDefault(t *testing.T) {
	if got := identityDefault([]string{"uin", "name"}); got != "uin" {
		t.Errorf("= %q, want uin", got)
	}
	if got := identityDefault([]string{"individualId", "uin"}); got != "individualId" {
		t.Errorf("prefers individualId, got %q", got)
	}
	if got := identityDefault([]string{"name", "dob"}); got != "" {
		t.Errorf("no identity column = %q, want empty", got)
	}
}

func TestRemapRows(t *testing.T) {
	rows := []map[string]string{
		{"col_a": "Grace", "col_b": "1906", "junk": "z"},
		{"col_a": "Ada"}, // missing col_b
	}
	mapping := map[string]string{"fullName": "col_a", "year": "col_b", "skip": ""}
	got := remapRows(rows, mapping)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if !reflect.DeepEqual(got[0], map[string]string{"fullName": "Grace", "year": "1906"}) {
		t.Errorf("row0 = %v (junk must be dropped, empty mapping skipped)", got[0])
	}
	// Missing source column → field omitted, not empty-stringed.
	if _, ok := got[1]["year"]; ok {
		t.Errorf("row1 should omit 'year' (col_b absent): %v", got[1])
	}
	if got[1]["fullName"] != "Ada" {
		t.Errorf("row1 fullName = %q, want Ada", got[1]["fullName"])
	}
}

func TestBuildRegistryProvider(t *testing.T) {
	sess := &Session{SchemaID: "TestaCredV1"}

	t.Run("manual only — entity falls back to credential key", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "")
		r := httptest.NewRequest("POST", "/x", strings.NewReader(url.Values{
			"reg_url": {"https://reg.example"},
		}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = r.ParseForm()
		p, entity := buildRegistryProvider(r, sess)
		if p.URL != "https://reg.example" || p.SearchField != "individualId" || entity != "TestaCredV1" {
			t.Errorf("got url=%q search=%q entity=%q", p.URL, p.SearchField, entity)
		}
	})

	t.Run("configured pick + manual override", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"sb","label":"Sunbird","url":"http://reg:18091","searchField":"individualId"}]`)
		r := httptest.NewRequest("POST", "/x", strings.NewReader(url.Values{
			"reg_pick":   {"sb"},
			"reg_entity": {"CustomEntity"},
			"reg_search": {"uin"},
		}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = r.ParseForm()
		p, entity := buildRegistryProvider(r, sess)
		if p.URL != "http://reg:18091" {
			t.Errorf("URL from pick = %q", p.URL)
		}
		if entity != "CustomEntity" || p.SearchField != "uin" {
			t.Errorf("overrides not applied: entity=%q search=%q", entity, p.SearchField)
		}
	})
}
