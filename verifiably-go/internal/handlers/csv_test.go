package handlers

import (
	"strings"
	"testing"
)

func TestParseCSVRows(t *testing.T) {
	in := strings.NewReader(`holder,degree,classification
Achieng Otieno,BSc Computer Science,First Class
,,
John Doe,MSc Data Science,Merit
Jane Smith,,Distinction
`)
	rows, header, err := parseCSVRows(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantHeader := []string{"holder", "degree", "classification"}
	if len(header) != len(wantHeader) {
		t.Fatalf("header len: got %d want %d", len(header), len(wantHeader))
	}
	for i, c := range wantHeader {
		if header[i] != c {
			t.Fatalf("header[%d]: got %q want %q", i, header[i], c)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("rows len: got %d want 3 (blank row dropped)", len(rows))
	}
	if rows[0]["holder"] != "Achieng Otieno" {
		t.Errorf("row[0] holder: %q", rows[0]["holder"])
	}
	if rows[2]["degree"] != "" {
		t.Errorf("row[2] degree should be empty, got %q", rows[2]["degree"])
	}
	if rows[2]["classification"] != "Distinction" {
		t.Errorf("row[2] classification: %q", rows[2]["classification"])
	}
}

func TestParseCSVRows_EmptyInput(t *testing.T) {
	_, _, err := parseCSVRows(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error on empty CSV, got nil")
	}
}

// Leading blank rows are skipped before the header is taken.
func TestParseCSVRows_SkipsLeadingEmptyRows(t *testing.T) {
	rows, header, err := parseCSVRows(strings.NewReader(",,\n\nname,age\nAda,36\n"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(header) != 2 || header[0] != "name" || header[1] != "age" {
		t.Errorf("header = %v, want [name age]", header)
	}
	if len(rows) != 1 || rows[0]["name"] != "Ada" || rows[0]["age"] != "36" {
		t.Errorf("rows = %v", rows)
	}
}

// A malformed header record (bare quote inside a field) surfaces the csv
// reader's error rather than being swallowed.
func TestParseCSVRows_HeaderParseError(t *testing.T) {
	_, _, err := parseCSVRows(strings.NewReader("na\"me,age\nAda,36\n"))
	if err == nil {
		t.Fatal("want error for malformed header")
	}
	if !strings.Contains(err.Error(), "bare \" in non-quoted-field") {
		t.Errorf("err = %v, want bare-quote parse error", err)
	}
}

// A malformed data record after a valid header also errors (no partial rows).
func TestParseCSVRows_DataParseError(t *testing.T) {
	rows, _, err := parseCSVRows(strings.NewReader("name,age\nAd\"a,36\n"))
	if err == nil {
		t.Fatal("want error for malformed data row")
	}
	if rows != nil {
		t.Errorf("rows = %v, want nil on error", rows)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("err = %v, want line 2 reference", err)
	}
}
