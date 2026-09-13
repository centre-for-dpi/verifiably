// SPDX-License-Identifier: Apache-2.0

package export_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/export"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
)

func sample() []record.Record {
	issued := time.Date(2026, 2, 3, 10, 0, 0, 0, time.UTC)
	return []record.Record{
		{
			ID: "r1", SchemaID: "diploma", SchemaVersion: 2, SubjectRef: "ref1",
			Format: "dc+sd-jwt", Status: record.Active, DPG: "waltid", IssuedAt: issued,
			Binding:          record.Binding{Kind: record.KindBitstring, ListID: "v1", Index: 42},
			SearchableClaims: map[string]string{"name": "Wanjiru", "course": "Law"},
			Hash:             "h1", RecordHash: "rh1",
		},
		{
			ID: "r2", SchemaID: "licence", SchemaVersion: 1, SubjectRef: "ref2",
			Format: "mso_mdoc", Status: record.Revoked, IssuedAt: issued.Add(time.Hour),
			StatusChangedAt: issued.Add(2 * time.Hour), StatusReason: "fraud",
			SearchableClaims: map[string]string{"name": "Otieno"},
		},
	}
}

func TestCSV(t *testing.T) {
	data, err := export.Bytes(sample(), export.CSV)
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	wantHeader := append(append([]string{}, export.Columns...), "course", "name")
	if !reflect.DeepEqual(rows[0], wantHeader) {
		t.Errorf("header = %v, want %v", rows[0], wantHeader)
	}
	index := map[string]int{}
	for i, name := range rows[0] {
		index[name] = i
	}
	if rows[1][index["id"]] != "r1" || rows[1][index["status_list_index"]] != "42" {
		t.Errorf("first row = %v", rows[1])
	}
	if rows[1][index["name"]] != "Wanjiru" || rows[1][index["course"]] != "Law" {
		t.Errorf("claims = %v", rows[1])
	}
	if rows[1][index["issued_at"]] != "2026-02-03T10:00:00Z" {
		t.Errorf("issued_at = %q", rows[1][index["issued_at"]])
	}
	// The second record has no status list and no course claim.
	if rows[2][index["status_list_index"]] != "" || rows[2][index["course"]] != "" {
		t.Errorf("second row = %v", rows[2])
	}
	if rows[2][index["status_reason"]] != "fraud" || rows[2][index["valid_from"]] != "" {
		t.Errorf("second row = %v", rows[2])
	}
}

func TestCSVOfNoRecordsIsTheHeaderOnly(t *testing.T) {
	data, err := export.Bytes(nil, export.CSV)
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1", len(lines))
	}
	if !strings.HasPrefix(lines[0], "id,schema_id,") {
		t.Errorf("header = %q", lines[0])
	}
}

func TestJSONLines(t *testing.T) {
	data, err := export.Bytes(sample(), export.JSON)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	var back record.Record
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.ID != "r1" || back.SearchableClaims["name"] != "Wanjiru" {
		t.Errorf("record = %+v", back)
	}
}

func TestChunks(t *testing.T) {
	got := export.Chunks([]byte("abcdefg"), 3)
	want := [][]byte{[]byte("abc"), []byte("def"), []byte("g")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chunks = %q, want %q", got, want)
	}
	if got := export.Chunks(nil, 3); len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("empty data must give one empty chunk, got %q", got)
	}
	if got := export.Chunks([]byte("ab"), 0); len(got) != 1 || string(got[0]) != "ab" {
		t.Errorf("a zero size must use the default, got %q", got)
	}
}

// broken is a writer that fails once its budget is gone.
type broken struct{ left int }

func (b *broken) Write(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errors.New("no space")
	}
	b.left -= len(p)
	return len(p), nil
}

func TestWriteErrorsReachTheCaller(t *testing.T) {
	// A CSV writer buffers its rows, so the failure surfaces on flush.
	if err := export.CSV(&broken{}, sample()); err == nil {
		t.Error("want a flush error")
	}
	if err := export.JSON(&broken{}, sample()); err == nil {
		t.Error("want an encode error")
	}
	if _, err := export.Bytes(sample(), func(io.Writer, []record.Record) error {
		return errors.New("no")
	}); err == nil {
		t.Error("Bytes must return the write error")
	}
}
