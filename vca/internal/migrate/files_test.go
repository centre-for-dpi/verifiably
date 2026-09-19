// SPDX-License-Identifier: Apache-2.0

package migrate_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/migrate"
)

// exportBundle builds a bundle from the sample state directory.
func exportBundle(t *testing.T) migrate.Bundle {
	t.Helper()
	legacy, err := migrate.ReadStateDir(writeStateDir(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b, err := migrate.Build(legacy, options(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return b
}

func TestBundleFiles(t *testing.T) {
	files, err := exportBundle(t).Files()
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	want := []string{
		migrate.IssuedFile, migrate.TrustFile,
		migrate.BitstringDir + "/lists/bitstring-v1.json",
		migrate.TokenDir + "/lists/token-v1.json",
	}
	for _, name := range want {
		if len(files[name]) == 0 {
			t.Fatalf("missing %s", name)
		}
	}
	if len(files) != len(want) {
		t.Fatalf("files: %d", len(files))
	}
}

func TestBundleFilesRejectsBadListID(t *testing.T) {
	b := migrate.Bundle{Bitstring: []migrate.ListRecord{{ID: "bad/id"}}}
	if _, err := b.Files(); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("want ErrInput, got %v", err)
	}
	for _, id := range []string{"", ".", "..", "a b"} {
		bad := migrate.Bundle{Token: []migrate.ListRecord{{ID: id}}}
		if _, err := bad.Files(); !errors.Is(err, migrate.ErrInput) {
			t.Fatalf("%q: %v", id, err)
		}
	}
}

func TestBundleWriteAndRead(t *testing.T) {
	b := exportBundle(t)
	dir := t.TempDir()
	written, err := b.Write(dir, false)
	if err != nil || len(written) != 4 {
		t.Fatalf("write: %v %v", written, err)
	}
	if _, gotErr := b.Write(dir, false); !errors.Is(gotErr, migrate.ErrExists) {
		t.Fatalf("want ErrExists, got %v", gotErr)
	}
	if _, gotErr := b.Write(dir, true); gotErr != nil {
		t.Fatalf("force: %v", gotErr)
	}
	back, err := migrate.Read(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(back.Issued.Entries) != 3 || len(back.Bitstring) != 1 || len(back.Token) != 1 {
		t.Fatalf("counts: %+v", back.Counts())
	}
	if back.Trust.Revision != 1 || len(back.Trust.Entries) != 1 {
		t.Fatalf("trust: %+v", back.Trust)
	}
}

func TestBundleWriteErrors(t *testing.T) {
	b := exportBundle(t)
	file := filepath.Join(t.TempDir(), "a-file")
	write(t, file, []byte("x"))
	if _, err := b.Write(file, true); err == nil {
		t.Fatal("want an error when the output is a file")
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, migrate.IssuedFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := b.Write(dir, true); err == nil {
		t.Fatal("want an error when the target is a directory")
	}
}

func TestWriteRejectsBadBundle(t *testing.T) {
	b := migrate.Bundle{Bitstring: []migrate.ListRecord{{ID: "bad/id"}}}
	if _, err := b.Write(t.TempDir(), true); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("want ErrInput, got %v", err)
	}
}

func TestReadSortsLists(t *testing.T) {
	b := migrate.Bundle{Bitstring: []migrate.ListRecord{
		{ID: "b-list", Kind: migrate.KindBitstring},
		{ID: "a-list", Kind: migrate.KindBitstring},
	}}
	dir := t.TempDir()
	if _, err := b.Write(dir, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	back, err := migrate.Read(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(back.Bitstring) != 2 || back.Bitstring[0].ID != "a-list" {
		t.Fatalf("order: %+v", back.Bitstring)
	}
}

func TestReadEmptyDirectory(t *testing.T) {
	got, err := migrate.Read(t.TempDir())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Issued.Entries) != 0 || len(got.Trust.Entries) != 0 {
		t.Fatalf("empty: %+v", got)
	}
}

func TestReadErrors(t *testing.T) {
	badIssued := t.TempDir()
	write(t, filepath.Join(badIssued, migrate.IssuedFile), []byte("{"))
	if _, err := migrate.Read(badIssued); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("issued: %v", err)
	}

	unreadable := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadable, migrate.IssuedFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := migrate.Read(unreadable); err == nil {
		t.Fatal("want an error for an unreadable log")
	}

	badTrust := t.TempDir()
	write(t, filepath.Join(badTrust, migrate.TrustFile), []byte("{"))
	if _, err := migrate.Read(badTrust); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("trust: %v", err)
	}

	unreadableTrust := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadableTrust, migrate.TrustFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := migrate.Read(unreadableTrust); err == nil {
		t.Fatal("want an error for an unreadable trust file")
	}

	badList := t.TempDir()
	listDir := filepath.Join(badList, migrate.BitstringDir, migrate.ListsDir)
	if err := os.MkdirAll(listDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write(t, filepath.Join(listDir, "v1.json"), []byte("{"))
	write(t, filepath.Join(listDir, "notes.txt"), []byte("x"))
	if err := os.Mkdir(filepath.Join(listDir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := migrate.Read(badList); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("list: %v", err)
	}

	notDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(notDir, migrate.TokenDir), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write(t, filepath.Join(notDir, migrate.TokenDir, migrate.ListsDir), []byte("x"))
	if _, err := migrate.Read(notDir); err == nil {
		t.Fatal("want an error when the lists path is a file")
	}

	brokenLink := t.TempDir()
	linkDir := filepath.Join(brokenLink, migrate.TokenDir, migrate.ListsDir)
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(linkDir, "gone"), filepath.Join(linkDir, "v1.json")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := migrate.Read(brokenLink); err == nil {
		t.Fatal("want an error for an unreadable list file")
	}
}

func TestImport(t *testing.T) {
	from := t.TempDir()
	if _, err := exportBundle(t).Write(from, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	into := t.TempDir()
	written, err := migrate.Import(from, into, false)
	if err != nil || len(written) != 4 {
		t.Fatalf("import: %v %v", written, err)
	}
	data, err := os.ReadFile(filepath.Clean(filepath.Join(into, migrate.BitstringDir, migrate.ListsDir, "bitstring-v1.json")))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rec migrate.ListRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.AllocatedCount != 8 || rec.Kind != migrate.KindBitstring {
		t.Fatalf("record: %+v", rec)
	}
	if _, err := migrate.Import(filepath.Join(t.TempDir(), "gone"), into, true); err != nil {
		t.Fatalf("missing source: %v", err)
	}
	bad := t.TempDir()
	write(t, filepath.Join(bad, migrate.IssuedFile), []byte("{"))
	if _, err := migrate.Import(bad, into, true); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad source: %v", err)
	}
}
