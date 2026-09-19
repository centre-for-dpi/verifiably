// SPDX-License-Identifier: Apache-2.0

package migrate_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/hashchain"
	"github.com/centre-for-dpi/vc-adapters/internal/migrate"
)

const salt = "test-salt"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v
}

func options(t *testing.T) migrate.Options {
	t.Helper()
	return migrate.Options{Salt: salt, Now: mustTime(t, "2026-01-02T03:04:05Z")}
}

func sampleIssued(t *testing.T) []migrate.LegacyIssued {
	t.Helper()
	revoked := mustTime(t, "2025-06-02T00:00:00Z")
	return []migrate.LegacyIssued{
		{
			ID: "vc-1", SchemaID: "schema-a", SchemaName: "Driving Licence",
			Format: "vc+sd-jwt", IssuerDpg: "waltid",
			SubjectFields: map[string]string{"id": "holder-1", "fullName": "A Person"},
			HolderHint:    "A Person",
			IssuedAt:      mustTime(t, "2025-06-01T00:00:00Z"),
			StatusList:    &migrate.LegacyStatusRef{Type: "bitstring", ListID: "bitstring-v1", Index: 7},
		},
		{
			ID: "vc-2", SchemaName: "Diploma", IssuedAt: mustTime(t, "2025-06-01T01:00:00Z"),
			RevokedAt: &revoked,
		},
	}
}

func TestParseIssuedLog(t *testing.T) {
	if got, err := migrate.ParseIssuedLog(nil); err != nil || got != nil {
		t.Fatalf("empty log: %v %v", got, err)
	}
	got, err := migrate.ParseIssuedLog([]byte(`[{"id":"vc-1","schemaId":"s"}]`))
	if err != nil || len(got) != 1 || got[0].ID != "vc-1" {
		t.Fatalf("parse: %v %v", got, err)
	}
	if _, err := migrate.ParseIssuedLog([]byte("{")); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("want ErrInput, got %v", err)
	}
}

func TestParseTrustFile(t *testing.T) {
	if got, err := migrate.ParseTrustFile(nil); err != nil || got != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	got, err := migrate.ParseTrustFile([]byte(`[{"did":"did:web:a"}]`))
	if err != nil || len(got) != 1 {
		t.Fatalf("parse: %v %v", got, err)
	}
	if _, err := migrate.ParseTrustFile([]byte("{")); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("want ErrInput, got %v", err)
	}
}

func TestKindOfListID(t *testing.T) {
	if migrate.KindOfListID("token-v1") != migrate.KindToken {
		t.Fatal("token id")
	}
	if migrate.KindOfListID("bitstring-v1") != migrate.KindBitstring {
		t.Fatal("bitstring id")
	}
}

func listFile(t *testing.T, size, nextFree int, bits []byte) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"size": size, "nextFree": nextFree,
		"bits": base64.RawURLEncoding.EncodeToString(bits),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return data
}

func TestParseListFile(t *testing.T) {
	bits := make([]byte, 4)
	got, err := migrate.ParseListFile("bitstring-v1", listFile(t, 32, 3, bits))
	if err != nil || got.Size != 32 || got.NextFree != 3 || got.Kind != migrate.KindBitstring {
		t.Fatalf("parse: %+v %v", got, err)
	}
	zero, err := migrate.ParseListFile("token-v1", listFile(t, 0, 0, bits))
	if err != nil || zero.Size != 32 || zero.Kind != migrate.KindToken {
		t.Fatalf("size fallback: %+v %v", zero, err)
	}
	if _, err := migrate.ParseListFile("x", []byte("{")); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad json: %v", err)
	}
	if _, err := migrate.ParseListFile("x", []byte(`{"bits":"!!!"}`)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad base64: %v", err)
	}
}

func TestListIDOfFile(t *testing.T) {
	cases := map[string]string{
		"status-list-bitstring-v1.json": "bitstring-v1",
		"issued-credentials.json":       "",
		"status-list-bitstring-v1.txt":  "",
		"status-list-.json":             "",
		"status-list-v1-key.json":       "",
		"status-list-ld-key.json":       "",
	}
	for name, want := range cases {
		got, ok := migrate.ListIDOfFile(name)
		if got != want || ok != (want != "") {
			t.Fatalf("%s: got %q %v, want %q", name, got, ok, want)
		}
	}
}

// writeStateDir builds a legacy state directory.
func writeStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	issued, err := json.Marshal(sampleIssued(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	write(t, filepath.Join(dir, migrate.IssuedLogName), issued)
	write(t, filepath.Join(dir, "status-list-bitstring-v1.json"), listFile(t, 32, 8, make([]byte, 4)))
	write(t, filepath.Join(dir, "status-list-token-v1.json"), listFile(t, 32, 2, make([]byte, 4)))
	write(t, filepath.Join(dir, "status-list-bitstring-v1-key.json"), []byte("{}"))
	write(t, filepath.Join(dir, "sessions"), nil)
	if err := os.Remove(filepath.Join(dir, "sessions")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sessions"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	trust, err := json.Marshal([]migrate.LegacyTrust{{
		DID: "did:web:issuer.example", DisplayName: "Issuer", Schemas: []string{"schema-a"},
		AccreditedAt: mustTime(t, "2025-01-01T00:00:00Z"),
	}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	write(t, filepath.Join(dir, migrate.TrustFileName), trust)
	return dir
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReadStateDir(t *testing.T) {
	got, err := migrate.ReadStateDir(writeStateDir(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Issued) != 2 || len(got.Lists) != 2 || len(got.Trust) != 1 {
		t.Fatalf("counts: %d %d %d", len(got.Issued), len(got.Lists), len(got.Trust))
	}
	if got.Lists[0].ListID != "bitstring-v1" || got.Lists[1].Kind != migrate.KindToken {
		t.Fatalf("lists: %+v", got.Lists)
	}
}

func TestReadStateDirErrors(t *testing.T) {
	if _, err := migrate.ReadStateDir(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("want an error for a missing directory")
	}

	badIssued := t.TempDir()
	write(t, filepath.Join(badIssued, migrate.IssuedLogName), []byte("{"))
	if _, err := migrate.ReadStateDir(badIssued); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad log: %v", err)
	}

	badTrust := t.TempDir()
	write(t, filepath.Join(badTrust, migrate.TrustFileName), []byte("{"))
	if _, err := migrate.ReadStateDir(badTrust); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad trust: %v", err)
	}

	badList := t.TempDir()
	write(t, filepath.Join(badList, "status-list-bitstring-v1.json"), []byte("{"))
	if _, err := migrate.ReadStateDir(badList); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad list: %v", err)
	}

	unreadableLog := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadableLog, migrate.IssuedLogName), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := migrate.ReadStateDir(unreadableLog); err == nil {
		t.Fatal("want an error for a directory in place of the log")
	}

	unreadableTrust := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadableTrust, migrate.TrustFileName), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := migrate.ReadStateDir(unreadableTrust); err == nil {
		t.Fatal("want an error for a directory in place of the trust file")
	}

	brokenLink := t.TempDir()
	link := filepath.Join(brokenLink, "status-list-bitstring-v1.json")
	if err := os.Symlink(filepath.Join(brokenLink, "gone"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := migrate.ReadStateDir(brokenLink); err == nil {
		t.Fatal("want an error for an unreadable list file")
	}
}

func TestOptionsCheck(t *testing.T) {
	if _, err := migrate.BuildIssuedDocument(nil, migrate.Options{}); !errors.Is(err, migrate.ErrOptions) {
		t.Fatalf("want ErrOptions, got %v", err)
	}
	doc, err := migrate.BuildIssuedDocument(nil, migrate.Options{Salt: salt})
	if err != nil || len(doc.Entries) != 0 {
		t.Fatalf("defaults: %v %v", doc, err)
	}
}

func TestSubjectOf(t *testing.T) {
	cases := []struct {
		in   migrate.LegacyIssued
		want string
	}{
		{migrate.LegacyIssued{SubjectFields: map[string]string{"id": "sub"}}, "sub"},
		{migrate.LegacyIssued{HolderHint: "hint"}, "hint"},
		{migrate.LegacyIssued{OwnerKey: "owner"}, "owner"},
		{migrate.LegacyIssued{ID: "vc-1"}, "vc-1"},
		{migrate.LegacyIssued{}, ""},
	}
	for _, c := range cases {
		if got := migrate.SubjectOf(c.in); got != c.want {
			t.Fatalf("got %q, want %q", got, c.want)
		}
	}
}

func TestKeep(t *testing.T) {
	claims := map[string]string{"a": "1", "b": "2"}
	if got := migrate.Keep(nil, []string{"a"}); got != nil {
		t.Fatalf("no claims: %v", got)
	}
	if got := migrate.Keep(claims, nil); got != nil {
		t.Fatalf("no allow list: %v", got)
	}
	if got := migrate.Keep(claims, []string{"z"}); got != nil {
		t.Fatalf("no match: %v", got)
	}
	got := migrate.Keep(claims, []string{"a"})
	if len(got) != 1 || got["a"] != "1" {
		t.Fatalf("keep: %v", got)
	}
}

func TestSubjectRef(t *testing.T) {
	one := migrate.SubjectRef(salt, "holder-1")
	if one == migrate.SubjectRef("other", "holder-1") || len(one) != 64 {
		t.Fatalf("salted reference: %s", one)
	}
}

func TestToIssuedRecord(t *testing.T) {
	opts := options(t)
	opts.KeepClaims = []string{"fullName"}
	opts.StatusBaseURL = "https://status.example/"
	r, err := migrate.ToIssuedRecord(sampleIssued(t)[0], opts)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if r.SchemaID != "schema-a" || r.SchemaVersion != 1 || r.Status != migrate.StatusActive {
		t.Fatalf("fields: %+v", r)
	}
	if r.SubjectRef != migrate.SubjectRef(salt, "holder-1") {
		t.Fatal("subject reference")
	}
	if r.Binding.PublishURL != "https://status.example/status/bitstring-v1" || r.Binding.Index != 7 {
		t.Fatalf("binding: %+v", r.Binding)
	}
	if r.SearchableClaims["fullName"] != "A Person" {
		t.Fatalf("claims: %v", r.SearchableClaims)
	}

	fallback, err := migrate.ToIssuedRecord(sampleIssued(t)[1], options(t))
	if err != nil || fallback.SchemaID != "Diploma" || fallback.Binding.ListID != "" {
		t.Fatalf("fallback: %+v %v", fallback, err)
	}
}

func TestToIssuedRecordErrors(t *testing.T) {
	opts := options(t)
	cases := map[string]migrate.LegacyIssued{
		"no id":     {SchemaID: "s", IssuedAt: opts.Now},
		"no schema": {ID: "vc-1", IssuedAt: opts.Now},
		"no time":   {ID: "vc-1", SchemaID: "s"},
	}
	for name, in := range cases {
		if _, err := migrate.ToIssuedRecord(in, opts); !errors.Is(err, migrate.ErrInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestBuildIssuedDocument(t *testing.T) {
	doc, err := migrate.BuildIssuedDocument(sampleIssued(t), options(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(doc.Entries) != 3 {
		t.Fatalf("entries: %d", len(doc.Entries))
	}
	if err := hashchain.Verify(doc.Entries); err != nil {
		t.Fatalf("chain: %v", err)
	}
	var last migrate.IssuedEvent
	if err := json.Unmarshal(doc.Entries[2].Body, &last); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if last.Kind != migrate.EventStatus || last.Change.Status != migrate.StatusRevoked {
		t.Fatalf("status event: %+v", last)
	}
	if last.Change.Reason != migrate.DefaultReason {
		t.Fatalf("reason: %s", last.Change.Reason)
	}
}

func TestBuildIssuedDocumentOrdersRevocations(t *testing.T) {
	early := mustTime(t, "2025-01-01T00:00:00Z")
	same := mustTime(t, "2025-02-01T00:00:00Z")
	items := []migrate.LegacyIssued{
		{ID: "vc-b", SchemaID: "s", IssuedAt: early, RevokedAt: &same},
		{ID: "vc-a", SchemaID: "s", IssuedAt: early, RevokedAt: &same},
		{ID: "vc-c", SchemaID: "s", IssuedAt: early, RevokedAt: &early},
	}
	doc, err := migrate.BuildIssuedDocument(items, options(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var order []string
	for _, e := range doc.Entries[3:] {
		var ev migrate.IssuedEvent
		if err := json.Unmarshal(e.Body, &ev); err != nil {
			t.Fatalf("decode: %v", err)
		}
		order = append(order, ev.Change.RecordID)
	}
	want := []string{"vc-c", "vc-a", "vc-b"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order: %v, want %v", order, want)
		}
	}
}

func TestBuildIssuedDocumentErrors(t *testing.T) {
	bad := []migrate.LegacyIssued{{SchemaID: "s", IssuedAt: mustTime(t, "2025-01-01T00:00:00Z")}}
	if _, err := migrate.BuildIssuedDocument(bad, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad record: %v", err)
	}
	dup := []migrate.LegacyIssued{
		{ID: "vc-1", SchemaID: "s", IssuedAt: mustTime(t, "2025-01-01T00:00:00Z")},
		{ID: "vc-1", SchemaID: "s", IssuedAt: mustTime(t, "2025-01-01T00:00:00Z")},
	}
	if _, err := migrate.BuildIssuedDocument(dup, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestIssuerSlugAndAllocatedBits(t *testing.T) {
	if migrate.IssuerSlug("") != "default" {
		t.Fatal("default slug")
	}
	if got := migrate.IssuerSlug("did:web:a"); len(got) != 16 {
		t.Fatalf("slug: %s", got)
	}
	bits := migrate.AllocatedBits(12, 9)
	if len(bits) != 2 || bits[0] != 0xff || bits[1] != 0x8f {
		t.Fatalf("bits: %x", bits)
	}
}

func TestToListRecord(t *testing.T) {
	list := migrate.LegacyList{Kind: migrate.KindBitstring, ListID: "bitstring-v1", Size: 16, NextFree: 3, Bits: []byte{0x01, 0x02}}
	rec, err := migrate.ToListRecord(list, options(t))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if rec.Size != 16 || rec.AllocatedCount != 3 || rec.Values[1] != 0x02 || rec.Bits != 1 {
		t.Fatalf("fields: %+v", rec)
	}
	if rec.Purpose != migrate.PurposeRevocation || rec.IssuerSlug != "default" {
		t.Fatalf("purpose or issuer: %+v", rec)
	}
	zero := list
	zero.Size = 0
	if got, err := migrate.ToListRecord(zero, options(t)); err != nil || got.Size != 16 {
		t.Fatalf("size fallback: %+v %v", got, err)
	}
}

func TestToListRecordErrors(t *testing.T) {
	good := migrate.LegacyList{Kind: migrate.KindBitstring, ListID: "v1", Size: 8, NextFree: 1, Bits: []byte{0}}
	if _, err := migrate.ToListRecord(good, migrate.Options{}); !errors.Is(err, migrate.ErrOptions) {
		t.Fatalf("options: %v", err)
	}
	cases := map[string]migrate.LegacyList{
		"kind":     {Kind: "other", ListID: "v1", Bits: []byte{0}},
		"id":       {Kind: migrate.KindToken, Bits: []byte{0}},
		"short":    {Kind: migrate.KindToken, ListID: "v1", Size: 64, Bits: []byte{0}},
		"count":    {Kind: migrate.KindToken, ListID: "v1", Size: 8, NextFree: 9, Bits: []byte{0}},
		"negative": {Kind: migrate.KindToken, ListID: "v1", Size: 8, NextFree: -1, Bits: []byte{0}},
	}
	for name, in := range cases {
		if _, err := migrate.ToListRecord(in, options(t)); !errors.Is(err, migrate.ErrInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestToTrustEntry(t *testing.T) {
	in := migrate.LegacyTrust{
		DID: "did:web:issuer.example", DisplayName: "Issuer", Schemas: []string{"schema-a"},
		ServiceEndpoint: "https://issuer.example", StatusListEndpoints: []string{"https://issuer.example/l"},
		StatusListPolicy: "fail-open", AccreditedAt: mustTime(t, "2025-01-01T00:00:00Z"),
		ValidUntil: mustTime(t, "2030-01-01T00:00:00Z"),
	}
	got, err := migrate.ToTrustEntry(in, options(t))
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	if got.Role != migrate.RoleIssuer || got.Status != migrate.TrustStatusActive || got.Version != 1 {
		t.Fatalf("fields: %+v", got)
	}
	if got.CredentialTypes[0] != "schema-a" || got.Source != migrate.SourceAdmin {
		t.Fatalf("types or source: %+v", got)
	}
}

func TestToTrustEntryErrors(t *testing.T) {
	if _, err := migrate.ToTrustEntry(migrate.LegacyTrust{}, migrate.Options{}); !errors.Is(err, migrate.ErrOptions) {
		t.Fatalf("options: %v", err)
	}
	if _, err := migrate.ToTrustEntry(migrate.LegacyTrust{DID: "issuer"}, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("did: %v", err)
	}
	window := migrate.LegacyTrust{
		DID:          "did:web:a",
		AccreditedAt: mustTime(t, "2030-01-01T00:00:00Z"),
		ValidUntil:   mustTime(t, "2025-01-01T00:00:00Z"),
	}
	if _, err := migrate.ToTrustEntry(window, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("window: %v", err)
	}
}

func TestBuildTrustDocument(t *testing.T) {
	items := []migrate.LegacyTrust{{DID: "did:web:a"}, {DID: "did:web:b"}}
	doc, err := migrate.BuildTrustDocument(items, options(t))
	if err != nil || doc.Revision != 2 || len(doc.Entries) != 2 {
		t.Fatalf("document: %+v %v", doc, err)
	}
	if _, err := migrate.BuildTrustDocument([]migrate.LegacyTrust{{DID: "a"}}, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("bad entry: %v", err)
	}
	dup := []migrate.LegacyTrust{{DID: "did:web:a"}, {DID: "did:web:a"}}
	if _, err := migrate.BuildTrustDocument(dup, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestBuild(t *testing.T) {
	legacy, err := migrate.ReadStateDir(writeStateDir(t))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b, err := migrate.Build(legacy, options(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	counts := b.Counts()
	if counts.Issued != 3 || counts.Bitstring != 1 || counts.Token != 1 || counts.Trust != 1 {
		t.Fatalf("counts: %+v", counts)
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := migrate.Build(migrate.Legacy{}, migrate.Options{}); !errors.Is(err, migrate.ErrOptions) {
		t.Fatalf("options: %v", err)
	}
	badIssued := migrate.Legacy{Issued: []migrate.LegacyIssued{{SchemaID: "s"}}}
	if _, err := migrate.Build(badIssued, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("issued: %v", err)
	}
	badList := migrate.Legacy{Lists: []migrate.LegacyList{{Kind: "other", ListID: "v1"}}}
	if _, err := migrate.Build(badList, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("list: %v", err)
	}
	badTrust := migrate.Legacy{Trust: []migrate.LegacyTrust{{DID: "a"}}}
	if _, err := migrate.Build(badTrust, options(t)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("trust: %v", err)
	}
}
