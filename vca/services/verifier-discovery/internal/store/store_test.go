// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

// open returns a store over a memory backend.
func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewNeedsBackend(t *testing.T) {
	if _, err := store.New(nil); err == nil {
		t.Error("a nil backend wants an error")
	}
}

func TestIssuerRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	record := catalog.Issuer{
		CredentialIssuer: "https://issuer.example", DID: "did:web:issuer.example",
		Types: []catalog.CredentialType{{Type: "A", Format: "ldp_vc"}}, CrawledAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := s.PutIssuer(ctx, record); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIssuer(ctx, record.CredentialIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if got.DID != record.DID || len(got.Types) != 1 {
		t.Errorf("issuer = %+v", got)
	}
	second := catalog.Issuer{CredentialIssuer: "https://a.example"}
	if serr := s.PutIssuer(ctx, second); serr != nil {
		t.Fatal(serr)
	}
	list, err := s.ListIssuers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].CredentialIssuer != "https://a.example" {
		t.Errorf("the list is ordered by URL, got %+v", list)
	}
	if serr := s.DeleteIssuer(ctx, record.CredentialIssuer); serr != nil {
		t.Fatal(serr)
	}
	_, err = s.GetIssuer(ctx, record.CredentialIssuer)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a removed issuer wants ErrNotFound, got %v", err)
	}
}

func TestIssuerKeyIsStable(t *testing.T) {
	first, second := store.IssuerKey("https://a.example"), store.IssuerKey("https://a.example")
	if first != second {
		t.Error("the key of one URL never changes")
	}
	if store.IssuerKey("https://a.example") == store.IssuerKey("https://b.example") {
		t.Error("two URLs get two keys")
	}
}

func TestIssuerBrokenDocument(t *testing.T) {
	ctx := context.Background()
	kv := shared.Memory()
	if err := kv.Put(ctx, store.IssuerKey("https://a.example"), []byte("{")); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(kv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIssuer(ctx, "https://a.example"); err == nil {
		t.Error("a broken document wants an error")
	}
	if _, err := s.ListIssuers(ctx); err == nil {
		t.Error("a broken document wants an error from the list too")
	}
}

func TestTemplateVersions(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	first := template.Template{ID: "age-check", Version: 1, DisplayName: "Age check", DCQL: "{}"}
	if err := s.PutTemplate(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTemplate(ctx, first); err == nil {
		t.Error("the store refuses to replace a stored version")
	}
	second := first
	second.Version = 2
	second.DisplayName = "Age check v2"
	if err := s.PutTemplate(ctx, second); err != nil {
		t.Fatal(err)
	}
	latest, err := s.GetTemplate(ctx, "age-check", 0)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != 2 || latest.DisplayName != "Age check v2" {
		t.Errorf("latest = %+v", latest)
	}
	old, err := s.GetTemplate(ctx, "age-check", 1)
	if err != nil {
		t.Fatal(err)
	}
	if old.DisplayName != "Age check" {
		t.Errorf("an old version stays readable, got %+v", old)
	}
	versions, err := s.Versions(ctx, "age-check")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0] != 1 {
		t.Errorf("versions = %v", versions)
	}
	if _, err := s.GetTemplate(ctx, "age-check", 7); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing version wants ErrNotFound, got %v", err)
	}
	if _, err := s.GetTemplate(ctx, "missing", 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing template wants ErrNotFound, got %v", err)
	}
	if _, err := s.LatestVersion(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing template wants ErrNotFound, got %v", err)
	}
}

func TestListAndDeleteTemplates(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	for _, id := range []string{"b-check", "a-check"} {
		if err := s.PutTemplate(ctx, template.Template{ID: id, Version: 1, DisplayName: id, DCQL: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "a-check" {
		t.Errorf("the list is ordered by id, got %+v", list)
	}
	removed, err := s.DeleteTemplate(ctx, "a-check")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d", removed)
	}
	if _, err := s.DeleteTemplate(ctx, "a-check"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing template wants ErrNotFound, got %v", err)
	}
}

func TestTemplateBrokenDocumentAndKeys(t *testing.T) {
	ctx := context.Background()
	kv := shared.Memory()
	if err := kv.Put(ctx, store.TemplateKey("x", 1), []byte("{")); err != nil {
		t.Fatal(err)
	}
	// A key that is not a version never joins the version list.
	if err := kv.Put(ctx, store.TemplatePrefix+"x/vnine", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := kv.Put(ctx, store.TemplatePrefix+"loose", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(kv)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := s.Versions(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Errorf("versions = %v", versions)
	}
	if _, err := s.GetTemplate(ctx, "x", 1); err == nil {
		t.Error("a broken document wants an error")
	}
	if _, err := s.ListTemplates(ctx); err == nil {
		t.Error("a broken document wants an error from the list too")
	}
}

// broken is a backend that fails every call.
type broken struct{ err error }

func (b broken) Get(context.Context, string) ([]byte, error) { return nil, b.err }
func (b broken) Put(context.Context, string, []byte) error   { return b.err }
func (b broken) Delete(context.Context, string) error        { return b.err }
func (b broken) List(context.Context, string) ([]string, error) {
	return nil, b.err
}
func (b broken) CompareAndSwap(context.Context, string, []byte, []byte) error { return b.err }

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	s, err := store.New(broken{err: errors.New("disk is full")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutIssuer(ctx, catalog.Issuer{CredentialIssuer: "https://a.example"}); err == nil {
		t.Error("PutIssuer wants the backend error")
	}
	if _, err := s.GetIssuer(ctx, "https://a.example"); err == nil {
		t.Error("GetIssuer wants the backend error")
	}
	if _, err := s.ListIssuers(ctx); err == nil {
		t.Error("ListIssuers wants the backend error")
	}
	if err := s.PutTemplate(ctx, template.Template{ID: "x", Version: 1}); err == nil {
		t.Error("PutTemplate wants the backend error")
	}
	if _, err := s.GetTemplate(ctx, "x", 1); err == nil {
		t.Error("GetTemplate wants the backend error")
	}
	if _, err := s.Versions(ctx, "x"); err == nil {
		t.Error("Versions wants the backend error")
	}
	if _, err := s.LatestVersion(ctx, "x"); err == nil {
		t.Error("LatestVersion wants the backend error")
	}
	if _, err := s.ListTemplates(ctx); err == nil {
		t.Error("ListTemplates wants the backend error")
	}
	if _, err := s.DeleteTemplate(ctx, "x"); err == nil {
		t.Error("DeleteTemplate wants the backend error")
	}
	if _, err := s.GetTemplate(ctx, "x", 0); err == nil {
		t.Error("the latest version wants the backend error")
	}
}

// halfBroken lists keys but fails to read or delete them.
type halfBroken struct {
	shared.KeyValue
	failGet    bool
	failDelete bool
}

func (h halfBroken) Get(ctx context.Context, key string) ([]byte, error) {
	if h.failGet {
		return nil, errors.New("read failed")
	}
	return h.KeyValue.Get(ctx, key)
}

func (h halfBroken) Delete(ctx context.Context, key string) error {
	if h.failDelete {
		return errors.New("delete failed")
	}
	return h.KeyValue.Delete(ctx, key)
}

func TestPartialBackendErrors(t *testing.T) {
	ctx := context.Background()
	kv := shared.Memory()
	if err := kv.Put(ctx, store.IssuerKey("https://a.example"), []byte(`{"credential_issuer":"https://a.example"}`)); err != nil {
		t.Fatal(err)
	}
	if err := kv.Put(ctx, store.TemplateKey("x", 1), []byte(`{"id":"x","version":1}`)); err != nil {
		t.Fatal(err)
	}
	readFails, err := store.New(halfBroken{KeyValue: kv, failGet: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := readFails.ListIssuers(ctx); serr == nil {
		t.Error("a read error stops the issuer list")
	}
	if _, serr := readFails.ListTemplates(ctx); serr == nil {
		t.Error("a read error stops the template list")
	}
	deleteFails, err := store.New(halfBroken{KeyValue: kv, failDelete: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleteFails.DeleteTemplate(ctx, "x"); err == nil {
		t.Error("a delete error stops the removal")
	}
}
