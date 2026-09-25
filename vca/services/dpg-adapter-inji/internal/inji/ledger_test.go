// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCertifyTimeReadsBothLayouts(t *testing.T) {
	var e struct {
		A CertifyTime `json:"a"`
		B CertifyTime `json:"b"`
		C CertifyTime `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"2026-09-20T08:15:00","b":"2026-09-20T08:15:00+02:00","c":null}`), &e); err != nil {
		t.Fatal(err)
	}
	if !e.A.Equal(time.Date(2026, 9, 20, 8, 15, 0, 0, time.UTC)) || !e.B.Equal(time.Date(2026, 9, 20, 6, 15, 0, 0, time.UTC)) || !e.C.IsZero() {
		t.Fatalf("%v %v %v", e.A, e.B, e.C)
	}
	if err := json.Unmarshal([]byte(`{"a":"yesterday"}`), &e); err == nil {
		t.Fatal("a bad time passed")
	}
	if got := (LedgerEntry{IssueDate: e.A}).Issued(); !got.Equal(e.A.Time) {
		t.Fatalf("the old field is the fallback: %v", got)
	}
}

func TestLedgerTypeSortsAndJoins(t *testing.T) {
	if got := LedgerType([]string{"VerifiableCredential", " FarmerCredential", "", "FarmerCredential"}); got != "FarmerCredential,VerifiableCredential" {
		t.Fatal(got)
	}
}

func TestLedgerCallsReadEveryAnswer(t *testing.T) {
	ctx := context.Background()
	q := LedgerSearch{IssuerID: "did:web:x", CredentialType: "A", Attributes: map[string]string{"k": "v"}}
	c := NewCertify(newHTTP(answerWith(t, 204, "")), "")
	if got, err := c.SearchLedger(ctx, q); err != nil || got != nil {
		t.Fatalf("204: %v %v", got, err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"errors":[{"errorCode":"invalid_search_criteria","errorMessage":"no"}]}`)), "")
	if _, err := c.SearchLedger(ctx, q); !IsAPIError(err, "invalid_search_criteria") {
		t.Fatalf("errors body: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"x":1}`)), "")
	if _, err := c.SearchLedger(ctx, q); err == nil {
		t.Fatal("an object passed as a list")
	}
	if _, err := c.UpdateStatus(ctx, "id", "revocation", true); err != nil {
		t.Fatalf("an object without errors is an answer: %v", err)
	}
	if _, err := c.ReadDIDDocument(ctx); err == nil {
		t.Fatal("a document without an id passed")
	}
	c = NewCertify(newHTTP(answerWith(t, 500, "")), "")
	if _, err := c.SearchLedger(ctx, q); err == nil {
		t.Fatal("a server error passed")
	}
	if _, err := c.UpdateStatus(ctx, "id", "revocation", true); err == nil || errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("a server error: %v", err)
	}
	if _, err := c.ReadDIDDocument(ctx); err == nil {
		t.Fatal("a server error passed")
	}
	c = NewCertify(newHTTP(answerWith(t, 404, "")), "")
	if _, err := c.UpdateStatus(ctx, "id", "revocation", true); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("404: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, `{"errors":[{"errorCode":"status_list_not_found_for_the_given_id","errorMessage":"no"}]}`)), "")
	if _, err := c.UpdateStatus(ctx, "id", "revocation", true); !IsAPIError(err, "status_list_not_found_for_the_given_id") {
		t.Fatalf("errors body: %v", err)
	}
	c = NewCertify(newHTTP(answerWith(t, 200, "[")), "")
	if _, err := c.UpdateStatus(ctx, "id", "revocation", true); err == nil {
		t.Fatal("a broken answer passed")
	}
	if _, err := c.ReadDIDDocument(ctx); err == nil {
		t.Fatal("a broken document passed")
	}
	var none *Certify
	if _, err := none.SearchLedger(ctx, q); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
	if _, err := none.UpdateStatus(ctx, "id", "revocation", true); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
	if _, err := none.ReadDIDDocument(ctx); !errors.Is(err, ErrNoCertify) {
		t.Fatal(err)
	}
}
