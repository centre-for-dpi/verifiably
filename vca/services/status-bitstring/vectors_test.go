// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/status-bitstring/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/status-bitstring/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/status-bitstring/internal/securer"
)

// vector is one file of testdata/vectors.
type vector struct {
	Source        string `json:"source"`
	Size          int    `json:"size"`
	EncodedList   string `json:"encodedList"`
	StatusPurpose string `json:"statusPurpose"`
}

func readVector(t *testing.T, name string) vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", name)) //nolint:gosec // G304: the path is a test directory
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestW3CVectorDecodes checks the encoded list of the specification.
func TestW3CVectorDecodes(t *testing.T) {
	v := readVector(t, "w3c-bitstring-empty.json")
	list, err := bitstring.Decode(v.EncodedList)
	if err != nil {
		t.Fatal(err)
	}
	if list.Size() != v.Size || v.Size != bitstring.MinSize {
		t.Fatalf("size = %d, want %d", list.Size(), v.Size)
	}
	if !bytes.Equal(list.Bytes(), make([]byte, v.Size/8)) {
		t.Fatal("the specification example is not an empty list")
	}
}

// TestPublishAndVerifyAgainstVector runs the service, publishes a list,
// and reads it back with the same code path a verifier uses.
func TestPublishAndVerifyAgainstVector(t *testing.T) {
	v := readVector(t, "w3c-bitstring-empty.json")
	quiet := app.Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.Build(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := statusv1connect.NewStatusServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	alloc, err := client.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{
		Purpose: statusv1.Purpose_PURPOSE_REVOCATION, Kind: statusv1.Kind_KIND_BITSTRING,
	}))
	if err != nil {
		t.Fatal(err)
	}
	// A new list carries the same bits as the specification example.
	// The gzip bytes differ, so the test compares the decoded arrays.
	want, err := bitstring.Decode(v.EncodedList)
	if err != nil {
		t.Fatal(err)
	}
	fresh := credentialOf(t, a, srv, alloc.Msg.GetListId())
	if !bytes.Equal(decodeList(t, fresh.encoded), want.Bytes()) {
		t.Fatalf("a new list encodes to %s", fresh.encoded)
	}
	if _, serr := client.SetStatus(ctx, connect.NewRequest(&statusv1.SetStatusRequest{
		ListId: alloc.Msg.GetListId(), Index: alloc.Msg.GetIndex(), Value: 1, Reason: "revoked in a test",
	})); serr != nil {
		t.Fatal(serr)
	}
	after := credentialOf(t, a, srv, alloc.Msg.GetListId())
	if bytes.Equal(decodeList(t, after.encoded), want.Bytes()) {
		t.Fatal("the published list did not change after the flip")
	}
	if string(after.purpose) != v.StatusPurpose {
		t.Fatalf("purpose = %s", after.purpose)
	}
	on, err := after.list.Get(int(alloc.Msg.GetIndex()))
	if err != nil || !on {
		t.Fatalf("bit at %d = %v %v", alloc.Msg.GetIndex(), on, err)
	}
	count := 0
	for i := 0; i < after.list.Size(); i++ {
		b, gerr := after.list.Get(i)
		if gerr != nil {
			t.Fatalf("unexpected error: %v", gerr)
		}
		if b {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d bits are set, want 1", count)
	}
}

// decodeList returns the raw bits of an encoded list.
func decodeList(t *testing.T, encoded string) []byte {
	t.Helper()
	list, err := bitstring.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return list.Bytes()
}

// published holds the parts of a verified list credential.
type published struct {
	encoded string
	purpose bitstring.Purpose
	list    *bitstring.List
}

// credentialOf fetches the public list, verifies the signature with the
// service JWKS, and parses the credential.
func credentialOf(t *testing.T, a *app.App, srv *httptest.Server, id string) published {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + "/status/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != securer.MediaType {
		t.Fatalf("GET status: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	set, err := jose.ParseJWKS(a.Manager.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	payload, header, err := jose.VerifyWithJWKS(string(body), set, jose.SigningAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if header.Typ != securer.Type {
		t.Fatalf("typ = %s", header.Typ)
	}
	var doc map[string]any
	if serr := json.Unmarshal(payload, &doc); serr != nil {
		t.Fatal(serr)
	}
	purpose, list, err := bitstring.ParseCredential(doc)
	if err != nil {
		t.Fatal(err)
	}
	subject := mustAs[map[string]any](t, doc["credentialSubject"])
	encoded := mustAs[string](t, subject["encodedList"])
	return published{encoded: encoded, purpose: purpose, list: list}
}
