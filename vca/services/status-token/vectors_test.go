// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/securer"
)

// vector is one file of testdata/vectors.
type vector struct {
	Source   string  `json:"source"`
	Bits     int     `json:"bits"`
	Size     int     `json:"size"`
	Statuses []uint8 `json:"statuses"`
	BytesHex string  `json:"bytesHex"`
	Lst      string  `json:"lst"`
}

func readVector(t *testing.T, name string) vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestIETFVectorRoundTrips checks the bits=1 example of the draft.
func TestIETFVectorRoundTrips(t *testing.T) {
	v := readVector(t, "ietf-token-bits1.json")
	want, err := hex.DecodeString(v.BytesHex)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := token.Decode(v.Bits, v.Lst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Bytes(), want) {
		t.Fatalf("decoded = %x, want %x", decoded.Bytes(), want)
	}
	built, err := token.New(v.Bits, v.Size)
	if err != nil {
		t.Fatal(err)
	}
	for i, status := range v.Statuses {
		if err := built.Set(i, status); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(built.Bytes(), want) {
		t.Fatalf("built = %x, want %x", built.Bytes(), want)
	}
	for i, status := range v.Statuses {
		got, err := decoded.Get(i)
		if err != nil || got != status {
			t.Fatalf("index %d = %d %v, want %d", i, got, err, status)
		}
	}
}

// TestPublishAndVerifyAgainstVector runs the service, writes the status
// values of the vector, and reads them back from both representations.
func TestPublishAndVerifyAgainstVector(t *testing.T) {
	v := readVector(t, "ietf-token-bits1.json")
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	quiet := app.Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a, err := app.Build(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := statusv1connect.NewStatusServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	listID := ""
	indices := make([]int, len(v.Statuses))
	for i, status := range v.Statuses {
		alloc, err := client.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{
			Purpose: statusv1.Purpose_PURPOSE_REVOCATION, Kind: statusv1.Kind_KIND_TOKEN, Bits: int32(v.Bits),
		}))
		if err != nil {
			t.Fatal(err)
		}
		if listID == "" {
			listID = alloc.Msg.GetListId()
		}
		if alloc.Msg.GetListId() != listID {
			t.Fatal("the service opened a second list before the first was full")
		}
		indices[i] = int(alloc.Msg.GetIndex())
		if _, err := client.SetStatus(ctx, connect.NewRequest(&statusv1.SetStatusRequest{
			ListId: listID, Index: alloc.Msg.GetIndex(), Value: int32(status), Reason: "vector",
		})); err != nil {
			t.Fatal(err)
		}
	}
	if repeated(indices) {
		t.Fatal("the service allocated one index twice")
	}
	jwtList := fetchJWT(t, a, srv, listID)
	cwtList := fetchCWT(t, a, srv, listID)
	for i, status := range v.Statuses {
		for name, list := range map[string]*token.List{"jwt": jwtList, "cwt": cwtList} {
			got, err := list.Get(indices[i])
			if err != nil || got != status {
				t.Fatalf("%s index %d = %d %v, want %d", name, indices[i], got, err, status)
			}
		}
	}
}

// repeated reports whether a value appears twice.
func repeated(values []int) bool {
	seen := map[int]bool{}
	for _, v := range values {
		if seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}

// fetchJWT gets the default representation and verifies it.
func fetchJWT(t *testing.T, a *app.App, srv *httptest.Server, id string) *token.List {
	t.Helper()
	body := fetch(t, srv, id, "", securer.MediaTypeJWT)
	set, err := jose.ParseJWKS(a.Manager.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	payload, header, err := jose.VerifyWithJWKS(string(body), set, jose.SigningAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if header.Typ != token.TypeJWT {
		t.Fatalf("typ = %s", header.Typ)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	parsed, list, err := token.ParseJWTClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject != a.Manager.URL(id) {
		t.Fatalf("sub = %s", parsed.Subject)
	}
	return list
}

// fetchCWT gets the COSE representation and verifies it.
func fetchCWT(t *testing.T, a *app.App, srv *httptest.Server, id string) *token.List {
	t.Helper()
	body := fetch(t, srv, id, securer.MediaTypeCWT, securer.MediaTypeCWT)
	issuer := a.Issuers.Default()
	key := issuer.Active()
	payload, err := token.VerifyCWT(body, token.KeyVerifier(key.Public(issuer.Kid(key)).Key))
	if err != nil {
		t.Fatal(err)
	}
	claims, list, err := token.ParseCWTClaims(payload)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != issuer.DID() {
		t.Fatalf("iss = %s", claims.Issuer)
	}
	return list
}

// fetch gets the public list and checks the served media type.
func fetch(t *testing.T, srv *httptest.Server, id, accept, want string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/status/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != want {
		t.Fatalf("GET status: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
