// SPDX-License-Identifier: Apache-2.0

package ports_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
)

// TestBearerPosterSendsTheCredentialRequest: the credential request of
// a claim goes as JSON with the access token of the claim. A refusal
// keeps its status and body. An empty token sends no Authorization.
func TestBearerPosterSendsTheCredentialRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		switch r.URL.Path {
		case "/credential":
			if r.Header.Get("Authorization") != "Bearer at-1" || r.Header.Get("Content-Type") != "application/json" || string(body) != `{"format":"dc+sd-jwt"}` {
				http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
				return
			}
			mustWrite(t, w, []byte(`{"credential":"c"}`))
		case "/nonce":
			if r.Header.Get("Authorization") != "" {
				http.Error(w, "no", http.StatusBadRequest)
				return
			}
			mustWrite(t, w, []byte(`{"c_nonce":"n"}`))
		default:
			http.Error(w, `{"error":"invalid_proof"}`, http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	post := ports.BearerPoster(nil, 1<<10)
	got, err := post(context.Background(), srv.URL+"/credential", "at-1", []byte(`{"format":"dc+sd-jwt"}`))
	if err != nil || string(got) != `{"credential":"c"}` {
		t.Fatalf("post = %q, %v", got, err)
	}
	nonce, nerr := post(context.Background(), srv.URL+"/nonce", "", nil)
	if nerr != nil || string(nonce) != `{"c_nonce":"n"}` {
		t.Fatalf("nonce = %q, %v", nonce, nerr)
	}
	_, err = post(context.Background(), srv.URL+"/other", "at-1", []byte(`{}`))
	var status *ports.StatusError
	if !errors.As(err, &status) || status.Status != http.StatusBadRequest {
		t.Fatalf("a refusal: %v", err)
	}
	for _, target := range []string{"http://%zz/", "http://127.0.0.1:0/"} {
		if _, err := post(context.Background(), target, "at-1", nil); err == nil {
			t.Errorf("%s: want an error", target)
		}
	}
}
