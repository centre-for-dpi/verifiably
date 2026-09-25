// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// verifier2 starts a server that answers with one body per path.
func verifier2(t *testing.T, answers map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := answers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		mustWrite(t, w, []byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(Options{Verifier2: dpgclient.New(dpgclient.Options{BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1})})
}

func TestSession2CallsNeedVerifier2(t *testing.T) {
	c := New(Options{})
	if c.HasVerifier2() {
		t.Fatal("a client without a URL has verifier 2")
	}
	if _, err := c.CreateSession2(context.Background(), Session2Setup{}); !errors.Is(err, ErrNoVerifier2) {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.SessionInfo2(context.Background(), "x"); !errors.Is(err, ErrNoVerifier2) {
		t.Fatalf("info: %v", err)
	}
}

func TestCreateSession2ReadsTheAnswer(t *testing.T) {
	c := verifier2(t, map[string]string{
		"/verification-session/create": `{"sessionId":"s1","fullAuthorizationRequestUrl":"openid4vp://authorize?full"}`,
	})
	got, err := c.CreateSession2(context.Background(), Session2Setup{FlowType: FlowCrossDevice})
	if err != nil {
		t.Fatalf("CreateSession2: %v", err)
	}
	if got.RequestURL() != "openid4vp://authorize?full" {
		t.Fatalf("a missing bootstrap URL falls back to the full URL: %q", got.RequestURL())
	}
	empty := verifier2(t, map[string]string{"/verification-session/create": `{}`})
	if _, err := empty.CreateSession2(context.Background(), Session2Setup{}); err == nil {
		t.Fatal("an answer without a session id was accepted")
	}
	broken := verifier2(t, nil)
	if _, err := broken.CreateSession2(context.Background(), Session2Setup{}); err == nil {
		t.Fatal("a failed call was accepted")
	}
	if _, err := broken.SessionInfo2(context.Background(), "s1"); err == nil {
		t.Fatal("a failed read was accepted")
	}
}

func TestVCPolicies2MapTheCheckNames(t *testing.T) {
	got := VCPolicies2([]string{"signature", "expired", "not-before", "status-list", "unknown"}, " ")
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `[{"policy":"signature"},{"policy":"expiration"},{"policy":"not-before"}]` {
		t.Fatalf("policies = %s", raw)
	}
}

func TestSession2ChecksReadEveryShape(t *testing.T) {
	var s Session2
	if s.Checks() != nil {
		t.Fatal("a session without results has checks")
	}
	if ids, tokens := s.Credentials(); ids != nil || tokens != nil {
		t.Fatal("a session without data has credentials")
	}
	raw := `{"setup":{"core_flow":{"dcql_query":{"credentials":[{"id":"a","format":"jwt_vc_json"}]}}},
	  "presented_raw_data":{"vpToken":{"b":["t2"],"a":["t1"]}},
	  "policy_results":{
	    "vp_policies":{"a":{"z-check":{"success":true},"y-check":{"policy_executed":{"id":"named"},"success":false,"errors":["one",{"message":"two"},{"other":1},null]}}},
	    "vc_policies":[{"policy":"plain","success":false},{"policy":{"id":"by-id"},"success":false,"error":{"error":"bad"}},{"policy":7,"success":true}],
	    "specific_vc_policies":{"a":[{"policy":{"policy":"specific"},"success":true}]}}}`
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	ids, tokens := s.Credentials()
	if strings.Join(ids, ",") != "a,b" || strings.Join(tokens, ",") != "t1,t2" {
		t.Fatalf("credentials = %v %v", ids, tokens)
	}
	if s.FormatOf("a") != "jwt_vc_json" || s.FormatOf("b") != "" {
		t.Fatal("the format of a query id is wrong")
	}
	var got []string
	for _, c := range s.Checks() {
		got = append(got, c.Name+"="+c.Reason)
	}
	want := "named=one; two; map[other:1],z-check=,plain=the check failed,by-id=bad,=,specific="
	if strings.Join(got, ",") != want {
		t.Fatalf("checks = %s", strings.Join(got, ","))
	}
}
