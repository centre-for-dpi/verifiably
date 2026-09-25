// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

func TestChecksAndFind(t *testing.T) {
	checks := Checks()
	if len(checks) != 11 {
		t.Fatalf("want eleven checks, got %d", len(checks))
	}
	mandatory := 0
	for _, c := range checks {
		if c.Run == nil {
			t.Fatalf("check %s has no function", c.Name)
		}
		if c.Description == "" {
			t.Fatalf("check %s has no description", c.Name)
		}
		if c.Mandatory {
			mandatory++
		}
	}
	if mandatory != 6 {
		t.Fatalf("want six mandatory checks, got %d", mandatory)
	}
	if _, ok := Find(NameStatus); !ok {
		t.Fatal("want the status check")
	}
	if _, ok := Find("nothing"); ok {
		t.Fatal("want no check with an unknown name")
	}
	if names := Names(); len(names) != 11 || names[0] != NameAudience {
		t.Fatalf("want eleven sorted names, got %v", names)
	}
}

// fullContext returns a context where every port answers.
func fullContext(t *testing.T, b builder) Context {
	pc := base()
	pc.Keys = b.keys(t)
	pc.Trust = trustAll
	pc.Status = bytesFetch(bitstringDoc(t, 7))
	pc.Schemas = bytesFetch(schemaDoc)
	return pc
}

func TestEvaluateValid(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true, aud: "verifier", nonce: "n1"})
	pc := fullContext(t, b)
	pc.Audience = "verifier"
	pc.Nonce = "n1"
	got := Evaluate(context.Background(), pres(c), pc, Set{
		ID: "default", Version: 2,
		Settings: []Setting{{Name: NameTrustChain, Blocking: true}},
	})
	if got.Verdict != Valid {
		t.Fatalf("want VALID, got %s: %+v", got.Verdict, got.Results)
	}
	if got.SetID != "default" || got.Version != 2 {
		t.Fatalf("want the policy set version, got %s %d", got.SetID, got.Version)
	}
}

func TestEvaluateInvalid(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{})
	pc := fullContext(t, b)
	got := Evaluate(context.Background(), pres(c), pc, Set{})
	if got.Verdict != Invalid {
		t.Fatalf("want INVALID, got %s", got.Verdict)
	}
}

func TestEvaluateIndeterminate(t *testing.T) {
	b := newBuilder(t)
	c := b.jwtCred(t, map[string]any{"iss": "did:web:issuer"})
	pc := base()
	got := Evaluate(context.Background(), pres(c), pc, Set{})
	if got.Verdict != Indeterminate {
		t.Fatalf("want INDETERMINATE, got %s: %+v", got.Verdict, got.Results)
	}
}

func TestEvaluateUnknownCheck(t *testing.T) {
	b := newBuilder(t)
	pc := fullContext(t, b)
	got := Evaluate(context.Background(), pres(b.sdjwtCred(t, sdjwtOptions{keyBinding: true})), pc,
		Set{Settings: []Setting{{Name: "nothing"}}})
	found := false
	for _, r := range got.Results {
		if r.Name == "nothing" && r.Result == Error {
			found = true
		}
	}
	if !found {
		t.Fatalf("want an ERROR for the unknown check, got %+v", got.Results)
	}
}

func TestEvaluateSkipsMandatorySetting(t *testing.T) {
	b := newBuilder(t)
	pc := fullContext(t, b)
	c := objectCred(vc.FormatJSONLD, map[string]any{"issuer": "did:web:issuer"})
	got := Evaluate(context.Background(), pres(c), pc, Set{
		Settings: []Setting{{Name: NameSignature}},
	})
	signatures := 0
	for _, r := range got.Results {
		if r.Name == NameSignature {
			signatures++
		}
	}
	if signatures != 1 {
		t.Fatalf("want the signature check once, got %d", signatures)
	}
}

func TestEvaluateNonBlockingFailure(t *testing.T) {
	b := newBuilder(t)
	pc := fullContext(t, b)
	pc.Trust = func(context.Context, string, string) (Trust, error) { return Trust{}, nil }
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true})
	got := Evaluate(context.Background(), pres(c), pc, Set{
		Settings: []Setting{{Name: NameTrustChain, Blocking: false}},
	})
	if got.Verdict != Valid {
		t.Fatalf("want VALID for a check that does not block, got %s", got.Verdict)
	}
}

func TestParamsOfSet(t *testing.T) {
	set := Set{Settings: []Setting{{Name: NameStatus, Params: map[string]string{ParamFailMode: FailOpen}}}}
	if got := paramsOf(set, NameStatus)[ParamFailMode]; got != FailOpen {
		t.Fatalf("want the fail mode, got %q", got)
	}
	if got := paramsOf(set, NameSchema); got != nil {
		t.Fatalf("want no parameters, got %v", got)
	}
}
