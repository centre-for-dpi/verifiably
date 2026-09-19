// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

func TestDerivedProofIsReserved(t *testing.T) {
	check, ok := Find(NameDerivedProof)
	if !ok {
		t.Fatal("want the derived proof check")
	}
	if check.Mandatory {
		t.Error("the reserved check must not be mandatory")
	}
	p := Presentation{Credentials: []Credential{{Format: vc.FormatJSONLD}}}
	got := check.Run(context.Background(), p, Context{})
	if len(got) != 1 {
		t.Fatalf("want one result, got %d", len(got))
	}
	if got[0].Result != Skip || got[0].Detail != DerivedProofDetail {
		t.Fatalf("result = %+v", got[0])
	}
	if got[0].Evidence["format"] != string(vc.FormatJSONLD) {
		t.Errorf("evidence = %v", got[0].Evidence)
	}
	empty := check.Run(context.Background(), Presentation{}, Context{})
	if len(empty) != 1 || empty[0].CredentialIndex != WholePresentation {
		t.Fatalf("empty presentation = %+v", empty)
	}
}
