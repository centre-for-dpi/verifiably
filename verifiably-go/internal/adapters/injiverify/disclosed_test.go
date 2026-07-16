package injiverify

import (
	"reflect"
	"testing"
)

// disclosedForRequest surfaces the disclosed claim values for a single-credential
// OID4VP verify: filtered to the requested fields, or all claims when nothing was
// requested / nothing matched (so the result never shows the empty "no structured
// claims" fallback when the VC actually carried the values).
func TestDisclosedForRequest(t *testing.T) {
	claims := map[string]string{"testa_id": "5500000005", "last_name": "Abdullahi", "extra": "x"}

	t.Run("filters to the requested fields", func(t *testing.T) {
		got := disclosedForRequest(claims, []string{"testa_id", "last_name"})
		want := map[string]string{"testa_id": "5500000005", "last_name": "Abdullahi"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("skips requested fields the credential does not carry", func(t *testing.T) {
		got := disclosedForRequest(claims, []string{"testa_id", "missing"})
		want := map[string]string{"testa_id": "5500000005"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("no requested fields (full disclosure) returns all claims", func(t *testing.T) {
		if got := disclosedForRequest(claims, nil); !reflect.DeepEqual(got, claims) {
			t.Errorf("got %v, want all claims %v", got, claims)
		}
	})

	t.Run("no requested field matches -> fall back to all claims", func(t *testing.T) {
		if got := disclosedForRequest(claims, []string{"nope", "also_nope"}); !reflect.DeepEqual(got, claims) {
			t.Errorf("got %v, want all claims (fallback) %v", got, claims)
		}
	})

	t.Run("empty claims -> nil", func(t *testing.T) {
		if got := disclosedForRequest(map[string]string{}, []string{"testa_id"}); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}
