package vctypes

import "testing"

func TestCredentialVct(t *testing.T) {
	cases := []struct {
		name string
		s    Schema
		base string
		want string
	}{
		{
			name: "explicit Vct wins",
			s:    Schema{ID: "custom-1", Vct: "https://issuer.example/vct/BankId"},
			base: "https://verify.example.test",
			want: "https://issuer.example/vct/BankId",
		},
		{
			name: "host-derived from base when Vct empty",
			s:    Schema{ID: "custom-1"},
			base: "https://verify.example.test",
			want: "https://verify.example.test/credentials/custom-1",
		},
		{
			name: "trailing slash on base is trimmed",
			s:    Schema{ID: "abc"},
			base: "https://verify.example.test/",
			want: "https://verify.example.test/credentials/abc",
		},
		{
			name: "empty base falls back to localhost (dev)",
			s:    Schema{ID: "abc"},
			base: "",
			want: "http://localhost:8080/credentials/abc",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.CredentialVct(c.base); got != c.want {
				t.Errorf("CredentialVct(%q) = %q, want %q", c.base, got, c.want)
			}
		})
	}
}
