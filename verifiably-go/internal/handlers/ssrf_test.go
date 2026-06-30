package handlers

import (
	"strings"
	"testing"
)

// net.LookupHost with a numeric IP literal returns that IP verbatim on all
// platforms, so these tests are deterministic without internet access.

func TestSsrfBlockHost_Blocked(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"loopback IPv4", "127.0.0.1"},
		{"loopback IPv4 alt", "127.100.0.1"},
		{"loopback hostname", "localhost"},
		{"private 10/8", "10.0.0.1"},
		{"private 172.16/12", "172.16.0.1"},
		{"private 192.168/16", "192.168.1.1"},
		{"link-local / AWS metadata", "169.254.169.254"},
		{"CGNAT / shared space", "100.64.0.1"},
		{"this-network 0/8", "0.0.0.1"},
		{"IPv6 loopback", "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ssrfBlockHost(tc.host)
			if err == nil {
				t.Errorf("ssrfBlockHost(%q) = nil, want error (host should be blocked)", tc.host)
			}
		})
	}
}

func TestValidateOfferURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name:    "openid-credential-offer passes through unconditionally",
			raw:     "openid-credential-offer://credential_offer%3Fissuer%3Dhttps%3A%2F%2Fissuer.example.com",
			wantErr: false,
		},
		{
			name:    "https loopback blocked",
			raw:     "https://127.0.0.1/offer",
			wantErr: true,
		},
		{
			name:    "https private 10/8 blocked",
			raw:     "https://10.1.2.3/offer",
			wantErr: true,
		},
		{
			name:    "https cloud metadata blocked",
			raw:     "https://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "https private 192.168 blocked",
			raw:     "https://192.168.0.1/offer",
			wantErr: true,
		},
		{
			name:    "https CGNAT blocked",
			raw:     "https://100.64.0.1/offer",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOfferURL(tc.raw)
			if tc.wantErr && err == nil {
				t.Errorf("validateOfferURL(%q) = nil, want error", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateOfferURL(%q) = %v, want nil", tc.raw, err)
			}
		})
	}
}

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		errFrag string
	}{
		{"empty string is allowed (optional field)", "", false, ""},
		{"non-https rejected", "http://example.com/hook", true, "https"},
		{"loopback rejected", "https://127.0.0.1/hook", true, "reserved"},
		{"private range rejected", "https://10.0.0.1/hook", true, "reserved"},
		{"cloud metadata rejected", "https://169.254.169.254/hook", true, "reserved"},
		{"missing host rejected", "https:///path", true, "host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateWebhookURL(tc.raw)
			if tc.wantErr && err == nil {
				t.Errorf("validateWebhookURL(%q) = nil, want error", tc.raw)
				return
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateWebhookURL(%q) = %v, want nil", tc.raw, err)
				return
			}
			if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("error %q should contain %q", err.Error(), tc.errFrag)
			}
		})
	}
}
