// SPDX-License-Identifier: Apache-2.0

package helptext_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"

	// The admin and trust services must be linked, so their descriptors
	// reach the global registry.
	_ "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	_ "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

const adminService = "vca.admin.v1.AdminService"

func TestDescribeReadsTheProtoOption(t *testing.T) {
	got := helptext.Describe(adminService, "CreateTenant")
	if got != "Creates one tenant." {
		t.Fatalf("Describe = %q", got)
	}
}

func TestDescribeAcceptsTheShortServiceName(t *testing.T) {
	if got := helptext.Describe("AdminService", "ListTenants"); got != "Returns tenants in pages." {
		t.Fatalf("Describe = %q", got)
	}
}

func TestDescribeReturnsEmptyForUnknownNames(t *testing.T) {
	cases := [][2]string{
		{adminService, "NoSuchRPC"},
		{"vca.admin.v1.NoService", "CreateTenant"},
		{"", "CreateTenant"},
	}
	for _, c := range cases {
		if got := helptext.Describe(c[0], c[1]); got != "" {
			t.Errorf("Describe(%q, %q) = %q, want empty", c[0], c[1], got)
		}
	}
}

func TestServiceReturnsEveryRPCInProtoOrder(t *testing.T) {
	entries := helptext.Service(adminService)
	if len(entries) < 20 {
		t.Fatalf("got %d entries, want every admin RPC", len(entries))
	}
	if entries[0].Method != "CreateTenant" {
		t.Errorf("first method = %q, want CreateTenant", entries[0].Method)
	}
	last := entries[len(entries)-1]
	if last.Method != "ListCommands" {
		t.Errorf("last method = %q, want ListCommands", last.Method)
	}
	for _, e := range entries {
		if e.Description == "" {
			t.Errorf("%s has no description option", e.Procedure)
		}
		if e.Service != adminService {
			t.Errorf("service = %q", e.Service)
		}
		if e.ShortService() != "AdminService" {
			t.Errorf("short service = %q", e.ShortService())
		}
		if want := "/" + adminService + "/" + e.Method; e.Procedure != want {
			t.Errorf("procedure = %q, want %q", e.Procedure, want)
		}
	}
}

func TestServiceReturnsNilForAnUnknownName(t *testing.T) {
	if got := helptext.Service("vca.nothing.v1.Service"); got != nil {
		t.Fatalf("Service = %v, want nil", got)
	}
}

func TestAllSortsByProcedureAndHoldsEveryLinkedService(t *testing.T) {
	all := helptext.All()
	if len(all) == 0 {
		t.Fatal("All returned nothing")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Procedure > all[i].Procedure {
			t.Fatalf("All is not sorted at %d: %q then %q", i, all[i-1].Procedure, all[i].Procedure)
		}
	}
	var admin, trust int
	for _, e := range all {
		switch e.Service {
		case adminService:
			admin++
		case "vca.trust.v1.TrustService":
			trust++
		}
	}
	if admin == 0 || trust == 0 {
		t.Fatalf("admin=%d trust=%d, want both services", admin, trust)
	}
}

func TestTrustRPCsHaveNoDescriptionOption(t *testing.T) {
	// The trust proto sets no description option. The reader must
	// return an empty string and must not fail.
	for _, e := range helptext.Service("vca.trust.v1.TrustService") {
		if e.Description != "" {
			t.Errorf("%s has description %q", e.Procedure, e.Description)
		}
	}
}

func TestShortServiceWithoutAPackage(t *testing.T) {
	e := helptext.Entry{Service: "AdminService"}
	if e.ShortService() != "AdminService" {
		t.Fatalf("ShortService = %q", e.ShortService())
	}
}

func TestDescriptionsAreOneSentence(t *testing.T) {
	for _, e := range helptext.Service(adminService) {
		if !strings.HasSuffix(e.Description, ".") {
			t.Errorf("%s: %q does not end with a full stop", e.Procedure, e.Description)
		}
		if strings.Contains(e.Description, "  ") {
			t.Errorf("%s: %q has a double space", e.Procedure, e.Description)
		}
	}
}
