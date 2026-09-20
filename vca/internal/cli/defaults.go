// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The laptop path asks no question. Every value that follows from the
// role and the DPG has a default here (ADR-007 decision 2,
// ADR-008 decision 7). An operator overrides any of them with a flag,
// the process environment, or the env file.

// dpgAPIURL is the container URL of the DPG API that one role calls.
// The host name and the port come from the compose file of the stack
// under deploy/vca/dpg. A production deployment overrides the value with
// VCA_DPG_URL.
var dpgAPIURL = map[configv1.Dpg]map[commonv1.Role]string{
	configv1.Dpg_DPG_WALTID: {
		commonv1.Role_ROLE_ISSUER:   "http://waltid-issuer-api:7002",
		commonv1.Role_ROLE_HOLDER:   "http://waltid-wallet-api:7001",
		commonv1.Role_ROLE_VERIFIER: "http://waltid-verifier-api:7003",
	},
	configv1.Dpg_DPG_INJI: {
		commonv1.Role_ROLE_ISSUER:   "http://inji-certify:8090",
		commonv1.Role_ROLE_HOLDER:   "http://inji-web:3000",
		commonv1.Role_ROLE_VERIFIER: "http://inji-verify-service:8000",
	},
	configv1.Dpg_DPG_CREDEBL: {
		commonv1.Role_ROLE_ISSUER:   "http://credebl-api-gateway:5000",
		commonv1.Role_ROLE_HOLDER:   "http://credebl-api-gateway:5000",
		commonv1.Role_ROLE_VERIFIER: "http://credebl-api-gateway:5000",
	},
}

// DefaultDpgURL returns the container URL of the DPG API of one pair.
// The admin role calls no DPG, so it gets an empty value.
func DefaultDpgURL(p Pair) string { return dpgAPIURL[p.Dpg][p.Role] }

// DpgURLTable renders the default DPG URL of every pair as a Markdown
// table. The deploy documentation includes it.
func DpgURLTable() string {
	rows := "| Role and DPG | Default `VCA_DPG_URL` |\n|---|---|\n"
	for _, p := range AllPairs() {
		url := DefaultDpgURL(p)
		if url == "" {
			continue
		}
		rows += fmt.Sprintf("| `%s` | `%s` |\n", p.Name(), url)
	}
	return rows
}
