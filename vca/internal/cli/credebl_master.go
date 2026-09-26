// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The master table of the CREDEBL initialisation (P6-C0d, ADR-055
// decision 1). The initialisation of the release reads the platform
// admin password, the password of the Keycloak user, the mail key and
// the user id of the platform admin from
// libs/prisma-service/prisma/data/credebl-master-table/credebl-master-table.json,
// which the platform repository commits. Setup writes a table of its
// own with the generated password of the stack .env, and the stack file
// mounts it over the committed one. The rows that hold no credential
// stay as the release has them: the organisation roles, the agent
// types, the ledgers, the user roles and the ecosystem roles.

// credeblMasterTable is the shape of the master table, in the order of
// the file of the release.
type credeblMasterTable struct {
	PlatformConfigData            credeblPlatformConfig `json:"platformConfigData"`
	PlatformAdminData             credeblPlatformUser   `json:"platformAdminData"`
	PlatformAdminOrganizationData credeblPlatformOrg    `json:"platformAdminOrganizationData"`
	PlatformAdminKeycloakPassword string                `json:"platformAdminKeycloakPassword"`
	OrgRoleData                   []credeblNamedRole    `json:"orgRoleData"`
	AgentTypeData                 []credeblAgentType    `json:"agentTypeData"`
	OrgAgentTypeData              []credeblAgentType    `json:"orgAgentTypeData"`
	LedgerData                    []credeblLedgerRow    `json:"ledgerData"`
	LedgerConfig                  []credeblLedgerConfig `json:"ledgerConfig"`
	UserRoleData                  []credeblUserRole     `json:"userRoleData"`
	EcosystemRoleData             []credeblNamedRole    `json:"ecosystemRoleData"`
}

// credeblPlatformConfig is the platform configuration row.
type credeblPlatformConfig struct {
	ExternalIP      string `json:"externalIp"`
	InboundEndpoint string `json:"inboundEndpoint"`
	Username        string `json:"username"`
	SgAPIKey        string `json:"sgApiKey"`
	EmailFrom       string `json:"emailFrom"`
	APIEndpoint     string `json:"apiEndpoint"`
	TailsFileServer string `json:"tailsFileServer"`
}

// credeblPlatformUser is the user row of the platform admin. The
// initialisation sets the email and the user name from
// PLATFORM_ADMIN_EMAIL.
type credeblPlatformUser struct {
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Email            string `json:"email"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	VerificationCode string `json:"verificationCode"`
	IsEmailVerified  bool   `json:"isEmailVerified"`
	SupabaseUserID   string `json:"supabaseUserId"`
}

// credeblPlatformOrg is the organisation of the platform admin.
type credeblPlatformOrg struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	LogoURL       string `json:"logoUrl"`
	Website       string `json:"website"`
	CreatedBy     string `json:"createdBy"`
	LastChangedBy string `json:"lastChangedBy"`
}

// credeblNamedRole is a role with a description.
type credeblNamedRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// credeblAgentType is one agent type.
type credeblAgentType struct {
	Agent string `json:"agent"`
}

// credeblUserRole is one user role.
type credeblUserRole struct {
	Role string `json:"role"`
}

// credeblLedgerRow is one ledger the platform writes on.
type credeblLedgerRow struct {
	Name           string `json:"name"`
	NetworkType    string `json:"networkType"`
	PoolConfig     string `json:"poolConfig"`
	IsActive       bool   `json:"isActive"`
	NetworkString  string `json:"networkString"`
	NymTxnEndpoint string `json:"nymTxnEndpoint"`
	IndyNamespace  string `json:"indyNamespace"`
}

// credeblLedgerConfig maps the DID methods of one ledger family.
type credeblLedgerConfig struct {
	Name    string         `json:"name"`
	Details map[string]any `json:"details"`
}

// Upstream rows that hold no credential, as the master table of the
// platform names them on 2026-09-27.
var (
	credeblOrgRoles = []credeblNamedRole{
		{"owner", "Organization Owner"},
		{"admin", "Organization Admin"},
		{"issuer", "Organization Credential Issuer"},
		{"verifier", "Organization Credential Verifier"},
		{"holder", "Receives credentials issued by organization"},
		{"member", "Joins the organization as member"},
		{"platform_admin", "To setup all the platform of the user"},
	}
	credeblEcosystemRoles = []credeblNamedRole{
		{"Ecosystem Lead", "Ecosystem Lead"},
		{"Ecosystem Member", "Ecosystem Member"},
	}
	credeblLedgers = []credeblLedgerRow{
		{"Bcovrin Testnet", "testnet", "https://raw.githubusercontent.com/bcgov/von-network/main/BCovrin/genesis_test", true, "testnet", "http://test.bcovrin.vonx.io/register", "bcovrin:testnet"},
		{"Indicio Testnet", "testnet", "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_testnet_genesis", true, "testnet", "https://selfserve.indiciotech.io/nym", "indicio:testnet"},
		{"Indicio Demonet", "demonet", "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_demonet_genesis", true, "demonet", "https://selfserve.indiciotech.io/nym", "indicio:demonet"},
		{"Indicio Mainnet", "mainnet", "https://raw.githubusercontent.com/Indicio-tech/indicio-network/main/genesis_files/pool_transactions_mainnet_genesis", true, "mainnet", "https://selfserve.indiciotech.io/nym", "indicio:mainnet"},
		{"Polygon Testnet", "testnet", "", true, "testnet", "", "polygon:testnet"},
		{"Polygon Mainnet", "mainnet", "", true, "mainnet", "", "polygon:mainnet"},
		{"NA", "NA", "NA", true, "NA", "NA", "no_ledger"},
	}
)

// credeblLedgerConfigs returns the DID methods of each ledger family.
func credeblLedgerConfigs() []credeblLedgerConfig {
	return []credeblLedgerConfig{
		{Name: "indy", Details: map[string]any{"did:indy": map[string]any{
			"bcovrin:testnet": "did:indy:bcovrin:testnet",
			"indicio:demonet": "did:indy:indicio:demonet",
			"indicio:mainnet": "did:indy:indicio:mainnet",
			"indicio:testnet": "did:indy:indicio:testnet",
		}}},
		{Name: "polygon", Details: map[string]any{"did:polygon": map[string]any{
			"mainnet": "did:polygon:mainnet",
			"testnet": "did:polygon:testnet",
		}}},
		{Name: "noLedger", Details: map[string]any{"did:key": "did:key", "did:web": "did:web"}},
	}
}

// credeblPlatformName is the first and last name of the platform admin
// that the release sets, and the name of its Keycloak user.
const credeblPlatformName = "CREDEBL"

// CredeblMasterTable renders the master table of the initialisation from
// the values of the CREDEBL stack .env. The platform admin password is
// PlatformAdminPasswordEnv, encrypted with CRYPTO_PRIVATE_KEY as the
// initialisation decrypts it, once for the platform user and once for
// the Keycloak user. The user id of the platform admin is random. The
// mail key stays empty until the operator names a mail provider.
func CredeblMasterTable(stack map[string]string, random io.Reader) ([]byte, error) {
	password := strings.TrimSpace(stack[PlatformAdminPasswordEnv])
	key := strings.TrimSpace(stack["CRYPTO_PRIVATE_KEY"])
	if password == "" || key == "" {
		return nil, fmt.Errorf("the CREDEBL master table needs %s and CRYPTO_PRIVATE_KEY", PlatformAdminPasswordEnv)
	}
	// The initialisation hands the decrypted text to Keycloak as it is,
	// so the plain text carries no JSON quotes.
	user, err := cryptoJSEncrypt([]byte(password), key, random)
	if err != nil {
		return nil, err
	}
	keycloak, err := cryptoJSEncrypt([]byte(password), key, random)
	if err != nil {
		return nil, err
	}
	id, err := randomUUID(random)
	if err != nil {
		return nil, err
	}
	table := credeblMasterTable{
		PlatformConfigData: credeblPlatformConfig{
			ExternalIP:      SharedAgentHost,
			InboundEndpoint: "http://" + SharedAgentHost + ":9001",
			Username:        "credebl",
			EmailFrom:       strings.TrimSpace(stack[PlatformAdminEmailEnv]),
			APIEndpoint:     "http://credebl-api-gateway:5000",
		},
		PlatformAdminData: credeblPlatformUser{
			FirstName: credeblPlatformName, LastName: credeblPlatformName,
			Password: user, IsEmailVerified: true, SupabaseUserID: id,
		},
		PlatformAdminOrganizationData: credeblPlatformOrg{Name: PlatformOrgName, Description: PlatformOrgName},
		PlatformAdminKeycloakPassword: keycloak,
		OrgRoleData:                   credeblOrgRoles,
		AgentTypeData:                 []credeblAgentType{{"AFJ"}, {"ACAPY"}},
		OrgAgentTypeData:              []credeblAgentType{{"DEDICATED"}, {"SHARED"}},
		LedgerData:                    credeblLedgers,
		LedgerConfig:                  credeblLedgerConfigs(),
		UserRoleData:                  []credeblUserRole{{"HOLDER"}, {"DEFAULT_USER"}},
		EcosystemRoleData:             credeblEcosystemRoles,
	}
	out, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the CREDEBL master table: %w", err)
	}
	return append(out, '\n'), nil
}

// randomUUID returns a random UUID of version 4.
func randomUUID(random io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("make a user id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
