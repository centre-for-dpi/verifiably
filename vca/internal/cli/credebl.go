// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // G501: the CREDEBL key derivation fixes MD5
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The CREDEBL platform admin and the first data of the platform
// (ADR-055 decision 4, plan section 3.8). The database initialisation
// of the CREDEBL release makes the platform admin from
// PLATFORM_ADMIN_EMAIL, with the roles, the agent types and the ledgers
// of the platform. The API gateway runs the migrations only, so vca dpg
// bootstrap credebl runs the initialisation once.

const (
	// PlatformAdminEmailSetting is the setting that names the platform
	// admin. It has no default.
	PlatformAdminEmailSetting = "VCA_CREDEBL_PLATFORM_ADMIN_EMAIL"
	// PlatformAdminEmailEnv is the variable of the CREDEBL stack .env
	// that the database initialisation reads.
	PlatformAdminEmailEnv = "PLATFORM_ADMIN_EMAIL"
	// PlatformInitMarker is the file under the deploy root that records
	// the initialisation. A run that finds it skips the initialisation.
	PlatformInitMarker = "credebl/initialised"
	// platformInitService is the container whose image holds the
	// initialisation script of the release with the tools it needs. Its
	// own command runs the migrations and then the script.
	platformInitService = "credebl-seed"
	// PlatformInitProfile is the compose profile of the initialisation.
	// No pair names it, so docker compose up never starts it.
	PlatformInitProfile = "credebl-init"
)

// The shared Credo agent that the stack file starts (P6-C0). The
// platform provisions an agent through the Docker socket upstream. The
// stack file starts one agent in multi tenancy mode instead, and the
// bootstrap binds it to the platform admin organisation with
// POST /v1/orgs/{org}/agents/configure. Every other organisation then
// gets a tenant wallet in it with POST /v1/orgs/{org}/agents/wallet.
const (
	// PlatformOrgName is the organisation that the initialisation of
	// the release makes for the platform admin.
	PlatformOrgName = "Platform-admin"
	// SharedAgentHost is the network alias of the shared agent. The
	// platform checks an agent address with a pattern that needs a
	// dotted host name.
	SharedAgentHost = "credebl-agent.vca.internal"
	// SharedAgentAdminURLSetting overrides the address the platform
	// reaches the admin port of the shared agent on.
	SharedAgentAdminURLSetting = "VCA_CREDEBL_AGENT_ADMIN_URL"
	// credeblAgentWallet is the wallet name the platform records for
	// the shared agent. The platform takes letters and digits only.
	credeblAgentWallet = "vcasharedagent"
	// credeblLabelMax is the longest wallet label the platform takes.
	credeblLabelMax = 25
)

// The generated keys of the shared agent and the schema file server in
// the CREDEBL stack .env (ADR-055 decision 1).
const (
	// SharedAgentWalletKeyEnv encrypts the wallet of the shared agent.
	SharedAgentWalletKeyEnv = "CREDEBL_AGENT_WALLET_KEY" //nolint:gosec // G101: this is a variable name, not a credential.
	// SharedAgentAPIKeyEnv is the API key of the admin port of the
	// shared agent. The agent needs 16 characters or more.
	SharedAgentAPIKeyEnv = "CREDEBL_AGENT_API_KEY" //nolint:gosec // G101: this is a variable name, not a credential.
	// SchemaFileServerSecretEnv signs the upload tokens of the
	// schema file server.
	SchemaFileServerSecretEnv = "CREDEBL_SCHEMA_FILE_SERVER_SECRET" //nolint:gosec // G101: this is a variable name, not a credential.
	// SchemaFileServerTokenEnv is the upload token the platform
	// sends to the schema file server. Setup signs it with the secret.
	SchemaFileServerTokenEnv = "CREDEBL_SCHEMA_FILE_SERVER_TOKEN" //nolint:gosec // G101: this is a variable name, not a credential.
	// SchemaFileServerIssuer is the issuer the schema file
	// server reads from its ISSUER variable, as the stack file sets it.
	SchemaFileServerIssuer = "credebl-platform"
)

// credeblPlatformAdmin returns the platform admin of a bootstrap run: the user
// of the environment, else the platform admin of the CREDEBL stack .env.
// No placeholder exists.
func credeblPlatformAdmin(opts BootstrapOptions) (string, error) {
	if user := opts.value(EnvBootstrapUser, ""); user != "" {
		return user, nil
	}
	stack, err := ReadStackEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		return "", err
	}
	if email := strings.TrimSpace(stack[PlatformAdminEmailEnv]); email != "" {
		return email, nil
	}
	return "", fmt.Errorf("CREDEBL sign in: run vca setup --role %s --dpg credebl with %s, or set %s",
		ShortName(opts.Pair.Role.String()), PlatformAdminEmailSetting, EnvBootstrapUser)
}

// initCredebl runs the database initialisation of the CREDEBL release
// once. The container of the API gateway reads the stack .env, so the
// script sees the platform admin and the generated secrets. A later run
// finds the marker and skips it. A failed run writes no marker.
func initCredebl(ctx context.Context, opts BootstrapOptions, result *BootstrapResult) error {
	deploy := filepath.Dir(opts.Dir)
	marker := filepath.Join(deploy, PlatformInitMarker)
	if _, err := os.Stat(marker); err == nil {
		result.step(opts.Out, "CREDEBL database initialisation present")
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", marker, err)
	}
	if opts.Run == nil {
		return errors.New("CREDEBL database initialisation: no command runner")
	}
	root := filepath.Dir(deploy)
	args := ComposeArgs(root, opts.Pair, []string{"--profile", PlatformInitProfile, "run", "--rm", platformInitService})
	if err := opts.Run(ctx, "docker", args); err != nil {
		return fmt.Errorf("CREDEBL database initialisation: %w", err)
	}
	if err := makeReadableDir(filepath.Dir(marker)); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(marker, []byte(stamp), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", marker, err)
	}
	result.step(opts.Out, "CREDEBL database initialisation done")
	return nil
}

// credeblOrgs is the answer of GET /v1/orgs.
type credeblOrgs struct {
	Data struct {
		Organizations []credeblOrg `json:"organizations"`
	} `json:"data"`
}

// findCredeblOrg looks one organisation up by its exact name. It
// returns an empty organisation when none has the name.
func findCredeblOrg(ctx context.Context, opts BootstrapOptions, base, token, name string) (credeblOrg, error) {
	listed, err := doJSON(ctx, opts.client(), http.MethodGet, base+"/v1/orgs?search="+url.QueryEscape(name), token, nil)
	if err != nil {
		return credeblOrg{}, fmt.Errorf("list the organisations: %w", err)
	}
	var orgs credeblOrgs
	if err := json.Unmarshal(listed, &orgs); err != nil {
		return credeblOrg{}, fmt.Errorf("list the organisations: %w", err)
	}
	for _, org := range orgs.Data.Organizations {
		if org.Name == name {
			return org, nil
		}
	}
	return credeblOrg{}, nil
}

// credeblCreated reports whether an agent call made the object, or
// found it made already: the platform answers the status conflict for an
// agent or a wallet that exists.
func credeblCreated(status int, answer []byte, action string) (bool, error) {
	switch {
	case status == http.StatusConflict:
		return false, nil
	case status >= 200 && status <= 299:
		return true, nil
	default:
		return false, fmt.Errorf("%s: the platform answered %d: %s", action, status, strings.TrimSpace(string(answer)))
	}
}

// bindSharedAgent binds the shared agent of the stack file to the
// platform admin organisation. A second run gets the status conflict and
// reports the agent present.
func bindSharedAgent(ctx context.Context, opts BootstrapOptions, base, token string, stack map[string]string, result *BootstrapResult) (credeblOrg, error) {
	platform, err := findCredeblOrg(ctx, opts, base, token, PlatformOrgName)
	if err != nil {
		return credeblOrg{}, err
	}
	if platform.ID == "" {
		return credeblOrg{}, fmt.Errorf("CREDEBL shared agent: the organisation %s is missing; the database initialisation makes it", PlatformOrgName)
	}
	key := strings.TrimSpace(stack[SharedAgentAPIKeyEnv])
	if key == "" {
		return credeblOrg{}, fmt.Errorf("CREDEBL shared agent: %s is missing from %s; run vca setup", SharedAgentAPIKeyEnv, StackEnvFile(configv1.Dpg_DPG_CREDEBL))
	}
	body, err := json.Marshal(map[string]string{
		"walletName":    credeblAgentWallet,
		"agentEndpoint": opts.value(SharedAgentAdminURLSetting, "http://"+SharedAgentHost+":8001"),
		"apiKey":        key,
	})
	if err != nil {
		return credeblOrg{}, fmt.Errorf("build the agent request: %w", err)
	}
	status, answer, err := doStatus(ctx, opts.client(), http.MethodPost,
		base+"/v1/orgs/"+url.PathEscape(platform.ID)+"/agents/configure", token, body)
	if err != nil {
		return credeblOrg{}, fmt.Errorf("CREDEBL shared agent: %w", err)
	}
	created, err := credeblCreated(status, answer, "CREDEBL shared agent")
	if err != nil {
		return credeblOrg{}, err
	}
	if created {
		result.step(opts.Out, "CREDEBL shared agent bound to %s", PlatformOrgName)
	} else {
		result.step(opts.Out, "CREDEBL shared agent present")
	}
	return platform, nil
}

// createOrgWallet gives one organisation a tenant wallet in the shared
// agent. A second run gets the status conflict and reports it present.
func createOrgWallet(ctx context.Context, opts BootstrapOptions, base, token string, org credeblOrg, result *BootstrapResult) error {
	label := org.Name
	if r := []rune(label); len(r) > credeblLabelMax {
		label = string(r[:credeblLabelMax])
	}
	body, err := json.Marshal(map[string]string{"label": label})
	if err != nil {
		return fmt.Errorf("build the wallet request: %w", err)
	}
	status, answer, err := doStatus(ctx, opts.client(), http.MethodPost,
		base+"/v1/orgs/"+url.PathEscape(org.ID)+"/agents/wallet", token, body)
	if err != nil {
		return fmt.Errorf("CREDEBL shared agent wallet: %w", err)
	}
	created, err := credeblCreated(status, answer, "CREDEBL shared agent wallet")
	if err != nil {
		return err
	}
	if created {
		result.step(opts.Out, "CREDEBL shared agent wallet created: %s", org.Name)
	} else {
		result.step(opts.Out, "CREDEBL shared agent wallet present: %s", org.Name)
	}
	return nil
}

// credeblPassword returns the password of the platform admin in the
// form the sign in of the platform reads: the JSON form of the value,
// encrypted by cryptoJSEncrypt under CRYPTO_PRIVATE_KEY of the stack
// .env. The sign in parses the decrypted text as JSON.
func credeblPassword(password, passphrase string, random io.Reader) (string, error) {
	return cryptoJSEncrypt([]byte(`"`+password+`"`), passphrase, random)
}

// cryptoJSEncrypt encrypts a text as CryptoJS.AES.encrypt does with a
// pass phrase: AES 256 in cipher block chaining mode with the OpenSSL
// key derivation, as base64 of the marker Salted__, the salt and the
// cipher text.
func cryptoJSEncrypt(text []byte, passphrase string, random io.Reader) (string, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("make the password salt: %w", err)
	}
	key, iv := evpKey([]byte(passphrase), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("make the cipher: %w", err)
	}
	n := aes.BlockSize - len(text)%aes.BlockSize
	plain := append(append([]byte(nil), text...), bytes.Repeat([]byte{byte(n)}, n)...)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(append(append([]byte("Salted__"), salt...), out...)), nil
}

// evpKey is the OpenSSL key derivation that CryptoJS uses, for a 32
// byte key and a 16 byte vector. The format fixes MD5.
func evpKey(passphrase, salt []byte) (key, iv []byte) {
	var derived, previous []byte
	for len(derived) < 48 {
		h := md5.New() //nolint:gosec // G401: the CREDEBL key derivation fixes MD5
		anyval.DiscardWrite(h.Write(previous))
		anyval.DiscardWrite(h.Write(passphrase))
		anyval.DiscardWrite(h.Write(salt))
		previous = h.Sum(nil)
		derived = append(derived, previous...)
	}
	return derived[:32], derived[32:48]
}

// schemaFileServerToken signs the upload token of the platform for the
// schema file server with its secret, as an HS256 JSON web token.
func schemaFileServerToken(secret string, now time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":%q,"sub":"credebl-platform","iat":%d}`, SchemaFileServerIssuer, now.Unix())))
	mac := hmac.New(sha256.New, []byte(secret))
	anyval.DiscardWrite(mac.Write([]byte(header + "." + claims)))
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// The platform admin password and the master table of the CREDEBL
// initialisation (P6-C0d, ADR-055 decision 1).
const (
	// PlatformAdminPasswordEnv is the generated password of the platform
	// admin in the CREDEBL stack .env.
	PlatformAdminPasswordEnv = "CREDEBL_PLATFORM_ADMIN_PASSWORD" //nolint:gosec // G101: this is a variable name, not a credential.
	// CredeblMasterTableFile is the master table that setup writes under
	// the deploy root.
	CredeblMasterTableFile = "credebl/credebl-master-table.json" //nolint:gosec // G101: a file path, not a credential.
	// CredeblMasterTableMount is where the initialisation reads its
	// master table: the working directory libs/prisma-service of the
	// image, then prisma/data/credebl-master-table.
	CredeblMasterTableMount = "/app/libs/prisma-service/prisma/data/credebl-master-table/credebl-master-table.json" //nolint:gosec // G101: a file path, not a credential.
)

// The sign in of the CREDEBL adapter in the .env of a CREDEBL pair.
const (
	// CredeblAdapterEmailEnv names the platform admin.
	CredeblAdapterEmailEnv = "VCA_CREDEBL_EMAIL" //nolint:gosec // G101: this is a variable name, not a credential.
	// CredeblAdapterPasswordEnv holds the password of the platform admin.
	CredeblAdapterPasswordEnv = "VCA_CREDEBL_PASSWORD" //nolint:gosec // G101: this is a variable name, not a credential.
	// CredeblAdapterCryptoKeyEnv holds CRYPTO_PRIVATE_KEY of the stack.
	CredeblAdapterCryptoKeyEnv = "VCA_CREDEBL_CRYPTO_KEY" //nolint:gosec // G101: this is a variable name, not a credential.
)

// CredeblAdapterValues returns the sign in of the CREDEBL adapter for
// the .env of a CREDEBL pair: the platform admin, its generated
// password, and CRYPTO_PRIVATE_KEY, all from the CREDEBL stack .env. A
// pair of another DPG gets nothing. A flag of the operator still wins,
// because the pass through values come later.
func CredeblAdapterValues(p Pair, stack map[string]string) map[string]string {
	if p.Dpg != configv1.Dpg_DPG_CREDEBL {
		return nil
	}
	out := map[string]string{}
	for name, from := range map[string]string{
		CredeblAdapterEmailEnv:     PlatformAdminEmailEnv,
		CredeblAdapterPasswordEnv:  PlatformAdminPasswordEnv,
		CredeblAdapterCryptoKeyEnv: "CRYPTO_PRIVATE_KEY",
	} {
		if value := strings.TrimSpace(stack[from]); value != "" {
			out[name] = value
		}
	}
	return out
}
