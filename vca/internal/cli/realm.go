// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
)

// EnvOidcPublicURL is the browser facing base URL of the Keycloak of the
// stack in the .env of a pair. The realm helper calls the admin API
// there.
const EnvOidcPublicURL = "VCA_OIDC_PUBLIC_URL"

// RealmOptions holds one run of vca dpg realm (ADR-035 decision 6).
type RealmOptions struct {
	BootstrapOptions
	// Allowed is the new value of self registration of the realm.
	Allowed bool
	// Admin records the change on the provider records of the realm, so
	// the first run checklist marks the step done. Nil records nothing.
	Admin *AdminClient
}

// keycloakURL returns the Keycloak base URL of the run: the bootstrap
// override, else the public OIDC URL of the pair.
func (o RealmOptions) keycloakURL() (string, error) {
	raw := o.Values[EnvBootstrapURL]
	if raw == "" {
		raw = o.Values[EnvOidcPublicURL]
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("realm: set %s or %s to an absolute http or https URL", EnvBootstrapURL, EnvOidcPublicURL)
	}
	return raw, nil
}

// RealmRegistration turns self registration of the realm of the pair role
// on or off at the Keycloak of the stack. It rewrites the generated realm
// file with the same value, so a later vca dpg bootstrap keeps it. It
// never creates a realm: a missing realm names the bootstrap command.
// With an admin client it also sets the register action of every
// provider record of that realm, so the first run checklist of the admin
// portal marks "Turn off self registration" done (ADR-035 decision 6).
func RealmRegistration(ctx context.Context, opts RealmOptions) (BootstrapResult, error) {
	var result BootstrapResult
	base, err := opts.keycloakURL()
	if err != nil {
		return result, err
	}
	realm := RealmName(opts.Pair.Role)
	path := opts.realmPath()
	body, err := realmWithRegistration(path, opts.Allowed)
	if err != nil {
		return result, err
	}
	token, err := keycloakToken(ctx, opts.BootstrapOptions, base)
	if err != nil {
		return result, err
	}
	status, _, err := doStatus(ctx, opts.client(), http.MethodGet, base+"/admin/realms/"+realm, token, nil)
	if err != nil {
		return result, fmt.Errorf("read the realm: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return result, fmt.Errorf("the Keycloak at %s has no realm %s; run vca dpg bootstrap %s --role %s first",
			base, realm, ShortName(opts.Pair.Dpg.String()), ShortName(opts.Pair.Role.String()))
	default:
		return result, fmt.Errorf("read the realm: the server answered %d", status)
	}
	if _, putErr := doJSON(ctx, opts.client(), http.MethodPut, base+"/admin/realms/"+realm, token, body); putErr != nil {
		return result, fmt.Errorf("update the realm: %w", putErr)
	}
	if writeErr := writeKeeping(path, body); writeErr != nil {
		return result, writeErr
	}
	result.step(opts.Out, "realm %s: self registration %s", realm, onOff(opts.Allowed))
	if opts.Admin == nil {
		return result, nil
	}
	ids, err := recordRegistration(ctx, opts, base, realm)
	if err != nil {
		return result, err
	}
	if len(ids) == 0 {
		result.step(opts.Out, "admin service: no provider record of realm %s to update", realm)
	}
	for _, id := range ids {
		result.step(opts.Out, "admin service: provider %s register action set to %s", id, registerWord(opts.Allowed))
	}
	return result, nil
}

// realmWithRegistration reads the generated realm file and returns it
// with the registrationAllowed member set. Every other member stays, so a
// hand edited realm survives.
func realmWithRegistration(path string, allowed bool) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from the pair
	if err != nil {
		return nil, fmt.Errorf("read the generated realm: %w", err)
	}
	var doc map[string]json.RawMessage
	if parseErr := json.Unmarshal(data, &doc); parseErr != nil {
		return nil, fmt.Errorf("read the generated realm %s: %w", path, parseErr)
	}
	doc["registrationAllowed"] = json.RawMessage(strconv.FormatBool(allowed))
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode the realm: %w", err)
	}
	return append(body, '\n'), nil
}

// writeKeeping replaces the file with data and keeps its mode.
func writeKeeping(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, data, mode); err != nil { // #nosec G306 -- the file keeps the mode setup gave it
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// recordRegistration sets the register action of every Keycloak provider
// record of the realm at the stack: none when registration is off, else
// unspecified so the metadata decides (ADR-035 decision 3). It returns
// the ids it changed.
func recordRegistration(ctx context.Context, opts RealmOptions, base, realm string) ([]string, error) {
	list := AdminCommand{Method: "ListAuthProviders"}
	answer, err := opts.Admin.Call(ctx, list, nil)
	if err != nil {
		return nil, fmt.Errorf("list the providers: %w", err)
	}
	var res adminv1.ListAuthProvidersResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(answer, &res); err != nil {
		return nil, fmt.Errorf("list the providers: %w", err)
	}
	want := adminv1.Registration_REGISTRATION_NONE
	if opts.Allowed {
		want = adminv1.Registration_REGISTRATION_UNSPECIFIED
	}
	hosts := map[string]bool{hostOf(base): true}
	if name := KeycloakContainer(opts.Pair.Dpg); name != "" {
		hosts[name] = true
	}
	var ids []string
	for _, pr := range res.GetProviders() {
		if !providerOfRealm(pr, realm, hosts) {
			continue
		}
		pr.Registration = want
		body, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(&adminv1.UpdateAuthProviderRequest{Provider: pr})
		if err != nil {
			return nil, fmt.Errorf("encode the provider %s: %w", pr.GetId(), err)
		}
		if _, err := opts.Admin.Call(ctx, AdminCommand{Method: "UpdateAuthProvider"}, body); err != nil {
			return nil, fmt.Errorf("update the provider %s: %w", pr.GetId(), err)
		}
		ids = append(ids, pr.GetId())
	}
	return ids, nil
}

// providerOfRealm reports whether a provider record is the realm at one
// of the Keycloak hosts of the stack: the record is of kind keycloak and
// its discovery URL names the realm at such a host.
func providerOfRealm(pr *adminv1.AuthProvider, realm string, hosts map[string]bool) bool {
	if pr.GetKind() != adminv1.ProviderKind_PROVIDER_KIND_KEYCLOAK {
		return false
	}
	u, err := url.Parse(pr.GetDiscoveryUrl())
	if err != nil || !hosts[u.Hostname()] {
		return false
	}
	got, ok := realmOfDiscovery(u)
	return ok && got == realm
}

// realmOfDiscovery returns the realm of a Keycloak discovery URL, which
// has the path /realms/<realm>/.well-known/openid-configuration.
func realmOfDiscovery(u *url.URL) (string, bool) {
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "realms" && parts[i+1] != "" && parts[i+2] == ".well-known" {
			return parts[i+1], true
		}
	}
	return "", false
}

// ParseOnOff reads on or off.
func ParseOnOff(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, errors.New("set --registration to on or off")
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// registerWord names the register action a provider record gets.
func registerWord(allowed bool) string {
	if allowed {
		return "the metadata default"
	}
	return "none"
}
