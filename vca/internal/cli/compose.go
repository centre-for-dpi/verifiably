// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"sort"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// ComposeFile is the path of the committed compose file, from the
// repository root (ADR-008 decision 1).
const ComposeFile = "deploy/vca/compose.yaml"

// ComposeProject is the compose project name.
const ComposeProject = "vca"

// Theme file delivery (ADR-032 decision 1). Every UI service reads
// ThemeFileEnv. Compose mounts the file of the host at ThemeMountPath,
// read only. The host file is deploy/vca/theme.yaml, next to the compose
// file, unless ThemeHostFileEnv names another one, for example the git
// ignored deploy/theme.local.yaml.
const (
	ThemeFileEnv     = "VCA_THEME_FILE"
	ThemeHostFileEnv = "VCA_THEME_HOST_FILE"
	ThemeMountPath   = "/etc/vca/theme.yaml"
	themeHostDefault = "./theme.yaml"
)

// DpgStackFiles lists the compose file of each DPG stack. The main
// compose file pulls them in with include (ADR-008 decision 3).
func DpgStackFiles() []string {
	out := make([]string, 0, len(Dpgs()))
	for _, d := range Dpgs() {
		out = append(out, "dpg/"+ShortName(d.String())+".yaml")
	}
	return out
}

// composeServiceName is the compose service name of one VCA service in
// one pair. Two pairs run the same image, so the pair name goes first.
func composeServiceName(p Pair, s Service) string { return p.Name() + "-" + s.Name }

// RenderCompose renders the whole compose file. The output is
// deterministic, so the committed file and the --dry-run output match.
//
// One profile exists per role and DPG pair. Compose starts only the
// services of the profile the operator names (ADR-008 decisions 1 and 2).
func RenderCompose() string {
	var b strings.Builder
	b.WriteString("# SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("# The vca CLI generates this file. Do not edit it by hand.\n")
	b.WriteString("# Run: go test ./internal/cli/ to check that it is current.\n")
	b.WriteString("#\n")
	b.WriteString("# One profile exists per role and DPG pair, named <role>-<dpg>.\n")
	b.WriteString("# Start one with: vca deploy --role <role> --dpg <dpg>\n")
	b.WriteString("# That runs: docker compose --profile <role>-<dpg> up -d\n")
	b.WriteString("#\n")
	b.WriteString("# Every service runs read only, as a non-root user, with no added\n")
	b.WriteString("# capabilities, and with no Docker socket (ADR-005 decisions 2 and 3).\n")
	b.WriteString("# Every host port binds to VCA_BIND. vca setup sets it to 127.0.0.1 on\n")
	b.WriteString("# a public host, so only the reverse proxy reaches the services.\n")
	fmt.Fprintf(&b, "name: %s\n\n", ComposeProject)

	// Compose resolves a relative path of an included file against the
	// directory of that file unless the include names another one. The
	// stack files mount ../keycloak-<dpg>, which sits beside the pair
	// directories like the ../<pair>/.env files of the service blocks,
	// so every include resolves against the directory of this file.
	b.WriteString("include:\n")
	for _, path := range DpgStackFiles() {
		fmt.Fprintf(&b, "  - path: %s\n", path)
		b.WriteString("    project_directory: .\n")
	}
	b.WriteString("\n")

	b.WriteString("x-vca-service: &vca-service\n")
	b.WriteString("  restart: unless-stopped\n")
	b.WriteString("  read_only: true\n")
	b.WriteString("  user: \"65532:65532\"\n")
	b.WriteString("  security_opt:\n")
	b.WriteString("    - no-new-privileges:true\n")
	b.WriteString("  cap_drop:\n")
	b.WriteString("    - ALL\n")
	b.WriteString("  tmpfs:\n")
	b.WriteString("    - /tmp\n")
	b.WriteString("  networks:\n")
	b.WriteString("    - vca\n\n")

	b.WriteString("services:\n")
	var volumes []string
	for _, p := range AllPairs() {
		fmt.Fprintf(&b, "\n  # Profile %s\n", p.Name())
		for _, a := range AssignPorts(p, nil) {
			volumes = append(volumes, renderComposeService(&b, p, a)...)
		}
	}
	for _, s := range DeploymentServices() {
		renderDeploymentService(&b, s)
	}

	b.WriteString("\nnetworks:\n  vca:\n    name: vca\n")
	if len(volumes) > 0 {
		sort.Strings(volumes)
		b.WriteString("\nvolumes:\n")
		for _, v := range volumes {
			fmt.Fprintf(&b, "  %s:\n", v)
		}
	}
	return b.String()
}

// renderComposeService writes one service block and returns the volume
// names it needs.
func renderComposeService(b *strings.Builder, p Pair, a PortAssignment) []string {
	name := composeServiceName(p, a.Service)
	hostVar := "VCA_HOST_PORT_" + envName(a.Service.Name)
	fmt.Fprintf(b, "  %s:\n", name)
	b.WriteString("    <<: *vca-service\n")
	fmt.Fprintf(b, "    image: %s:${VCA_VERSION:-latest}\n", a.Service.Image())
	fmt.Fprintf(b, "    profiles: [%s]\n", p.Name())
	fmt.Fprintf(b, "    container_name: %s\n", name)
	b.WriteString("    env_file:\n")
	fmt.Fprintf(b, "      - path: ../%s/%s\n", p.Name(), EnvFileName)
	b.WriteString("        required: true\n")
	b.WriteString("    ports:\n")
	// A public host sets VCA_BIND to the loopback address, so only the
	// reverse proxy of the host reaches the port.
	fmt.Fprintf(b, "      - \"${%s:-0.0.0.0}:${%s:-%d}:${%s:-%d}\"\n", BindEnv, hostVar, a.Host, a.PortEnv, a.Listen)
	if a.Service.UI {
		b.WriteString("    environment:\n")
		fmt.Fprintf(b, "      %s: %s\n", ThemeFileEnv, ThemeMountPath)
	}
	var volumes []string
	if a.Service.Stateful {
		volumes = append(volumes, name+"-data")
	}
	if a.Service.Stateful || a.Service.UI {
		b.WriteString("    volumes:\n")
	}
	for _, v := range volumes {
		fmt.Fprintf(b, "      - %s:/data\n", v)
	}
	if a.Service.UI {
		fmt.Fprintf(b, "      - ${%s:-%s}:%s:ro\n", ThemeHostFileEnv, themeHostDefault, ThemeMountPath)
	}
	return volumes
}

// DeploymentServiceName is the compose service name of a deployment
// scoped service. No pair name goes first, because one copy runs.
func DeploymentServiceName(s Service) string { return ComposeProject + "-" + s.Name }

// renderDeploymentService writes the block of a service that runs once
// per deployment (ADR-033 decision 2). Every pair profile lists it, so
// the first pair that starts brings it up and the others find it
// running. It reads the .env of its own directory under deploy.
func renderDeploymentService(b *strings.Builder, s Service) {
	name := DeploymentServiceName(s)
	fmt.Fprintf(b, "\n  # The %s of the deployment. Every profile starts it once.\n", s.Name)
	fmt.Fprintf(b, "  %s:\n", name)
	b.WriteString("    <<: *vca-service\n")
	fmt.Fprintf(b, "    image: %s:${%s:-latest}\n", s.Image(), VersionEnv)
	fmt.Fprintf(b, "    profiles: [%s]\n", strings.Join(Profiles(AllPairs()), ", "))
	fmt.Fprintf(b, "    container_name: %s\n", name)
	b.WriteString("    env_file:\n")
	fmt.Fprintf(b, "      - path: ../%s/%s\n", s.Name, EnvFileName)
	b.WriteString("        required: true\n")
	b.WriteString("    ports:\n")
	fmt.Fprintf(b, "      - \"${%s:-0.0.0.0}:${VCA_HOST_PORT_%s:-%d}:${VCA_PORTS_%s:-%d}\"\n",
		BindEnv, envName(s.Name), LandingHostPort, envName(s.Name), s.ExposedPort)
	if s.UI {
		b.WriteString("    environment:\n")
		fmt.Fprintf(b, "      %s: %s\n", ThemeFileEnv, ThemeMountPath)
		b.WriteString("    volumes:\n")
		fmt.Fprintf(b, "      - ${%s:-%s}:%s:ro\n", ThemeHostFileEnv, themeHostDefault, ThemeMountPath)
	}
}

// Profiles lists the compose profiles of a deploy run. One pair gives one
// profile. The --all flag gives every pair of the chosen DPG
// (ADR-008 decision 2).
func Profiles(pairs []Pair) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.Name())
	}
	return out
}

// PairsForRole lists every DPG of one role, in DPG order. The order is
// the proto order, so no DPG reads as the first choice
// (ADR-001 decision 2, ADR-002 decision 2).
func PairsForRole(r commonv1.Role) []Pair {
	var out []Pair
	for _, p := range AllPairs() {
		if p.Role == r {
			out = append(out, p)
		}
	}
	return out
}

// PairsForDpg lists every role of one DPG, in role order.
func PairsForDpg(d configv1.Dpg) []Pair {
	var out []Pair
	for _, p := range AllPairs() {
		if p.Dpg == d {
			out = append(out, p)
		}
	}
	return out
}
