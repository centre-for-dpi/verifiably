// SPDX-License-Identifier: Apache-2.0

package service

import (
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// DisplayName is the name of the DPG as a page shows it. Only the
// adapter knows it (ADR-001 decision 4).
const DisplayName = "CREDEBL"

// Repository and documentation links of the platform.
const (
	repositoryURL = "https://github.com/credebl/platform"
	docsURL       = "https://docs.credebl.id"
	licence       = "Apache-2.0"
)

// component describes one part of the stack.
type component struct {
	name string
	repo string
	docs string
	lic  string
}

// components lists the stack in the order of the stack file. The
// adapter serves the issuer and the verifier from the api gateway, so
// every deployment runs every component.
var components = []component{
	{name: "keycloak",
		repo: "https://github.com/keycloak/keycloak", docs: "https://www.keycloak.org/documentation", lic: "Apache-2.0"},
	{name: "api-gateway", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "agent-provisioning", repo: repositoryURL, docs: docsURL, lic: licence},
}

// dpgInfo names the platform and its components (ADR-034 decision 4).
func (s *Service) dpgInfo() *backendv1.DpgInfo {
	info := &backendv1.DpgInfo{DisplayName: DisplayName, Version: s.dpgVersion}
	for _, c := range components {
		info.Components = append(info.Components, &backendv1.Component{
			Name: c.name, Version: s.versions[c.name], RepositoryUrl: c.repo, DocsUrl: c.docs, License: c.lic,
		})
	}
	return info
}
