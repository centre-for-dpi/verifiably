// SPDX-License-Identifier: Apache-2.0

package service

import (
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// DisplayName is the name of the DPG as a page shows it. Only the
// adapter knows it (ADR-001 decision 4).
const DisplayName = "walt.id Community Stack"

// Repository and documentation links of the stack.
const (
	repositoryURL = "https://github.com/walt-id/waltid-identity"
	docsURL       = "https://docs.walt.id/community-stack"
	licence       = "Apache-2.0"
)

// component describes one part of the stack and the role that runs it.
type component struct {
	name string
	// wired reports whether this deployment runs the component. Nil
	// means every deployment.
	wired func(*Service) bool
	repo  string
	docs  string
	lic   string
}

// components lists the stack in the order of the stack file.
var components = []component{
	{name: "keycloak",
		repo: "https://github.com/keycloak/keycloak", docs: "https://www.keycloak.org/documentation", lic: "Apache-2.0"},
	{name: "issuer-api", wired: func(s *Service) bool { return s.client.HasIssuer() },
		repo: repositoryURL, docs: docsURL + "/issuer", lic: licence},
	{name: "verifier-api", wired: func(s *Service) bool { return s.client.HasVerifier() },
		repo: repositoryURL, docs: "https://docs.walt.id/verifier", lic: licence},
	{name: "wallet-api", wired: func(s *Service) bool { return s.client.HasWallet() },
		repo: repositoryURL, docs: docsURL + "/wallet/getting-started", lic: licence},
}

// dpgInfo names the stack and the components this deployment runs
// (ADR-034 decision 4).
func (s *Service) dpgInfo() *backendv1.DpgInfo {
	info := &backendv1.DpgInfo{DisplayName: DisplayName, Version: s.dpgVersion}
	for _, c := range components {
		if c.wired != nil && !c.wired(s) {
			continue
		}
		info.Components = append(info.Components, &backendv1.Component{
			Name: c.name, Version: s.versions[c.name], RepositoryUrl: c.repo, DocsUrl: c.docs, License: c.lic,
		})
	}
	return info
}
