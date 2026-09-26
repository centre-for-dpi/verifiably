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

// agentRepositoryURL is the source of the Credo agent of the platform.
const agentRepositoryURL = "https://github.com/credebl/agent-controller"

// components lists the stack in the order of the stack file, which runs
// the whole platform (ADR-045 decision 4). The adapter serves the issuer
// and the verifier from the api gateway, so every deployment runs every
// component. The database, the message bus and the cache are not listed:
// they carry no feature of their own.
var components = []component{
	{name: "keycloak",
		repo: "https://github.com/keycloak/keycloak", docs: "https://www.keycloak.org/documentation", lic: "Apache-2.0"},
	{name: "schema-file-server", repo: "https://github.com/credebl/schema-file-server", docs: docsURL, lic: licence},
	{name: "api-gateway", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "user", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "utility", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "connection", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "issuance", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "ledger", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "organization", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "verification", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "agent-provisioning", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "agent-service", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "cloud-wallet", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "geolocation", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "notification", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "webhook", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "ecosystem", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "oid4vc-issuance", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "oid4vc-verification", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "x509", repo: repositoryURL, docs: docsURL, lic: licence},
	{name: "agent", repo: agentRepositoryURL, docs: docsURL, lic: licence},
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
