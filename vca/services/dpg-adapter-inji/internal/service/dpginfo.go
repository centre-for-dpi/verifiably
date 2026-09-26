// SPDX-License-Identifier: Apache-2.0

package service

import (
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// DisplayName is the name of the DPG as a page shows it. Only the
// adapter knows it (ADR-001 decision 4).
const DisplayName = "MOSIP Inji"

// docsURL is the documentation site of the stack.
const docsURL = "https://docs.inji.io"

// mplLicence is the licence of every MOSIP component.
const mplLicence = "MPL-2.0"

// component describes one part of the stack and the role that runs it.
type component struct {
	name string
	// wired reports whether this deployment runs the component. Nil
	// means every deployment.
	wired func(*Service) bool
	repo  string
	docs  string
	lic   string
	// page returns the public address of a component that serves pages
	// to people. Nil means none.
	page func(*Service) string
}

// hasIssuer, hasVerifier, and hasHolder read the wired roles.
func hasIssuer(s *Service) bool   { return s.certify != nil }
func hasVerifier(s *Service) bool { return s.verify != nil }
func hasHolder(s *Service) bool   { return s.mimoto != nil }

// hasLogin reports whether the pair runs eSignet and the mock identity
// system: the issuer and the holder profiles of the stack file do.
func hasLogin(s *Service) bool { return hasIssuer(s) || hasHolder(s) }

// components lists the stack in the order of the stack file.
var components = []component{
	{name: "keycloak",
		repo: "https://github.com/keycloak/keycloak", docs: "https://www.keycloak.org/documentation", lic: "Apache-2.0"},
	{name: "certify", wired: hasIssuer,
		repo: "https://github.com/mosip/inji-certify", docs: docsURL + "/inji-certify/overview", lic: mplLicence},
	{name: "esignet", wired: hasLogin,
		repo: "https://github.com/mosip/esignet", docs: "https://docs.esignet.io", lic: mplLicence},
	{name: "mock-identity", wired: hasLogin,
		repo: "https://github.com/mosip/esignet-mock-services", docs: "https://docs.esignet.io", lic: mplLicence},
	{name: "mimoto", wired: hasHolder,
		repo: "https://github.com/mosip/mimoto", docs: docsURL + "/inji-wallet/inji-web/technical-overview/backend-services/mimoto-bff", lic: mplLicence},
	{name: "inji-web", wired: hasHolder,
		repo: "https://github.com/mosip/inji-web", docs: docsURL + "/inji-wallet/inji-web/overview", lic: mplLicence,
		page: func(s *Service) string { return s.injiWebURL }},
	{name: "verify-service", wired: hasVerifier,
		repo: "https://github.com/mosip/inji-verify", docs: docsURL + "/inji-verify", lic: mplLicence},
	{name: "verify-ui", wired: hasVerifier,
		repo: "https://github.com/mosip/inji-verify", docs: docsURL + "/inji-verify", lic: mplLicence},
}

// dpgInfo names the stack and the components this deployment runs
// (ADR-034 decision 4).
func (s *Service) dpgInfo() *backendv1.DpgInfo {
	info := &backendv1.DpgInfo{DisplayName: DisplayName, Version: s.dpgVersion}
	if hasIssuer(s) {
		info.Plugins = append(info.Plugins, s.plugins...)
	}
	for _, c := range components {
		if c.wired != nil && !c.wired(s) {
			continue
		}
		comp := &backendv1.Component{
			Name: c.name, Version: s.versions[c.name], RepositoryUrl: c.repo, DocsUrl: c.docs, License: c.lic,
		}
		if c.page != nil {
			comp.Url = c.page(s)
		}
		info.Components = append(info.Components, comp)
	}
	return info
}
