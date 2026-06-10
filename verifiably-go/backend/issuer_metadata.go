package backend

import "github.com/verifiably/verifiably-go/vctypes"

// IssuerMetadata is the subset of OpenID4VCI Credential Issuer Metadata
// (OpenID4VCI §11.2) needed for credential discovery: it identifies the issuer
// and lists the credential configurations it can issue. The discovery layer
// serves this so a wallet (or the hub catalog aggregator) can browse what a
// federation member offers without an operator in the loop. See
// docs/credential-delivery.md (holder-initiated quadrant).
//
// CredentialIssuer and CredentialEndpoint are absolute URLs filled by the HTTP
// handler from the request's public base; adapters leave them empty and only
// populate CredentialsSupported.
type IssuerMetadata struct {
	CredentialIssuer     string             `json:"credential_issuer,omitempty"`
	CredentialEndpoint   string             `json:"credential_endpoint,omitempty"`
	CredentialsSupported []CredentialConfig `json:"credential_configurations_supported"`
}

// CredentialConfig describes one offerable credential configuration. It carries
// both the OID4VCI format/type identifiers a wallet needs to request the
// credential and the claim-name preview the hub catalog renders on its
// "Descubrir" screen.
type CredentialConfig struct {
	ID      string   `json:"id"`
	Format  string   `json:"format"`
	Types   []string `json:"types,omitempty"` // VC type array (jwt_vc_json / ldp_vc)
	Vct     string   `json:"vct,omitempty"`   // SD-JWT VC type id (vc+sd-jwt)
	Display string   `json:"display,omitempty"`
	Issuer  string   `json:"issuer,omitempty"` // issuer display-name attribution
	Claims  []string `json:"claims,omitempty"` // available claim names (claims_preview)
}

// CredentialConfigsFromSchemas maps a schema slice onto OID4VCI credential
// configurations, deriving each format from Schema.Std. Shared by every issuer
// adapter so the schema→config mapping lives in one place rather than being
// re-derived per vendor.
func CredentialConfigsFromSchemas(schemas []vctypes.Schema) []CredentialConfig {
	out := make([]CredentialConfig, 0, len(schemas))
	for _, s := range schemas {
		out = append(out, credentialConfigFromSchema(s))
	}
	return out
}

func credentialConfigFromSchema(s vctypes.Schema) CredentialConfig {
	claims := make([]string, 0, len(s.FieldsSpec))
	for _, f := range s.FieldsSpec {
		claims = append(claims, f.Name)
	}
	c := CredentialConfig{
		ID:      s.ID,
		Format:  OID4VCIFormat(s.Std),
		Display: s.Name,
		Issuer:  s.IssuerDisplayName,
		Claims:  claims,
	}
	if c.Format == "vc+sd-jwt" {
		if s.Vct != "" {
			c.Vct = s.Vct
		} else {
			c.Vct = s.ID
		}
		return c
	}
	types := []string{"VerifiableCredential"}
	switch {
	case s.BaseType() != "":
		types = append(types, s.BaseType())
	case len(s.AdditionalTypes) > 0:
		types = append(types, s.AdditionalTypes...)
	}
	c.Types = types
	return c
}

// OID4VCIFormat maps a verifiably-go Schema.Std onto the OpenID4VCI credential
// format identifier. Mirrors the primary wire format the walt.id adapter
// registers per Std (see waltidWireFormatsForStd); kept here, not in an
// adapter, so every adapter and the discovery handler agree on one mapping.
func OID4VCIFormat(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)", "sd_jwt_vc":
		return "vc+sd-jwt"
	case "mso_mdoc":
		return "mso_mdoc"
	default: // w3c_vcdm_2, w3c_vcdm_1, jwt_vc, ""
		return "jwt_vc_json"
	}
}
