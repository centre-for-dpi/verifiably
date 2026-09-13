// SPDX-License-Identifier: Apache-2.0

package etsi

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
)

// Namespace is the XML namespace of ETSI TS 119 612 trusted lists.
const Namespace = "http://uri.etsi.org/02231/v2#"

// TrustedList is the subset of a TS 119 612 TrustServiceStatusList that
// the import reads. Element names match clause 5 of the specification.
type TrustedList struct {
	XMLName           xml.Name           `xml:"TrustServiceStatusList"`
	SchemeInformation TSLSchemeInfo      `xml:"SchemeInformation"`
	Providers         []TrustServiceProv `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

// TSLSchemeInfo is the SchemeInformation element.
type TSLSchemeInfo struct {
	VersionIdentifier int             `xml:"TSLVersionIdentifier"`
	SequenceNumber    uint64          `xml:"TSLSequenceNumber"`
	Type              string          `xml:"TSLType"`
	OperatorName      []MultiLangName `xml:"SchemeOperatorName>Name"`
	Territory         string          `xml:"SchemeTerritory"`
	ListIssueDateTime string          `xml:"ListIssueDateTime"`
	NextUpdate        string          `xml:"NextUpdate>dateTime"`
}

// MultiLangName is a Name element with a language tag.
type MultiLangName struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// TrustServiceProv is one TrustServiceProvider element.
type TrustServiceProv struct {
	Name     []MultiLangName `xml:"TSPInformation>TSPName>Name"`
	Services []TSPService    `xml:"TSPServices>TSPService"`
}

// TSPService is one TSPService element.
type TSPService struct {
	TypeIdentifier     string          `xml:"ServiceInformation>ServiceTypeIdentifier"`
	Name               []MultiLangName `xml:"ServiceInformation>ServiceName>Name"`
	DigitalIdentities  []DigitalID     `xml:"ServiceInformation>ServiceDigitalIdentity>DigitalId"`
	Status             string          `xml:"ServiceInformation>ServiceStatus"`
	StatusStartingTime string          `xml:"ServiceInformation>StatusStartingTime"`
}

// DigitalID is one DigitalId element.
type DigitalID struct {
	X509Certificate string `xml:"X509Certificate"`
	X509SubjectName string `xml:"X509SubjectName"`
}

// ParseTrustedList decodes a TS 119 612 XML document.
func ParseTrustedList(data []byte) (TrustedList, error) {
	var tl TrustedList
	if err := xml.Unmarshal(data, &tl); err != nil {
		return TrustedList{}, fmt.Errorf("etsi: parse xml: %w", err)
	}
	if tl.XMLName.Space != Namespace {
		return TrustedList{}, fmt.Errorf("etsi: namespace %q is not %s", tl.XMLName.Space, Namespace)
	}
	return tl, nil
}

// Skipped names a service the import did not convert, with a reason.
type Skipped struct {
	Provider string
	Service  string
	Reason   string
}

// String returns "provider / service: reason".
func (s Skipped) String() string {
	return s.Provider + " / " + s.Service + ": " + s.Reason
}

// Import converts every TSPService into an issuer entry. Services with no
// x509 identity are skipped. The status maps as clause 5.5.4 says:
// granted and recognised statuses become active, the rest become revoked.
func Import(tl TrustedList, now time.Time) ([]entry.Entry, []Skipped) {
	var out []entry.Entry
	var skipped []Skipped
	for _, tsp := range tl.Providers {
		provider := englishName(tsp.Name)
		for _, svc := range tsp.Services {
			e, err := importService(tsp, svc, now)
			if err != nil {
				skipped = append(skipped, Skipped{Provider: provider, Service: englishName(svc.Name), Reason: err.Error()})
				continue
			}
			out = append(out, e)
		}
	}
	return out, skipped
}

func importService(tsp TrustServiceProv, svc TSPService, now time.Time) (entry.Entry, error) {
	subject, notAfter, err := identity(svc.DigitalIdentities)
	if err != nil {
		return entry.Entry{}, err
	}
	name := englishName(svc.Name)
	if name == "" {
		name = englishName(tsp.Name)
	}
	e := entry.Entry{
		X509Subject: subject,
		DisplayName: name,
		Role:        entry.RoleIssuer,
		Status:      mapStatus(svc.Status),
		ValidUntil:  notAfter,
		UpdatedAt:   now,
		Source:      entry.SourceEtsiImport,
	}
	if svc.StatusStartingTime != "" {
		t, err := time.Parse(time.RFC3339, svc.StatusStartingTime)
		if err != nil {
			return entry.Entry{}, fmt.Errorf("status starting time: %w", err)
		}
		e.ValidFrom = t.UTC()
	}
	if err := e.Validate(); err != nil {
		return entry.Entry{}, err
	}
	return e, nil
}

// identity returns the subject name and, when a certificate is present,
// its expiry. A certificate wins over a bare subject name.
func identity(ids []DigitalID) (string, time.Time, error) {
	var subject string
	for _, id := range ids {
		if id.X509Certificate != "" {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(id.X509Certificate), ""))
			if err != nil {
				return "", time.Time{}, fmt.Errorf("x509 certificate base64: %w", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("x509 certificate: %w", err)
			}
			return cert.Subject.String(), cert.NotAfter.UTC(), nil
		}
		if id.X509SubjectName != "" && subject == "" {
			subject = strings.TrimSpace(id.X509SubjectName)
		}
	}
	if subject == "" {
		return "", time.Time{}, errors.New("no x509 digital identity")
	}
	return subject, time.Time{}, nil
}

func mapStatus(uri string) entry.Status {
	switch strings.TrimSpace(uri) {
	case StatusGranted,
		"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
		"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw":
		return entry.StatusActive
	}
	return entry.StatusRevoked
}

func englishName(names []MultiLangName) string {
	for _, n := range names {
		if strings.EqualFold(n.Lang, "en") {
			return strings.TrimSpace(n.Value)
		}
	}
	if len(names) > 0 {
		return strings.TrimSpace(names[0].Value)
	}
	return ""
}
