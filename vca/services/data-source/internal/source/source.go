// SPDX-License-Identifier: Apache-2.0

// Package source is the stored form of one data source (ADR-015
// decisions 1, 2, and 3). A source holds secret references only. The
// package converts to and from the proto message and validates a
// source. It is pure.
package source

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/csvsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Kind names the type of a source.
type Kind string

// Kinds the service knows.
const (
	KindCSV  Kind = "csv"
	KindHTTP Kind = "http"
	KindSQL  Kind = "sql"
)

// Errors the package returns.
var (
	ErrInvalid = errors.New("source: the source is not valid")
)

// DefaultTimeout applies when a source gives no timeout.
const DefaultTimeout = 30 * time.Second

// MaxTimeout caps the timeout a source may ask for.
const MaxTimeout = 5 * time.Minute

// Access lists which roles may do what with the source.
type Access struct {
	ViewFields  []string `json:"view_fields,omitempty"`
	PreviewRows []string `json:"preview_rows,omitempty"`
	Issue       []string `json:"issue,omitempty"`
}

// CSV describes a CSV source. FileRef is a plain file name in the CSV
// directory of the service or a data URL with the file bytes.
type CSV struct {
	FileRef   string `json:"file_ref"`
	Delimiter string `json:"delimiter,omitempty"`
	HasHeader bool   `json:"has_header"`
	Encoding  string `json:"encoding,omitempty"`
}

// HTTP describes an HTTP API source.
type HTTP struct {
	URL       string            `json:"url"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Bearer    secrets.Ref       `json:"bearer,omitempty"`
	BasicUser string            `json:"basic_user,omitempty"`
	BasicPass secrets.Ref       `json:"basic_password,omitempty"`
	MTLSCert  secrets.Ref       `json:"mtls_certificate,omitempty"`
	MTLSKey   secrets.Ref       `json:"mtls_private_key,omitempty"`
	RowsPath  string            `json:"rows_path,omitempty"`
	Timeout   time.Duration     `json:"timeout,omitempty"`
}

// SQL describes a database source.
type SQL struct {
	Driver  string        `json:"driver"`
	DSN     secrets.Ref   `json:"dsn"`
	Query   string        `json:"query"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Source is one stored data source.
type Source struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Kind        Kind      `json:"kind"`
	CSV         *CSV      `json:"csv,omitempty"`
	HTTP        *HTTP     `json:"http,omitempty"`
	SQL         *SQL      `json:"sql,omitempty"`
	Access      Access    `json:"access"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Validate checks s. It does not resolve secrets.
func (s Source) Validate() error {
	if strings.TrimSpace(s.DisplayName) == "" {
		return fmt.Errorf("%w: display_name is empty", ErrInvalid)
	}
	switch s.Kind {
	case KindCSV:
		if s.CSV == nil {
			return fmt.Errorf("%w: csv is missing", ErrInvalid)
		}
		return s.CSV.validate()
	case KindHTTP:
		if s.HTTP == nil {
			return fmt.Errorf("%w: http is missing", ErrInvalid)
		}
		return s.HTTP.validate()
	case KindSQL:
		if s.SQL == nil {
			return fmt.Errorf("%w: sql is missing", ErrInvalid)
		}
		return s.SQL.validate()
	}
	return fmt.Errorf("%w: set exactly one of csv, http, or sql", ErrInvalid)
}

func (c CSV) validate() error {
	if strings.TrimSpace(c.FileRef) == "" {
		return fmt.Errorf("%w: csv.file_ref is empty", ErrInvalid)
	}
	if err := (csvsrc.Options{Delimiter: c.Delimiter, Encoding: c.Encoding}).Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func (h HTTP) validate() error {
	u, err := url.Parse(h.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%w: http.url is not an absolute URL", ErrInvalid)
	}
	switch strings.ToUpper(h.Method) {
	case "", "GET", "POST":
	default:
		return fmt.Errorf("%w: http.method must be GET or POST", ErrInvalid)
	}
	for k := range h.Headers {
		if strings.EqualFold(k, "Authorization") {
			return fmt.Errorf("%w: put the credential in a secret reference, not in a header", ErrInvalid)
		}
	}
	if h.RowsPath != "" && !strings.HasPrefix(h.RowsPath, "/") {
		return fmt.Errorf("%w: http.rows_path must be a JSON pointer that starts with /", ErrInvalid)
	}
	set := 0
	for _, r := range []secrets.Ref{h.Bearer, h.BasicPass, h.MTLSCert} {
		if !r.IsZero() {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("%w: set at most one of bearer, basic, or mtls", ErrInvalid)
	}
	if !h.BasicPass.IsZero() && strings.TrimSpace(h.BasicUser) == "" {
		return fmt.Errorf("%w: basic.username is empty", ErrInvalid)
	}
	if h.MTLSCert.IsZero() != h.MTLSKey.IsZero() {
		return fmt.Errorf("%w: mtls needs both a certificate and a private key reference", ErrInvalid)
	}
	for _, r := range []secrets.Ref{h.Bearer, h.BasicPass, h.MTLSCert, h.MTLSKey} {
		if r.IsZero() {
			continue
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	return checkTimeout(h.Timeout)
}

func (q SQL) validate() error {
	if strings.TrimSpace(q.Driver) == "" {
		return fmt.Errorf("%w: sql.driver is empty", ErrInvalid)
	}
	if err := q.DSN.Validate(); err != nil {
		return fmt.Errorf("%w: sql.dsn: %v", ErrInvalid, err)
	}
	if err := sqlsrc.CheckQuery(q.Query); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return checkTimeout(q.Timeout)
}

func checkTimeout(d time.Duration) error {
	if d < 0 || d > MaxTimeout {
		return fmt.Errorf("%w: timeout_seconds must be between 0 and %d", ErrInvalid, int(MaxTimeout.Seconds()))
	}
	return nil
}

// TimeoutOf returns the timeout of the source or the default.
func (s Source) TimeoutOf() time.Duration {
	var d time.Duration
	switch s.Kind {
	case KindHTTP:
		d = s.HTTP.Timeout
	case KindSQL:
		d = s.SQL.Timeout
	}
	if d <= 0 {
		return DefaultTimeout
	}
	return d
}

// FromProto converts a proto source. It ignores the timestamps.
func FromProto(p *datasourcev1.Source) Source {
	s := Source{
		ID:          p.GetId(),
		DisplayName: strings.TrimSpace(p.GetDisplayName()),
		TenantID:    p.GetTenantId(),
		Access: Access{
			ViewFields:  cleanRoles(p.GetAccess().GetViewFields()),
			PreviewRows: cleanRoles(p.GetAccess().GetPreviewRows()),
			Issue:       cleanRoles(p.GetAccess().GetIssue()),
		},
	}
	switch k := p.GetKind().(type) {
	case *datasourcev1.Source_Csv:
		s.Kind = KindCSV
		s.CSV = &CSV{FileRef: k.Csv.GetFileRef(), Delimiter: k.Csv.GetDelimiter(), HasHeader: k.Csv.GetHasHeader(), Encoding: k.Csv.GetEncoding()}
	case *datasourcev1.Source_Http:
		s.Kind = KindHTTP
		h := &HTTP{
			URL: k.Http.GetUrl(), Method: strings.ToUpper(k.Http.GetMethod()), Headers: k.Http.GetHeaders(),
			RowsPath: k.Http.GetRowsPath(), Timeout: time.Duration(k.Http.GetTimeoutSeconds()) * time.Second,
		}
		switch a := k.Http.GetAuth().(type) {
		case *datasourcev1.HttpSource_BearerToken:
			h.Bearer = refFromProto(a.BearerToken)
		case *datasourcev1.HttpSource_Basic:
			h.BasicUser = a.Basic.GetUsername()
			h.BasicPass = refFromProto(a.Basic.GetPassword())
		case *datasourcev1.HttpSource_Mtls:
			h.MTLSCert = refFromProto(a.Mtls.GetCertificate())
			h.MTLSKey = refFromProto(a.Mtls.GetPrivateKey())
		}
		s.HTTP = h
	case *datasourcev1.Source_Sql:
		s.Kind = KindSQL
		s.SQL = &SQL{Driver: k.Sql.GetDriver(), DSN: refFromProto(k.Sql.GetDsn()), Query: k.Sql.GetQuery(), Timeout: time.Duration(k.Sql.GetTimeoutSeconds()) * time.Second}
	}
	return s
}

// ToProto converts s. The result holds references, never secret values.
func ToProto(s Source) *datasourcev1.Source {
	p := &datasourcev1.Source{
		Id: s.ID, DisplayName: s.DisplayName, TenantId: s.TenantID,
		Access: &datasourcev1.Source_Access{ViewFields: s.Access.ViewFields, PreviewRows: s.Access.PreviewRows, Issue: s.Access.Issue},
	}
	if !s.CreatedAt.IsZero() {
		p.CreatedAt = timestamppb.New(s.CreatedAt)
	}
	if !s.UpdatedAt.IsZero() {
		p.UpdatedAt = timestamppb.New(s.UpdatedAt)
	}
	switch s.Kind {
	case KindCSV:
		p.Kind = &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: s.CSV.FileRef, Delimiter: s.CSV.Delimiter, HasHeader: s.CSV.HasHeader, Encoding: s.CSV.Encoding}}
	case KindHTTP:
		h := &datasourcev1.HttpSource{Url: s.HTTP.URL, Method: s.HTTP.Method, Headers: s.HTTP.Headers, RowsPath: s.HTTP.RowsPath, TimeoutSeconds: int32(s.HTTP.Timeout / time.Second)}
		switch {
		case !s.HTTP.Bearer.IsZero():
			h.Auth = &datasourcev1.HttpSource_BearerToken{BearerToken: refToProto(s.HTTP.Bearer)}
		case !s.HTTP.BasicPass.IsZero():
			h.Auth = &datasourcev1.HttpSource_Basic{Basic: &datasourcev1.HttpSource_BasicAuth{Username: s.HTTP.BasicUser, Password: refToProto(s.HTTP.BasicPass)}}
		case !s.HTTP.MTLSCert.IsZero():
			h.Auth = &datasourcev1.HttpSource_Mtls{Mtls: &datasourcev1.HttpSource_MtlsAuth{Certificate: refToProto(s.HTTP.MTLSCert), PrivateKey: refToProto(s.HTTP.MTLSKey)}}
		}
		p.Kind = &datasourcev1.Source_Http{Http: h}
	case KindSQL:
		p.Kind = &datasourcev1.Source_Sql{Sql: &datasourcev1.SqlSource{Driver: s.SQL.Driver, Dsn: refToProto(s.SQL.DSN), Query: s.SQL.Query, TimeoutSeconds: int32(s.SQL.Timeout / time.Second)}}
	}
	return p
}

func cleanRoles(in []string) []string {
	var out []string
	for _, r := range in {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

func refFromProto(p *commonv1.SecretRef) secrets.Ref {
	if p == nil {
		return secrets.Ref{}
	}
	r := secrets.Ref{Name: p.GetName()}
	switch p.GetStore() {
	case commonv1.SecretRef_STORE_ENV:
		r.Store = secrets.Env
	case commonv1.SecretRef_STORE_FILE:
		r.Store = secrets.File
	case commonv1.SecretRef_STORE_KMS:
		r.Store = secrets.KMS
	}
	return r
}

func refToProto(r secrets.Ref) *commonv1.SecretRef {
	p := &commonv1.SecretRef{Name: r.Name}
	switch r.Store {
	case secrets.Env:
		p.Store = commonv1.SecretRef_STORE_ENV
	case secrets.File:
		p.Store = commonv1.SecretRef_STORE_FILE
	case secrets.KMS:
		p.Store = commonv1.SecretRef_STORE_KMS
	}
	return p
}
