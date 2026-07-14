// Package mailer is a minimal SMTP sender used for holder-activation email OTPs.
// It is deliberately tiny: one transactional message at a time over STARTTLS
// (the Gmail submission port 587 path). When SMTP_* env is unset FromEnv returns
// nil and callers treat email as unavailable.
package mailer

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// Mailer holds the resolved SMTP submission settings.
type Mailer struct {
	host, port, user, pass, from, fromName string
}

// FromEnv builds a Mailer from SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD/
// SMTP_FROM/SMTP_FROM_NAME. Returns nil when host/user/password are not all set,
// so the rest of the app can detect "email not configured" with a simple nil
// check. SMTP_PORT defaults to 587 (STARTTLS submission); SMTP_FROM defaults to
// SMTP_USER; SMTP_FROM_NAME (the From display name) defaults to "Verifiably".
func FromEnv() *Mailer {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	user := strings.TrimSpace(os.Getenv("SMTP_USER"))
	pass := os.Getenv("SMTP_PASSWORD")
	if host == "" || user == "" || pass == "" {
		return nil
	}
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if port == "" {
		port = "587"
	}
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	if from == "" {
		from = user
	}
	fromName := strings.TrimSpace(os.Getenv("SMTP_FROM_NAME"))
	if fromName == "" {
		fromName = "Verifiably"
	}
	return &Mailer{host: host, port: port, user: user, pass: pass, from: from, fromName: fromName}
}

// Send delivers a plain-text message. smtp.SendMail negotiates STARTTLS when the
// server advertises it (Gmail :587 does) and PlainAuth only sends credentials
// over that TLS channel, so this is safe against a downgrade.
func (m *Mailer) Send(to, subject, body string) error {
	if m == nil {
		return fmt.Errorf("mailer not configured")
	}
	addr := m.host + ":" + m.port
	auth := smtp.PlainAuth("", m.user, m.pass, m.host)
	// The From HEADER carries the display name ("Verifiably <addr>"); the SMTP
	// envelope sender stays the bare address (m.from) below.
	fromHeader := m.from
	if m.fromName != "" {
		fromHeader = m.fromName + " <" + m.from + ">"
	}
	msg := "From: " + fromHeader + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body + "\r\n"
	if err := smtp.SendMail(addr, auth, m.from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// From returns the configured From address (for log/UI context).
func (m *Mailer) From() string {
	if m == nil {
		return ""
	}
	return m.from
}
