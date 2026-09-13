// SPDX-License-Identifier: Apache-2.0

// Package delivery sends an offer or a document to a citizen
// (ADR-016 decision 5). The sender is an interface, so a deployment can
// add a real email gateway or a real SMS gateway without a change to the
// issuance flow.
//
// The package ships two senders that need nothing: log writes the
// message to the service log, and file writes it to a directory. The
// email sender and the SMS sender are stubs. Each returns
// ErrNotConfigured until a deployment adds a gateway.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Channel names a delivery way.
type Channel string

// The delivery channels of ADR-016 decision 5.
const (
	// ChannelOID4VCI hands the offer to a wallet.
	ChannelOID4VCI Channel = "oid4vci"
	// ChannelPDF renders a document with a QR code.
	ChannelPDF Channel = "pdf"
	// ChannelEmail sends the offer by email.
	ChannelEmail Channel = "email"
	// ChannelSMS sends the offer by SMS.
	ChannelSMS Channel = "sms"
	// ChannelLink hands the citizen a download link.
	ChannelLink Channel = "link"
)

// ErrNotConfigured reports a channel without a gateway.
var ErrNotConfigured = errors.New("delivery: the channel has no gateway in this deployment")

// ErrNoAddress reports a message without an address.
var ErrNoAddress = errors.New("delivery: the message has no address")

// Message is one thing to send.
type Message struct {
	// Channel is the way to send it.
	Channel Channel
	// Address is the email address or the phone number.
	Address string
	// Locale is the BCP 47 language tag of the text.
	Locale string
	// Subject is the heading of an email.
	Subject string
	// Body is the text of the message.
	Body string
	// Link is the address the citizen opens.
	Link string
	// Attachment holds the document bytes. It is empty for a message
	// without one.
	Attachment []byte
	// AttachmentName is the file name of the attachment.
	AttachmentName string
}

// Validate checks that the message can go out.
func (m Message) Validate() error {
	switch m.Channel {
	case ChannelEmail, ChannelSMS:
		if strings.TrimSpace(m.Address) == "" {
			return fmt.Errorf("%w: the %s channel needs an address", ErrNoAddress, m.Channel)
		}
	}
	return nil
}

// Sender sends one message.
type Sender interface {
	// Send delivers the message. It returns ErrNotConfigured when the
	// deployment has no gateway for the channel.
	Send(ctx context.Context, m Message) error
}

// SenderFunc makes a function a Sender.
type SenderFunc func(ctx context.Context, m Message) error

// Send calls the function.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Log returns a sender that writes the message to the log. It sends
// nothing, so a demo deployment needs no gateway.
func Log(log *slog.Logger) Sender {
	if log == nil {
		log = slog.Default()
	}
	return SenderFunc(func(_ context.Context, m Message) error {
		if err := m.Validate(); err != nil {
			return err
		}
		log.Info("delivery",
			"channel", string(m.Channel),
			"address", m.Address,
			"subject", m.Subject,
			"link", m.Link,
			"attachment_bytes", len(m.Attachment))
		return nil
	})
}

// File returns a sender that writes the message to a directory. An
// operator reads the files, which makes a test deployment easy to check.
func File(dir string, now func() time.Time) Sender {
	if now == nil {
		now = time.Now
	}
	return SenderFunc(func(_ context.Context, m Message) error {
		if err := m.Validate(); err != nil {
			return err
		}
		if strings.TrimSpace(dir) == "" {
			return fmt.Errorf("%w: the file sender has no directory", ErrNotConfigured)
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("delivery: make the directory: %w", err)
		}
		stamp := now().UTC().Format("20060102T150405.000000000")
		name := filepath.Join(dir, stamp+"-"+string(m.Channel)+".txt")
		var b strings.Builder
		fmt.Fprintf(&b, "channel: %s\n", m.Channel)
		fmt.Fprintf(&b, "address: %s\n", m.Address)
		fmt.Fprintf(&b, "locale: %s\n", m.Locale)
		fmt.Fprintf(&b, "subject: %s\n", m.Subject)
		fmt.Fprintf(&b, "link: %s\n\n", m.Link)
		b.WriteString(m.Body)
		b.WriteString("\n")
		if err := os.WriteFile(name, []byte(b.String()), 0o600); err != nil {
			return fmt.Errorf("delivery: write the message: %w", err)
		}
		if len(m.Attachment) > 0 {
			attachment := filepath.Join(dir, stamp+"-"+safeName(m.AttachmentName))
			if err := os.WriteFile(attachment, m.Attachment, 0o600); err != nil {
				return fmt.Errorf("delivery: write the attachment: %w", err)
			}
		}
		return nil
	})
}

// safeName keeps a file name inside the directory.
func safeName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "attachment.bin"
	}
	return name
}

// Email returns the email sender of the deployment. The stub reports
// ErrNotConfigured, so an operator learns at once that the deployment
// needs a mail gateway.
func Email() Sender {
	return SenderFunc(func(_ context.Context, m Message) error {
		if err := m.Validate(); err != nil {
			return err
		}
		return fmt.Errorf("%w: set a mail gateway to use the email channel", ErrNotConfigured)
	})
}

// SMS returns the SMS sender of the deployment. The stub reports
// ErrNotConfigured.
func SMS() Sender {
	return SenderFunc(func(_ context.Context, m Message) error {
		if err := m.Validate(); err != nil {
			return err
		}
		return fmt.Errorf("%w: set an SMS gateway to use the SMS channel", ErrNotConfigured)
	})
}

// Registry holds one sender per channel.
type Registry struct {
	senders map[Channel]Sender
}

// NewRegistry returns a registry with the senders.
func NewRegistry(senders map[Channel]Sender) *Registry {
	out := make(map[Channel]Sender, len(senders))
	for k, v := range senders {
		out[k] = v
	}
	return &Registry{senders: out}
}

// Send delivers the message with the sender of its channel.
func (r *Registry) Send(ctx context.Context, m Message) error {
	sender, ok := r.senders[m.Channel]
	if !ok {
		return fmt.Errorf("%w: the channel %s has no sender", ErrNotConfigured, m.Channel)
	}
	return sender.Send(ctx, m)
}
