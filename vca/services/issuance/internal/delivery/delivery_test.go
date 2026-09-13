// SPDX-License-Identifier: Apache-2.0

package delivery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
)

// fixedTime is the clock of the tests.
var fixedTime = time.Date(2026, 7, 1, 10, 30, 0, 0, time.UTC)

func TestValidateNeedsAnAddressForEmailAndSms(t *testing.T) {
	for _, channel := range []delivery.Channel{delivery.ChannelEmail, delivery.ChannelSMS} {
		if err := (delivery.Message{Channel: channel}).Validate(); !errors.Is(err, delivery.ErrNoAddress) {
			t.Fatalf("the channel %s accepted a message without an address", channel)
		}
	}
	ok := delivery.Message{Channel: delivery.ChannelEmail, Address: "ada@example.org"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := (delivery.Message{Channel: delivery.ChannelPDF}).Validate(); err != nil {
		t.Fatalf("the document channel needs no address: %v", err)
	}
}

func TestLogWritesOneLine(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	sender := delivery.Log(log)
	err := sender.Send(context.Background(), delivery.Message{
		Channel: delivery.ChannelEmail, Address: "ada@example.org", Subject: "Your credential",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	var line map[string]any
	if jerr := json.Unmarshal(buf.Bytes(), &line); jerr != nil {
		t.Fatalf("the log is not JSON: %v", jerr)
	}
	if line["channel"] != "email" || line["address"] != "ada@example.org" {
		t.Fatalf("line = %v", line)
	}
}

func TestLogChecksTheMessage(t *testing.T) {
	if err := delivery.Log(nil).Send(context.Background(),
		delivery.Message{Channel: delivery.ChannelSMS}); err == nil {
		t.Fatal("the log sender accepted a message without an address")
	}
}

func TestFileWritesTheMessageAndTheAttachment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	sender := delivery.File(dir, func() time.Time { return fixedTime })
	err := sender.Send(context.Background(), delivery.Message{
		Channel:        delivery.ChannelEmail,
		Address:        "ada@example.org",
		Locale:         "en",
		Subject:        "Your credential",
		Body:           "Open the link.",
		Link:           "https://issuance.example.org/issuance/pdf/1",
		Attachment:     []byte("%PDF-1.4"),
		AttachmentName: "credential.pdf",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("read the directory: %v", rerr)
	}
	if len(entries) != 2 {
		t.Fatalf("files = %d, want the message and the attachment", len(entries))
	}
	found := false
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(raw), "ada@example.org") {
			found = true
		}
	}
	if !found {
		t.Fatal("no file carries the address")
	}
}

func TestFileNeedsADirectory(t *testing.T) {
	err := delivery.File("  ", nil).Send(context.Background(),
		delivery.Message{Channel: delivery.ChannelPDF})
	if !errors.Is(err, delivery.ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
}

func TestFileChecksTheMessage(t *testing.T) {
	err := delivery.File(t.TempDir(), nil).Send(context.Background(),
		delivery.Message{Channel: delivery.ChannelEmail})
	if !errors.Is(err, delivery.ErrNoAddress) {
		t.Fatalf("error = %v", err)
	}
}

func TestFileReportsABadDirectory(t *testing.T) {
	blocking := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocking, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := delivery.File(filepath.Join(blocking, "out"), nil).Send(context.Background(),
		delivery.Message{Channel: delivery.ChannelPDF})
	if err == nil {
		t.Fatal("the file sender accepted a directory inside a file")
	}
}

func TestFileKeepsTheAttachmentInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	err := delivery.File(dir, func() time.Time { return fixedTime }).Send(context.Background(),
		delivery.Message{
			Channel:        delivery.ChannelPDF,
			Attachment:     []byte("x"),
			AttachmentName: "../../escape.pdf",
		})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "..") {
			t.Fatalf("the file %q leaves the directory", e.Name())
		}
	}
	if err := delivery.File(dir, nil).Send(context.Background(), delivery.Message{
		Channel: delivery.ChannelPDF, Attachment: []byte("x"),
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestTheEmailAndTheSmsStubsReportTheMissingGateway(t *testing.T) {
	ctx := context.Background()
	err := delivery.Email().Send(ctx, delivery.Message{
		Channel: delivery.ChannelEmail, Address: "ada@example.org",
	})
	if !errors.Is(err, delivery.ErrNotConfigured) {
		t.Fatalf("email error = %v", err)
	}
	err = delivery.SMS().Send(ctx, delivery.Message{
		Channel: delivery.ChannelSMS, Address: "+254700000000",
	})
	if !errors.Is(err, delivery.ErrNotConfigured) {
		t.Fatalf("SMS error = %v", err)
	}
	if err := delivery.Email().Send(ctx, delivery.Message{Channel: delivery.ChannelEmail}); err == nil {
		t.Fatal("the email stub accepted a message without an address")
	}
	if err := delivery.SMS().Send(ctx, delivery.Message{Channel: delivery.ChannelSMS}); err == nil {
		t.Fatal("the SMS stub accepted a message without an address")
	}
}

func TestRegistryPicksTheSenderOfTheChannel(t *testing.T) {
	seen := ""
	registry := delivery.NewRegistry(map[delivery.Channel]delivery.Sender{
		delivery.ChannelPDF: delivery.SenderFunc(func(_ context.Context, m delivery.Message) error {
			seen = string(m.Channel)
			return nil
		}),
	})
	if err := registry.Send(context.Background(),
		delivery.Message{Channel: delivery.ChannelPDF}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seen != "pdf" {
		t.Fatalf("channel = %q", seen)
	}
	err := registry.Send(context.Background(), delivery.Message{Channel: delivery.ChannelSMS})
	if !errors.Is(err, delivery.ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
}
