// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
)

// claim169Text builds the text of an identity QR code: a CWT with the
// iss claim and claim 169 in a COSE_Sign1 message, zlib, and base45.
func claim169Text(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := cbor.Marshal(map[int64]any{
		1: "did:web:certify.example", 6: 1700000000, 169: map[int64]any{4: "Wanjiku Njeri", 8: "1987-04-12", 9: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int64]any{1: -8, 4: "did:web:certify.example#key-0"})
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, claims})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, claims, ed25519.Sign(key, toSign)}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return pixelpass.EncodeBase45(buf.Bytes())
}

// TestCheckOfAClaim169CodeNamesTheIssuerAndClaims reads an identity QR
// code. The service hands the signed CWT to the policy service, not the
// bare claims, so the policy service can check the signature. The stored
// result names the carrier claim169, the issuer and the claims.
func TestCheckOfAClaim169CodeNamesTheIssuerAndClaims(t *testing.T) {
	pol, res := &evaluator{}, &keeper{}
	svc, _ := build(t, service.Options{Policy: pol, Results: res})
	resp, err := svc.Ingest(context.Background(), connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(claim169Text(t))}))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	raw := resp.Msg.GetPresentation()
	if raw.GetDetectedType() != ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169 || len(raw.GetCredentials()) != 1 {
		t.Fatalf("presentation = %v", raw)
	}
	if f := vc.DetectFormat(raw.GetCredentials()[0].GetPayload()); f != vc.FormatClaim169 {
		t.Fatalf("the credential is %q, want the signed CWT", f)
	}
	got, err := svc.Check(context.Background(), raw, service.CarrierUpload)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.GetCarrier() != service.CarrierClaim169 {
		t.Fatalf("carrier = %q, want %q", got.GetCarrier(), service.CarrierClaim169)
	}
	card := got.GetCredentials()[0]
	if card.GetIssuer() != "did:web:certify.example" || card.GetDisplayFields()["Full Name"] != "Wanjiku Njeri" ||
		card.GetDisplayFields()["Gender"] != "Female" || card.GetType() != vc.Claim169Type {
		t.Fatalf("card = %v", card)
	}
}
