package mdl

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestBuildIssuerSignedItemsAssignsUniqueRandomAndDigestIDs(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{
		"family_name": "Pérez",
		"given_name":  "Ana",
	})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	seenIDs := map[uint]bool{}
	for _, it := range items {
		if len(it.Random) < 16 {
			t.Errorf("%s: random must be at least 16 bytes, got %d", it.ElementIdentifier, len(it.Random))
		}
		if seenIDs[it.DigestID] {
			t.Errorf("duplicate digestID %d", it.DigestID)
		}
		seenIDs[it.DigestID] = true
	}

	// Two items with the same value must still get different salts.
	a, _ := BuildIssuerSignedItems(map[string]any{"family_name": "X"})
	b, _ := BuildIssuerSignedItems(map[string]any{"family_name": "X"})
	if bytes.Equal(a[0].Random, b[0].Random) {
		t.Error("random salt must differ between issuances")
	}
}

func TestEncodeItemWrapsInTag24(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{"family_name": "Pérez"})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	enc, err := EncodeItem(items[0])
	if err != nil {
		t.Fatalf("encode item: %v", err)
	}
	// Tag 24 encodes as d8 18, followed by a byte string.
	if len(enc) < 2 || enc[0] != 0xd8 || enc[1] != 0x18 {
		t.Errorf("expected tag 24 prefix d818, got %x", enc)
	}
}

func TestComputeValueDigestsMatchesSHA256OfEncodedItem(t *testing.T) {
	items, err := BuildIssuerSignedItems(map[string]any{"family_name": "Pérez"})
	if err != nil {
		t.Fatalf("build items: %v", err)
	}
	digests, err := ComputeValueDigests(items)
	if err != nil {
		t.Fatalf("compute digests: %v", err)
	}

	enc, err := EncodeItem(items[0])
	if err != nil {
		t.Fatalf("encode item: %v", err)
	}
	want := sha256.Sum256(enc)

	got, ok := digests[items[0].DigestID]
	if !ok {
		t.Fatalf("no digest for digestID %d", items[0].DigestID)
	}
	// The digest must be taken over the tagged bytes, not the bare structure.
	if !bytes.Equal(got, want[:]) {
		t.Errorf("digest mismatch:\n got %x\nwant %x", got, want[:])
	}
}

func TestBuildIssuerSignedItemsRejectsUnknownElement(t *testing.T) {
	if _, err := BuildIssuerSignedItems(map[string]any{"not_a_real_element": "x"}); err == nil {
		t.Fatal("expected error for element outside the dataset")
	}
}
