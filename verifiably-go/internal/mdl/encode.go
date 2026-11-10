package mdl

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// randomSaltLen is the entropy per item. The standard requires at least 16
// bytes so that a verifier holding a digest cannot brute-force the value of
// an element that was not disclosed.
const randomSaltLen = 16

// BuildIssuerSignedItems turns a map of element values into the item
// structures the issuer signs over.
//
// Elements are processed in sorted order so digest IDs are assigned
// deterministically for a given input set, which keeps test vectors stable.
// The salt, by contrast, is fresh on every call.
func BuildIssuerSignedItems(elements map[string]any) ([]IssuerSignedItem, error) {
	names := make([]string, 0, len(elements))
	for name := range elements {
		if !containsElement(DatasetElements, name) {
			return nil, fmt.Errorf("mdl: %q is not part of the emitted dataset", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]IssuerSignedItem, 0, len(names))
	for i, name := range names {
		salt := make([]byte, randomSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("mdl: read random salt: %w", err)
		}
		items = append(items, IssuerSignedItem{
			DigestID:          uint(i),
			Random:            salt,
			ElementIdentifier: name,
			ElementValue:      elements[name],
		})
	}
	return items, nil
}

// EncodeItem produces IssuerSignedItemBytes: the item encoded as CBOR and
// then wrapped in tag 24 as an embedded byte string.
//
// Digests are computed over these tagged bytes, so encoding must be
// deterministic — otherwise a holder re-encoding the item would produce a
// digest that no longer matches the MSO.
func EncodeItem(item IssuerSignedItem) (cbor.RawMessage, error) {
	em, err := EncMode()
	if err != nil {
		return nil, err
	}
	inner, err := em.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("mdl: marshal item %q: %w", item.ElementIdentifier, err)
	}
	tagged, err := em.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("mdl: tag item %q: %w", item.ElementIdentifier, err)
	}
	return tagged, nil
}

// ComputeValueDigests hashes each encoded item, keyed by its digest ID. This
// map is what goes into the MSO and what lets a verifier confirm that a
// disclosed element was not altered.
func ComputeValueDigests(items []IssuerSignedItem) (map[uint][]byte, error) {
	digests := make(map[uint][]byte, len(items))
	for _, item := range items {
		enc, err := EncodeItem(item)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(enc)
		digests[item.DigestID] = sum[:]
	}
	return digests, nil
}
