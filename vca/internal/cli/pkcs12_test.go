// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- the known answer of RFC 7292 uses SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
	"unicode/utf16"
)

// decodeTestPKCS12 reads the key store that EncodePKCS12 writes: it
// checks the MAC, decrypts the shrouded key bag, and returns the alias,
// the key, and the certificate. It reads only that layout.
func decodeTestPKCS12(data []byte, password string) (string, *rsa.PrivateKey, *x509.Certificate, error) {
	var pfx struct {
		Version  int
		AuthSafe struct {
			Type    asn1.ObjectIdentifier
			Content []byte `asn1:"explicit,tag:0"`
		}
		Mac struct {
			Digest struct {
				Algorithm struct {
					Algorithm asn1.ObjectIdentifier
					Params    asn1.RawValue `asn1:"optional"`
				}
				Value []byte
			}
			Salt       []byte
			Iterations int
		}
	}
	if rest, err := asn1.Unmarshal(data, &pfx); err != nil || len(rest) != 0 {
		return "", nil, nil, fmt.Errorf("pfx: %w", err)
	}
	if pfx.Version != 3 || !pfx.AuthSafe.Type.Equal(oidData) || !pfx.Mac.Digest.Algorithm.Algorithm.Equal(oidSHA256) {
		return "", nil, nil, errors.New("pfx: an unknown layout")
	}
	mac := hmac.New(sha256.New, pkcs12KDF(sha256.New, 3, bmpPassword(password), pfx.Mac.Salt, pfx.Mac.Iterations, 32))
	mac.Write(pfx.AuthSafe.Content)
	if !hmac.Equal(mac.Sum(nil), pfx.Mac.Digest.Value) {
		return "", nil, nil, errors.New("pfx: the MAC does not match")
	}
	var safes []struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content, &safes); err != nil {
		return "", nil, nil, fmt.Errorf("authenticated safe: %w", err)
	}
	var (
		alias string
		key   *rsa.PrivateKey
		cert  *x509.Certificate
		ids   [][]byte
	)
	for _, safe := range safes {
		var bags []struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"explicit,tag:0"`
			Attrs []struct {
				ID     asn1.ObjectIdentifier
				Values asn1.RawValue `asn1:"set"`
			} `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(safe.Content, &bags); err != nil {
			return "", nil, nil, fmt.Errorf("safe contents: %w", err)
		}
		for _, bag := range bags {
			for _, attr := range bag.Attrs {
				switch {
				case attr.ID.Equal(oidLocalKeyID):
					var id []byte
					if _, err := asn1.Unmarshal(attr.Values.Bytes, &id); err != nil {
						return "", nil, nil, err
					}
					ids = append(ids, id)
				case attr.ID.Equal(oidFriendlyName):
					var name asn1.RawValue
					if _, err := asn1.Unmarshal(attr.Values.Bytes, &name); err != nil || name.Tag != asn1.TagBMPString {
						return "", nil, nil, errors.New("friendly name: not a BMPString")
					}
					units := make([]uint16, len(name.Bytes)/2)
					for i := range units {
						units[i] = uint16(name.Bytes[2*i])<<8 | uint16(name.Bytes[2*i+1])
					}
					alias = string(utf16.Decode(units))
				}
			}
			switch {
			case bag.ID.Equal(oidCertBag):
				var cb struct {
					ID    asn1.ObjectIdentifier
					Value []byte `asn1:"explicit,tag:0"`
				}
				if _, err := asn1.Unmarshal(bag.Value.Bytes, &cb); err != nil {
					return "", nil, nil, err
				}
				c, err := x509.ParseCertificate(cb.Value)
				if err != nil {
					return "", nil, nil, err
				}
				cert = c
			case bag.ID.Equal(oidShroudedKeyBag):
				k, err := decryptTestKey(bag.Value.Bytes, password)
				if err != nil {
					return "", nil, nil, err
				}
				key = k
			}
		}
	}
	if key == nil || cert == nil || len(ids) != 2 || !bytes.Equal(ids[0], ids[1]) {
		return "", nil, nil, errors.New("the key store does not pair one key with one certificate")
	}
	return alias, key, cert, nil
}

// decryptTestKey opens a PBES2 EncryptedPrivateKeyInfo with PBKDF2 and
// HMAC SHA-256, and AES-256-CBC.
func decryptTestKey(der []byte, password string) (*rsa.PrivateKey, error) {
	var info struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				KDF struct {
					Algorithm asn1.ObjectIdentifier
					Params    struct {
						Salt       []byte
						Iterations int
						PRF        struct {
							Algorithm asn1.ObjectIdentifier
							Params    asn1.RawValue `asn1:"optional"`
						}
					}
				}
				Cipher struct {
					Algorithm asn1.ObjectIdentifier
					IV        []byte
				}
			}
		}
		Data []byte
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("encrypted key: %w", err)
	}
	p := info.Algorithm.Params
	if !info.Algorithm.Algorithm.Equal(oidPBES2) || !p.KDF.Algorithm.Equal(oidPBKDF2) ||
		!p.KDF.Params.PRF.Algorithm.Equal(oidHMACSHA256) || !p.Cipher.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("encrypted key: an unknown scheme")
	}
	dk, err := pbkdf2.Key(sha256.New, password, p.KDF.Params.Salt, p.KDF.Params.Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	if len(info.Data)%aes.BlockSize != 0 || len(info.Data) == 0 {
		return nil, errors.New("encrypted key: a bad length")
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(block, p.Cipher.IV).CryptBlocks(plain, info.Data)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errors.New("encrypted key: a bad padding, so the password is wrong")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plain[:len(plain)-pad])
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("encrypted key: not an RSA key")
	}
	return rsaKey, nil
}

// TestEncodePKCS12RoundTrip writes a key store that a Java key store
// of type PKCS12 opens: one key with its certificate under an alias,
// the key in a PBES2 shrouded bag, and an HMAC SHA-256 MAC. A wrong
// password fails the MAC.
func TestEncodePKCS12RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := EncodePKCS12(key, "vca-inji", "a long password", rand.Reader)
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}
	alias, got, cert, err := decodeTestPKCS12(store, "a long password")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if alias != "vca-inji" || !got.Equal(key) || !key.PublicKey.Equal(cert.PublicKey) || cert.Subject.CommonName != "vca-inji" {
		t.Fatalf("alias %q, subject %q", alias, cert.Subject.CommonName)
	}
	if _, _, _, err := decodeTestPKCS12(store, "another password"); err == nil {
		t.Fatal("a wrong password opened the key store")
	}
	if _, err := EncodePKCS12(key, "vca-inji", "p", failingReader{}); err == nil {
		t.Fatal("a failing random source passed")
	}
}

// TestPKCS12KDFKnownAnswer checks the key derivation of RFC 7292
// appendix B against the test vector of the SHA-1 MAC key of the
// PKCS #12 test suite of Bouncy Castle ("smeg", salt 0A58CF64530D823F,
// one iteration, 24 bytes, ID 1).
func TestPKCS12KDFKnownAnswer(t *testing.T) {
	got := pkcs12KDF(sha1.New, 1, bmpPassword("smeg"), []byte{0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F}, 1, 24)
	want := []byte{
		0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46, 0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51, 0x28, 0x4E,
		0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("KDF = %X", got)
	}
}

// failingReader is a random source that always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }
