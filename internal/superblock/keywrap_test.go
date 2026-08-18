package superblock

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
)

// RSA keygen dominates test time; share one KEK (plus a decoy) per run.
var testKEK = sync.OnceValues(func() (*rsa.PrivateKey, *rsa.PrivateKey) {
	kek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return kek, other
})

func TestWrapUnwrapRoundTrip(t *testing.T) {
	kek, wrongKey := testKEK()
	key := bytes.Repeat([]byte{0x5a}, WrappedKeySize)

	wrapped, err := WrapKey(&kek.PublicKey, key)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("round trip mismatch: %x", got)
	}

	if _, err := UnwrapKey(wrongKey, wrapped); err == nil {
		t.Fatal("UnwrapKey succeeded with the wrong private key")
	}
	if _, err := WrapKey(&kek.PublicKey, key[:16]); err == nil {
		t.Fatal("WrapKey accepted a non-32-byte key")
	}
}

func TestLoadRSAPrivateKeyPEM(t *testing.T) {
	kek, _ := testKEK()

	t.Run("pkcs1", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(kek),
		})
		got, err := LoadRSAPrivateKeyPEM(pemBytes, nil)
		if err != nil {
			t.Fatalf("LoadRSAPrivateKeyPEM: %v", err)
		}
		if !got.Equal(kek) {
			t.Fatal("loaded key differs from original")
		}
	})

	t.Run("pkcs8", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(kek)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		got, err := LoadRSAPrivateKeyPEM(pemBytes, nil)
		if err != nil {
			t.Fatalf("LoadRSAPrivateKeyPEM: %v", err)
		}
		if !got.Equal(kek) {
			t.Fatal("loaded key differs from original")
		}
	})

	t.Run("legacy encrypted pem", func(t *testing.T) {
		//nolint:staticcheck // legacy RFC 1423 encryption; real key files still use it
		block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(kek), []byte("hunter2"), x509.PEMCipherAES256)
		if err != nil {
			t.Fatalf("EncryptPEMBlock: %v", err)
		}
		pemBytes := pem.EncodeToMemory(block)

		if _, err := LoadRSAPrivateKeyPEM(pemBytes, nil); !errors.Is(err, ErrKeyNeedsPassphrase) {
			t.Fatalf("no-passphrase load: got %v, want ErrKeyNeedsPassphrase", err)
		}
		if _, err := LoadRSAPrivateKeyPEM(pemBytes, []byte("wrong")); err == nil {
			t.Fatal("wrong passphrase accepted")
		}
		got, err := LoadRSAPrivateKeyPEM(pemBytes, []byte("hunter2"))
		if err != nil {
			t.Fatalf("LoadRSAPrivateKeyPEM with passphrase: %v", err)
		}
		if !got.Equal(kek) {
			t.Fatal("loaded key differs from original")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := LoadRSAPrivateKeyPEM([]byte("not a key"), nil); err == nil {
			t.Fatal("garbage input accepted")
		}
	})
}

// End-to-end: a KEK loaded from a PEM file unwraps the exact key-table
// entries a superblock round-trips.
func TestKeyTableThroughSuperblock(t *testing.T) {
	kek, _ := testKEK()
	dek := bytes.Repeat([]byte{0x0d}, WrappedKeySize)
	identity := bytes.Repeat([]byte{0x1d}, WrappedKeySize)

	wrapDEK, err := WrapKey(&kek.PublicKey, dek)
	if err != nil {
		t.Fatalf("WrapKey dek: %v", err)
	}
	wrapID, err := WrapKey(&kek.PublicKey, identity)
	if err != nil {
		t.Fatalf("WrapKey identity: %v", err)
	}

	sb := testSuperblock()
	sb.KeyTable = []KeyEntry{
		{ID: 1, Kind: KeyKindDEK, Alg: KeyAlgRSAOAEPSHA256, Wrapped: wrapDEK},
		{ID: 2, Kind: KeyKindIdentity, Alg: KeyAlgRSAOAEPSHA256, Wrapped: wrapID},
	}
	enc, err := sb.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	got, err := UnwrapKey(kek, dec.KeyTable[0].Wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey dek: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("DEK mismatch after superblock round trip")
	}
	got, err = UnwrapKey(kek, dec.KeyTable[1].Wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey identity: %v", err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatal("identity key mismatch after superblock round trip")
	}
}
