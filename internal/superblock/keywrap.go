// Key wrapping for the superblock key table: 32-byte DEKs and the
// identity key are RSA-OAEP/SHA-256 encrypted under the user's KEK, the
// RSA private key file --encrypt-key names. The OAEP label is "keys".
// The PEM loader is deliberately permissive, restricted to RSA: PKCS#1,
// PKCS#8, legacy-encrypted PEM blocks, and passphrase-protected PKCS#8.
// Passphrase sourcing is the caller's job — this package never reads the
// environment.

package superblock

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/youmark/pkcs8"
)

// oaepLabel matches JuiceFS's RSA key encryptor so the v1 KEK is directly
// usable. Changing it would silently orphan every wrapped key.
var oaepLabel = []byte("keys")

// WrappedKeySize is the size of every key the table wraps (BLAKE3 keys
// and AES-256 DEKs are both 32 bytes).
const WrappedKeySize = 32

// WrapKey encrypts a 32-byte key under the KEK public key.
func WrapKey(pub *rsa.PublicKey, key []byte) ([]byte, error) {
	if len(key) != WrappedKeySize {
		return nil, fmt.Errorf("wrap key: key is %d bytes, want %d", len(key), WrappedKeySize)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, oaepLabel)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}
	return wrapped, nil
}

// UnwrapKey decrypts a wrapped key with the KEK private key and enforces
// the 32-byte contract.
func UnwrapKey(priv *rsa.PrivateKey, wrapped []byte) ([]byte, error) {
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, wrapped, oaepLabel)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	if len(key) != WrappedKeySize {
		return nil, fmt.Errorf("unwrap key: unwrapped %d bytes, want %d", len(key), WrappedKeySize)
	}
	return key, nil
}

// ErrKeyNeedsPassphrase reports an encrypted private key loaded without a
// passphrase.
var ErrKeyNeedsPassphrase = errors.New("passphrase is required for this private key")

// LoadRSAPrivateKeyPEM parses an RSA private key from PEM bytes,
// accepting the same shapes as v1's --encrypt-key parser (see the file
// comment). passphrase may be nil for unencrypted keys.
func LoadRSAPrivateKeyPEM(pemBytes, passphrase []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("load KEK: no PEM block found")
	}

	der := block.Bytes
	//nolint:staticcheck // legacy RFC 1423 encryption, kept for v1 key-file compat
	if x509.IsEncryptedPEMBlock(block) {
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("load KEK: %w", ErrKeyNeedsPassphrase)
		}
		var err error
		//nolint:staticcheck // see above
		if der, err = x509.DecryptPEMBlock(block, passphrase); err != nil {
			return nil, fmt.Errorf("load KEK: decrypt PEM block: %w", err)
		}
	} else if strings.Contains(block.Type, "ENCRYPTED") {
		// "ENCRYPTED PRIVATE KEY": passphrase-protected PKCS#8.
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("load KEK: %w", ErrKeyNeedsPassphrase)
		}
		key, err := pkcs8.ParsePKCS8PrivateKeyRSA(der, passphrase)
		if err != nil {
			return nil, fmt.Errorf("load KEK: parse encrypted PKCS#8: %w", err)
		}
		return key, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("load KEK: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("load KEK: key is %T, want *rsa.PrivateKey", key)
	}
	return rsaKey, nil
}

// LoadRSAPrivateKeyFile reads path and parses it with LoadRSAPrivateKeyPEM.
func LoadRSAPrivateKeyFile(path string, passphrase []byte) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load KEK: %w", err)
	}
	return LoadRSAPrivateKeyPEM(pemBytes, passphrase)
}
