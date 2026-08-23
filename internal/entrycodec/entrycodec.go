// Package entrycodec encodes individual pack entries for the v2 format
// (docs/design-packfs.md, "Compression is per-entry, never per-pack-stream"):
// zstd-compress under a store-if-smaller policy (the git/borg trick that
// avoids paying for incompressible data), then optionally AES-256-GCM
// encrypt — compress-then-encrypt, because ciphertext does not compress.
//
// The compression algorithm is recorded explicitly by the caller (the
// catalog chunkref's alg column), never sniffed from magic bytes; the key
// id likewise rides in the referencing record, and key==nil here means
// plaintext (key id 0). The GCM tag is redundant with the hash tree for
// integrity but comes free with the AEAD; the Merkle path up to the
// superblock signature remains the authoritative integrity mechanism.
package entrycodec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// Compression algorithm ids, recorded in catalog chunkref rows. New
// algorithms are new ids; id values are format constants.
const (
	AlgNone uint8 = 0
	AlgZstd uint8 = 1
)

// KeySize is the only entry-encryption key size (AES-256).
const KeySize = 32

// nonceSize is the GCM nonce length prepended to every encrypted entry.
const nonceSize = 12

// Shared codecs: EncodeAll/DecodeAll are stateless and safe for concurrent
// use (same pattern as the packstore trailer codec).
//
// The encoder's concurrency is not about splitting one call across cores —
// EncodeAll never does that — it sizes the pool of encoder states callers
// draw from, so it is really the number of ENTRIES that may be encoded at
// once. At one, a publish building several catalogs in parallel would
// queue them all behind a single state and get nothing for the
// parallelism. Small rather than GOMAXPROCS because each state carries a
// window's worth of hash tables, the pool is allocated on first use and
// then kept for the life of the process, and compression is only part of
// a catalog build: four is enough not to be the queue.
var (
	encoderStates = min(runtime.GOMAXPROCS(0), 4)

	zEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(encoderStates))
	zDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
)

// Encode prepares one pack entry: zstd-compress data, keep the smaller of
// compressed/raw (alg reports which), then encrypt with AES-256-GCM when
// key is non-nil (a random 12-byte nonce is prepended to the ciphertext).
// A nil or empty key means plaintext; any other length than KeySize is an
// error. The returned slice never aliases data.
func Encode(data, key []byte) ([]byte, uint8, error) {
	payload := zEnc.EncodeAll(data, nil)
	alg := AlgZstd
	if len(payload) >= len(data) {
		payload = data
		alg = AlgNone
	}
	out, err := seal(payload, key, alg == AlgNone)
	if err != nil {
		return nil, 0, err
	}
	return out, alg, nil
}

// EncodeZstd compresses unconditionally (no store-if-smaller), then
// encrypts like Encode. Catalog, shard, and other entries referenced by
// records with no alg column (nested rows, the superblock's root-catalog
// hash) need a deterministic encoding the reader can assume.
func EncodeZstd(data, key []byte) ([]byte, error) {
	return seal(zEnc.EncodeAll(data, nil), key, false)
}

// Decode reverses Encode/EncodeZstd: decrypt when key is non-nil, then
// decompress according to alg. Tampered or wrongly-keyed entries fail the
// GCM open.
func Decode(stored []byte, alg uint8, key []byte) ([]byte, error) {
	payload := stored
	if len(key) != 0 {
		aead, err := newAEAD(key)
		if err != nil {
			return nil, err
		}
		if len(stored) < nonceSize+aead.Overhead() {
			return nil, fmt.Errorf("entrycodec: entry too short (%d bytes) for AES-GCM", len(stored))
		}
		payload, err = aead.Open(nil, stored[:nonceSize], stored[nonceSize:], nil)
		if err != nil {
			return nil, fmt.Errorf("entrycodec: decrypt entry: %w", err)
		}
	}
	switch alg {
	case AlgNone:
		if len(key) == 0 {
			// No transform happened; copy so the result never aliases stored.
			payload = append([]byte(nil), payload...)
		}
		return payload, nil
	case AlgZstd:
		out, err := zDec.DecodeAll(payload, nil)
		if err != nil {
			return nil, fmt.Errorf("entrycodec: decompress entry: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("entrycodec: unknown compression alg %d", alg)
	}
}

// seal encrypts payload under key (nil key = plaintext passthrough).
// mustCopy forces a copy in the passthrough case, for callers whose
// payload aliases their input.
func seal(payload, key []byte, mustCopy bool) ([]byte, error) {
	if len(key) == 0 {
		if mustCopy {
			return append([]byte(nil), payload...), nil
		}
		return payload, nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, nonceSize, nonceSize+len(payload)+aead.Overhead())
	if _, err := rand.Read(out[:nonceSize]); err != nil {
		return nil, fmt.Errorf("entrycodec: nonce: %w", err)
	}
	return aead.Seal(out, out[:nonceSize], payload, nil), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("entrycodec: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
