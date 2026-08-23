package entrycodec

import (
	"bytes"
	"math/rand"
	"testing"
)

func testKey(b byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = b ^ byte(i)
	}
	return k
}

// incompressible returns deterministic pseudorandom bytes zstd cannot shrink.
func incompressible(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(7)).Read(b)
	return b
}

func TestRoundTrips(t *testing.T) {
	compressible := bytes.Repeat([]byte("pelfs entry codec round trip "), 500)
	random := incompressible(8 << 10)
	key := testKey(0x5a)

	cases := []struct {
		name    string
		data    []byte
		key     []byte
		wantAlg uint8
	}{
		{"compressible-plain", compressible, nil, AlgZstd},
		{"compressible-keyed", compressible, key, AlgZstd},
		{"incompressible-plain", random, nil, AlgNone},
		{"incompressible-keyed", random, key, AlgNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored, alg, err := Encode(tc.data, tc.key)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if alg != tc.wantAlg {
				t.Fatalf("alg = %d, want %d", alg, tc.wantAlg)
			}
			if tc.key != nil && bytes.Contains(stored, tc.data[:64]) {
				t.Fatalf("encrypted entry contains plaintext")
			}
			if tc.key == nil && alg == AlgNone && len(stored) != len(tc.data) {
				t.Fatalf("plain stored-raw entry is %d bytes, want %d", len(stored), len(tc.data))
			}
			got, err := Decode(stored, alg, tc.key)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(tc.data))
			}
			// The result must never alias the caller's buffers.
			if len(got) > 0 {
				got[0] ^= 0xff
				if got[0] == tc.data[0] {
					t.Fatalf("decoded slice aliases the input")
				}
			}
		})
	}
}

func TestEncodeZstdAlwaysCompresses(t *testing.T) {
	// Even incompressible data must come back through the AlgZstd path:
	// records with no alg column depend on the encoding being fixed.
	for _, key := range [][]byte{nil, testKey(0x11)} {
		data := incompressible(4 << 10)
		stored, err := EncodeZstd(data, key)
		if err != nil {
			t.Fatalf("EncodeZstd: %v", err)
		}
		got, err := Decode(stored, AlgZstd, key)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("EncodeZstd round trip mismatch (keyed=%v)", key != nil)
		}
	}
}

func TestTamperDetection(t *testing.T) {
	key := testKey(0x33)
	stored, alg, err := Encode(bytes.Repeat([]byte("tamper"), 200), key)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tampered := append([]byte(nil), stored...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Decode(tampered, alg, key); err == nil {
		t.Fatalf("Decode accepted a tampered entry")
	}
	if _, err := Decode(stored[:8], alg, key); err == nil {
		t.Fatalf("Decode accepted a truncated entry")
	}
}

func TestWrongKeyFails(t *testing.T) {
	stored, alg, err := Encode(bytes.Repeat([]byte("secret"), 100), testKey(0x01))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := Decode(stored, alg, testKey(0x02)); err == nil {
		t.Fatalf("Decode accepted the wrong key")
	}
	// An encrypted zstd entry is undecodable without any key at all.
	if got, err := Decode(stored, AlgZstd, nil); err == nil {
		t.Fatalf("keyless Decode of an encrypted entry succeeded (%d bytes)", len(got))
	}
}

func TestBadInputs(t *testing.T) {
	if _, _, err := Encode([]byte("x"), make([]byte, 16)); err == nil {
		t.Fatalf("Encode accepted a 16-byte key")
	}
	if _, err := Decode([]byte("x"), AlgNone, make([]byte, 16)); err == nil {
		t.Fatalf("Decode accepted a 16-byte key")
	}
	if _, err := Decode([]byte("x"), 42, nil); err == nil {
		t.Fatalf("Decode accepted an unknown alg")
	}
}

// SealedLen has to answer before any key is in hand, so it states GCM's tag
// length as a constant rather than asking a cipher for it. The whole of
// cross-generation dedup rests on that number: a stored entry's algorithm
// is recovered by comparing its length against SealedLen, so a tag size
// that drifted from the AEAD's would make every encrypted volume refuse to
// deduplicate — silently, since refusing is the safe direction.
func TestSealedLenStatesTheRealTagSize(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	if aead.Overhead() != gcmTagSize {
		t.Fatalf("gcmTagSize is %d, the AEAD's overhead is %d", gcmTagSize, aead.Overhead())
	}
	if aead.NonceSize() != nonceSize {
		t.Fatalf("nonceSize is %d, the AEAD wants %d", nonceSize, aead.NonceSize())
	}
	// And end to end, against bytes zstd cannot shrink, which is the only
	// case where the predicted length is the raw one.
	raw := make([]byte, 4096)
	for i := range raw {
		raw[i] = byte(i*7 ^ i>>3)
	}
	for _, k := range [][]byte{nil, key} {
		enc, alg, err := Encode(raw, k)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := AlgOfStored(raw, k, int64(len(enc))); !ok || got != alg {
			t.Errorf("key %v: Encode produced alg %d in %d bytes; AlgOfStored recovered %d (ok=%v)",
				k != nil, alg, len(enc), got, ok)
		}
		if alg == AlgNone && SealedLen(len(raw), k) != int64(len(enc)) {
			t.Errorf("key %v: SealedLen says %d, Encode produced %d",
				k != nil, SealedLen(len(raw), k), len(enc))
		}
	}
}
