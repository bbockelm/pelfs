package entrycodec

import (
	"bytes"
	"testing"
)

// Pack entry bytes are untrusted federation content. Decode must never
// panic on arbitrary input, and on encrypted volumes any mutation must
// fail the GCM open (never yield different plaintext silently).
//
//	go test -tags nogspt,notikv -fuzz FuzzDecode ./internal/entrycodec/
func FuzzDecode(f *testing.F) {
	key := bytes.Repeat([]byte{7}, KeySize)
	plainZ, algZ, _ := Encode([]byte("hello hello hello hello"), nil)
	encZ, _, _ := Encode([]byte("secret secret secret secret"), key)
	f.Add(plainZ, algZ, false)
	f.Add(encZ, AlgZstd, true)
	f.Add([]byte{}, AlgNone, false)
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd}, AlgZstd, false) // zstd magic, truncated

	f.Fuzz(func(t *testing.T, data []byte, alg uint8, keyed bool) {
		var k []byte
		if keyed {
			k = key
		}
		out, err := Decode(data, alg, k)
		if err != nil {
			return
		}
		// Decoded output must round-trip: re-encoding under the same key
		// and decoding again yields identical bytes (no aliasing, no
		// state leakage between calls).
		re, realg, err := Encode(out, k)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(re, realg, k)
		if err != nil || !bytes.Equal(back, out) {
			t.Fatalf("re-encode round trip diverged (err %v)", err)
		}
	})
}
