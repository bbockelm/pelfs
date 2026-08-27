package packstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// Pack trailers are UNTRUSTED federation bytes: a compromised origin or a
// range-mangling cache can hand back anything. decodeTrailer and parseTail
// must never panic and never return entries pointing outside the object.
//
//	go test -fuzz FuzzDecodeTrailer ./internal/packstore/

func FuzzDecodeTrailer(f *testing.F) {
	// Seeds: a valid PK2 trailer, a valid legacy PK1 body, and junk.
	tr := trailer{Version: 1, Created: 12345, Entries: []PackEntry{
		{Key: "aa", Off: 0, Length: 10}, {Key: "bb", Off: 10, Length: 5, Type: EntryCatalog},
	}, Dead: []string{"gone"}}
	raw, _ := json.Marshal(&tr)
	stored, _, err := encodeTrailer(&tr)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(stored, true)
	f.Add(raw, false)
	f.Add([]byte("{"), false)
	f.Add([]byte{}, true)

	f.Fuzz(func(t *testing.T, data []byte, compressed bool) {
		// The bool chooses between the two JSON forms, as it always has.
		// The TABLE form is tried on top of it, unconditionally: it is the
		// form every pack written today carries, and this target had never
		// once handed the decoder a magicT — which is how a hole in it
		// survived. The table reads extents as raw uint64s and so skipped
		// the sign check the JSON path had always applied.
		//
		// The bool stays in the signature because the checked-in corpus is
		// encoded with it.
		m := magic
		if compressed {
			m = magicZ
		}
		for _, form := range []string{m, magicT} {
			tr, err := decodeTrailer(data, form)
			if err != nil {
				continue
			}
			if tr.Version != 1 {
				t.Fatalf("decodeTrailer accepted version %d", tr.Version)
			}
			// Whatever form it arrived in, an entry that would send a
			// range read to a negative offset must not get out of here.
			for _, e := range tr.Entries {
				if e.Off < 0 || e.Length < 0 || e.Off+e.Length < 0 {
					t.Fatalf("decodeTrailer (%s) accepted extent %+v", form, e)
				}
			}
		}
	})
}

func FuzzParseTail(f *testing.F) {
	// Seed: a full valid mini-pack tail (entries + trailer + footer).
	tr := trailer{Version: 1, Created: 1}
	tr.Entries = append(tr.Entries, PackEntry{Key: "k", Off: 0, Length: 4})
	stored, footer, err := encodeTrailer(&tr)
	if err != nil {
		f.Fatal(err)
	}
	valid := append(append([]byte("data"), stored...), footer...)
	f.Add(valid)
	bad := bytes.Clone(valid)
	binary.LittleEndian.PutUint64(bad[len(bad)-16:len(bad)-8], 1<<60) // absurd index length
	f.Add(bad)
	f.Add([]byte("PELFSPK1"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// parseTail's overflow path range-reads from the store; hand it a
		// nil store — the fuzz input IS the whole object, so idxLen larger
		// than the buffer must error before any store call (size == len).
		tr, _, _, err := parseTail(context.Background(), nil, "p-0-fuzz", int64(len(data)), data)
		if err != nil {
			return
		}
		for _, e := range tr.Entries {
			if e.Off < 0 || e.Length < 0 {
				t.Fatalf("parseTail accepted negative extent %+v", e)
			}
		}
	})
}
