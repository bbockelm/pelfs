package memtable

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBufferAppendAndScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b0.buf")
	b, err := CreateBuffer(path, 1<<16, 0)
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("alpha"), bytes.Repeat([]byte{0x5a}, 4096), {}}
	for i, p := range payloads {
		rec := Record{Handle: Handle(i + 1), Inode: uint64(100 + i), FileOff: int64(i * 10)}
		if err := b.Append(&rec, p); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if got := b.At(rec.Off, rec.Length); !bytes.Equal(got, p) {
			t.Fatalf("record %d reads back %q, want %q", i, got, p)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b2, recs, err := OpenBuffer(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close() //nolint:errcheck
	if len(recs) != len(payloads) {
		t.Fatalf("recovered %d records, want %d", len(recs), len(payloads))
	}
	for i, rec := range recs {
		if rec.Handle != Handle(i+1) || rec.Inode != uint64(100+i) || rec.FileOff != int64(i*10) {
			t.Errorf("record %d metadata = %+v", i, rec)
		}
		if got := b2.At(rec.Off, rec.Length); !bytes.Equal(got, payloads[i]) {
			t.Errorf("record %d payload = %q, want %q", i, got, payloads[i])
		}
	}
}

func TestBufferFull(t *testing.T) {
	b, err := CreateBuffer(filepath.Join(t.TempDir(), "b.buf"), recordHeader+16, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close() //nolint:errcheck
	rec := Record{Handle: 1}
	if err := b.Append(&rec, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if err := b.Append(&Record{Handle: 2}, []byte{0}); err != ErrBufferFull {
		t.Fatalf("second append err = %v, want ErrBufferFull", err)
	}
	if b.Room(1) {
		t.Error("Room reports space in a full buffer")
	}
}

// A truncated buffer file is the ordinary crash shape: the tail of the
// mapping never reached the disk. Recovery must keep what validates and
// stop, not guess at the rest.
func TestBufferScanStopsAtTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "torn.buf")
	b, err := CreateBuffer(path, 1<<16, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ends []int
	for i := range 4 {
		rec := Record{Handle: Handle(i + 1), Inode: 7}
		if err := b.Append(&rec, bytes.Repeat([]byte{byte(i)}, 100)); err != nil {
			t.Fatal(err)
		}
		ends = append(ends, b.Used())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	// Cut the file inside the third record's payload.
	if err := os.Truncate(path, int64(ends[1]+recordHeader+50)); err != nil {
		t.Fatal(err)
	}
	b2, recs, err := OpenBuffer(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close() //nolint:errcheck
	if len(recs) != 2 {
		t.Fatalf("recovered %d records from a tail cut inside the third, want 2", len(recs))
	}
}

// A record whose payload was corrupted in place — the length still
// plausible, the bytes not what was written — must not be handed back.
func TestBufferScanRejectsCorruptPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.buf")
	b, err := CreateBuffer(path, 1<<16, 0)
	if err != nil {
		t.Fatal(err)
	}
	var second Record
	for i := range 3 {
		rec := Record{Handle: Handle(i + 1)}
		if err := b.Append(&rec, bytes.Repeat([]byte{byte(i)}, 64)); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			second = rec
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xff}, int64(second.Off+3)); err != nil {
		t.Fatal(err)
	}
	f.Close() //nolint:errcheck

	b2, recs, err := OpenBuffer(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close() //nolint:errcheck
	if len(recs) != 1 {
		t.Fatalf("recovered %d records past a corrupt second record, want 1", len(recs))
	}
}
