package memtable

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// countingStore is a federation that remembers exactly what it was
// handed. The design's central claim — dead extents are never uploaded —
// is only testable against something that counts, not against a store
// that merely works.
type countingStore struct {
	mu   sync.Mutex
	objs map[string][]byte
	puts int
	// bytesPut is what actually crossed the wire, trailers included, so
	// it is always at least the store's own UploadedBytes accounting.
	bytesPut int64
	failPut  error
}

func newCountingStore() *countingStore {
	return &countingStore{objs: make(map[string][]byte)}
}

func (m *countingStore) String() string { return "counting://" }

func (m *countingStore) Put(_ context.Context, key string, in io.Reader) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut != nil {
		return m.failPut
	}
	m.objs[key] = data
	m.puts++
	m.bytesPut += int64(len(data))
	return nil
}

func (m *countingStore) Get(_ context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	data = data[off:]
	if limit >= 0 && limit < int64(len(data)) {
		data = data[:limit]
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), data...))), nil
}

func (m *countingStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

func (m *countingStore) Head(_ context.Context, key string) (*pelicanobj.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &pelicanobj.Object{Key: key, Size: int64(len(data))}, nil
}

func (m *countingStore) ListAll(context.Context, string, string) (<-chan *pelicanobj.Object, error) {
	return nil, errors.New("not implemented")
}

func (m *countingStore) ListDir(_ context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []pelicanobj.DirEntry
	for k, v := range m.objs {
		if strings.HasPrefix(k, dir+"/") {
			out = append(out, pelicanobj.DirEntry{Name: strings.TrimPrefix(k, dir+"/"), Size: int64(len(v))})
		}
	}
	return out, nil
}

func (m *countingStore) StatKey(_ context.Context, key string) (*pelicanobj.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &pelicanobj.KeyInfo{Size: int64(len(data))}, nil
}

func (m *countingStore) stats() (puts int, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts, m.bytesPut
}

// contains reports whether any uploaded object holds needle. It is the
// blunt instrument the dead-extent claim deserves: not "the accounting
// says we did not send it" but "the bytes are not on the wire".
func (m *countingStore) contains(needle []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.objs {
		if bytes.Contains(v, needle) {
			return true
		}
	}
	return false
}

// smallChunks keeps CDC parameters proportional to test-sized data;
// the production 1/4/16 MiB defaults would make every test file a single
// chunk and hide every boundary bug.
var smallChunks = chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10}

func newTestStore(t *testing.T, tableSize int, hooks Hooks) (*Store, *countingStore) {
	t.Helper()
	obj := newCountingStore()
	s, err := New(Options{
		Dir:       t.TempDir(),
		TableSize: tableSize,
		Obj:       obj,
		Chunk:     smallChunks,
		Hooks:     hooks,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s, obj
}

// readAll reads ino's whole content through the store's resolver.
func readAll(t *testing.T, s *Store, ino uint64) []byte {
	t.Helper()
	buf := make([]byte, s.Size(ino))
	n, err := s.Read(context.Background(), ino, 0, buf)
	if err != nil {
		t.Fatalf("read inode %d: %v", ino, err)
	}
	return buf[:n]
}
