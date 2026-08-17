package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// memStore is the smallest thing the counter can wrap: a map. What is
// under test is the counting, not any transport.
type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) String() string { return "mem://" }

func (m *memStore) Put(_ context.Context, key string, in io.Reader) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = data
	return nil
}

func (m *memStore) Get(_ context.Context, key string, off, limit int64) (io.ReadCloser, error) {
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
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

func (m *memStore) Head(_ context.Context, key string) (*pelicanobj.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &pelicanobj.Object{Key: key, Size: int64(len(data))}, nil
}

func (m *memStore) ListAll(context.Context, string, string) (<-chan *pelicanobj.Object, error) {
	return nil, errors.New("not implemented")
}

func TestCountingAndSummary(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "stats.json")
	c := New("pelican://fed/pfx", "sess-1", path)
	s := WrapStorage(newMemStore(), c)

	payload := strings.Repeat("x", 1000)
	if err := s.Put(ctx, "a/b", strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get(ctx, "a/b", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	var total int
	for {
		n, err := rc.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	rc.Close()
	if total != 1000 {
		t.Fatalf("read %d bytes", total)
	}

	// A failing Get must count as an error with a sample.
	if _, err := s.Get(ctx, "no/such", 0, -1); err == nil {
		t.Fatal("expected error")
	}
	if err := s.Delete(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}

	if err := c.Finalize(0, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sum Summary
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Put.Ops != 1 || sum.Put.Bytes != 1000 {
		t.Fatalf("put counters: %+v", sum.Put)
	}
	if sum.Get.Ops != 2 || sum.Get.Bytes != 1000 || sum.Get.Errors != 1 {
		t.Fatalf("get counters: %+v", sum.Get)
	}
	if sum.Delete.Ops != 1 || sum.Delete.Errors != 0 {
		t.Fatalf("delete counters: %+v", sum.Delete)
	}
	if sum.ObjectErrorsTotal != 1 || len(sum.ErrorSamples) != 1 || sum.ErrorSamples[0].Op != "get" {
		t.Fatalf("error accounting: total=%d samples=%+v", sum.ObjectErrorsTotal, sum.ErrorSamples)
	}
	if !sum.CleanShutdown || sum.ExitCode != 0 || sum.Finished.IsZero() {
		t.Fatalf("outcome fields: %+v", sum)
	}
}
