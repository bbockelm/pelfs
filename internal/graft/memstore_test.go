package graft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// memStore is the smallest store a spider and a windowed reader can be
// tested against: a map, with per-request counters so a test can assert
// that a large index is NOT fetched whole, and a concurrency watermark so
// a test can assert the walk actually parallelises.
type memStore struct {
	mu    sync.Mutex
	objs  map[string]*memObj
	gets  atomic.Int64
	bytes atomic.Int64

	live atomic.Int64
	peak atomic.Int64
	// delay stands in for a round trip, so a test can see parallelism.
	delay time.Duration
	// shortBy makes a Get deliver less than it listed, which is what a
	// source truncated under the walk looks like.
	shortBy int64
	// onGet runs before each read, so a test can move the tree
	// underneath the walk.
	onGet func(key string)
}

type memObj struct {
	data  []byte
	mtime time.Time
}

func newMemStore() *memStore {
	return &memStore{objs: map[string]*memObj{}}
}

func (m *memStore) put(key string, data []byte, mtime time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = &memObj{data: append([]byte(nil), data...), mtime: mtime}
}

func (m *memStore) String() string { return "mem://" }

func (m *memStore) Put(_ context.Context, key string, in io.Reader) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = &memObj{data: data, mtime: time.Unix(0, 0)}
	return nil
}

func (m *memStore) Get(_ context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	n := m.live.Add(1)
	for {
		p := m.peak.Load()
		if n <= p || m.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if m.onGet != nil {
		m.onGet(key)
	}
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.live.Add(-1)
	m.gets.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("mem: %s: %w", key, os.ErrNotExist)
	}
	data := o.data
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	data = data[off:]
	if limit >= 0 && limit < int64(len(data)) {
		data = data[:limit]
	}
	if m.shortBy > 0 && int64(len(data)) > m.shortBy {
		data = data[:int64(len(data))-m.shortBy]
	}
	m.bytes.Add(int64(len(data)))
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
	o, ok := m.objs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &pelicanobj.Object{Key: key, Size: int64(len(o.data)), Mtime: o.mtime}, nil
}

func (m *memStore) ListAll(_ context.Context, prefix, marker string) (<-chan *pelicanobj.Object, error) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.objs))
	for k := range m.objs {
		if len(prefix) > 0 && !bytes.HasPrefix([]byte(k), []byte(prefix)) {
			continue
		}
		if k <= marker {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*pelicanobj.Object, 0, len(keys))
	for _, k := range keys {
		o := m.objs[k]
		out = append(out, &pelicanobj.Object{Key: k, Size: int64(len(o.data)), Mtime: o.mtime})
	}
	m.mu.Unlock()
	ch := make(chan *pelicanobj.Object, len(out))
	for _, o := range out {
		ch <- o
	}
	close(ch)
	return ch, nil
}

func (m *memStore) ListDir(context.Context, string) ([]pelicanobj.DirEntry, error) {
	return nil, errors.New("not implemented")
}

func (m *memStore) StatKey(context.Context, string) (*pelicanobj.KeyInfo, error) {
	return nil, errors.New("not implemented")
}

var _ pelicanobj.Store = (*memStore)(nil)
