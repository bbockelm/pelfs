package vfsbilly

import (
	"fmt"
	"testing"
)

// The cache must never grow without bound, and retiring a generation must
// not be able to drop what is still in active use before at least one full
// turnover has passed.
func TestDirCacheRetiresGenerations(t *testing.T) {
	c := newDirCache()
	c.limit, c.disabled = 8, false

	hot := dirKey{parent: 1, name: "hot"}
	c.put(hot.parent, hot.name, 99)

	for i := 0; i < c.limit*10; i++ {
		c.put(2, fmt.Sprintf("cold%d", i), uint64(1000+i))
		// Touching the hot edge each round promotes it out of the retired
		// generation, so it survives indefinitely.
		if ino, ok := c.get(hot.parent, hot.name); !ok || ino != 99 {
			t.Fatalf("round %d: hot edge = %d, %v", i, ino, ok)
		}
		c.mu.Lock()
		n := len(c.young) + len(c.old)
		c.mu.Unlock()
		if n > 2*c.limit {
			t.Fatalf("round %d: cache holds %d entries, bound is %d", i, n, 2*c.limit)
		}
	}
}

func TestDirCacheForget(t *testing.T) {
	c := newDirCache()
	c.limit, c.disabled = 4, false
	c.put(1, "a", 10)

	// Retire the generation the edge landed in, so forget has to reach
	// both halves.
	for i := 0; i < c.limit; i++ {
		c.put(2, fmt.Sprintf("f%d", i), uint64(20+i))
	}
	c.forget(1, "a")
	if ino, ok := c.get(1, "a"); ok {
		t.Fatalf("a forgotten edge still resolves to %d", ino)
	}
	// Forgetting an edge that was never cached is a no-op, not a panic.
	c.forget(7, "never")
}
