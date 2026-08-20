package repack_test

import (
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
)

func headWith(packs uint32, m *superblock.Maint) *superblock.Superblock {
	return &superblock.Superblock{
		Manifests: []superblock.ManifestRef{{Name: "m", Packs: packs}},
		Maint:     m,
	}
}

// The gate has to be readable from the head alone and has to answer in
// both directions with a reason: it decides whether a background job
// runs, and a job that silently does nothing looks exactly like a broken
// one.
func TestWorthwhileJudgesFromTheHeadAlone(t *testing.T) {
	now := time.Now()
	policy := repack.AutoPolicy{Packs: 100, Interval: time.Hour, Now: now}

	for _, tc := range []struct {
		name string
		head *superblock.Superblock
		want bool
	}{
		{
			// A volume written long before this existed must be looked at
			// once, not exempted forever by a missing record.
			"never repacked and large", headWith(500, nil), true,
		},
		{
			"never repacked and small", headWith(10, nil), false,
		},
		{
			"enough added since the last repack",
			headWith(400, &superblock.Maint{RepackGeneration: 7, RepackPacks: 100,
				RepackUnixNano: now.Add(-4 * time.Hour).UnixNano()}), true,
		},
		{
			"not enough added",
			headWith(150, &superblock.Maint{RepackGeneration: 7, RepackPacks: 100,
				RepackUnixNano: now.Add(-4 * time.Hour).UnixNano()}), false,
		},
		{
			// The interval floor wins over the count, so a burst of writes
			// cannot make a volume sweep once per burst.
			"enough added but inside the interval floor",
			headWith(400, &superblock.Maint{RepackGeneration: 7, RepackPacks: 100,
				RepackUnixNano: now.Add(-10 * time.Minute).UnixNano()}), false,
		},
		{
			// A repack REMOVES packs, so the count can go down. That must
			// read as "nothing accumulated", never as a huge number.
			"fewer packs than at the last repack",
			headWith(50, &superblock.Maint{RepackGeneration: 7, RepackPacks: 400,
				RepackUnixNano: now.Add(-4 * time.Hour).UnixNano()}), false,
		},
		{"no head at all", nil, false},
	} {
		got, why := repack.Worthwhile(tc.head, policy)
		if got != tc.want {
			t.Errorf("%s: Worthwhile = %v (%s), want %v", tc.name, got, why, tc.want)
		}
		if why == "" {
			t.Errorf("%s: Worthwhile gave no reason", tc.name)
		}
	}
}

// The defaults have to be usable without being passed, since the mount
// asks this on a timer with no configuration.
func TestWorthwhileHasWorkingDefaults(t *testing.T) {
	if got, why := repack.Worthwhile(headWith(5, nil), repack.AutoPolicy{}); got {
		t.Errorf("a five-pack volume is worth sweeping by default: %s", why)
	}
	if got, _ := repack.Worthwhile(headWith(repack.DefaultAutoPacks+1, nil), repack.AutoPolicy{}); !got {
		t.Error("a volume past the default pack threshold is not worth sweeping")
	}
}
