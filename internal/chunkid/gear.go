package chunkid

// gearSeed fixes the gear table for all time. Cut points are part of
// the on-disk format: changing this constant (or the generator) would
// re-chunk every volume and break cross-version dedup, so it must never
// change once volumes exist.
const gearSeed uint64 = 0x70656c6673763264 // "pelfsv2d"

// gearTable maps each input byte to a fixed 64-bit random value for the
// gear rolling hash. Generated deterministically at init from gearSeed —
// baked-in randomness, never runtime randomness.
var gearTable = generateGear(gearSeed)

// generateGear expands a seed into 256 gear values with splitmix64,
// chosen because it is trivially reimplementable from the reference
// constants if the table ever needs to be reproduced outside Go.
func generateGear(seed uint64) [256]uint64 {
	var t [256]uint64
	s := seed
	for i := range t {
		s += 0x9e3779b97f4a7c15
		z := s
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		t[i] = z ^ (z >> 31)
	}
	return t
}
