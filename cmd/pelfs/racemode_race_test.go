//go:build race

package main

// raceSlowdown scales the deadlines of tests that write real volumes of
// data. The race detector costs roughly an order of magnitude on the
// chunk-hash-compress path, and TestCheckpointFiresUnderWritePressure
// stages a gigabyte on purpose — its whole point is that the pressure
// trigger fires where a five-minute timer would not.
//
// Under -race that test reached "checkpoint started: 1.0 GiB staged" and
// then ran out of its sixty-second deadline before the publish landed:
// a failure about the machine rather than about the trigger. It has
// failed this way since before the trigger existed.
const raceSlowdown = 5
