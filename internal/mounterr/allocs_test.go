package mounterr

import "testing"

// testingAllocs is testing.AllocsPerRun, wrapped so the allocation
// assertion above reads as one line. It is a separate file because
// -race disables the accounting AllocsPerRun depends on, and keeping the
// helper apart makes that easy to say once.
func testingAllocs(fn func()) float64 { return testing.AllocsPerRun(200, fn) }
