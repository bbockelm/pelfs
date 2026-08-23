package memtable

// SetMinReuseBytes lowers the cross-generation dedup threshold for a test
// whose fixtures are cut with test-sized chunker parameters, and restores
// it afterwards. The threshold is derived from what one index lookup
// transfers (64 KiB), which is larger than every chunk a test-sized
// chunker produces — so without this a test could only exercise the
// mechanism by writing megabytes.
func SetMinReuseBytes(n int64) func() {
	old := minReuseBytes
	minReuseBytes = n
	return func() { minReuseBytes = old }
}
