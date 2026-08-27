package webapi

// SetFlightJoined installs a callback the listing guard fires when a caller
// finds a listing already in flight and is about to wait on it.
//
// The tests live in package webapi_test, so this is the seam that reaches
// flightJoined. It exists because collapsing cannot be asserted by timing:
// counting readdirs after starting N goroutines asserts a scheduling
// outcome, and it failed on an idle CI runner twice while passing locally.
// The join is the one moment a follower is observably inside the guard.
func SetFlightJoined(f func()) { flightJoined = f }
