//go:build !race

package main

// raceSlowdown is 1 without the race detector; see the race-tagged twin.
const raceSlowdown = 1
