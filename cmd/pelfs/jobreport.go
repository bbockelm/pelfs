package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/chirp"
	"github.com/bbockelm/pelfs/internal/mounterr"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/ui"
)

// This file is the pelfs half of the chirp reporting: what a mount tells
// the HTCondor job it is serving, while that job runs.
//
// internal/stats already writes a JSON summary "so an external
// supervisor can determine AFTER THE FACT whether the filesystem
// encountered errors". That is the right artefact for a post-mortem and
// the wrong one for a job that is still burning wall-clock on a broken
// mount. Chirp is the live channel: internal/chirp publishes a handful
// of attributes into the job ad, and -- the part that motivated this --
// reports the moment the mount answers the payload with an I/O error, so
// the job can be held by policy instead of being left to produce
// plausible garbage.
//
// What it does NOT do is decide policy on the user's behalf. See
// mountErrorPolicy.

// mountErrorPolicy is what pelfs does the first time the mount answers
// the payload with an unexplained I/O error.
//
// # Why `report` is the default and `hold` is not
//
// Chirp has no "hold me" verb, so there are exactly two routes to a held
// job and they have different blast radii:
//
//   - Declarative. pelfs sets ChirpPelfsMountError, and the submit file
//     carries `periodic_hold = ChirpPelfsMountError =?= true`. The
//     schedd holds the job at its next periodic evaluation, with a hold
//     reason that names the failure. The job's own process is untouched
//     until then.
//
//   - Imperative. pelfs kills the payload, which it owns as a child
//     process under `pelfs shell -- cmd`, and exits with a distinctive
//     status so `on_exit_hold` fires at once.
//
// The second is faster and strictly more dangerous, and three things
// argue against making it the default:
//
//  1. A transient error killing a ten-hour job is its own failure mode.
//     The latch fires on the FIRST unexplained error, which is the right
//     trigger for "tell someone" and a poor one for "destroy nine hours
//     of work" -- and pelfs cannot tell a corrupt pack from a federation
//     that was unreachable for the length of one read.
//  2. It does not work everywhere. Under apptainer, pelfs is a
//     `--fusemount` driver serving a descriptor its parent opened; it
//     has no payload to kill and never sees one. Under `pelfs mount-gen`
//     the same. Making the default a behaviour that only exists in one
//     of three deployment shapes teaches users something false.
//  3. The owner's goal -- "users don't have to be very good at catching
//     exceptions" -- is met by a HELD JOB WITH A REAL HOLD REASON, not
//     by a kill. A held job keeps its sandbox, tells the user what
//     happened in words, and can be released. A killed one has thrown
//     away the only copy of the failure's context.
//
// So: report by default, everywhere; kill only when asked for, and only
// where pelfs actually owns the process.
type mountErrorPolicy string

const (
	// onMountErrorReport publishes the failure -- user log, job ad,
	// pelfs's own output -- and lets the payload keep running.
	onMountErrorReport mountErrorPolicy = "report"
	// onMountErrorHold does that AND takes the payload down.
	onMountErrorHold mountErrorPolicy = "hold"
	// onMountErrorIgnore publishes nothing. It exists for the workload
	// that legitimately expects I/O errors and handles them, where a
	// periodic_hold expression somebody else wrote would be a nuisance.
	onMountErrorIgnore mountErrorPolicy = "ignore"
)

func parseMountErrorPolicy(s string) (mountErrorPolicy, error) {
	switch mountErrorPolicy(s) {
	case onMountErrorReport, onMountErrorHold, onMountErrorIgnore:
		return mountErrorPolicy(s), nil
	}
	return "", fmt.Errorf("--on-mount-error must be report, hold or ignore (got %q)", s)
}

// exitMountError is the status pelfs exits with when --on-mount-error=hold
// took the payload down.
//
// 75 is EX_TEMPFAIL from sysexits.h -- "temporary failure; the user is
// invited to retry" -- which is exactly the claim being made, is
// documented somewhere other than pelfs, and sits clear of both the
// shell's 126/127 and the 128+signum range a killed process reports.
const exitMountError = 75

// takeDownGrace is how long a payload gets between the SIGTERM that asks
// it to stop and the SIGKILL that makes it. Long enough for a program
// that flushes on a signal, short enough that a program that ignores
// signals does not hold the job open on a mount that is already broken.
const takeDownGrace = 10 * time.Second

// chirpInterval is how often the mount's numbers are refreshed in the
// job ad. See chirp.DefaultInterval for why the cadence is what it is;
// the short version is that everything on this timer uses the DELAYED
// verb, so the schedd sees it at the starter's rate no matter what is
// chosen here.
const chirpInterval = chirp.DefaultInterval

// startJobReporting connects to the condor_starter, if there is one, and
// begins publishing. It is a no-op on every pelfs that is not running
// inside a job, which is nearly all of them.
func (g *genSession) startJobReporting(ctx context.Context, o *cmdOpts, hasPayload bool) {
	g.onMountError = o.onMountError
	if g.onMountError == onMountErrorHold && !hasPayload {
		// Say it once, at startup, rather than letting the user find out
		// at the moment of failure that the flag did nothing.
		ui.Warn("--on-mount-error=hold has no payload to take down in this mode "+
			"(pelfs owns a child process only under `pelfs shell -- command`); "+
			"the failure is still reported, pelfs still exits {code}, and `periodic_hold` on "+
			"{attribute} still holds the job",
			"code", exitMountError, "attribute", chirp.AttrMountError)
	}

	r, err := chirp.Open(ctx)
	if err != nil {
		// Never fatal. A mount that refuses to serve because it could not
		// reach a reporting channel would be a worse bug than the one it
		// is reporting.
		ui.Warn("chirp reporting is unavailable: {error}", "error", err)
	}
	g.chirp = r
	if r.InJob() {
		ui.Info("reporting mount health to the HTCondor job over chirp ({config}, every {interval})",
			"config", r.Config(), "interval", chirpInterval)
		for _, name := range append([]string{chirp.AttrMountError}, chirp.PeriodicAttrs...) {
			if !chirp.DelayedPrefixAllows(name) {
				ui.Warn("this pool's CHIRP_DELAYED_UPDATE_PREFIX does not accept {attribute}, "+
					"so periodic updates will be dropped by the starter without an error",
					"attribute", name)
				break
			}
		}
		// A reporting channel that has quietly stopped working is worth
		// exactly one line: repeating it every minute for ten hours
		// would bury the mount's own output, and the condition is
		// already visible in the job ad as a heartbeat that stopped
		// advancing.
		var said sync.Once
		go r.Run(ctx, chirpInterval, g.chirpSample, func(err error) {
			said.Do(func() {
				ui.Warn("chirp reporting to the job has stopped working: {error} "+
					"(the mount is unaffected; {attribute} will stop advancing)",
					"error", err, "attribute", chirp.AttrHeartbeat)
			})
		})
	}

	mounterr.OnFirst(g.onMountFailure)
}

// chirpSample reads the live counters the job ad publishes. It takes the
// statistics lock briefly and copies out an identifier and five numbers;
// it must not do anything slower, because it runs on the reporting
// goroutine's timer while the mount is serving.
func (g *genSession) chirpSample() chirp.Mount {
	var m chirp.Mount
	g.stats.Update(func(s *stats.Summary) {
		m.Session = s.Session
		m.Generation = s.Generation
		m.BytesDown = s.Get.Bytes
		m.BytesUp = s.Put.Bytes
		m.ObjectErrors = s.ObjectErrorsTotal
		if s.Write != nil {
			m.UploadBacklog = s.Write.UploadBacklog
		}
	})
	return m
}

// onMountFailure runs once, on its own goroutine, the first time either
// frontend answers the payload with an I/O error it could not explain
// (internal/mounterr).
func (g *genSession) onMountFailure(ev mounterr.Event) {
	reason := fmt.Sprintf("%s mount: %v", ev.Frontend, ev.Err)

	// Recorded in the statistics file regardless of policy: the file is
	// the after-the-fact record, and "did this session ever hand the
	// payload an unexplained error" is exactly the question it exists to
	// answer. It was previously unanswerable -- object_errors_total
	// counts federation retries, most of which the mount recovered from.
	g.stats.Update(func(s *stats.Summary) {
		s.MountError = true
		s.MountErrorReason = reason
		s.MountErrorAt = ev.At
	})

	if g.onMountError == onMountErrorIgnore {
		ui.Debug("mount I/O error reported to the payload; --on-mount-error=ignore, saying nothing to the job: {error}",
			"error", ev.Err)
		return
	}

	ui.Error("the mount answered the job's {frontend} request with an I/O error it could not explain: {error}",
		"frontend", ev.Frontend, "error", ev.Err)

	if err := g.chirp.Fail(reason); err != nil {
		ui.Warn("could not tell the HTCondor job about the mount error: {error}", "error", err)
	} else if g.chirp.InJob() {
		ui.Info("told the job: {attribute} = true (a submit file with `periodic_hold = {attribute} =?= true` will hold it)",
			"attribute", chirp.AttrMountError)
	}

	if g.onMountError != onMountErrorHold {
		return
	}
	select {
	case g.takeDown <- reason:
	default: // already asked; the latch means this cannot be a second failure
	}
}

// mountErrorExit rewrites the session's exit status when
// --on-mount-error=hold saw a failure.
//
// It overrides the payload's OWN status deliberately, including a
// successful one. A payload that read a truncated file, got EIO, and
// exited 0 anyway is precisely the case this feature exists for: the
// job "succeeded" and its output is wrong. In `report` mode nothing here
// touches the status, because there the user has not asked pelfs to
// have an opinion about their exit code.
func (g *genSession) mountErrorExit(code int) int {
	if g.onMountError != onMountErrorHold {
		return code
	}
	ev, ok := mounterr.Fired()
	if !ok {
		return code
	}
	ui.Error("exiting {code} because the mount failed during this session ({error}); "+
		"`on_exit_hold = ExitCode =?= {code}` in the submit file holds the job",
		"code", exitMountError, "error", ev.Err)
	return exitMountError
}
