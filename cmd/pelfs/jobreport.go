package main

import (
	"context"
	"errors"
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
// # The failure this exists to prevent
//
// It is not the error. It is EXIT 0 WITH A CORRUPT RESULT.
//
// Programs that read a filesystem overwhelmingly do not check read(2)
// for EIO -- there was never a reason to think a read could fail -- so a
// job handed one typically carries on, writes output, and exits
// successfully. That output is indistinguishable from a correct answer
// by anything downstream, and the job's own exit status vouches for it.
// A user who is bad at error handling therefore does not get a crash;
// they get a wrong scientific result with a green tick beside it.
//
// The cost asymmetry settles the default. Re-running a job costs some
// CPU on a machine that was going to be busy anyway. Recording a wrong
// result costs whatever gets built on top of it, possibly years later,
// possibly after publication. So pelfs defaults to the behaviour that
// makes the job RUN AGAIN rather than the one that records a success it
// cannot vouch for.
//
// # Where enforcement actually happens
//
// The schedd, not this process. A chirp update is written into the
// SHADOW's copy of the job ad -- the same ClassAd pointer the shadow's
// UserPolicy evaluates at exit (shadow.cpp hands one jobAd to both
// RemoteResource::setJobAd and shadow_user_policy.init) -- so a submit
// file's on_exit_remove or on_exit_hold acts on it in every deployment
// shape: `pelfs shell`, `pelfs mount-gen`, and an apptainer --fusemount
// driver that never sees a payload process at all.
//
// That is why the policy below is not about ownership. Every mode
// publishes the attribute; what the modes choose is what PELFS does
// locally, on top of it.
//
// # The modes
//
// Two independent things, which an earlier version of this flag
// conflated: does pelfs stop the payload, and does pelfs refuse to
// report a success it cannot vouch for.
//
//	              tell the job   stop the payload   exit non-zero
//	rerun (default)    yes             no                yes
//	abort              yes             yes               yes
//	report             yes             no                no
//	ignore             no              no                no
//
// The local exit status is REINFORCEMENT, not the mechanism. It matters
// where pelfs owns the payload -- `pelfs shell -- cmd`, where pelfs's
// status IS the job's -- because it makes a pool whose submit file
// carries no policy expression still record a failure instead of a
// success. Where pelfs owns nothing it is merely honest.
//
// There is no `hold` mode, and there was one. Holding is not something
// this process can do: chirp has no such verb, and the decision belongs
// in the submit file, where `on_exit_hold` composes with everything
// else. See docs/design-chirp.md, which gives both expressions and says
// when to reach for the second.
type mountErrorPolicy string

const (
	// onMountErrorRerun is the default: publish the failure -- user log,
	// job ad, pelfs's own output -- leave the payload alone, and exit
	// non-zero so that a payload's exit 0 cannot stand as this session's
	// verdict. The submit-side companion is on_exit_remove.
	onMountErrorRerun mountErrorPolicy = "rerun"
	// onMountErrorAbort additionally stops the payload. For a workload
	// where continuing after the first bad read produces MORE corrupt
	// output rather than merely finishing the same one.
	onMountErrorAbort mountErrorPolicy = "abort"
	// onMountErrorReport publishes everything and touches neither the
	// payload nor the exit status. This was the old default, and it is
	// now what a workload asks for when it genuinely handles I/O errors
	// and wants only the telemetry.
	onMountErrorReport mountErrorPolicy = "report"
	// onMountErrorIgnore says nothing to the job at all. The periodic
	// statistics continue; only the error latch is suppressed.
	onMountErrorIgnore mountErrorPolicy = "ignore"
)

// setsExitStatus reports whether this policy refuses to let a payload's
// own exit status stand once the mount has failed.
func (p mountErrorPolicy) setsExitStatus() bool {
	return p == onMountErrorRerun || p == onMountErrorAbort
}

func parseMountErrorPolicy(s string) (mountErrorPolicy, error) {
	switch mountErrorPolicy(s) {
	case onMountErrorRerun, onMountErrorAbort, onMountErrorReport, onMountErrorIgnore:
		return mountErrorPolicy(s), nil
	}
	if s == "hold" {
		// Answered by name rather than by the generic list, because the
		// person who typed it wants a real thing that pelfs cannot do and
		// the submit file can.
		return "", errors.New("--on-mount-error has no `hold`: holding a job is the schedd's, " +
			"and it is asked for in the submit file with " +
			"`on_exit_hold = (ChirpPelfsMountError =?= true)`, which works whether or not " +
			"pelfs owns the payload. Use --on-mount-error=rerun (the default) or abort here")
	}
	return "", fmt.Errorf("--on-mount-error must be rerun, abort, report or ignore (got %q)", s)
}

// exitMountError is the status pelfs exits with when the mount failed
// during a session run under `rerun` or `abort`.
//
// 75 is EX_TEMPFAIL from sysexits.h -- "temporary failure; the user is
// invited to retry" -- which is exactly the claim being made, is
// documented somewhere other than pelfs, and sits clear of both the
// shell's 126/127 and the 128+signum range a killed process reports.
//
// It is the second line of defence, not the first: the job ad attribute
// is what a submit-side policy acts on in every deployment shape. This
// is what a pool with NO policy expression sees, and under `pelfs shell`
// it is the job's own exit status, so an exit 0 the payload produced
// after reading a broken file never reaches the queue as a success.
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
	if g.onMountError == onMountErrorAbort && !hasPayload {
		// Precise about what is and is not lost. The old version of this
		// line implied that enforcement needed payload ownership, which
		// is false and was the wrong lesson to teach: the attribute
		// reaches the schedd either way, and the schedd is what acts.
		ui.Warn("--on-mount-error=abort has no payload to stop in this mode "+
			"(pelfs owns a child process only under `pelfs shell -- command`), "+
			"so a mount error is reported and this process exits {code}, but nothing here "+
			"interrupts the job's own program. Enforcement is the schedd's: "+
			"`on_exit_remove = ({attribute} =!= true) || (NumJobCompletions > 2)` in the "+
			"submit file re-runs the job whatever it exited with",
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
		// One synchronous write per ATTEMPT, before anything else: the
		// mount-error flag is sticky across a requeue, so a run that has
		// not failed yet has to say so or it inherits the verdict of the
		// run that got it requeued. See chirp.Reporter.Begin.
		if err := r.Begin(); err != nil {
			ui.Warn("could not clear {attribute} for this attempt: {error} "+
				"(a policy expression may act on an earlier attempt's failure)",
				"attribute", chirp.AttrMountError, "error", err)
		}
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
		ui.Info("told the job: {attribute} = true (a submit file with "+
			"`on_exit_remove = ({attribute} =!= true) || (NumJobCompletions > 2)` re-runs it)",
			"attribute", chirp.AttrMountError)
	}

	if g.onMountError != onMountErrorAbort {
		return
	}
	select {
	case g.takeDown <- reason:
	default: // already asked; the latch means this cannot be a second failure
	}
}

// mountErrorExit rewrites the session's exit status when the mount
// failed and the policy is one that refuses to vouch for the run.
//
// It overrides the payload's OWN status, INCLUDING A SUCCESSFUL ONE, and
// that is the entire point rather than an unfortunate side effect. A
// payload that read a truncated file, got EIO, did not check for it, and
// exited 0 is the failure this feature exists to prevent: the queue
// would otherwise record a success over a corrupt result, and nothing
// downstream could tell. Re-running costs CPU; recording it costs
// whatever gets built on the answer.
//
// `report` and `ignore` leave the status alone, because there the user
// has said they handle I/O errors themselves.
func (g *genSession) mountErrorExit(code int) int {
	if !g.onMountError.setsExitStatus() {
		return code
	}
	ev, ok := mounterr.Fired()
	if !ok {
		return code
	}
	ui.Error("exiting {code} rather than {was}: the mount handed this job an I/O error "+
		"it could not explain ({error}), so this run cannot be reported as a success",
		"code", exitMountError, "was", code, "error", ev.Err)
	return exitMountError
}
