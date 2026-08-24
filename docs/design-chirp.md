# Telling a running HTCondor job how its mount is doing

`internal/stats` writes a JSON summary so that "an external supervisor
(e.g. HTCondor) can determine **after the fact** whether the filesystem
encountered errors". That is the right artefact for a post-mortem and the
wrong one for a job that is still burning wall-clock on a broken mount.

This is the live channel. pelfs speaks **Chirp** to the `condor_starter`
that launched it, publishes a handful of attributes into the job ad, and
— the part that motivated the feature — reports the moment the mount
hands the payload an I/O error it cannot explain, so the job can be held
by policy instead of being left to produce plausible garbage.

There is no `condor_chirp` binary involved and no new dependency: pelfs
builds `CGO_ENABLED=0` with a tight `go.mod`, so `internal/chirp` is a
Go client written against the reference implementation
(`src/condor_chirp/chirp_client.c` and
`src/condor_starter.V6.1/io_proxy_handler.cpp`).

## Copy-pasteable submit file

```
executable  = run.sh
log         = job.log

# Chirp: the periodic statistics work without this line, because a
# starter enables DELAYED updates by default. This line is what buys the
# IMMEDIATE update and the user-log message on the error path -- i.e. a
# hold in seconds instead of at the starter's next update.
+WantIOProxy = true

# (a) Declarative: hold the job when the mount says it broke.
periodic_hold         = (ChirpPelfsMountError =?= true)
periodic_hold_reason  = strcat("pelfs mount error: ", \
                               ifThenElse(ChirpPelfsMountErrorReason =?= undefined, \
                                          "unexplained I/O error", \
                                          ChirpPelfsMountErrorReason))
periodic_hold_subcode = 1

# Optional, and the only thing that catches a mount that has WEDGED
# rather than failed -- a hung mount produces no error to report:
# periodic_hold = (ChirpPelfsMountError =?= true) || \
#                 (ChirpPelfsHeartbeat =!= undefined && \
#                  (time() - ChirpPelfsHeartbeat) > 1800)

# (b) Imperative, and opt-in on BOTH sides. With
# `pelfs shell --on-mount-error=hold -- ./payload`, pelfs stops the
# payload itself and exits 75 (EX_TEMPFAIL):
# on_exit_hold        = (ExitCode =?= 75)
# on_exit_hold_reason = "pelfs stopped the payload: the mount failed"

queue
```

The hold reason a user sees reads, for example:

```
pelfs mount error: fuse mount: read chunk 91af…: pack 3 trailer is truncated
```

## The attributes

All nine live in the `ChirpPelfs` namespace. **The `Chirp` prefix is not
decoration**: the starter refuses `set_job_attr_delayed` for any name
that does not match `CHIRP_DELAYED_UPDATE_PREFIX`, whose shipped default
is `Chirp*` — and refuses it in a way the client cannot see
(`jic_shadow.cpp` logs and returns a non-negative status). `PelfsMountError`
would have worked only on a pool whose admin had changed that setting.

| Attribute | Verb | What an operator does with it |
| --- | --- | --- |
| `ChirpPelfsSession` | delayed | Finds this session's statistics file and log lines afterwards. |
| `ChirpPelfsGeneration` | delayed | Provenance: which published generation the payload actually read. |
| `ChirpPelfsHeartbeat` | delayed | Unix seconds. The only signal that catches a **wedged** mount, which produces no error at all. |
| `ChirpPelfsBytesDown` | delayed | Progress. Flat for an hour is stuck, not slow. |
| `ChirpPelfsBytesUp` | delayed | Output actually leaving the node. |
| `ChirpPelfsUploadBacklog` | delayed | Bytes cut into packs and not yet sent — what is **lost** if the job is evicted now, and the best predictor of how long the seal after the payload takes. |
| `ChirpPelfsObjectErrors` | delayed | Transient federation failures that were retried successfully. Rising here is a sick federation before it is a failed job. |
| `ChirpPelfsMountError` | **immediate** | `true` once the mount has handed the payload an unexplained I/O error. |
| `ChirpPelfsMountErrorReason` | **immediate** | One line of prose, for `periodic_hold_reason`. |

Everything considered and rejected — cache occupancy, eviction counts,
per-phase splits, dedup ratios — answers a question asked *after* the
job, and after the job the statistics file is a better answer than a job
ad.

## Cadence, and why it is not a knob

Two verbs, and the choice between them is the whole cost story.

- `set_job_attr` is **synchronous**: starter → shadow → schedd queue,
  and only then does the call return. It writes to somebody's schedd.
- `set_job_attr_delayed` is **local**: the starter records the value and
  folds it into the update it was going to send anyway
  (`STARTER_UPDATE_INTERVAL`, 300 s by default).

So everything on the timer uses the delayed verb, and the schedd sees
pelfs's numbers at the *starter's* rate no matter what pelfs chooses. The
one-minute interval (`chirp.DefaultInterval`) therefore governs only
loopback round trips: comfortably inside the starter's window so no
forwarded update carries a figure more than a minute stale, five times
cheaper than riding the 30-second statistics tick, and about a hundred
short socket writes over a ten-hour job. Unchanged values are not
resent, so an idle mount's cycle is the single heartbeat write.

The error latch is the one thing that would be worthless five minutes
late, so it pays the synchronous trip — **once per session**, because it
is latched.

## The error path

Each frontend has exactly one place where a Go error it does not
recognize becomes the filesystem's "something broke" answer:

- `internal/rawfuse`, `errStatus`, the fall-through that returns
  `fuse.EIO`;
- `internal/vfsbilly`, `sentinel`, the fall-through that hands go-nfs an
  error it maps to `NFS3ERR_IO`.

Both report to `internal/mounterr`, which latches the first event (a
broken file answers every read a `tar` issues; the suppressed path is one
atomic load and allocates nothing) and hands it to the session on a
goroutine of its own — calling a socket inline from a FUSE handler would
turn "the mount reported an error" into "the mount hung".

`vfsbilly` additionally asks whether the error is one it *chose*: a bare
`syscall.Errno` handed to `pe` is a deliberate answer (`EACCES`,
`EINVAL`, `ELOOP`…) and does not latch, and neither does `ENOSPC`, which
go-nfs maps to `NFS3ERR_NOSPC` rather than to `IO`. The FUSE side needs
no such test — `errStatus` translates its deliberate answers before the
fall-through.

## `--on-mount-error`: report, hold, or ignore

Chirp has **no "hold me" verb**, so there are exactly two routes to a
held job:

**(a) Declarative.** pelfs sets the attribute; the submit file's
`periodic_hold` holds the job at the schedd's next periodic evaluation.
Correct, and it works in every deployment shape.

**(b) Imperative.** Under `pelfs shell -- cmd` pelfs *owns* the payload
as a child process, so it can stop it (SIGTERM, then SIGKILL after ten
seconds) and exit 75 so `on_exit_hold` fires at once.

**`report` is the default and `hold` must be typed.** Three reasons:

1. *A transient error killing a ten-hour job is its own failure mode.*
   The latch fires on the first unexplained error, which is the right
   trigger for "tell someone" and a poor one for "destroy nine hours of
   work" — and pelfs cannot tell a corrupt pack from a federation that
   was unreachable for the length of one read.
2. *It does not work everywhere.* Under apptainer, pelfs is a
   `--fusemount` driver serving a descriptor its parent opened; it has no
   payload to kill and never sees one. Same for `pelfs mount-gen`. A
   default that only exists in one of three deployment shapes teaches
   users something false. (pelfs says so at startup if you ask for `hold`
   where it cannot deliver.)
3. *The goal is met without it.* "Users don't have to be very good at
   catching exceptions" is satisfied by a **held job with a real hold
   reason** — which keeps its sandbox, says what happened in words, and
   can be released — not by a kill, which has thrown the context away.

`hold` deliberately overrides the payload's own exit status, **including
a successful one**: a payload that read a truncated file, got EIO and
exited 0 anyway is precisely the case the flag exists for. `report`
never touches the exit code.

`ignore` publishes nothing about the error (the periodic statistics
continue). It is for the workload that legitimately expects I/O errors
and handles them, where somebody else's `periodic_hold` would be a
nuisance.

## What the starter will and will not let through

| Command | Starter knob | Job-ad attribute | Default |
| --- | --- | --- | --- |
| `set_job_attr_delayed` | `ENABLE_CHIRP_DELAYED` | `WantDelayedUpdates` | **enabled** — a vanilla job needs no submit change |
| `set_job_attr`, `ulog` | `ENABLE_CHIRP_UPDATES` | `WantRemoteUpdates`, defaulting to `WantIOProxy` | **off** unless `+WantIOProxy = true` |
| delayed attribute names | `CHIRP_DELAYED_UPDATE_PREFIX` | — | `Chirp*` |

A refusal is invisible to the client: the starter's dispatch chain falls
through to `CHIRP_ERROR_INVALID_REQUEST`, which is also what an unknown
verb produces. So `Reporter.Fail` **falls back** from the immediate verb
to the delayed one — a job that never opted in still gets held, a few
minutes later than one that did — and pelfs warns at startup if the
pool's exported `_CHIRP_DELAYED_UPDATE_PREFIX` would reject the
`ChirpPelfs` namespace.

## Wire-format notes that are not guessable

Recorded because getting them wrong does not fail cleanly — it hangs a
job.

- **Config discovery.** `_CONDOR_CHIRP_CONFIG` holds an absolute path and
  is consulted first, because `pelfs shell` makes the payload's working
  directory the **mount**, so the reference client's relative
  `./.chirp.config` finds nothing exactly when it matters.
- **Replies** are one line holding a decimal integer, read with
  `sscanf("%d")` — leading whitespace skipped, trailing text ignored. A
  value ≥ 0 is success; negative values are `CHIRP_ERROR_*`.
- **A wrong cookie is not a closed connection.** The starter answers
  `-1`, *sleeps one second first*, and keeps the socket open. A deadline
  under two seconds reports a credential mismatch as a timeout.
- **An oversized request costs the session**, not the request: over 5120
  bytes the starter answers `CHIRP_ERROR_TOO_BIG` and closes. The client
  refuses locally instead.
- **There is no empty argument.** Arguments are words; an empty one makes
  the starter's parse run out of input and the command falls through to
  "invalid request".
- **Delayed expressions are capped at 993 bytes** by the starter, applied
  to the *unescaped* text.
- **`ulog` is truncated** to a fixed buffer (1024 bytes today, 128 in
  older releases), so messages put the useful part first.
- **Two layers of escaping, and both matter.** The value is a ClassAd
  string literal (`"…"` with the lexer's escapes, and three-digit octal
  for other control bytes — three because the lexer consumes up to three,
  so `\1` followed by `2` would be read as `\12`); that literal is then
  escaped as a chirp word (space, tab, newline, CR, backslash). An error
  message carries whatever a user put in a filename, so a value that
  reaches the ad unquoted is an expression somebody else wrote into
  somebody else's job. `internal/chirp` makes that unrepresentable: the
  verb takes an `Expr`, not a `string`, and the only constructor that
  emits its argument verbatim is called `Raw`.
- **Order on the error path.** The reason is sent *before* the flag, so a
  schedd evaluating `periodic_hold` between the two writes never sees a
  hold with no reason to put in it.

## Testing

`internal/chirp` carries a **fake starter** that speaks the real wire
format: the same `sscanf_chirp` unescaping, the same three gates, the
same numeric status lines, and the two behaviours that are expensive to
get wrong — a wrong cookie answered and the socket *kept*, an oversized
request answered and the socket *dropped*. Covered: no config (the common
case), six shapes of malformed config, discovery precedence, a wrong
cookie, a rejecting starter, a **stalled** starter on both the connect
and the mid-session path, delayed-vs-immediate, the delayed fallback, the
latch firing once (including under concurrency), and a table of hostile
string values round-tripped through both escaping layers.

## What only a real pool can confirm

Everything above is checked against the HTCondor source and a faithful
fake. These need a live schedd:

- that the delayed updates actually land in the queue and survive to
  `condor_q -af ChirpPelfs*`;
- that `periodic_hold` on `ChirpPelfsMountError` produces the hold reason
  as written above, with the schedd's own quoting;
- the real end-to-end latency of the immediate path under load;
- behaviour across a shadow reconnect (the starter's delayed-update
  dictionary survives, this client's `last` map does not — it is cleared
  on reconnect, which resends everything, but a shadow-side reconnect is
  not something a fake can reproduce);
- a Docker-universe job, where the starter binds the IO proxy to the
  docker network interface rather than to loopback.
