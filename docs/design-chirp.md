# Telling a running HTCondor job how its mount is doing

`internal/stats` writes a JSON summary so that "an external supervisor
(e.g. HTCondor) can determine **after the fact** whether the filesystem
encountered errors". That is the right artefact for a post-mortem and the
wrong one for a job that is still burning wall-clock on a broken mount.

This is the live channel. pelfs speaks **Chirp** to the `condor_starter`
that launched it, publishes a handful of attributes into the job ad, and
— the part that motivated the feature — reports the moment the mount
hands the payload an I/O error it cannot explain, so the job is **re-run
by policy** instead of being recorded as a success over a corrupt
result.

There is no `condor_chirp` binary involved and no new dependency: pelfs
builds `CGO_ENABLED=0` with a tight `go.mod`, so `internal/chirp` is a
Go client written against the reference implementation
(`src/condor_chirp/chirp_client.c` and
`src/condor_starter.V6.1/io_proxy_handler.cpp`).

## The failure this exists to prevent

Not the I/O error. **Exit 0 with a corrupt result.**

Programs that read a filesystem overwhelmingly do not check `read(2)` for
`EIO` — there was never a reason to think a read could fail. So a job
handed one typically carries on, writes output, and exits successfully.
That output is indistinguishable from a correct answer by anything
downstream, and the job's own exit status vouches for it. A user who is
bad at error handling does not get a crash; they get a wrong scientific
result with a green tick beside it.

The cost asymmetry settles every design question below. **Re-running a
job costs some CPU on a machine that was going to be busy anyway.
Recording a wrong result costs whatever gets built on top of it,
possibly years later, possibly after publication.** So the default leans
hard toward re-running, and the recommended policy is a re-run rather
than a hold: a mount `EIO` is usually transient and usually will not
recur on the next machine, whereas a hold needs a human to notice it.

## Copy-pasteable submit file

```
executable  = run.sh
log         = job.log

# Chirp: the periodic statistics work without this line, and so does the
# on_exit_remove expression below (see "Where enforcement happens"). What
# this buys is the flag being in the queue DURING the run -- what
# periodic_hold can act on, and what survives an eviction.
+WantIOProxy = true

# Re-run the job if the pelfs mount ever handed it an I/O error it could
# not explain -- INCLUDING when the payload exited 0, which is the
# dangerous case. Bounded at three attempts.
#
# DO NOT also set max_retries. See "The max_retries trap" below: submit
# ORs your expression into its generated one, which silently defeats
# this.
on_exit_remove = (ChirpPelfsMountError =!= true) || (NumJobCompletions > 2)

queue
```

`NumJobCompletions > 2` is exactly the bound `max_retries = 2` would
give: the shadow increments `NumJobCompletions` on every normal exit
before the policy is evaluated, so three attempts in total. HTCondor's
own generated expression uses the identical idiom
(`NumJobCompletions > JobMaxRetries`).

### When to reach for a hold instead

A re-run is right for a transient error. It is wrong when the failure
will recur on every machine — a pack that is genuinely corrupt in the
federation, a credential that has expired — because then the job burns
its attempts and lands in the same place with nobody told. If you would
rather a human looked at it:

```
+WantIOProxy = true
on_exit_hold        = (ChirpPelfsMountError =?= true)
on_exit_hold_reason = strcat("pelfs mount error: ", \
                             ifThenElse(ChirpPelfsMountErrorReason =?= undefined, \
                                        "unexplained I/O error", \
                                        ChirpPelfsMountErrorReason))
```

The hold reason a user sees then reads, for example:

```
pelfs mount error: fuse mount: read chunk 91af…: pack 3 trailer is truncated
```

`periodic_hold` with the same expression holds the job *during* the run
rather than at its exit, which is what you want for a job that would
otherwise keep burning wall-clock on a dead mount. It needs
`+WantIOProxy = true`, because only the immediate update puts the value
in the queue before the job ends.

Optionally, and this is the only thing that catches a mount that has
**wedged** rather than failed — a hung mount produces no error to
report:

```
periodic_hold = (ChirpPelfsMountError =?= true) || \
                (ChirpPelfsHeartbeat =!= undefined && \
                 (time() - ChirpPelfsHeartbeat) > 1800)
```

## The `max_retries` trap

**`max_retries` and a hand-written `on_exit_remove` do not compose. The
combination silently defeats this feature.**

`condor_submit` generates a retry expression only when `max_retries`,
`success_exit_code` or `retry_until` is present
(`SubmitHash::SetJobRetries`, `src/condor_utils/submit_utils.cpp`). When
it does, it builds:

```
OnExitRemove = NumJobCompletions > JobMaxRetries || ExitCode =?= <success_code>
               [ || <retry_until> ] [ || <your on_exit_remove> ]
```

Your expression is **OR-ed in**. `ExitCode =?= 0` is already a disjunct,
so a payload that exits 0 after a mount error is removed from the queue
whatever you wrote — a clause OR-ed into that can only make removal
*more* likely, never less. The feature appears to be configured and does
nothing.

With **no** retry knobs set, submit assigns your expression verbatim
(`AssignJobExpr(ATTR_ON_EXIT_REMOVE_CHECK, erc)`), which is why the
headline snippet works.

Three ways out, in order of preference:

**1. Write the whole expression, bound included.** This is the headline
snippet. If you also want ordinary retries on a nonzero exit:

```
on_exit_remove = ((ChirpPelfsMountError =!= true) && (ExitCode =?= 0)) \
                 || (NumJobCompletions > 2)
```

Note that `ExitCode` is *undefined* when the job was killed by a signal,
so `ExitCode =?= 0` is false and the job is requeued. That is arguably
right, and it differs from what people expect from `max_retries`.

**2. Keep `max_retries` and use `on_exit_hold` instead.** This one
composes cleanly, and it is the answer if you already depend on
`max_retries`:

```
max_retries  = 2
on_exit_hold = (ChirpPelfsMountError =?= true)
```

`SetJobRetries` assigns a user-supplied `on_exit_hold` **verbatim** — it
is never OR-ed with anything — and `UserPolicy::AnalyzePolicy` checks
`OnExitHold` *before* `OnExitRemove`, so the hold wins over the retry
logic when the mount failed and `max_retries` governs everything else.

**3. Rely on the exit status alone.** With the default
`--on-mount-error=rerun`, pelfs exits 75 when the mount failed, so
`max_retries` on its own will re-run the job — the generated
`ExitCode =?= 0` disjunct is false. This works only under
`pelfs shell -- cmd`, where pelfs's exit status *is* the job's, and it
gives you no hold reason.

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
| `ChirpPelfsMountError` | **immediate** | `false` at mount time, `true` once the mount has handed the payload an unexplained I/O error. What `on_exit_remove` / `on_exit_hold` / `periodic_hold` act on. |
| `ChirpPelfsMountErrorReason` | **immediate** | One line of prose, for `on_exit_hold_reason` or `periodic_hold_reason`. |

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
is latched. The per-attempt reset (`Begin`) is the only other
synchronous write, and it is one per mount, not one per cycle.

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

The line is *answering* versus *failing*, not *named* versus *unnamed*.
`vfsbilly` asks whether the error is one it chose: a bare `syscall.Errno`
handed to `pe` is a deliberate answer (`EACCES`, `EINVAL`, `ELOOP`…) and
does not latch, and neither does `ENOSPC`, which go-nfs maps to
`NFS3ERR_NOSPC` rather than to `IO`. On the FUSE side `errStatus`
translates its deliberate answers before the fall-through — with one
exception: a **graft-integrity failure** has a status of its own
(`EBADMSG`) and still latches, because it means the mount could not
deliver bytes it had promised, and no more code checks `read(2)` for
`EBADMSG` than checks it for `EIO`. The NFS frontend has no case for
that sentinel and latches it by falling through, so latching it
explicitly on the FUSE side is what keeps the two frontends agreeing
about the same event.

## Where enforcement happens: the schedd, not pelfs

This is the fact that decides the whole design, and it is worth stating
precisely because an earlier draft of this document got it wrong.

A chirp update is written into the **shadow's** copy of the job ad.
`shadow.cpp` hands one `ClassAd*` to both `RemoteResource::setJobAd` and
`shadow_user_policy.init`, so the ad that `pseudo_set_job_attr` mutates
(`pseudo_ops.cpp:603`) is the same one `UserPolicy::AnalyzePolicy`
evaluates at exit. The delayed path lands in the same ad
(`remoteresource.cpp:1647`).

And the delayed path lands **in time**. The starter drains its
delayed-update dictionary into the job *exit* ad as well as into its
periodic updates (`jic_shadow.cpp`, `notifyJobExit` →
`publishUpdateAd`), and the shadow applies that ad before it evaluates
the policy (`pseudo_ops.cpp`, `pseudo_job_exit` → `updateFromStarter` →
`resourceExit`).

Two consequences:

- A submit-side `on_exit_remove` / `on_exit_hold` expression works in
  **every** deployment shape, including `pelfs mount-gen` and the
  apptainer `--fusemount` driver, where pelfs never sees a payload
  process. Payload ownership was never the mechanism.
- It works with **no submit-file change at all**. `+WantIOProxy = true`
  buys the value being in the queue *during* the run — which is what
  `periodic_hold` acts on, and what survives an eviction rather than a
  normal exit.

## `--on-mount-error`: rerun, abort, report, ignore

The flag governs what **pelfs** does locally, on top of publishing the
attribute. It is not the enforcement.

|  | tells the job | stops the payload | exits non-zero |
| --- | --- | --- | --- |
| `rerun` (**default**) | yes | no | yes (75) |
| `abort` | yes | yes | yes (75) |
| `report` | yes | no | no |
| `ignore` | no | no | no |

`rerun` is the default because of the cost asymmetry at the top of this
document: a payload that read a truncated file, got `EIO`, did not check
for it and exited 0 must not reach the queue as a success. The exit
status is **reinforcement**, not the mechanism — it is what a pool whose
submit file carries no policy expression still sees, and under
`pelfs shell -- cmd` pelfs's status *is* the job's. Where pelfs owns
nothing it is merely honest, and pelfs says so at startup if you ask for
`abort` there.

75 is `EX_TEMPFAIL` from `sysexits.h`: "temporary failure; the user is
invited to retry", which is exactly the claim being made.

`abort` additionally stops the payload (SIGTERM, then SIGKILL after ten
seconds). Reach for it when continuing past the first bad read produces
*more* corrupt output rather than merely finishing the same one.

`report` leaves the exit status alone — the old default, now what a
workload asks for when it genuinely handles I/O errors and wants only
the telemetry. `ignore` suppresses the error report entirely; the
periodic statistics continue.

**There is no `hold` mode, and there was one.** Holding is not something
this process can do — chirp has no such verb — and the decision belongs
in the submit file, where `on_exit_hold` composes with everything else
including `max_retries`. Typing `--on-mount-error=hold` gets an error
that hands you the expression.

### The flag is sticky, so pelfs clears it per attempt

A chirp update goes into the schedd's job ad and therefore **survives a
requeue** — which is exactly what the recommended expression causes. Left
alone, one bad run would requeue every later attempt on the strength of a
failure that happened on another machine an hour ago, until the retry
bound cut it off.

So `chirp.Reporter.Begin` sets `ChirpPelfsMountError = false` once at
mount time, before anything else: one synchronous write per *attempt*,
which makes the flag mean "**this** attempt's mount failed". It goes out
on the same channel `Fail` uses, and that matters: the delayed updates
are a dictionary the starter flushes on its own schedule, so a `false`
parked there while a `true` went out immediately would land in the wrong
order and revert the failure. Whether the immediate verb works is a
property of the job ad and does not change mid-run, so one call for both
is unambiguous.

The *reason* attribute is deliberately not cleared. `Fail` writes the
reason before the flag, so `flag == true` implies "the reason beside it
is this attempt's" at every instant.

## What the starter will and will not let through

| Command | Starter knob | Job-ad attribute | Default |
| --- | --- | --- | --- |
| `set_job_attr_delayed` | `ENABLE_CHIRP_DELAYED` | `WantDelayedUpdates` | **enabled** — a vanilla job needs no submit change |
| `set_job_attr`, `ulog` | `ENABLE_CHIRP_UPDATES` | `WantRemoteUpdates`, defaulting to `WantIOProxy` | **off** unless `+WantIOProxy = true` |
| delayed attribute names | `CHIRP_DELAYED_UPDATE_PREFIX` | — | `Chirp*` |

A refusal is invisible to the client: the starter's dispatch chain falls
through to `CHIRP_ERROR_INVALID_REQUEST`, which is also what an unknown
verb produces. So `Reporter.Fail` **falls back** from the immediate verb
to the delayed one — and because the starter drains that dictionary into
the job *exit* ad too, a job that never opted in still gets its
`on_exit_remove` evaluated correctly. pelfs warns at startup if the
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
- **`NumJobCompletions` is maintained regardless of `max_retries`.** The
  shadow increments it on every normal exit (`pseudo_job_exit` →
  `incrementJobCompletionCount`), *before* it applies the chirp updates
  and evaluates the policy, and every job is submitted with it set to 0.
  So `NumJobCompletions > 2` is a usable retry bound in a hand-written
  expression, and means the same three attempts `max_retries = 2` does.

## Testing

`internal/chirp` carries a **fake starter** that speaks the real wire
format: the same `sscanf_chirp` unescaping, the same three gates, the
same numeric status lines, and the two behaviours that are expensive to
get wrong — a wrong cookie answered and the socket *kept*, an oversized
request answered and the socket *dropped*. Covered: no config (the common
case), six shapes of malformed config, discovery precedence, a wrong
cookie, a rejecting starter, a **stalled** starter on both the connect
and the mid-session path, delayed-vs-immediate, the delayed fallback, the
per-attempt reset landing on the same channel as the failure, the latch
firing once (including under concurrency), and a table of hostile string
values round-tripped through both escaping layers.

## What only a real pool can confirm

Everything above is checked against the HTCondor source and a faithful
fake. These need a live schedd:

- that the delayed updates actually land in the queue and survive to
  `condor_q -af ChirpPelfs*`;
- that `on_exit_remove` on `ChirpPelfsMountError` actually requeues the
  job, and that the flag `Begin` clears is the one the *next* attempt's
  policy sees — the sticky-attribute reasoning is read off the source,
  and only a real requeue proves the sequence;
- that `periodic_hold` on `ChirpPelfsMountError` produces the hold reason
  as written above, with the schedd's own quoting;
- that `max_retries` composes as described — in particular that a
  user-supplied `on_exit_hold` really does survive `SetJobRetries`
  untouched;
- the real end-to-end latency of the immediate path under load;
- behaviour across a shadow reconnect (the starter's delayed-update
  dictionary survives, this client's `last` map does not — it is cleared
  on reconnect, which resends everything, but a shadow-side reconnect is
  not something a fake can reproduce);
- a Docker-universe job, where the starter binds the IO proxy to the
  docker network interface rather than to loopback.
