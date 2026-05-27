# Processor Concurrency Redesign — Pluggable Engines (Pebble + Prefork)

**Date:** 2026-05-27
**Component:** `utils/process.py` (CAPE report processor, systemd `cape-processor.service`)
**Branch:** `feature/processor-prefork-engine` (off `feature/guac-auth-evtx-snapshots`)
**Status:** Design — awaiting review before implementation planning

---

## 1. Background & Problem

`utils/process.py auto` continuously pulls `TASK_COMPLETED` analyses from the DB and runs
`process()` on each (processing modules → signatures → reporting), `-p20` in parallel,
with a `-pt 900` per-task timeout. It uses a `pebble.ProcessPool` (default **fork** start
method, `maxtasksperchild=7`). Each worker also lazily builds a **nested**
`pebble.ProcessPool` (`_EXTRACTOR_POOL`, 6 procs) for file extractors.

On 2026-05-27 the processor wedged: all 20 worker slots stuck, scheduler parked in its
"pool full" sleep, log silent for hours, and **zero `Processing timeout` lines ever**
despite `-pt 900`. Diagnosis (py-spy + strace + log forensics) found **two independent
deadlocks**, both rooted in forking a process that owns threads and child processes:

1. **Startup thread-soup fork hazard.** `lib/cuckoo/common/cleaners_utils.py` created
   `resolver_pool = ThreadPool(50)` at *import* time; `process.py` imports that module, so
   the parent held 50+ threads when pebble forked workers. Forked children inherited locks
   held by now-dead threads. *(Mitigated: `resolver_pool` made lazy — main thread count
   73 → 20.)*

2. **Worker-recycle exit deadlock (primary).** pebble's `worker_process` *returns normally*
   when it hits `max_tasks`, so the worker runs `multiprocessing.util._exit_function`, which
   `join()`s the worker's child processes — the nested `_EXTRACTOR_POOL` workers, which never
   terminate → hang forever. Every worker deadlocks on its 7th-task recycle (observed:
   exactly `140 completed ÷ 20 workers = 7`). *(Stopgap: `-mc 0` disables recycling so the
   exit path is never reached; tradeoff is no per-worker memory reclaim.)*

3. **Timeout enforcement gap.** pebble only times out *acknowledged* tasks
   (`TaskManager.timeout()` requires `task.started`). A worker that hangs before/while
   starting is immortal, and even when the timeout fires it kills one PID, not the worker's
   descendant tree (extractors, external tools orphan to init).

These are properties of the **fork + long-lived pool + pool-inside-a-worker** model, not
one-off bugs. This redesign replaces that model while keeping the old one runnable for A/B.

## 2. Goals / Non-Goals

**Goals**
- A processing model where a single hung/crashy task or extractor can never wedge the pool.
- A per-task timeout that **always** fires and fully cleans up the task's entire process tree.
- No fork-from-multithreaded-process hazard; no orphaned grandchildren; no immortal tasks.
- Keep the existing (pebble) model selectable so the new model can be A/B-tested against it
  in production with a flag flip and measurable comparison.
- Per-task init cost stays near zero (preserve the warm-state benefit of long-lived workers).

**Non-Goals**
- Changing what `process()` does (the processing/signature/reporting pipeline is unchanged).
- Changing the DB task lifecycle/statuses.
- Reworking `cape.service` or other CAPE components.

## 3. Workload facts (measured, this deployment)
- Task duration: p50 22s, p90 52s, p99 107s, **max 129s** — none near the 900s limit.
- Throughput: a few tasks/min, bursty; ~160 tasks over a working day.
- Host: 16 CPU, 125 GB RAM; worker RSS ~1.8 GB. Memory is not the binding constraint.
- Implication: tasks are short and heavyweight; warm workers exist only to amortize
  cold init (YARA compile ~3s + importing all processing/signature/reporting modules).

## 4. Architecture — pluggable engines

A clean seam splits "pull & track work" from "isolate & run one task." Both engines share
everything except worker isolation.

**Shared (unchanged):**
- `process(task, report=True, auto=True, ...)` — the per-task work.
- DB poll for `TASK_COMPLETED`, concurrency accounting (`parallel`), status update helpers,
  config (`-pt`, `-p`).

**Selection:** new CLI flag `--engine {pebble,prefork}` (default `pebble` until prefork wins
the A/B; then flip the default). systemd `ExecStart` / drop-in carries the flag. Each engine
tags log lines with its name and emits per-task timing so A/B is measurable.

```
                 ┌───────────────────────────┐
                 │  autoprocess(engine=...)   │  DB poll, concurrency, status
                 └─────────────┬─────────────┘
              ┌────────────────┴────────────────┐
        ┌─────▼──────┐                    ┌──────▼───────┐
        │ PebbleEngine│  (control/baseline)│ PreforkEngine│  (target)
        └────────────┘                    └──────────────┘
```

### 4.1 `PebbleEngine` (preserved baseline)
Today's implementation, kept intact as the A/B control. Default `max_tasks=0` (recycling is
what deadlocks it; with 0 the exit path is never hit). It is explicitly *not* the long-term
target — it remains for comparison and rollback.

### 4.2 `PreforkEngine` (target — Approach A)

A single-threaded **supervisor** owning the full lifecycle. No library-internal pool, no
channels, no background manager threads.

**(a) Warm base (once):** supervisor calls `init_database()` + `init_modules()` + YARA
compile, then **stays single-threaded** — no MongoClient, no thread pools in the supervisor.
Invariant enforced by `assert threading.active_count() == 1` immediately before each fork.

**(b) Scheduler loop (supervisor main thread):**
- Poll DB for up to `parallel - in_flight` `TASK_COMPLETED` tasks.
- For each: `fork()` a task child (inherits warm modules/YARA copy-on-write ≈ zero init).
- Track `in_flight = {pid: (task_id, start_monotonic, pgid)}`.
- Reap finished children non-blocking (`os.waitpid(-1, WNOHANG)` / `pidfd`); on reap, apply
  status (see (e)).
- **Timeout:** for each in-flight child where `now - start > processing_timeout`,
  `os.killpg(pgid, SIGTERM)`, then `SIGKILL` after a short grace; mark task
  `FAILED_PROCESSING`. Timer starts at *launch* — no "started" bookkeeping to be blind to.
- Emit a periodic heartbeat (`in_flight=N oldest=Xs`) so a stall is never silent.

**(c) Task child:**
- `os.setsid()` → own session/process group, so the supervisor's `killpg` sweeps the entire
  subtree (extractor sub-pool, external tools like sigma/suricata).
- Post-fork re-init: dispose+recreate SQLAlchemy engine connection, reset log handlers
  (reuse current `init_worker` logic), establish its own Mongo client lazily.
- Run `process(task, ...)` **exactly once**.
- Terminate with **`os._exit(code)`** — never `return`/`sys.exit`, so the multiprocessing
  atexit `join` (the exact thing that deadlocked pebble) never runs.

**(d) Extractors — per-task process sub-pool (replaces `_EXTRACTOR_POOL`):**
- Created **inside** the task child, used for the file extractors, then **explicitly
  `close()`+`join()`d** before the child exits.
- All sub-pool processes live in the task child's process group → swept by the supervisor's
  `killpg` on timeout. The child's `os._exit()` is the backstop if teardown is imperfect.
- Each extractor keeps its existing per-tool subprocess timeout.
- **Open implementation detail (resolve with measurement, not guesswork):** how the sub-pool
  is spawned. `forkserver` gives clean isolation but re-imports modules per task (cost on a
  22s task); `fork` from the *warm, still-single-threaded* task child inherits modules
  cheaply but must be created before the child spawns any thread. Decision criterion: measure
  per-task extractor-pool startup cost both ways on a representative task; pick the faster one
  that preserves the os._exit + process-group-kill safety properties.

**(e) Status (child sets, supervisor overrides):**
- The child runs `process()`, which performs the existing status writes (e.g. → reported).
- The supervisor overrides to `FAILED_PROCESSING` only on timeout (killpg) or abnormal child
  exit (non-zero / signal). One proven status path; supervisor adds the failure cases.

### 4.3 Why this removes all three hazards
- Fork-from-multithreaded: base is single-threaded (asserted) → safe forks.
- Immortal tasks: supervisor owns a launch-relative wall-clock timeout → always fires.
- Orphans / exit deadlock: `os._exit()` in the child (no atexit join) + `killpg` of the
  process group → complete cleanup, nothing to hang on.

### 4.4 Memory model & shared state (audited 2026-05-27)

The heavy load-once structures were audited for post-load mutation. All are **read-only
after load** or per-worker caches never shared across workers:

| Structure | Loaded at | Post-load writes | Verdict |
|---|---|---|---|
| `File.yara_rules` (compiled YARA) | `init_yara()` (idempotent) | none — read at scan (`objects.py:593`) | read-only |
| `_MAXMINDDB_CLIENT` (geoip) | module-level, mtime-guarded | reload only if DB file changes | read-only (mmap) |
| capa `RuleSet` | import-time `get_rules()` | none — read at match | read-only |
| `mitre`/pyattck (`BASE_OBJECTS`, `RELATIONSHIP_MAP`) | `Attck()` at `abstracts.py:71` import | none — `techniques` recomputes views; caches nothing | read-only |
| `DECRYPTORS` (vbadeobf) | import-time decorator registry | none — read via `.get` | read-only |
| `_CLAMAV_CACHE` | during processing | per-worker, self-`clear()`s (`clamav.py:113`) | per-worker, not shared |

**Nothing requires a live mutable instance shared across concurrent workers.** Decisive
proof: today's pebble model already shares these *only* via COW-fork (parent loads → workers
inherit, diverging on write). If anything needed cross-worker mutation it would already be
broken in production.

Consequence for Approach A: the "load once, share" model is **preserved identically** — the
single-threaded warm base loads them where `init_modules`/import does today; per-task children
inherit by COW. Per-task `fork()` copies page tables, not the GBs of data. Short-lived
children also retain COW sharing better than 7-task workers, which gradually un-share heavy
pages via CPython refcount writes + cyclic GC.

The leak concern is *better* served by A: a fresh process per task reclaims C-lib leaks every
task (recycle-every-task), strictly stronger than `maxtasksperchild=7`, without the
`_exit_function` deadlock.

**Known per-task recompute cost:** pyattck `techniques` recomputes on each access (observed
burning CPU in `_get_relationship_objects`) — same in both models, but paid per-task under A
vs amortized over 7. Mitigation if material: pre-compute/cache it in the warm base so children
inherit the result. Treated as an A/B-measured optimization, not a correctness item.

## 5. A/B testing & metrics
- Run identical workload under each engine (flag flip + restart). Compare:
  - throughput (tasks/min), per-task wall-clock (p50/p90/p99),
  - wedge incidents (should be 0 for prefork), peak/sustained RSS,
  - orphaned-process count after induced timeouts.
- Engine name + per-task timing logged for both so comparison is from the same source.

## 6. Risks & mitigations
| Risk | Mitigation |
|---|---|
| Supervisor accidentally goes multithreaded before fork (Mongo/thread pool import side effect) | `assert active_count()==1` pre-fork; keep Mongo/cleaners out of supervisor; test it. |
| `init_modules()` import side effects differ under the supervisor vs `main()` | Supervisor performs the same init `main()` did; integration test runs a real task end-to-end. |
| Per-task extractor sub-pool startup cost erodes throughput | Measure both spawn strategies (§4.2d); choose empirically; this is the A/B's job to catch. |
| Post-fork SQLAlchemy/Mongo/logging state | Reuse the proven `init_worker` re-init; child establishes its own connections. |
| `-mc 0` stopgap on PebbleEngine grows memory until prefork ships | Monitor RSS; add a periodic clean systemd restart (`RuntimeMaxSec`) if it climbs. |

## 7. Testing strategy
- **Timeout:** task that sleeps > `-pt` → asserted `killpg`'d at limit, task `FAILED_PROCESSING`,
  no orphan processes remain, pool keeps running.
- **Crash:** task that raises / segfaults → supervisor detects abnormal exit, marks failed,
  other tasks unaffected.
- **External-tool cleanup:** task whose extractor spawns a long subprocess → on timeout the
  subprocess is killed (process-group sweep), zero orphans (PPID 1 check).
- **Concurrency:** N>parallel queued → max in-flight never exceeds `parallel`.
- **Fork-safety invariant:** assert supervisor single-threaded before each fork.
- **A/B parity:** same corpus through both engines → identical task outputs/statuses.

## 8. Rollout
1. Land `PreforkEngine` behind `--engine prefork`, default remains `pebble`.
2. A/B in production via flag; collect §5 metrics.
3. Flip default to `prefork` once it wins; keep `pebble` selectable for one release.
4. Remove the `-mc 0` stopgap drop-in once `prefork` is the default.

## 9. Out of scope / follow-ups
- Committing the already-applied `resolver_pool` lazy fix on the mainline.
- Broader processing-pipeline changes inside `process()`.
