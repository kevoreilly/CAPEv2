# Processor Engine A/B Runbook

**Date:** 2026-05-27  
**Scope:** How to flip between `pebble` and `prefork` processing engines, what to measure, how to declare a winner, when to retire the `-mc 0` stopgap.  
**Status:** Ready for A/B — branch `feature/processor-prefork-engine` implementation complete.  
**Audience:** Engineer running the A/B in production.

---

## Preconditions

Before running the A/B, confirm:

1. Branch `feature/processor-prefork-engine` is deployed. Implementation spans commits `47576a166` through `beb829e67` (14 commits: `TaskSource`, engine registry/base, `run_task` adapter, `PebbleEngine`, `PreforkEngine` scaffolding, fork-per-task execution, wall-clock timeout + `killpg`, extractor sub-pool rewrite, and a docs revert).

2. The existing stopgap drop-in is in place at `/etc/systemd/system/cape-processor.service.d/stopgap-no-recycle.conf`:
   ```
   # STOPGAP (2026-05-27): maxtasksperchild=0 disables worker recycling.
   # Worker recycle at max_tasks>0 deadlocks in multiprocessing _exit_function
   # joining the nested _EXTRACTOR_POOL children. See cape-processor redesign.
   # Tradeoff: no per-worker memory reclaim; monitor RSS / pair with periodic restart.
   [Service]
   ExecStart=
   ExecStart=/etc/poetry/bin/poetry run python process.py -p20 auto -pt 900 -mc 0
   ```
   This drop-in does **not** pass `--engine`, so the pebble engine (argparse default) is active.

3. `cape-processor.service` is running and healthy (check for recent `Reports generation completed for Task #N` lines in `/opt/CAPEv2/log/process.log`).

4. You have `sudo` on this host.

---

## Database Note (important)

The A/B runs against the **production PostgreSQL database**. Both engines share the module-level `db = Database()` instance configured from `conf/cuckoo.conf` (`postgresql://...`). There is no separate staging database path.

The `sqlite://` database in `tests/conftest.py` is the unit-test fixture only. It has no production code path and is completely irrelevant to the A/B.

---

## Flipping Engines

### To enable the prefork engine

Edit the drop-in at `/etc/systemd/system/cape-processor.service.d/stopgap-no-recycle.conf`. Add `--engine prefork` to the `ExecStart` line:

```
# STOPGAP (2026-05-27): maxtasksperchild=0 disables worker recycling.
# Worker recycle at max_tasks>0 deadlocks in multiprocessing _exit_function
# joining the nested _EXTRACTOR_POOL children. See cape-processor redesign.
# Tradeoff: no per-worker memory reclaim; monitor RSS / pair with periodic restart.
# NOTE: -mc 0 is a pebble-specific workaround; it is harmless but meaningless
# under prefork (different lifecycle, no worker-recycle exit path).
[Service]
ExecStart=
ExecStart=/etc/poetry/bin/poetry run python process.py -p20 auto -pt 900 -mc 0 --engine prefork
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cape-processor.service
```

Verify it started with the right engine — look for this log line within a few seconds of restart:

```bash
sudo journalctl -u cape-processor.service -f --since "1 minute ago"
grep -m1 "engine" /opt/CAPEv2/log/process.log | tail -5
```

Expected: a log line referencing `PreforkEngine` or `engine=prefork` at startup (exact text from `utils/process.py`).

### To switch back to pebble

Remove `--engine prefork` from the `ExecStart` line (or explicitly add `--engine pebble`), then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cape-processor.service
```

---

## Rollback

If at any point you need to revert to the exact pre-A/B pebble configuration, restore the drop-in to its original content (no `--engine` flag):

```
[Service]
ExecStart=
ExecStart=/etc/poetry/bin/poetry run python process.py -p20 auto -pt 900 -mc 0
```

Then `sudo systemctl daemon-reload && sudo systemctl restart cape-processor.service`. This fully restores the pebble+`-mc 0` baseline.

---

## Metrics to Compare

Run each engine for at least **48 hours** (or 500 completed tasks, whichever comes first) under the same workload before drawing conclusions. Collect all four metrics for both engines.

### 1. Throughput (tasks/min)

Parse `Reports generation completed` completions from the log, compute rate per minute:

```bash
grep "Reports generation completed" /opt/CAPEv2/log/process.log \
  | awk '{print $1, $2}' \
  | awk -F'[: ]' '{print $1"T"$2":"$3":00"}' \
  | sort | uniq -c \
  | awk '{printf "%s  completions=%d\n", $2, $1}'
```

Or a simpler rolling summary over the last hour:

```bash
SINCE=$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')
awk -v since="$SINCE" '$0 >= since && /Reports generation completed/' \
  /opt/CAPEv2/log/process.log | wc -l
```

Target: prefork throughput within 5% of pebble. Any significant regression needs investigation before declaring prefork the winner.

### 2. Wedge incidents

A "wedge" is a period of >5 minutes with no `Reports generation completed` lines while tasks are still scheduled. The `-mc 0` stopgap eliminated wedges for pebble; prefork should also have zero.

Check for silent gaps in the last 24 hours:

```bash
grep "Reports generation completed" /opt/CAPEv2/log/process.log \
  | awk '{print $1" "$2}' \
  | awk 'NR>1 {
      cmd="date -d \""$1"\" +%s"; cmd | getline ts; close(cmd)
      cmd2="date -d \""prev"\" +%s"; cmd2 | getline pts; close(cmd2)
      gap = ts - pts
      if (gap > 300) printf "GAP %d s ending at %s\n", gap, $1
      prev=$1" "$2
    }
    NR==1 {prev=$1" "$2}'
```

Alternatively, watch the heartbeat log line that `PreforkEngine` emits periodically (`in_flight=N oldest=Xs`). A heartbeat without completions for >5 minutes while `in_flight > 0` is an early wedge indicator.

**Decision criterion:** any wedge under either engine is a failure for that engine. Both should show zero over the observation window.

### 3. Peak and sustained RSS

Sum the RSS of all python workers under the processor's main PID at 5-minute intervals. First find the service's MainPID:

```bash
MAIN_PID=$(systemctl show cape-processor.service --property=MainPID --value)
echo "MainPID: $MAIN_PID"
```

Then poll (run in a loop, or via cron, or as a one-shot snapshot):

```bash
# One snapshot (GB):
MAIN_PID=$(systemctl show cape-processor.service --property=MainPID --value)
ps --no-headers -o rss --ppid "$MAIN_PID" \
  | awk '{sum+=$1} END {printf "RSS %.2f GB (%d workers)\n", sum/1048576, NR}'
```

For a continuous 5-minute polling log:

```bash
while true; do
  MAIN_PID=$(systemctl show cape-processor.service --property=MainPID --value)
  RSS=$(ps --no-headers -o rss --ppid "$MAIN_PID" \
        | awk '{sum+=$1} END {printf "%.2f", sum/1048576}')
  echo "$(date '+%Y-%m-%dT%H:%M:%S') RSS=${RSS}GB"
  sleep 300
done | tee /tmp/rss-log.txt
```

**Expected behavior difference:**
- Pebble with `-mc 0`: RSS grows gradually over time (workers never recycle, C-lib leaks accumulate). This is the known trade-off of the `-mc 0` stopgap.
- Prefork: RSS should be roughly steady (each task child exits via `os._exit()`, reclaiming its memory per-task). A monotonically growing RSS trend under prefork is a regression.

**Decision criterion:** prefork RSS should not trend upward continuously over 48 hours. Pebble RSS growing is expected and acceptable (it is a known stopgap trade-off). A periodic `RuntimeMaxSec` systemd restart can bound pebble RSS if needed.

### 4. Orphan count after induced timeouts

This metric requires inducing a task that exceeds `-pt 900` (or temporarily reducing `-pt` for a test). It validates that `killpg` in prefork actually cleans up the entire process tree and leaves no grandchildren reparented to init.

**Procedure:**

1. Before the test, note the current `in_flight` from logs or the heartbeat line.
2. Submit (or identify) a task known to run longer than the current `-pt` value. Alternatively: temporarily set `-pt 60` in the drop-in to trigger timeouts faster, then restore.
3. When a `Processing timeout` line appears in `process.log`, immediately check for orphans:

```bash
# Check for python processes reparented to init (PPID=1):
pgrep -P 1 | xargs -I{} ps -o pid,ppid,cmd -p {} 2>/dev/null \
  | grep -i python

# Or check for any surviving members of the task's process group.
# Get the task child PID from the timeout log line first, then:
# (The supervisor logs the child PID and PGID in the SIGTERM/SIGKILL log lines.)
TASK_PGID=<pgid from log>
pgrep -g "$TASK_PGID"
```

**Expected results:**
- Prefork: `pgrep` returns nothing. The `killpg` swept the entire process group (task child + extractor sub-pool workers). Zero orphans.
- Pebble: `pgrep` may return orphaned grandchildren. Pebble's `stop_process` sends a signal to one worker PID; it does not sweep the extractor sub-pool children, which may reparent to init.

**Decision criterion:** prefork must show zero orphans after any induced timeout. Non-zero is a regression in the primary correctness guarantee of the new engine.

---

## Decision Criterion

Declare prefork the **winner** if, over the observation window (48 hours or 500 tasks):

- Throughput within 5% of pebble (tasks/min).
- Zero wedge incidents (same as pebble with `-mc 0`).
- RSS steady-state, not trending upward.
- Zero orphaned processes after any induced or naturally-occurring timeout.

Declare pebble the **winner** (and treat prefork as needing more work) if any of:

- Prefork throughput is >5% lower than pebble.
- Prefork wedges (even once).
- Prefork RSS trends upward monotonically over 48 hours.
- Prefork leaves orphans after a timeout.

If there is a prefork regression, file an issue, roll back to pebble (one `systemctl` command — see Rollback above), and investigate before re-attempting the A/B.

---

## Stopgap Retirement

The `-mc 0` flag in the drop-in exists solely to work around the pebble worker-recycle deadlock (`multiprocessing._exit_function` joining the nested `_EXTRACTOR_POOL` children). It is a **pebble-specific stopgap**.

Under `--engine prefork`, the `-mc 0` flag is meaningless (prefork has no worker-recycle exit path) but harmless. It does not need to be removed immediately.

**When to remove `-mc 0`:** once `--engine prefork` is made the argparse default in `utils/process.py` (a one-line code change flipping the `--engine` default from `pebble` to `prefork`, done after A/B declares prefork the winner), the pebble engine will no longer be the active engine on startup and the `-mc 0` stopgap becomes dead weight. At that point:

1. Remove the `-mc 0` argument from the drop-in's `ExecStart` line.
2. The drop-in itself can eventually be deleted entirely once `--engine prefork` is also baked into the unit file's `ExecStart` (or once the old pebble path is removed from the codebase).

Do not remove `-mc 0` earlier than this. It is harmless under prefork and removing it prematurely would leave the pebble engine unprotected if someone ever toggles back.

---

## Open Follow-ups

These items are not part of the A/B itself but are outstanding work to track:

1. **Uncommitted `resolver_pool` lazy fix.** `lib/cuckoo/common/cleaners_utils.py` contains the `_LazyThreadPool` fix that defers `ThreadPool(50)` creation to the first call (reduces supervisor thread count 73 → 20, making prefork forks clean). This fix is in the working tree on `feature/processor-prefork-engine` but has not been committed as a standalone commit. It should be committed on a separate branch or PR — see §9 of the spec (`docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md`).

2. **Proctitle/formatter cleanup deferral.** Task 4 (`d944dcc4d`) restored per-task `proctitle` and logging formatter cleanup in `run_task`. The prefork engine's per-task children already have isolated address spaces (no shared log handlers), so the cleanup is technically redundant under prefork — but it was kept for parity and correctness under the pebble path. A future cleanup could remove it from `run_task` and make it engine-specific if it shows measurable cost.

3. **`--tasks-per-child` knob.** The design spec (§4.2) documents this as a YAGNI future knob: recycling a prefork child across N>1 tasks requires a supervisor→child dispatch channel, which was deliberately not built. If the measured per-task fork cost ever becomes material, this is the documented path to amortize it. Current measured cost: ~0.35 s/task (~1.6% of p50 22 s task) — not material.

4. **pyattck `techniques` recompute.** Observed burning CPU in `_get_relationship_objects` on each access. The fix (pre-compute in the warm base so children inherit the cached result via COW) was deferred as an A/B-measured optimization. If the A/B reveals CPU spikes on prefork attributable to pyattck, this is the first place to look.

---

## Related Artifacts

| Artifact | Path |
|---|---|
| Concurrency redesign spec | `docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md` |
| Implementation plan (11 tasks) | `docs/superpowers/plans/2026-05-27-processor-prefork-engine.md` |
| Extractor sub-pool spike (fork vs forkserver) | `docs/superpowers/notes/2026-05-27-extractor-subpool-spike.md` |
| Stopgap drop-in (live) | `/etc/systemd/system/cape-processor.service.d/stopgap-no-recycle.conf` |
| Processor entry point | `utils/process.py` |
| Engine implementations | `utils/engines/pebble_engine.py`, `utils/engines/prefork_engine.py` |
| Engine registry | `utils/engines/__init__.py` |
| Extractor sub-pool (rewritten in Task 10) | `lib/cuckoo/common/integrations/file_extra_info.py` |
