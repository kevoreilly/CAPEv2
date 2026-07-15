# Multitenancy — Supported Configurations & Boundaries

Multitenancy (the `[multitenancy]` section of `cuckoo.conf`) scopes every read
surface so a user of one tenant cannot see or act on another tenant's tasks,
samples, reports, artifacts, statistics, search results, or live-VM (Guacamole)
sessions. This document states exactly which deployment modes that guarantee
covers today, and what is intentionally **fail-closed** (safe but limited) until
support is added.

## Enabling on an existing (populated) install — run the backfill

Turning `enabled = yes` stamps tenant/visibility onto **new** analyses only. Reports
already in MongoDB have no `info.tenant_id` / `info.user_id` / `info.visibility`
stamp, so the scoped search / statistics / compare surfaces treat them as
**fail-closed / invisible** to every tenant (no leak, but the history disappears
from those views) until they are stamped. Run the one-shot backfill once, after
flipping the flag:

```
python utils/db_migration/mongo_backfill_tenant.py
```

It reads each selected `analysis` doc's Postgres task and writes
`info.tenant_id` / `info.user_id` / `info.visibility` (orphans whose task was pruned
fail closed to `private`), and creates the `tenant_scope_idx` index. It touches only
(a) un-stamped docs (missing `info.visibility`, first-enable) and (b) crash-orphans in
the exact reporter fail-closed shape (`visibility=private` + null `tenant_id` AND
`user_id`) — never a stamped permissive doc — so it stays idempotent and safe to re-run.
In a **central** deployment run it on the CENTRAL node **while quiesced**: it only
restamps docs whose id space matches the node (broker `ui-*` ids ⇔ central RDS;
worker-local ids ⇔ single-node), and it is not lock-serialized against a live toggle.
The Alembic migration backfills the **SQL** columns only — the mongo stamp is this
separate step. A fresh install needs no backfill (every report is stamped at
creation).

## Supported (isolation enforced end-to-end)

- **Report store: MongoDB.** MT scoping of the aggregate/search/statistics/
  compare surfaces reads the tenant stamp (`info.tenant_id` / `info.user_id` /
  `info.visibility`) written into the mongo analysis document. **MongoDB is
  required for multitenancy.**
- **Single-node CAPE** (one host running web + processing + analysis).
- **Central control plane + broker workers** (the "central mode" path): the
  central UI serves artifacts staged from workers, keyed by the broker `job_id`.
  Tenant stamping works across this path **only when workers can resolve the
  submitter's tenancy from the central control-plane DB**: a worker's own
  `[database]` is its LOCAL per-worker task DB (a different id space), and
  `centralstore` rewrites `info.id` to the CENTRAL task id, so the worker resolves
  and stamps tenancy against the central RDS via `[central_mode] central_database_url`
  (read-only). If that URL is unset, central-mode analyses stamp **fail-closed**
  (private / unowned — invisible to everyone but break-glass), never leaked. The
  visibility toggle serializes with the worker's report write via a per-task advisory
  lock only within a single DB; a toggle issued on the central node concurrently with
  a worker reprocess is not cross-node serialized (narrow, documented residual).
- **Guacamole interactive sessions** for task-backed analyses: minting a live-VM
  session (and the WebSocket tunnel re-check) is gated by `can_manage_task`
  (owner / tenant-admin / break-glass), NOT mere read visibility — live keyboard/
  mouse/framebuffer control is a task action, so a read-only viewer of a public/
  tenant task cannot tunnel into another user's or tenant's VM.

## Not yet supported (fail-closed — safe, but limited)

These modes do **not** carry tenant context correctly. Rather than leak, MT
**fails closed** on them (data is stamped private / invisible, or the surface is
admin-only), so enabling MT on these modes is safe but the affected analyses
will simply not be visible. Adding real support is tracked as future work.

- **Elasticsearch report store.** The visibility toggle syncs the tenant stamp
  only to MongoDB; an ES-backed install would not update the ES stamp, and the ES
  statistics aggregates cannot be per-record gated. **Run MT with MongoDB.** (An
  ES bool-filter analogue of the scope predicate exists but is unexercised.)
- **Legacy distributed (`utils/dist.py`).** The main→worker submission does not
  forward tenant/user/visibility, so a distributed worker cannot stamp the shared
  mongo document correctly. When a worker processes a distributed task
  (`options.main_task_id` set), the report is stamped **private/invisible**
  (fail-closed) instead of world-visible. Use the broker/central path for
  distributed multitenant analysis. (Our central path keys by `job_id` and never
  sets `main_task_id`, so it is unaffected.)

## Behavior notes

- **Statistics API shape (shared mode).** With MT enabled in `shared` mode, the
  `apiv2` statistics endpoint returns **per-scope** results
  (`data['public']`, `data['tenant']`, `data['mine']`) instead of the legacy flat
  `data['signatures']`. This is the correct scoped behavior; it is a breaking
  change for API clients that assumed the flat shape on an MT-shared install.
  Multitenancy-disabled installs and break-glass local-admins still receive the
  flat dict.
- **Direct VNC / VM operator console.** The task-less direct-console endpoints
  (`task_id=0`: raw host:port VNC, plus VM console/start/shutdown/route/snapshot
  by name) have no tenant scoping and mint sessions the per-task tunnel gate does
  not cover, so **all** of them are restricted to break-glass admins
  (`viewer_for(user).is_local_admin`) in addition to the existing config gate —
  never a tenant user. (On an MT-disabled / no-auth install every principal is a
  local-admin, so the operator console stays usable.)
- **Threat-hunt facets.** `hunt()` scopes its aggregation by the viewer's entitled
  scopes (`viewer_scope` `$match`); its facet `task_ids` rely on that stamp-based
  `$match` with no per-id SQL backstop (a `$facet` count can't be post-filtered
  per task). This is safe because the report tenant stamp is written fail-closed
  on every path, so a doc can't carry a spoofed cross-tenant stamp.
- **Modes:** `shared` (public pool + own tenant + own tasks) and `locked`
  (tenant-isolated). An unknown/typo `mode` fails closed to `locked`.
