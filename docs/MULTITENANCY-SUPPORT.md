# Multitenancy — Supported Configurations & Boundaries

Multitenancy (the `[multitenancy]` section of `cuckoo.conf`) scopes every read
surface so a user of one tenant cannot see or act on another tenant's tasks,
samples, reports, artifacts, statistics, search results, or live-VM (Guacamole)
sessions. This document states exactly which deployment modes that guarantee
covers today, and what is intentionally **fail-closed** (safe but limited) until
support is added.

## Supported (isolation enforced end-to-end)

- **Report store: MongoDB.** MT scoping of the aggregate/search/statistics/
  compare surfaces reads the tenant stamp (`info.tenant_id` / `info.user_id` /
  `info.visibility`) written into the mongo analysis document. **MongoDB is
  required for multitenancy.**
- **Single-node CAPE** (one host running web + processing + analysis).
- **Central control plane + broker workers** (the "central mode" path): the
  central UI serves artifacts staged from workers, keyed by the broker `job_id`.
  Tenant stamping and scoping work across this path.
- **Guacamole interactive sessions** for task-backed analyses: the live-VM tunnel
  is gated by `can_view_task`, so a token cannot tunnel into another tenant's VM.

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
- **Direct VNC console.** The direct host:port VNC console (`task_id=0`, not tied
  to a task) is an operator tool with no tenant scoping; it is restricted to
  **superusers** (in addition to the existing config gate).
- **Modes:** `shared` (public pool + own tenant + own tasks) and `locked`
  (tenant-isolated). An unknown/typo `mode` fails closed to `locked`.
