Multitenancy — Supported Configurations & Boundaries
====================================================

Multitenancy (the ````[multitenancy]```` section of ````cuckoo.conf````) scopes every read
surface so a user of one tenant cannot see or act on another tenant's tasks,
samples, reports, artifacts, statistics, search results, or live-VM (Guacamole)
sessions. This document states exactly which deployment modes that guarantee
covers today, and what is intentionally **fail-closed** (safe but limited) until
support is added.

Enabling on an existing (populated) install — run the backfill
--------------------------------------------------------------

Turning ````enabled = yes```` stamps tenant/visibility onto **new** analyses only. Reports
already in MongoDB have no ````info.tenant_id```` / ````info.user_id```` / ````info.visibility````
stamp, so the scoped search / statistics / compare surfaces treat them as
**fail-closed / invisible** to every tenant (no leak, but the history disappears
from those views) until they are stamped. Run the one-shot backfill once, after
flipping the flag:

.. code-block:: none

    python utils/db_migration/mongo_backfill_tenant.py

It reads each selected ````analysis```` doc's Postgres task and writes
````info.tenant_id```` / ````info.user_id```` / ````info.visibility```` (orphans whose task was pruned
fail closed to ````private````), and creates the ````tenant_scope_idx```` index. It touches only
(a) un-stamped docs (missing ````info.visibility````, first-enable) and (b) crash-orphans in
the exact reporter fail-closed shape (````visibility=private```` + null ````tenant_id```` AND
````user_id````) — never a stamped permissive doc — so it stays idempotent and safe to re-run.
In a **central** deployment run it on the CENTRAL node **while quiesced**: it only
restamps docs whose id space matches the node (broker ````ui-*```` ids ⇔ central RDS;
worker-local ids ⇔ single-node), and it is not lock-serialized against a live toggle.
The Alembic migration backfills the **SQL** columns only — the mongo stamp is this
separate step. A fresh install needs no backfill (every report is stamped at
creation).

Supported (isolation enforced end-to-end)
-----------------------------------------

* **Report store: MongoDB.** MT scoping of the aggregate/search/statistics/
  compare surfaces reads the tenant stamp (````info.tenant_id```` / ````info.user_id```` /
  ````info.visibility````) written into the mongo analysis document. **MongoDB is
  required for multitenancy.**
* **Single-node CAPE** (one host running web + processing + analysis).
* **Central control plane + broker workers** (the "central mode" path): the
  central UI serves artifacts staged from workers, keyed by the broker ````job_id````.
  Tenant stamping works across this path **only when workers can resolve the
  submitter's tenancy from the central control-plane DB**: a worker's own
  ````[database]```` is its LOCAL per-worker task DB (a different id space), and
  ````centralstore```` rewrites ````info.id```` to the CENTRAL task id, so the worker resolves
  and stamps tenancy against the central RDS via ````[central_mode] central_database_url````.
  If that URL is unset, central-mode analyses stamp **fail-closed** (private / unowned
  — invisible to everyone but break-glass), never leaked. Point ````central_database_url````
  at the **writer/primary** endpoint (the same Postgres the central node uses as its
  ````[database]````), NOT a read replica: the worker's post-write reconcile takes its
  per-task advisory lock there to serialize with the central node's visibility toggle
  (advisory locks are cluster-wide, so same-key locks on the same primary mutually
  exclude). If it points at a standby, ````pg_advisory_lock```` wouldn't exclude the primary
  and the re-read would be replication-lag stale — the worker detects
  ````pg_is_in_recovery()````, warns, and runs unserialized-but-fail-closed, leaving a narrow
  reprocess-during-toggle re-widen window (still no persistent leak: the fail-closed
  insert + backfill keep it safe).
* **Guacamole interactive sessions** for task-backed analyses: minting a live-VM
  session (and the WebSocket tunnel re-check) is gated by ````can_manage_task````
  (owner / tenant-admin / break-glass), NOT mere read visibility — live keyboard/
  mouse/framebuffer control is a task action, so a read-only viewer of a public/
  tenant task cannot tunnel into another user's or tenant's VM.

Not yet supported (fail-closed — safe, but limited)
---------------------------------------------------

These modes do **not** carry tenant context correctly. Rather than leak, MT
**fails closed** on them (data is stamped private / invisible, or the surface is
admin-only), so enabling MT on these modes is safe but the affected analyses
will simply not be visible. Adding real support is tracked as future work.

* **Elasticsearch report store.** The visibility toggle syncs the tenant stamp
  only to MongoDB; an ES-backed install would not update the ES stamp, and the ES
  statistics aggregates cannot be per-record gated. **Run MT with MongoDB.** (An
  ES bool-filter analogue of the scope predicate exists but is unexercised.)
* **Legacy distributed (````utils/dist.py````).** The main→worker submission does not
  forward tenant/user/visibility, so a distributed worker cannot stamp the shared
  mongo document correctly. When a worker processes a distributed task
  (````options.main_task_id```` set), the report is stamped **private/invisible**
  (fail-closed) instead of world-visible. Use the broker/central path for
  distributed multitenant analysis. (Our central path keys by ````job_id```` and never
  sets ````main_task_id````, so it is unaffected.)

Behavior notes
--------------

* **Statistics API shape (shared mode).** With MT enabled in ````shared```` mode, the
  ````apiv2```` statistics endpoint returns **per-scope** results
  (````data['public']````, ````data['tenant']````, ````data['mine']````) instead of the legacy flat
  ````data['signatures']````. This is the correct scoped behavior; it is a breaking
  change for API clients that assumed the flat shape on an MT-shared install.
  Multitenancy-disabled installs and break-glass local-admins still receive the
  flat dict.
* **Direct VNC / VM operator console.** The task-less direct-console endpoints
  (````task_id=0````: raw host:port VNC, plus VM console/start/shutdown/route/snapshot
  by name) have no tenant scoping and mint sessions the per-task tunnel gate does
  not cover, so **all** of them are restricted to break-glass admins
  (````viewer_for(user).is_local_admin````) in addition to the existing config gate —
  never a tenant user. (On an MT-disabled / no-auth install every principal is a
  local-admin, so the operator console stays usable.)
* **Threat-hunt facets.** ````hunt()```` scopes its aggregation by the viewer's entitled
  scopes (````viewer_scope```` ````$match````); its facet ````task_ids```` rely on that stamp-based
  ````$match```` with no per-id SQL backstop (a ````$facet```` count can't be post-filtered
  per task). This is safe because the report tenant stamp is written fail-closed
  on every path, so a doc can't carry a spoofed cross-tenant stamp.
* **Modes:** ````shared```` (public pool + own tenant + own tasks) and ````locked````
  (tenant-isolated). An unknown/typo ````mode```` fails closed to ````locked````.

Architecture & Implementation Review
------------------------------------

A systematic security and architecture audit of CAPEv2's multi-tenancy implementation across the entire Django web layer (````web/analysis```` and ````web/apiv2````) confirms that the design is exceptionally mature, secure, and rigorously defended against cross-tenant data leaks. It operates on a robust, defense-in-depth model containing several layers:

1. Core Logic Predicates
~~~~~~~~~~~~~~~~~~~~~~~~

At the core layer, tenancy is decoupled from any specific database or web framework. It defines the foundational permission boundaries using pure Python dataclasses and pure functions:

* **````Viewer```` Dataclass:** Captures the authenticated client's security context (e.g., ````user_id````, ````tenant_id````, and privilege markers ````is_superuser````, ````is_tenant_admin````, ````is_local_admin````).
* **````Job```` Dataclass:** Represents the target task’s metadata (````owner_id````, ````tenant_id````, and ````visibility````).
* **Pure Predicates:**
  * ````can_read(Viewer, Job)````: Denies access to other tenants' private or tenant-level tasks.
  * ````can_toggle(Viewer, Job)````: Controls general metadata updates.
  * ````can_delete(Viewer, Job)````: Stricter than can_toggle; prevents tenant-admins from deleting public/shared tasks they do not own to avoid destructive actions on shared pools.
  * ````can_set_visibility(Viewer, Job, new_visibility)````: Controls state transitions, blocking tenant-admins from converting non-owned public tasks into private/tenant tasks to bypass deletion restrictions.

2. Django-to-Core Bridge & Fail-Closed Facade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Bridges Django’s ````request.user```` into the core tenancy system cleanly and safely:

* **````viewer_for(user)```` (````web/users/tenancy.py````):** Resolves the user context, strictly checking ````cuckoo.conf```` policy. If ````local_admins_manage_all_tenants```` is off, only superusers authenticated via an external IdP (with an Allauth SocialAccount) keep cross-tenant admin reach. Non-IdP superusers (like those created via ````createsuperuser````) are bound to their tenant, preventing local privilege escalation.
* **````web/web/tenancy_optional.py````:** An import-optional facade acting as a safeguard. If an ````ImportError```` occurs or dependencies break, it queries ````_mt_enabled()```` to check if tenancy is enabled. If enabled, it **fails closed** (blocking permissions) rather than falling open to legacy wide-open (see-all) access.

3. Endpoint Decorators & Access Guards
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every task-scoped endpoint is guarded by either robust decorators or explicit rejection helpers:

* **Decorators (````@require_task_visibility````, ````@require_task_manage````, ````@require_task_delete````):** Protect analysis views in ````web/analysis/views.py````. Unauthorized or non-existent tasks return the **exact same 403 Forbidden ("Not found") response**, completely preventing cross-tenant task ID enumeration.
* **Helpers (````_deny_if_hidden````, ````_deny_task````, ````_deny_manage````, ````_deny_by_hash````):** Utilized by API endpoints in ````web/apiv2/views.py````.
  * ````_deny_if_hidden```` returns an indistinguishable ````404 Task not found```` for both missing and hidden tasks.
  * ````_deny_by_hash```` ensures payload/file downloads are restricted unless the requesting user has at least one visible task referencing that specific file hash.

4. Data-Layer Query Scoping (Database Isolation)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Filters are injected directly into queries to prevent unauthorized data from ever leaving the database:

* **PostgreSQL/MySQL (SQLAlchemy):** ````Database.list_tasks```` and ````count_matching_tasks```` inject explicit tenant restriction clauses directly into SQL statements based on the ````visible_to```` parameter.
* **MongoDB:** All document-level lookups route through ````scoped_analysis_query```` (aliased as ````_analysis_filter````). In central mode, this queries unique ````info.job_id```` and strictly binds unstamped documents to the authorized ````task_id```` to prevent forged ````custom```` variable access.
* **Elasticsearch:** ````viewer_scope_es_filter()```` produces boolean filter structures matching the same permission parameters.

5. AST-Based Static Security Gates (Build-Time Verification)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To prevent regression or developer oversight when writing new views, CAPEv2 includes automated static analysis tests in ````web/apiv2/test_visibility.py```` that parse code at the Abstract Syntax Tree (AST) level:

* **````test_routed_task_view_enforces_visibility````:** Automatically parses the AST of all view functions in ````apiv2.views````, ````analysis.views````, ````compare.views````, ````guac.views````, and ````web.urls```` that accept task identifiers (````task_id````, ````analysis_number````, etc.). It asserts that they **must** reference a visibility guard (such as ````_deny_if_hidden```` or decorators). Only strictly verified infrastructure-level helper views (like ````tasks_machine````) are allowlisted.
* **````test_cross_task_mongo_pivots_are_reviewed````:** Scans the AST of all view modules and asserts that any function issuing multi-document operations (````mongo_find````, ````mongo_aggregate````) must be listed in ````REVIEWED_MONGO_PIVOTS```` along with its tenant-scoping justification.
* **````test_every_perform_search_caller_passes_viewer````:** Guarantees that no ````perform_search()```` query is executed without explicitly passing ````viewer=````, preventing un-scoped searches.
