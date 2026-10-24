Multitenancy & Object Storage — Supported Configurations & Boundaries
=====================================================================

Multitenancy (the ``[multitenancy]`` section of ``cuckoo.conf``, powered by the
built-in ``lib.tenancy`` module) scopes every read surface so a user of one tenant
cannot see or act on another tenant's tasks, samples, reports, artifacts,
statistics, search results, or live-VM (Guacamole) sessions, and allows
administrators to control which VMs (``machines``), network routes (``routing``),
and machine ``tags`` different Django ``Group``s can see and use.

Alongside ``[multitenancy]``, ``lib.tenancy`` provides pluggable cloud-agnostic
artifact object storage (the ``[object_storage]`` section of ``cuckoo.conf``,
supporting ``s3`` for AWS S3 / MinIO / Ceph RGW, ``gcs`` for Google Cloud
Storage, ``azure`` for Azure Blob Storage, and ``local`` for shared NFS mounts).
Both ``[multitenancy]`` and ``[object_storage]`` default to ``enabled = no`` and
can be enabled independently or together.

Configuration (``conf/cuckoo.conf``)
------------------------------------

Both features are configured in ``conf/cuckoo.conf`` and default to ``enabled = no``:

.. code-block:: ini

    [multitenancy]
    # [BETA] Multi-tenancy and per-group sandbox resource policy support.
    enabled = no
    # "shared" (default visibility = public) or "locked" (default visibility = tenant)
    mode = shared
    default_visibility =
    local_admins_manage_all_tenants = yes
    allow_superuser_all = yes

    [object_storage]
    # [BETA] Central / remote object storage integration (s3, gcs, azure, local).
    enabled = no
    # Backend: s3 | gcs | azure | local
    backend = s3
    bucket =
    prefix = results
    region = us-east-1
    endpoint_url =
    access_key =
    secret_key =
    gcp_project =
    gcp_credentials_path =
    azure_connection_string =
    azure_account_url =
    azure_credential =
    local_root =

**Optional Dependencies:**

* ``[multitenancy]`` requires **no extra packages** (uses core Django, SQLAlchemy, and PyMongo).
* ``[object_storage]`` requires only the SDK for the backend you configure:

  * ``backend = s3`` (AWS S3, MinIO, Ceph RGW): ``poetry install --extras s3``
  * ``backend = gcs`` (Google Cloud Storage): ``poetry install --extras gcp``
  * ``backend = azure`` (Azure Blob Storage): ``poetry install --extras azure``
  * ``backend = local`` (shared NFS / filesystem): no extra packages required.

Enabling on an existing (populated) install — run the backfill
--------------------------------------------------------------

Turning ``enabled = yes`` stamps tenant/visibility onto **new** analyses only.
Reports already in MongoDB have no ``info.tenant_id`` / ``info.user_id`` /
``info.visibility`` stamp, so the scoped search / statistics / compare surfaces
treat them as **fail-closed / invisible** to every tenant until they are
stamped. Run the batched backfill helper from ``lib.tenancy.backfill``
(``backfill_from_task_acl_batched`` or ``backfill_legacy_uniform``) once after
enabling the flag.

Django Group-Native Tenancy & Sandbox Resource Policies
-------------------------------------------------------

In ``lib.tenancy``, Django's built-in ``django.contrib.auth.models.Group``
(``/admin/auth/group/``) is the **single administrative surface** for both:

1. **Tenant Isolation (Who sees which tasks & reports):**
   When ``is_tenant_boundary = True`` (the default on ``GroupSandboxPolicy``) and
   ``tenant`` is left blank, the Django ``Group``'s own numeric primary key
   (``group.id``) **is** the ``tenant_id`` stamped onto ``TaskAcl`` rows and
   MongoDB ``info.tenant_id`` documents. Administrators do **not** need to
   populate a separate ``Tenant`` table unless they want multiple tenant-boundary
   groups to alias to a single external ``Tenant`` row.
2. **Sandbox Resource Entitlements (Who sees & uses which VMs, Routes, and Tags):**
   ``GroupSandboxPolicy`` (attached inline on ``/admin/auth/group/``) controls
   which VMs, network routes, and machine tags members of that group can see in
   the Web UI / APIv2 and request at task submission time:

   * ``is_tenant_boundary`` (default ``True``): when ``True``, ``group.id`` acts
     as a tenant ID for ``visibility="tenant"`` report sharing. Set ``False`` for
     pure **Role / Capability add-on groups** (e.g. ``role-direct-internet``)
     that grant extra routes or VMs without creating a separate report silo.
   * ``is_tenant_admin_group`` (default ``False``): grants tenant-admin
     privileges (toggle visibility / delete ``tenant``-scoped analyses) strictly
     for that group's ``tenant_id``.
   * ``priority`` (default ``0``): higher priority wins when resolving a user's
     primary submission ``tenant_id`` and ``default_route`` across multiple
     groups.
   * ``allowed_machines``: list of allowed VM names or glob patterns (e.g.
     ``["win10_tier1_*", "win11_x64"]`` or ``["*"]``).
   * ``allowed_tags``: list of allowed machine tags or glob patterns (e.g.
     ``["win10", "x64", "office*"]`` or ``["*"]``).
   * ``allowed_routes``: list of allowed routing options (e.g.
     ``["none", "inetsim", "tor", "internet", "vpn:vpn_uk", "socks5:*", "exit:*"]``
     or ``["*"]``).
   * ``default_route``: default route pre-selected in the submission UI and
     injected when ``route`` is omitted on ``POST /submit/`` or
     ``POST /apiv2/tasks/create/*``.
   * ``default_visibility``: optional per-group default task visibility
     (``"private"``, ``"tenant"``, or ``"public"``). When blank, falls back to
     ``cuckoo.conf`` ``[multitenancy] default_visibility``.
   * ``parent_group``, ``inherit_parent_resources`` (default ``True``),
     ``inherit_parent_tasks`` (default ``True``): optional parent/company Django
     Group from which this sub-group inherits baseline VMs/routes/tags and
     one-way shared task read access.
   * ``forced_machine_tags``: machine tags automatically appended when a user
     submits with ``machine=""`` ("First available") so ``Scheduler`` only picks
     VMs in that group's pool.
   * ``allow_all_vms``, ``allow_interactive``, ``max_timeout``: per-group
     controls for ``machine="all"``, interactive Guacamole desktop sessions, and
     maximum analysis timeout.

Task Visibility Levels: ``private`` vs. ``tenant`` (Group) vs. ``public``
-------------------------------------------------------------------------

Every task in ``lib.tenancy`` has one of three visibility states recorded in the
``task_acl`` side-table (``TaskAcl.visibility``) and stamped into the MongoDB
report (``info.visibility``):

1. **User-Private (``visibility = "private"``):**

   * **Who can view/download/search it:** **The submitting user**
     (``task.user_id == viewer.user_id``), **Group Admins of that task's group**
     (``is_tenant_admin_group = True`` for ``task.tenant_id``), and break-glass
     box superusers (``is_local_admin``).
   * **Hidden from regular teammates and other groups:** Regular members of the
     submitter's own Django Group, parent/child groups, and admins of other
     groups **cannot** view, toggle, or delete another user's ``private`` task.
   * **How to submit a private task:**

     - Pass ``visibility=private`` on ``POST /submit/`` or
       ``POST /apiv2/tasks/create/file/`` (any authenticated user can **always**
       choose ``private`` regardless of their group's default).
     - Or set ``default_visibility = "private"`` on the group's
       ``GroupSandboxPolicy`` (or in ``cuckoo.conf`` ``[multitenancy]``) so all
       submissions by that group start out private until the user or group admin
       shares them.
     - Or toggle an existing task to ``private`` after submission via the Web UI
       dropdown (``cape_tenancy/visibility_control.html``) or
       ``POST /apiv2/tasks/visibility/<task_id>/`` with ``visibility=private``.

2. **Group / Tenant Shared (``visibility = "tenant"``):**

   * **Who can view/download/search it:** The submitting user, all members of the
     task's Django Group (``tenant_id == group.id``), any child sub-group with
     ``parent_group`` pointing to that group and ``inherit_parent_tasks = True``,
     and break-glass box superusers.
   * **Who can manage/delete it:** The submitting user, Group Admins
     (``is_tenant_admin_group = True``) of that specific group, and break-glass
     box superusers.

3. **Instance-Public (``visibility = "public"``):**

   * **Who can view/download/search it:** All users on the CAPEv2 instance.
   * **Who can delete it or make it private again:** **Only the original
     submitting user** (``user_id``) or a break-glass box superuser. A Group
     Admin can widen a ``tenant`` or ``private`` task to ``public``, but cannot
     delete a ``public`` task or downgrade someone else's ``public`` task to
     ``tenant`` / ``private``.

Visibility & Permission Matrix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

=======================  ========================  =========================  ========================
Principal                ``private`` Task          ``tenant`` (Group) Task    ``public`` Task
=======================  ========================  =========================  ========================
**Submitting User**      Read / Toggle / Delete    Read / Toggle / Delete     Read / Toggle / Delete
**Group Admin**          Read / Toggle / Delete    Read / Widen / Delete      Read (No Delete/Narrow)
**Same-Group Member**    **Denied (404)**          Read                       Read
**Child Sub-Group**      **Denied (404)**          Read (if inherit=True)     Read
**Parent Group Member**  **Denied (404)**          **Denied (404)**           Read
**Other Group / Admin**  **Denied (404)**          **Denied (404)**           Read
**Box Superuser**        Read / Toggle / Delete    Read / Toggle / Delete     Read / Toggle / Delete
=======================  ========================  =========================  ========================

Administrator Guide: 4 Common Setup Patterns
--------------------------------------------

Pattern 1: One Django Group = One Team / Tenant (Recommended Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this when each team, SOC tier, or customer organization is a Django Group:

1. Open **Django Admin → Authentication and Authorization → Groups → Add group**.
2. Name the group (e.g. ``SOC-Team-Alpha``).
3. In the **Sandbox Resource Policy (VMs, Routes, Tags)** inline section on the
   same page:

   * Leave **Is tenant boundary** checked (``True``) and **Tenant** blank —
     ``SOC-Team-Alpha``'s ``group.id`` automatically becomes its ``tenant_id``.
   * Set ``allowed_machines`` (e.g. ``["win10_alpha_*"]``), ``allowed_routes``
     (e.g. ``["none", "inetsim", "vpn:vpn_alpha"]``), ``default_route``
     (``"inetsim"``), and ``forced_machine_tags`` (``["pool_alpha"]``).
4. Assign users to ``SOC-Team-Alpha`` (either manually in Django Admin or
   automatically via OIDC/SAML ``idp_groups``).
5. Members of ``SOC-Team-Alpha`` will only see ``win10_alpha_*`` VMs and
   ``inetsim`` / ``vpn_alpha`` routes, and any analysis they submit with
   ``visibility="tenant"`` is shared exclusively with ``SOC-Team-Alpha``.

Pattern 2: Multi-Group Users (Cross-Team Incident Responders / Leads)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because ``ViewerContext`` tracks ``tenant_ids: tuple[int, ...]`` across all of a
user's active tenant-boundary groups:

* A user assigned to **both** ``SOC-Team-Alpha`` (``group.id=10``) and
  ``SOC-Team-Beta`` (``group.id=20``) automatically:

  1. Reads ``visibility="tenant"`` analyses from **both** teams (filtered via
     ``TaskAcl.tenant_id IN (10, 20)`` in SQL, ``{"info.tenant_id": {"$in": [10, 20]}}``
     in MongoDB, and ``{"terms": {"info.tenant_id": [10, 20]}}`` in
     Elasticsearch).
  2. Receives the **union** of both groups' ``allowed_machines``,
     ``allowed_routes``, and ``allowed_tags``.
  3. Stamps newly submitted tasks with the ``tenant_id`` of whichever group has
     the higher ``priority`` value.
  4. Retains per-group admin isolation (``admin_tenant_ids``): if the user is a
     group admin in ``SOC-Team-Alpha`` (``is_tenant_admin_group=True``) and a
     regular member in ``SOC-Team-Beta`` (``is_tenant_admin_group=False``), they
     can view/manage/delete ``SOC-Team-Alpha`` tasks (including ``private`` tasks
     in ``SOC-Team-Alpha``) without being able to delete or view private
     ``SOC-Team-Beta`` tasks.

Pattern 3: Capability / Role Add-On Groups Inside a Team (``is_tenant_boundary = False``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this when analysts within the same team share one pool of reports, but a
subset of users needs extra VMs or network routes (e.g. direct ``internet`` or a
restricted VPN):

1. Keep the team group ``SOC-Team-Alpha`` with ``is_tenant_boundary = True`` and
   restricted baseline routes (``["none", "inetsim"]``).
2. Create a second Django Group ``Role-Internet-Access`` with:

   * ``is_tenant_boundary = False`` (unchecked)
   * ``allowed_routes = ["internet", "tor"]``
3. Add senior analysts to both ``SOC-Team-Alpha`` and ``Role-Internet-Access``.
4. Because ``is_tenant_boundary = False`` on ``Role-Internet-Access``, it grants
   the ``internet`` and ``tor`` routes to those senior analysts **without**
   changing their ``tenant_id`` or splitting their shared reports away from
   ``SOC-Team-Alpha``.

Pattern 4: Sub-Groups Inside a Main Company Group (``parent_group`` One-Way Inheritance)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this when you have a main company group (e.g. ``Company-Main``) and a
specialized sub-team (e.g. ``Team-Alpha`` / Threat Intel / Red Team) where:

* You only want to assign ``Team-Alpha`` analysts to **one** group
  (``Team-Alpha``) instead of manually adding them to both ``Company-Main`` and
  ``Team-Alpha``.
* ``Team-Alpha`` members should automatically inherit ``Company-Main``'s
  baseline VMs, routes, and tags **and** be able to view ``Company-Main``'s
  shared analyses.
* General ``Company-Main`` members **must not** see ``Team-Alpha``'s sensitive
  analyses or use ``Team-Alpha``'s specialized VMs/routes.

Steps in ``/admin/auth/group/``:

1. Create ``Company-Main`` (``parent_group = None``, ``allowed_machines = ["win10_company_*"]``,
   ``allowed_routes = ["none", "inetsim"]``).
2. Create ``Team-Alpha`` and set:

   * ``parent_group = Company-Main``
   * ``inherit_parent_resources = True`` (checked by default)
   * ``inherit_parent_tasks = True`` (checked by default)
   * ``allowed_machines = ["win11_alpha_*"]``, ``allowed_routes = ["vpn:vpn_alpha"]``
3. Add sub-team members **only** to ``Team-Alpha``. They automatically inherit
   ``Company-Main``'s VMs/routes and read both ``Team-Alpha`` and
   ``Company-Main`` shared tasks, while ``Company-Main`` users cannot see
   ``Team-Alpha``'s tasks or VMs.

Supported (isolation enforced end-to-end)
-----------------------------------------

* **Report store: MongoDB.** MT scoping of the aggregate/search/statistics/
  compare surfaces reads the tenant stamp (``info.tenant_id`` / ``info.user_id`` /
  ``info.visibility``) written into the mongo analysis document via the core
  ``register_report_hook`` / ``register_mongo_filter`` hooks. **MongoDB is
  required for multitenancy.**
* **Single-node CAPE** (one host running web + processing + analysis).
* **Single-tenant with ``WEB_AUTHENTICATION = True``** (``[multitenancy] enabled = no``):
  when ``WEB_AUTHENTICATION`` is enabled, non-staff users can view, manage, and
  delete their own private tasks and legacy ownerless tasks (``user_id = None``),
  while staff/superusers retain full local-admin visibility. Group sandbox
  resource policies (``GroupSandboxPolicy``) can be used with or without
  ``[multitenancy] enabled = yes``.
* **Cloud / Object Storage Artifact Serving** (``[object_storage]`` in ``cuckoo.conf``,
  implemented in ``lib.tenancy.storage``): workers upload analysis artifacts and
  Guacamole session recordings to S3/MinIO (``backend = s3``), Google Cloud Storage
  (``backend = gcs``), Azure Blob Storage (``backend = azure``), or a shared NFS
  mount (``backend = local``), and the web UI streams or lazily stages artifacts on
  demand via ``TenancyMiddleware.process_view``. Multi-tenancy itself requires no
  extra packages; for object storage, install only the SDK for your chosen backend:
  ``poetry install --extras s3`` (or ``-E s3``), ``poetry install --extras gcp`` (or
  ``-E gcp``), or ``poetry install --extras azure`` (or ``-E azure``).
* **Guacamole interactive sessions** for task-backed analyses: gated by
  ``can_toggle`` / ``can_manage`` (owner / tenant-admin / break-glass), not mere
  read visibility.

Architecture Overview
---------------------

1. **Core Logic Predicates (``lib/tenancy/policy.py``, ``lib/tenancy/resources.py``):**
   Pure dataclasses (``ViewerContext``, ``ResourceScope``,
   ``ResourceEntitlements``) and predicates (``can_read``, ``can_toggle``,
   ``can_delete``, ``can_set_visibility``, ``scope_match``,
   ``viewer_scope_match``, ``viewer_scope_es_filter``,
   ``merge_group_policies``, ``validate_and_normalize_submission``).
2. **Side-Table ACL & Monotonic CAS (``lib/tenancy/acl.py``):**
   Stores per-task tenancy metadata in the dedicated ``task_acl`` table without
   altering CAPEv2's core ``tasks`` table, and synchronizes visibility changes
   to MongoDB using a lock-free monotonic ``visibility_seq`` compare-and-swap
   (CAS) predicate.
3. **Middleware View & Route Gating (``lib/tenancy/middleware.py``, ``lib/tenancy/views.py``):**
   ``TenancyMiddleware`` resolves ``request.viewer`` and
   ``request.entitlements``, binds per-request ``ContextVar``s, gates
   ``task_id`` / ``analysis_id`` / sample hash / ``machines_view`` / task
   submission routes in ``process_view``, serves
   ``POST /apiv2/tasks/visibility/<task_id>/``, and dispatches object-storage
   artifact views.
4. **Cloud-Agnostic Object Storage (``lib/tenancy/storage/``):**
   Pluggable ``ArtifactStore`` backends (``S3Store``, ``GCSStore``,
   ``AzureBlobStore``, ``LocalFSStore``) configured via ``[object_storage]``
   (with backward-compatible ``[central_mode]`` and ``lib.tenancy.central``
   aliases).
5. **Core Hook Integration (``lib/tenancy/hooks.py`` -> ``lib.cuckoo.common.hooks``):**
   Automatically registers ``default_mongo_analysis_filter``,
   ``default_sql_task_query_filter``, ``default_es_query_filter``,
   ``default_report_stamp_hook``, and wraps ``list_machines()``,
   ``load_vms_tags()``, ``load_vms_exits()``, and ``submission/index.html``
   when ``[multitenancy] enabled = yes`` or ``[object_storage] enabled = yes``.
