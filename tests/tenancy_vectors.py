"""Canonical visibility test-vectors — the single source of truth shared by the
CAPE predicate (lib/cuckoo/common/tenancy.py) and, later, the broker's DynamoDB
reimplementation. Each case: a viewer + a job + expected read/toggle outcome.

Viewer/job tenants are small ints; None means "no tenant".
"""

from lib.cuckoo.common.tenancy import Viewer, Job

# Visibility levels
PUBLIC, TENANT, PRIVATE = "public", "tenant", "private"

# Each vector: (label, viewer, job, can_read, can_toggle, can_delete)
#   viewer = dict(user_id, tenant_id, is_superuser, is_tenant_admin, is_local_admin)
#   job    = dict(owner_id, tenant_id, visibility)
#   is_local_admin = the cuckoo.conf local_admins_manage_all_tenants gate already
#                    resolved for this viewer (True only when flag on AND superuser).
#   can_delete = irreversible-delete authority: stricter than can_toggle for PUBLIC jobs
#                (a tenant-admin may toggle but NOT delete a public job).
VECTORS = [
    # --- public: everyone reads; only submitter/break-glass may DELETE (tenant-admin may toggle, not delete) ---
    ("public/anon",      dict(user_id=None, tenant_id=None, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PUBLIC), True,  False, False),
    ("public/other",     dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PUBLIC), True,  False, False),
    # --- tenant: only same-tenant members read ---
    ("tenant/same",      dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=TENANT), True,  False, False),
    ("tenant/other",     dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=TENANT), False, False, False),
    ("tenant/null-job",  dict(user_id=2, tenant_id=None, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=None, visibility=TENANT), False, False, False),  # null tenant != "everyone"
    # --- private: only owner ---
    ("private/owner",    dict(user_id=1, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PRIVATE), True,  True,  True),
    ("private/teammate", dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PRIVATE), False, False, False),
    ("private/tadmin",   dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True,  is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PRIVATE), False, False, False),  # tenant-admin can't reach private
    # --- tenant-admin: manages (toggles) public/tenant jobs in own tenant; may DELETE only a TENANT job ---
    ("tadmin/toggle-tenant", dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=TENANT), True,  True,  True),
    ("tadmin/other-tenant",  dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=TENANT), False, False, False),
    ("tadmin/public-nodelete", dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PUBLIC), True,  True,  False),  # toggle yes, DELETE no (the delta)
    # --- owner always reads + toggles own ---
    ("owner/tenant-job", dict(user_id=1, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=TENANT), True,  True,  True),
    # --- superuser break-glass (local_admins_manage_all_tenants resolved into is_local_admin) ---
    ("breakglass/read",  dict(user_id=9, tenant_id=None, is_superuser=True, is_tenant_admin=False, is_local_admin=True),
                         dict(owner_id=1, tenant_id=10, visibility=PRIVATE), True,  True,  True),
    ("breakglass/off",   dict(user_id=9, tenant_id=None, is_superuser=True, is_tenant_admin=False, is_local_admin=False),
                         dict(owner_id=1, tenant_id=10, visibility=PRIVATE), False, False, False),  # flag off => no cross-owner reach
]

# Scope membership vectors: does a job appear in a given stat scope for a viewer?
# (viewer, job, scope) -> bool. Viewer/Job reuse the dataclasses already imported here.
SCOPE_VECTORS = [
    # public scope: every public job, regardless of viewer
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "public", True),
    (Viewer(user_id=2, tenant_id=99), Job(owner_id=1, tenant_id=10, visibility="public"), "public", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="tenant"), "public", False),
    # tenant scope: tenant-visibility jobs of the viewer's own tenant
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="tenant"), "tenant", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=99, visibility="tenant"), "tenant", False),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "tenant", False),
    (Viewer(user_id=2, tenant_id=None), Job(owner_id=1, tenant_id=10, visibility="tenant"), "tenant", False),
    # mine scope: jobs the viewer owns, any visibility
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=2, tenant_id=10, visibility="private"), "mine", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "mine", False),
    (Viewer(user_id=None, tenant_id=10), Job(owner_id=2, tenant_id=10, visibility="private"), "mine", False),  # user-less sentinel
    # global: everything (break-glass / shared)
    (Viewer(user_id=2, tenant_id=10, is_local_admin=True), Job(owner_id=1, tenant_id=99, visibility="private"), "global", True),
]
