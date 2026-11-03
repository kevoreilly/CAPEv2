"""Canonical visibility test-vectors for `lib.tenancy`."""

from lib.tenancy.policy import ResourceScope as Job, ViewerContext as Viewer

PUBLIC, TENANT, PRIVATE = "public", "tenant", "private"

# Each vector: (label, viewer, job, can_read, can_toggle, can_delete)
VECTORS = [
    # --- public: everyone reads; only submitter/break-glass may DELETE (tenant-admin may toggle, not delete) ---
    (
        "public/anon",
        dict(user_id=None, tenant_id=None, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PUBLIC),
        True,
        False,
        False,
    ),
    (
        "public/other",
        dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PUBLIC),
        True,
        False,
        False,
    ),
    # --- tenant: only same-tenant members read ---
    (
        "tenant/same",
        dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=TENANT),
        True,
        False,
        False,
    ),
    (
        "tenant/other",
        dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=TENANT),
        False,
        False,
        False,
    ),
    (
        "tenant/null-job",
        dict(user_id=2, tenant_id=None, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=None, visibility=TENANT),
        False,
        False,
        False,
    ),
    # --- private: owner, same-group admin (is_tenant_admin), or break-glass local admin ---
    (
        "private/owner",
        dict(user_id=1, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PRIVATE),
        True,
        True,
        True,
    ),
    (
        "private/teammate",
        dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PRIVATE),
        False,
        False,
        False,
    ),
    (
        "private/tadmin",
        dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PRIVATE),
        True,
        True,
        True,
    ),
    # --- tenant-admin: manages (toggles) public/tenant/private jobs in own tenant; may DELETE TENANT or PRIVATE job in own tenant ---
    (
        "tadmin/toggle-tenant",
        dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=TENANT),
        True,
        True,
        True,
    ),
    (
        "tadmin/other-tenant",
        dict(user_id=2, tenant_id=20, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=TENANT),
        False,
        False,
        False,
    ),
    (
        "tadmin/public-nodelete",
        dict(user_id=2, tenant_id=10, is_superuser=False, is_tenant_admin=True, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PUBLIC),
        True,
        True,
        False,
    ),
    # --- owner always reads + toggles own ---
    (
        "owner/tenant-job",
        dict(user_id=1, tenant_id=10, is_superuser=False, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=TENANT),
        True,
        True,
        True,
    ),
    # --- superuser break-glass ---
    (
        "breakglass/read",
        dict(user_id=9, tenant_id=None, is_superuser=True, is_tenant_admin=False, is_local_admin=True),
        dict(owner_id=1, tenant_id=10, visibility=PRIVATE),
        True,
        True,
        True,
    ),
    (
        "breakglass/off",
        dict(user_id=9, tenant_id=None, is_superuser=True, is_tenant_admin=False, is_local_admin=False),
        dict(owner_id=1, tenant_id=10, visibility=PRIVATE),
        False,
        False,
        False,
    ),
]

SCOPE_VECTORS = [
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "public", True),
    (Viewer(user_id=2, tenant_id=99), Job(owner_id=1, tenant_id=10, visibility="public"), "public", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="tenant"), "public", False),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="tenant"), "tenant", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=99, visibility="tenant"), "tenant", False),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "tenant", False),
    (Viewer(user_id=2, tenant_id=None), Job(owner_id=1, tenant_id=10, visibility="tenant"), "tenant", False),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=2, tenant_id=10, visibility="private"), "mine", True),
    (Viewer(user_id=2, tenant_id=10), Job(owner_id=1, tenant_id=10, visibility="public"), "mine", False),
    (Viewer(user_id=None, tenant_id=10), Job(owner_id=2, tenant_id=10, visibility="private"), "mine", False),
    (
        Viewer(user_id=2, tenant_id=10, is_local_admin=True),
        Job(owner_id=1, tenant_id=99, visibility="private"),
        "global",
        True,
    ),
]
