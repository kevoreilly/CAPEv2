import pytest

from tests.tenancy_vectors import VECTORS
from lib.cuckoo.common.tenancy import can_read, can_toggle, Viewer, Job


@pytest.mark.parametrize("label,viewer,job,want_read,want_toggle", VECTORS, ids=[v[0] for v in VECTORS])
def test_predicate_matches_vectors(label, viewer, job, want_read, want_toggle):
    v = Viewer(**viewer)
    j = Job(**job)
    assert can_read(v, j) is want_read, f"{label}: read"
    assert can_toggle(v, j) is want_toggle, f"{label}: toggle"


def test_config_defaults():
    from lib.cuckoo.common import tenancy
    cfg = tenancy.multitenancy_config()
    assert cfg.enabled in (True, False)
    assert cfg.mode in ("shared", "locked")
    assert isinstance(cfg.local_admins_manage_all_tenants, bool)
    # default_visibility resolves per mode when blank
    assert tenancy.default_visibility(cfg) in ("public", "tenant", "private")


def test_default_visibility_per_mode():
    from lib.cuckoo.common import tenancy
    shared = tenancy.MTConfig(enabled=True, mode="shared", default_visibility="",
                              local_admins_manage_all_tenants=True)
    locked = tenancy.MTConfig(enabled=True, mode="locked", default_visibility="",
                              local_admins_manage_all_tenants=True)
    assert tenancy.default_visibility(shared) == "public"
    assert tenancy.default_visibility(locked) == "tenant"


def test_disabled_is_legacy_open():
    """With multitenancy disabled, default visibility is public and a legacy
    NULL-tenant public task is visible to anyone (current single-tenant behavior)."""
    from lib.cuckoo.common import tenancy
    cfg = tenancy.MTConfig(enabled=False, mode="shared", default_visibility="",
                           local_admins_manage_all_tenants=True)
    assert tenancy.default_visibility(cfg) == "public"
    v = tenancy.Viewer(user_id=None, tenant_id=None)
    j = tenancy.Job(owner_id=1, tenant_id=None, visibility="public")
    assert tenancy.can_read(v, j) is True


def test_scope_match_membership():
    from lib.cuckoo.common.tenancy import scope_match
    from tests.tenancy_vectors import SCOPE_VECTORS

    def doc_matches(match, job):
        if match is None:
            return True  # global
        for k, v in match.items():
            if k == "info.id":  # impossible-sentinel -> matches nothing
                return False
            field = {"info.visibility": job.visibility, "info.tenant_id": job.tenant_id,
                     "info.user_id": job.owner_id}.get(k)
            if field != v:
                return False
        return True

    for viewer, job, scope, expected in SCOPE_VECTORS:
        assert doc_matches(scope_match(scope, viewer), job) is expected, (scope, viewer, job)


def test_scope_match_none_viewer():
    """Defensive (PR#2 review): scope_match must not AttributeError when called
    with a scope but no viewer (statistics(viewer=None) path)."""
    from lib.cuckoo.common.tenancy import scope_match
    assert scope_match("tenant", None) == {"info.id": -1}
    assert scope_match("mine", None) == {"info.id": -1}
    assert scope_match("public", None) == {"info.visibility": "public"}
    assert scope_match("global", None) is None
