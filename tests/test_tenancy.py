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


# ── Adversarial-review regressions (2026-07-13): mongo-side fail-open ──

def _mtcfg(mode, enabled=True):
    from lib.cuckoo.common import tenancy
    return tenancy.MTConfig(enabled=enabled, mode=mode, default_visibility="",
                            local_admins_manage_all_tenants=True)


def test_viewer_scope_match_scopes_in_shared_mode(monkeypatch):
    """Finding #2: shared mode (the DEFAULT) must still restrict mongo aggregates
    to public OR own-tenant TENANT OR mine. A private/other-tenant analysis must
    not leak via search/compare/stats/hunt. Previously shared mode returned None
    (see-all) while can_read enforced private in all modes."""
    from lib.cuckoo.common import tenancy
    monkeypatch.setattr(tenancy, "multitenancy_config", lambda: _mtcfg("shared"))
    m = tenancy.viewer_scope_match(tenancy.Viewer(user_id=7, tenant_id=10))
    assert m is not None, "shared mode must scope, not return see-all None"
    clauses = m["$or"]
    assert {"info.visibility": "public"} in clauses
    assert {"info.tenant_id": 10, "info.visibility": "tenant"} in clauses
    assert {"info.user_id": 7} in clauses


def test_viewer_scope_es_filter_scopes_in_shared_mode(monkeypatch):
    """Finding #2 (ES analogue): shared-mode ES filter must scope, not be None."""
    from lib.cuckoo.common import tenancy
    monkeypatch.setattr(tenancy, "multitenancy_config", lambda: _mtcfg("shared"))
    f = tenancy.viewer_scope_es_filter(tenancy.Viewer(user_id=7, tenant_id=10))
    assert f is not None, "shared-mode ES filter must scope, not None"
    assert f["bool"]["minimum_should_match"] == 1


def test_viewer_scope_still_scopes_in_locked_mode(monkeypatch):
    """Locked mode keeps scoping (no regression)."""
    from lib.cuckoo.common import tenancy
    monkeypatch.setattr(tenancy, "multitenancy_config", lambda: _mtcfg("locked"))
    assert tenancy.viewer_scope_match(tenancy.Viewer(user_id=7, tenant_id=10)) is not None


def test_viewer_scope_none_when_disabled(monkeypatch):
    """MT disabled -> no filter (legacy see-all), unchanged."""
    from lib.cuckoo.common import tenancy
    monkeypatch.setattr(tenancy, "multitenancy_config", lambda: _mtcfg("shared", enabled=False))
    assert tenancy.viewer_scope_match(tenancy.Viewer(user_id=7, tenant_id=10)) is None


def test_local_admin_breakglass_still_sees_all(monkeypatch):
    """Break-glass local admin keeps global visibility in any enabled mode."""
    from lib.cuckoo.common import tenancy
    monkeypatch.setattr(tenancy, "multitenancy_config", lambda: _mtcfg("shared"))
    v = tenancy.Viewer(user_id=1, tenant_id=None, is_superuser=True, is_local_admin=True)
    assert tenancy.viewer_scope_match(v) is None
    assert tenancy.viewer_scope_es_filter(v) is None


def _patch_conf(monkeypatch, mode):
    from lib.cuckoo.common import config as _cfgmod

    class _FakeConf:
        def __init__(self, name):
            pass

        def get(self, section):
            return {"enabled": True, "mode": mode, "default_visibility": "",
                    "local_admins_manage_all_tenants": True}

    monkeypatch.setattr(_cfgmod, "Config", _FakeConf)


def test_unknown_mode_fails_closed_to_locked(monkeypatch):
    """Finding #6: an invalid/typo mode must not silently disable scoping; it must
    fail closed to locked (the more restrictive mode)."""
    from lib.cuckoo.common import tenancy
    _patch_conf(monkeypatch, "bogusmode")
    assert tenancy.multitenancy_config().mode == "locked"


def test_known_modes_normalized(monkeypatch):
    """Finding #6: valid modes preserved, case/whitespace-normalized."""
    from lib.cuckoo.common import tenancy
    for raw, want in (("shared", "shared"), ("locked", "locked"),
                      ("LOCKED", "locked"), (" Shared ", "shared")):
        _patch_conf(monkeypatch, raw)
        assert tenancy.multitenancy_config().mode == want, f"mode {raw!r}"
