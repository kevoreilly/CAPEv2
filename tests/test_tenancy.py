import pytest

from tests.tenancy_vectors import VECTORS
from lib.cuckoo.common.tenancy import can_read, can_toggle, can_delete, Viewer, Job


@pytest.mark.parametrize("label,viewer,job,want_read,want_toggle,want_delete", VECTORS, ids=[v[0] for v in VECTORS])
def test_predicate_matches_vectors(label, viewer, job, want_read, want_toggle, want_delete):
    v = Viewer(**viewer)
    j = Job(**job)
    assert can_read(v, j) is want_read, f"{label}: read"
    assert can_toggle(v, j) is want_toggle, f"{label}: toggle"
    assert can_delete(v, j) is want_delete, f"{label}: delete"


def test_can_delete_public_stricter_than_toggle():
    """can_delete is can_toggle minus tenant-admin-on-PUBLIC: a public task is a shared/instance
    resource, deletable ONLY by its submitter or a break-glass box admin. TENANT: submitter /
    tenant-admin(same tenant) / box admin. PRIVATE: submitter / box admin."""
    from lib.cuckoo.common.tenancy import can_delete, can_toggle, Viewer, Job

    owner = Viewer(user_id=1, tenant_id=10)
    tadmin = Viewer(user_id=2, tenant_id=10, is_tenant_admin=True)
    boxadmin = Viewer(user_id=3, tenant_id=None, is_local_admin=True)
    other = Viewer(user_id=4, tenant_id=10)
    foreign_tadmin = Viewer(user_id=5, tenant_id=99, is_tenant_admin=True)  # admin of a DIFFERENT tenant
    pub = Job(owner_id=1, tenant_id=10, visibility="public")
    ten = Job(owner_id=1, tenant_id=10, visibility="tenant")
    priv = Job(owner_id=1, tenant_id=10, visibility="private")

    # PUBLIC -- the delta: tenant-admin may TOGGLE/manage a public job but may NOT delete it.
    assert can_toggle(tadmin, pub) is True
    assert can_delete(tadmin, pub) is False
    assert can_delete(owner, pub) is True
    assert can_delete(boxadmin, pub) is True
    assert can_delete(other, pub) is False

    # TENANT -- submitter / same-tenant tenant-admin / box admin.
    assert [can_delete(x, ten) for x in (owner, tadmin, boxadmin, other)] == [True, True, True, False]
    # A DIFFERENT tenant's admin must NOT delete this tenant's job -- exercises the _same_tenant conjunct
    # (RED against a mutant can_delete with _same_tenant dropped, which would let tenant-99 delete tenant-10).
    assert can_delete(foreign_tadmin, ten) is False

    # PRIVATE -- submitter / box admin only (a tenant-admin cannot delete a member's private job).
    assert [can_delete(x, priv) for x in (owner, tadmin, boxadmin, other)] == [True, False, True, False]


def test_can_set_visibility_blocks_tenant_admin_public_downgrade():
    """The visibility transition itself is authorized so can_delete's PUBLIC boundary can't be reached
    in two steps: a tenant-admin may toggle a public job but may NOT downgrade it to tenant/private
    (which would move it into can_delete's tenant branch). Widening / same-value / owner / break-glass
    stay allowed. RED against the pre-fix code where the write gated on can_toggle alone."""
    from lib.cuckoo.common.tenancy import can_set_visibility, can_toggle, can_delete, Viewer, Job

    owner = Viewer(user_id=1, tenant_id=10)
    tadmin = Viewer(user_id=2, tenant_id=10, is_tenant_admin=True)
    boxadmin = Viewer(user_id=3, tenant_id=None, is_local_admin=True)
    other = Viewer(user_id=4, tenant_id=10)
    pub = Job(owner_id=1, tenant_id=10, visibility="public")
    ten = Job(owner_id=1, tenant_id=10, visibility="tenant")

    # the escalation the guard closes: toggle allowed, but the downgrade transition is not.
    assert can_toggle(tadmin, pub) is True
    assert can_set_visibility(tadmin, pub, "tenant") is False   # <- the former bypass step
    assert can_set_visibility(tadmin, pub, "private") is False
    assert can_delete(tadmin, pub) is False                     # and the delete itself still refused
    # widening / same-value stays allowed for the tenant-admin
    assert can_set_visibility(tadmin, ten, "public") is True
    assert can_set_visibility(tadmin, pub, "public") is True
    # owner + break-glass may set any value they can already toggle
    assert can_set_visibility(owner, pub, "tenant") is True
    assert can_set_visibility(boxadmin, pub, "private") is True
    # a caller with no toggle right is refused regardless of direction
    assert can_set_visibility(other, pub, "public") is False


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


def test_absent_section_is_mt_off(monkeypatch):
    """A merely-absent [multitenancy] section (Config.get raises CuckooOperationalError)
    is the legitimate single-tenant default: MT OFF. Must NOT fail closed / lock out a
    single-tenant deployment that never configured the section."""
    from lib.cuckoo.common import config as _cfgmod
    from lib.cuckoo.common.exceptions import CuckooOperationalError
    from lib.cuckoo.common import tenancy

    class _AbsentConf:
        def __init__(self, name):
            pass

        def get(self, section):
            raise CuckooOperationalError("Option multitenancy is not found in configuration")
    monkeypatch.setattr(_cfgmod, "Config", _AbsentConf)
    assert tenancy.multitenancy_config().enabled is False


def test_config_read_error_fails_closed(monkeypatch):
    """A genuinely unreadable [multitenancy] (parse/IO error — NOT a merely-absent
    section) must fail CLOSED: MT enabled + locked, never silently disable isolation.
    Mirrors test_unknown_mode_fails_closed_to_locked + the backfill node-role guard —
    an unreadable policy config never degrades to the permissive (MT-off) branch."""
    from lib.cuckoo.common import config as _cfgmod
    from lib.cuckoo.common import tenancy

    class _BoomConf:
        def __init__(self, name):
            pass

        def get(self, section):
            raise RuntimeError("cuckoo.conf parse error")
    monkeypatch.setattr(_cfgmod, "Config", _BoomConf)
    cfg = tenancy.multitenancy_config()
    assert cfg.enabled is True and cfg.mode == "locked", (
        f"config-read error must fail closed (enabled+locked), got {cfg}")
    # fail closed on EVERY knob: local_admins_manage_all_tenants=False is the restrictive
    # value (don't hand a local superuser full break-glass on the fail-closed path).
    assert cfg.local_admins_manage_all_tenants is False, (
        f"fail-closed must be restrictive on local_admins_manage_all_tenants, got {cfg}")


def test_failclosed_default_visibility_is_private(monkeypatch):
    """Fail-closed sentinel (unreadable config) must resolve the submit default to the
    MOST restrictive PRIVATE — default_visibility="" would fall through to TENANT under
    mode=locked, widening exposure during a config outage."""
    from lib.cuckoo.common import config as _cfgmod
    from lib.cuckoo.common import tenancy

    class _Boom:
        def __init__(self, name):
            raise ValueError("simulated corrupt cuckoo.conf")
    monkeypatch.setattr(_cfgmod, "Config", _Boom)
    cfg = tenancy.multitenancy_config()
    assert cfg.enabled is True and cfg.mode == "locked"
    assert tenancy.default_visibility(cfg) == tenancy.PRIVATE, (
        f"fail-closed submit default should be PRIVATE (owner-only), got {tenancy.default_visibility(cfg)!r}")


def test_typo_default_visibility_fails_closed(monkeypatch):
    """An explicitly-set but unrecognized default_visibility (typo/artifact) must fail
    CLOSED to private — never fall open to the widest per-mode default (PUBLIC in shared),
    which is what the sibling `mode` knob already does on unknown values."""
    from lib.cuckoo.common import config as _cfgmod
    from lib.cuckoo.common import tenancy

    class _Conf:
        def __init__(self, name):
            pass

        def get(self, section):
            return {"enabled": True, "mode": "shared", "default_visibility": "privte",
                    "local_admins_manage_all_tenants": True}
    monkeypatch.setattr(_cfgmod, "Config", _Conf)
    cfg = tenancy.multitenancy_config()
    assert tenancy.default_visibility(cfg) == tenancy.PRIVATE, (
        f"unrecognized default_visibility must fail closed to private, got {tenancy.default_visibility(cfg)!r}")


def test_default_visibility_normalized(monkeypatch):
    """default_visibility must be case/whitespace-normalized like `mode` — otherwise a
    'Private'/' private ' misparse fails the exact `in VISIBILITIES` check and silently
    WIDENS to the per-mode default (PUBLIC in shared)."""
    from lib.cuckoo.common import config as _cfgmod
    from lib.cuckoo.common import tenancy

    for raw, want in ((" Private ", "private"), ("PUBLIC", "public"), ("Tenant", "tenant")):
        class _Conf:
            def __init__(self, name):
                pass

            def get(self, section):
                return {"enabled": True, "mode": "shared", "default_visibility": raw,
                        "local_admins_manage_all_tenants": True}
        monkeypatch.setattr(_cfgmod, "Config", _Conf)
        cfg = tenancy.multitenancy_config()
        assert cfg.default_visibility == want, f"default_visibility {raw!r} -> {cfg.default_visibility!r}"
        # and it now resolves through default_visibility() instead of falling back
        assert tenancy.default_visibility(cfg) == want
