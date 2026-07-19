"""Web MT facade fails CLOSED (deny), not see-all, when MT is enabled but users.tenancy /
dashboard.views can't be imported (adversarial-review MED — the sole isolation gate)."""
import builtins


def _hide(monkeypatch, modname):
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == modname or name.startswith(modname + "."):
            raise ImportError("simulated-absent: " + modname)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


def test_web_authz_gates_fail_closed_when_mt_enabled_but_broken(monkeypatch):
    from web import tenancy_optional as fac
    _hide(monkeypatch, "users.tenancy")
    monkeypatch.setattr(fac, "_mt_enabled", lambda: True)
    assert fac.can_view_task(object(), object()) is False
    assert fac.can_toggle_task(object(), object()) is False
    assert fac.can_manage_task(object(), object()) is False
    assert fac.can_view_sample(object(), sha256="a" * 64) is False
    assert fac.viewer_for(object()).is_local_admin is False
    assert fac.submission_scope(object()) == (None, fac.PRIVATE)


def test_web_authz_gates_see_all_when_mt_genuinely_absent(monkeypatch):
    from web import tenancy_optional as fac
    _hide(monkeypatch, "users.tenancy")
    monkeypatch.setattr(fac, "_mt_enabled", lambda: False)
    assert fac.can_view_task(object(), object()) is True
    assert fac.viewer_for(object()).is_local_admin is True
    assert fac.submission_scope(object()) == (None, fac.PUBLIC)


def test_web_scope_filters_fail_closed(monkeypatch):
    from web import tenancy_optional as fac
    _hide(monkeypatch, "dashboard.views")
    monkeypatch.setattr(fac, "_mt_enabled", lambda: True)
    assert fac.viewer_scope_filter(object()) == {"_id": {"$in": []}}  # deny-all, not None(see-all)
    assert fac.entitled_scopes(object()) == ()
    monkeypatch.setattr(fac, "_mt_enabled", lambda: False)
    assert fac.viewer_scope_filter(object()) is None
    assert fac.entitled_scopes(object()) == ("global",)
