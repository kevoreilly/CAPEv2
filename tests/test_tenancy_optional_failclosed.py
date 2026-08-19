"""Import-optional MT facade must FAIL CLOSED, not see-all, when MT is enabled but its import chain
breaks (adversarial-review MED). The `except ImportError` arms historically returned see-all, which
can't tell 'MT layer genuinely absent' (upstream/single-tenant) from 'MT enabled but users.tenancy /
dashboard.views import broke' — the latter silently degraded the sole isolation gate to see-all.
"""
import builtins


def _hide(monkeypatch, modname):
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == modname or name.startswith(modname + "."):
            raise ImportError("simulated-absent: " + modname)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


def test_mt_enabled_reads_pure_config(monkeypatch):
    import lib.cuckoo.common.tenancy_optional as fac
    monkeypatch.setattr("lib.cuckoo.common.tenancy.multitenancy_config", lambda: type("C", (), {"enabled": True})())
    assert fac._mt_enabled() is True
    monkeypatch.setattr("lib.cuckoo.common.tenancy.multitenancy_config", lambda: type("C", (), {"enabled": False})())
    assert fac._mt_enabled() is False


def test_lib_viewer_for_fail_closed_when_mt_enabled_but_broken(monkeypatch):
    import lib.cuckoo.common.tenancy_optional as fac
    _hide(monkeypatch, "users.tenancy")
    monkeypatch.setattr(fac, "_mt_enabled", lambda: True)
    assert fac.viewer_for(object()).is_local_admin is False, "MT enabled + broken import must NOT see-all"
    monkeypatch.setattr(fac, "_mt_enabled", lambda: False)
    assert fac.viewer_for(object()).is_local_admin is True, "MT genuinely absent -> single-tenant see-all"
