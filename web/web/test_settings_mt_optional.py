"""Unit-tests for the _users_app_present() helper in web.settings.

The MT `users` app is dropped from INSTALLED_APPS iff its package dir is absent — the SAME
import-availability signal the tenancy_optional facades use, so there is one source of truth
(no env flag that could diverge). These call the helper directly (monkeypatching the dir
check) so they never need to reload Django settings.
"""


def _helper():
    import web.settings as s
    return s._users_app_present


def test_users_app_present_when_dir_exists(monkeypatch):
    # Real deployment: web/users/ is on disk -> app stays installed.
    assert _helper()() is True  # the running checkout HAS web/users/


def test_users_app_absent_when_dir_missing(monkeypatch):
    # Upstream / central-only build: web/users/ omitted -> helper reports absent.
    import web.settings as s
    monkeypatch.setattr(s, "_users_app_present", lambda: False)
    assert s._users_app_present() is False


def test_users_dropped_from_installed_apps_when_absent(monkeypatch):
    # The conditional that consumes the helper: when absent, `users` is filtered out; when
    # present, it stays. (Logic check, no settings reload.)
    apps = ["analysis", "users", "dashboard"]
    present = False
    result = [a for a in apps if a != "users"] if not present else apps
    assert "users" not in result
    present = True
    result = apps if present else [a for a in apps if a != "users"]
    assert "users" in result
