import pytest
from django.contrib.auth.models import User


class _Req:
    def __init__(self, user):
        self.user = user


def _patch_db(monkeypatch, *, find_sample=None, list_tasks=None):
    """Patch the methods on the underlying _Database singleton. _deny_by_hash now
    delegates to tenancy.can_view_sample, which resolves its own Database() proxy;
    every Database() proxy delegates via __getattr__ to the same _DATABASE
    singleton, so patch THAT (patching one proxy instance's attrs wouldn't reach
    can_view_sample's proxy)."""
    import lib.cuckoo.core.database as dbmod

    if find_sample is not None:
        monkeypatch.setattr(dbmod._DATABASE, "find_sample", find_sample, raising=False)
    if list_tasks is not None:
        monkeypatch.setattr(dbmod._DATABASE, "list_tasks", list_tasks, raising=False)


class _Sample:
    id = 7


@pytest.mark.django_db
def test_deny_by_hash_noop_when_multitenancy_disabled(cape_db, monkeypatch):
    # NO mt_enabled fixture -> multitenancy disabled -> viewer_for returns is_local_admin=True
    import apiv2.views as views
    called = {"find": False}

    def _find(**k):
        called["find"] = True
        return None

    _patch_db(monkeypatch, find_sample=_find)
    u = User.objects.create_user("pub", "p@x.com", "x")
    # disabled => allow (return None) without gating; can_view_sample short-circuits on is_local_admin
    assert views._deny_by_hash(_Req(u), sha256="a" * 64) is None
    assert called["find"] is False  # short-circuited before any sample lookup


@pytest.mark.django_db
def test_deny_by_hash_blocks_when_no_visible_task(cape_db, mt_enabled, monkeypatch):
    import apiv2.views as views

    _patch_db(monkeypatch, find_sample=lambda **k: _Sample(), list_tasks=lambda **k: [])  # none visible
    other = User.objects.create_user("b", "b@x.com", "x")
    resp = views._deny_by_hash(_Req(other), sha256="a" * 64)
    assert resp is not None and resp.status_code == 404


@pytest.mark.django_db
def test_deny_by_hash_allows_when_visible_task_exists(cape_db, mt_enabled, monkeypatch):
    import apiv2.views as views

    _patch_db(monkeypatch, find_sample=lambda **k: _Sample(), list_tasks=lambda **k: [object()])  # 1 visible
    u = User.objects.create_user("o", "o@x.com", "x")
    assert views._deny_by_hash(_Req(u), sha256="a" * 64) is None


@pytest.mark.django_db
def test_deny_by_hash_missing_sample_is_404(cape_db, mt_enabled, monkeypatch):
    import apiv2.views as views

    _patch_db(monkeypatch, find_sample=lambda **k: None)
    u = User.objects.create_user("o", "o@x.com", "x")
    resp = views._deny_by_hash(_Req(u), sha256="a" * 64)
    assert resp is not None and resp.status_code == 404


@pytest.mark.django_db
def test_can_view_sample_centralizes_the_boundary(cape_db, mt_enabled, monkeypatch):
    """The shared helper: a sample with a visible task -> True; a sample with no
    visible task -> False; break-glass / MT-disabled -> True (no-op)."""
    from users.tenancy import can_view_sample

    _patch_db(monkeypatch, find_sample=lambda **k: _Sample(), list_tasks=lambda **k: [])
    u = User.objects.create_user("cv", "cv@x.com", "x")
    assert can_view_sample(u, sha256="a" * 64) is False  # exists but no visible task
    _patch_db(monkeypatch, list_tasks=lambda **k: [object()])
    assert can_view_sample(u, sha256="a" * 64) is True   # now visible
    _patch_db(monkeypatch, find_sample=lambda **k: None)
    assert can_view_sample(u, sha256="b" * 64) is False  # absent
