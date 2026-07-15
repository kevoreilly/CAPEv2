import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



@pytest.mark.django_db
def test_dashboard_entitled_scopes(cape_db, mt_enabled, monkeypatch):
    from dashboard.views import entitled_scopes
    from users.models import Tenant, UserProfile
    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("a", "a@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)
    assert entitled_scopes(u) == ["public", "tenant", "mine"]
    tl = User.objects.create_user("b", "b@x.com", "x")  # tenant-less
    assert entitled_scopes(tl) == ["public", "mine"]


@pytest.mark.django_db
def test_dashboard_entitled_scopes_shared_mode(cape_db, monkeypatch):
    """Finding #2: shared mode (the DEFAULT) must still return the scoped panels
    (public/tenant/mine), NOT the single see-all 'global' panel. Previously shared
    mode returned ['global'], leaking other tenants' private analyses into the
    dashboard/statistics aggregates while can_read enforced private in all modes."""
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut
    monkeypatch.setattr(
        ut, "multitenancy_config",
        lambda: MTConfig(enabled=True, mode="shared", default_visibility="",
                         local_admins_manage_all_tenants=True),
    )
    from dashboard.views import entitled_scopes
    from users.models import Tenant, UserProfile
    t = Tenant.objects.create(slug="acme-shared", name="AcmeShared")
    u = User.objects.create_user("ash", "ash@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)
    assert entitled_scopes(u) == ["public", "tenant", "mine"]


@pytest.mark.django_db
def test_disabled_shows_single_global_scope():
    """Back-compat: with multitenancy disabled (the default / basic public install),
    every user gets a single Global panel == today's dashboard. No mt_enabled fixture
    here, so multitenancy_config() reads the default (disabled) -> viewer_for() returns
    is_local_admin=True -> entitled_scopes short-circuits to ['global']."""
    from dashboard.views import entitled_scopes
    u = User.objects.create_user("c", "c@x.com", "x")
    assert entitled_scopes(u) == ["global"]


@pytest.mark.django_db
def test_entitled_scope_filter_builds_viewer_mongo_match(cape_db, mt_enabled):
    """The combined mongo $match used by hunt + compare must select exactly the
    viewer's entitled scopes (public OR own-tenant-tenant OR mine)."""
    from dashboard.views import entitled_scope_filter
    from users.models import Tenant, UserProfile

    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("sf", "sf@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)

    f = entitled_scope_filter(u)
    assert "$or" in f
    assert {"info.visibility": "public"} in f["$or"]
    assert {"info.tenant_id": t.id, "info.visibility": "tenant"} in f["$or"]
    assert {"info.user_id": u.id} in f["$or"]


@pytest.mark.django_db
def test_entitled_scope_filter_disabled_is_none():
    """MT disabled (default) -> 'global' scope -> None (no filter), so aggregate
    queries are unchanged in the public install."""
    from dashboard.views import entitled_scope_filter

    u = User.objects.create_user("sg", "sg@x.com", "x")
    assert entitled_scope_filter(u) is None
