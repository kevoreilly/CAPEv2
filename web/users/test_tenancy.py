import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



@pytest.mark.django_db
def test_tenant_and_profile_fields():
    from users.models import Tenant, UserProfile

    t = Tenant.objects.create(
        slug="acme", name="Acme", idp_groups=["acme-soc"], admin_idp_groups=["acme-admins"]
    )
    u = User.objects.create_user("a", "a@acme.com", "x")
    prof = UserProfile.objects.get(user=u)  # auto-created by signal
    prof.tenant = t
    prof.is_tenant_admin = True
    prof.save()

    refreshed = UserProfile.objects.get(user=u)
    assert refreshed.tenant.slug == "acme"
    assert refreshed.is_tenant_admin is True


@pytest.mark.django_db
def test_resolve_tenant_from_groups():
    from users.models import Tenant, UserProfile
    from web.allauth_adapters import reconcile_tenant

    t = Tenant.objects.create(
        slug="acme", name="Acme", idp_groups=["acme-soc"], admin_idp_groups=["acme-admins"]
    )
    u = User.objects.create_user("a", "a@acme.com", "x")

    reconcile_tenant(u, {"acme-soc", "acme-admins"})
    p = UserProfile.objects.get(user=u)
    assert p.tenant_id == t.id and p.is_tenant_admin is True

    reconcile_tenant(u, {"acme-soc"})  # demoted from admin, still a member
    p.refresh_from_db()
    assert p.tenant_id == t.id and p.is_tenant_admin is False

    reconcile_tenant(u, set())  # no matching groups -> no tenant
    p.refresh_from_db()
    assert p.tenant_id is None and p.is_tenant_admin is False


@pytest.mark.django_db
def test_resolve_tenant_multi_match_fails_closed():
    from users.models import Tenant, UserProfile
    from web.allauth_adapters import reconcile_tenant

    Tenant.objects.create(slug="a", name="A", idp_groups=["shared-grp"])
    Tenant.objects.create(slug="b", name="B", idp_groups=["shared-grp"])
    u = User.objects.create_user("m", "m@x.com", "x")
    reconcile_tenant(u, {"shared-grp"})
    p = UserProfile.objects.get(user=u)
    assert p.tenant_id is None  # ambiguous -> fail closed


@pytest.mark.django_db
def test_resolve_tenant_string_idp_groups_not_char_matched():
    """A misconfigured idp_groups stored as a bare STRING (e.g. "acme-soc" instead of
    ["acme-soc"]) must be treated as ONE group, not iterated character-by-character —
    else a user in group 'a'/'c'/… would spuriously match and get the wrong tenant."""
    from users.models import Tenant, UserProfile
    from web.allauth_adapters import reconcile_tenant

    t = Tenant.objects.create(slug="acmestr", name="AcmeStr", idp_groups="acme-soc")  # bare string (misconfig)
    u = User.objects.create_user("astr", "astr@x.com", "x")

    # a single-character group must NOT char-match the string
    reconcile_tenant(u, {"a"})
    p = UserProfile.objects.get(user=u)
    assert p.tenant_id is None

    # the whole string, treated as one group, matches
    reconcile_tenant(u, {"acme-soc"})
    p.refresh_from_db()
    assert p.tenant_id == t.id


@pytest.mark.django_db
def test_viewer_for_maps_user(mt_enabled):
    from users.models import Tenant, UserProfile
    from users.tenancy import viewer_for

    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("a", "a@acme.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.is_tenant_admin = True
    p.save()

    # re-fetch so the user's cached userprofile reflects the saved tenant
    # (a real request loads request.user.userprofile fresh)
    fresh = User.objects.get(pk=u.pk)
    v = viewer_for(fresh)
    assert v.user_id == u.id
    assert v.tenant_id == t.id
    assert v.is_tenant_admin is True


@pytest.mark.django_db
def test_disabled_is_backcompat_see_all(monkeypatch):
    """H1 back-compat: with multitenancy OFF (the default / existing `sb`
    deployment), any authenticated user sees every task — including a legacy
    private job owned by someone else — exactly like today. The feature must be
    fully opt-in and must not retroactively hide existing rows."""
    from lib.cuckoo.common.tenancy import MTConfig
    from users.tenancy import can_view_task, viewer_for
    import users.tenancy as ut

    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))

    nonowner = User.objects.create_user("n", "n@x.com", "x")

    class LegacyTask:  # owned by a different user, marked private
        user_id = 999
        tenant_id = None
        visibility = "private"

    v = viewer_for(nonowner)
    assert v.is_local_admin is True          # short-circuit to legacy see-all
    assert v.tenant_id is None
    assert can_view_task(nonowner, LegacyTask()) is True  # not hidden


@pytest.mark.django_db
def test_disabled_anonymous_is_backcompat_see_all(monkeypatch):
    """B0 back-compat (the headline gating regression): on a DISABLED install a
    no-auth public deployment (WEB_AUTHENTICATION off) or apiv2 with token-auth
    off (DRF AllowAny) serves every request as AnonymousUser. viewer_for MUST
    short-circuit the disabled case BEFORE the is_authenticated check so an
    anonymous viewer is is_local_admin=True and can_read a private-default task,
    exactly like upstream. Regression guard: previously the anon branch returned
    is_local_admin=False before reading cfg, so ~45 guards denied non-public
    tasks on a plain public install."""
    from django.contrib.auth.models import AnonymousUser
    from lib.cuckoo.common.tenancy import MTConfig
    from users.tenancy import can_view_task, can_manage_task, viewer_for
    import users.tenancy as ut

    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))

    class PrivateTask:  # private-default, owned by someone (no anon owner)
        user_id = 999
        tenant_id = 10
        visibility = "private"

    anon = AnonymousUser()
    v = viewer_for(anon)
    assert v.is_local_admin is True          # disabled => see-all even for anon
    assert v.user_id is None
    assert can_view_task(anon, PrivateTask()) is True   # not hidden (upstream parity)
    assert can_manage_task(anon, PrivateTask()) is True # mutations also unblocked when disabled


@pytest.mark.django_db
def test_enabled_anonymous_stays_public_only(monkeypatch):
    """Counterpart to B0: when MT is ENABLED (locked), an anonymous viewer must
    remain public-only — the disabled short-circuit must NOT leak into enabled
    mode."""
    from django.contrib.auth.models import AnonymousUser
    from lib.cuckoo.common.tenancy import MTConfig
    from users.tenancy import can_view_task, viewer_for
    import users.tenancy as ut

    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))

    class PrivateTask:
        user_id = 999
        tenant_id = 10
        visibility = "private"

    class PublicTask:
        user_id = 999
        tenant_id = 10
        visibility = "public"

    anon = AnonymousUser()
    v = viewer_for(anon)
    assert v.is_local_admin is False
    assert can_view_task(anon, PrivateTask()) is False  # enabled => restricted
    assert can_view_task(anon, PublicTask()) is True     # public still readable


@pytest.mark.django_db
def test_viewer_for_local_admin_gate(monkeypatch):
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut

    u = User.objects.create_superuser("root", "root@x.com", "x")  # local superuser, no SocialAccount

    # flag ON -> local superuser is break-glass
    monkeypatch.setattr(ut, "multitenancy_config",
                        lambda: MTConfig(True, "locked", "", True))
    assert ut.viewer_for(u).is_local_admin is True

    # flag OFF -> local (non-IdP) superuser is NOT break-glass
    monkeypatch.setattr(ut, "multitenancy_config",
                        lambda: MTConfig(True, "locked", "", False))
    assert ut.viewer_for(u).is_local_admin is False

    # anonymous -> empty viewer
    from django.contrib.auth.models import AnonymousUser
    assert ut.viewer_for(AnonymousUser()).user_id is None


@pytest.mark.django_db
def test_submission_scope(mt_enabled, monkeypatch):
    import pytest as _pytest
    from lib.cuckoo.common.tenancy import MTConfig
    from users.models import Tenant, UserProfile
    import users.tenancy as ut

    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("a", "a@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)

    class Req:
        pass

    # explicit visibility honoured + tenant from user
    r = Req()
    r.user = u
    r.data = {"visibility": "tenant"}
    assert ut.submission_scope(r) == (t.id, "tenant")

    # omitted -> per-mode default (shared -> public)
    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(True, "shared", "", True))
    r2 = Req()
    r2.user = u
    r2.data = {}
    assert ut.submission_scope(r2)[1] == "public"

    # invalid -> ValueError (view turns this into a 400)
    r3 = Req()
    r3.user = u
    r3.data = {"visibility": "bogus"}
    with _pytest.raises(ValueError):
        ut.submission_scope(r3)


@pytest.mark.django_db
def test_submission_scope_tenant_without_tenant_fails_closed(mt_enabled, monkeypatch):
    """A tenant-less submitter must never mint a ('tenant', tenant_id=None) job — it
    would be readable only by its owner (or nobody, for anon), never a tenant pool.
    Explicit 'tenant' -> ValueError (400); a per-mode default resolving to 'tenant'
    downgrades to 'private' (owner still reads via _is_owner; fail closed, not
    world-public in locked mode)."""
    import pytest as _pytest
    from lib.cuckoo.common import tenancy as core_ten
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut

    u = User.objects.create_user("nt", "nt@x.com", "x")  # tenant-less
    u = User.objects.get(pk=u.pk)

    class Req:
        pass

    # explicit 'tenant' from a tenant-less user -> 400 (ValueError)
    r = Req()
    r.user = u
    r.data = {"visibility": "tenant"}
    with _pytest.raises(ValueError):
        ut.submission_scope(r)

    # locked-mode default resolves to 'tenant' but user has no tenant -> downgrade to private
    def locked():
        return MTConfig(True, "locked", "", True)

    monkeypatch.setattr(ut, "multitenancy_config", locked)          # viewer_for (module-level name)
    monkeypatch.setattr(core_ten, "multitenancy_config", locked)    # submission_scope (in-func import)
    r2 = Req()
    r2.user = u
    r2.data = {}
    assert ut.submission_scope(r2) == (None, "private")


@pytest.mark.django_db
def test_reconcile_tenant_tolerates_non_string_groups():
    """Copilot: a tenant's idp_groups JSONField may contain non-string junk; the
    set intersection must not TypeError (and must still match on the valid names)."""
    from web.allauth_adapters import reconcile_tenant
    from users.models import Tenant, UserProfile
    from django.contrib.auth.models import User

    Tenant.objects.create(slug="acme", name="Acme", idp_groups=["acme-soc", {"bad": 1}, None])
    u = User.objects.create_user("ns", "ns@x.com", "x")
    reconcile_tenant(u, {"acme-soc"})  # must not raise despite the non-string entries
    assert UserProfile.objects.get(user=u).tenant.slug == "acme"


@pytest.mark.django_db
def test_sso_login_reconciles_tenant_from_userinfo_claims(monkeypatch, settings):
    """Codex/Copilot: the openid_connect provider nests claims under
    extra['userinfo']; the login guard must normalize (via _claims) before deciding
    the groups claim is absent, else SSO users get no tenant/admin membership."""
    import types
    from web import allauth_adapters as aa
    from users.models import Tenant, UserProfile
    from django.contrib.auth.models import User

    Tenant.objects.create(slug="acme", name="Acme", idp_groups=["acme-soc"])
    settings.OIDC_CFG = {"groups_claim": "groups"}
    # isolate the tenant path (role/email reconciliation is tested elsewhere)
    monkeypatch.setattr(aa, "_apply_idp_roles_and_email", lambda user, extra: False)

    u = User.objects.create_user("sso", "sso@x.com", "x")
    extra = {"id_token": "jwt", "userinfo": {"groups": ["acme-soc"]}}  # nested claim shape
    sl = types.SimpleNamespace(account=types.SimpleNamespace(extra_data=extra))
    aa._reconcile_sso_user_on_login(sender=None, request=None, user=u, sociallogin=sl)

    assert UserProfile.objects.get(user=u).tenant.slug == "acme"


@pytest.mark.django_db
def test_viewer_for_inactive_tenant_fails_closed(mt_enabled):
    """Codex: a deactivated Tenant must drop from the viewer immediately (not wait
    for the next SSO login) — else its members keep tenant-scoped read/submit
    access via the stale profile until reconcile."""
    from users.models import Tenant, UserProfile
    from users.tenancy import viewer_for

    t = Tenant.objects.create(slug="acme-inact", name="AcmeInact")
    u = User.objects.create_user("iat", "iat@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.is_tenant_admin = True
    p.save()

    assert viewer_for(User.objects.get(pk=u.pk)).tenant_id == t.id  # active -> tenant present
    t.active = False
    t.save()
    v = viewer_for(User.objects.get(pk=u.pk))  # fresh load
    assert v.tenant_id is None and v.is_tenant_admin is False  # inactive -> fail closed


@pytest.mark.django_db
def test_submission_scope_ignores_visibility_when_mt_disabled(monkeypatch):
    """With MT disabled the real submission_scope must IGNORE a caller-supplied
    visibility and return the legacy (None, public) scope — persisting private/tenant
    would plant a backfill landmine and contradict the disabled-MT toggle guard."""
    from lib.cuckoo.common import tenancy as core_ten
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut

    def _off():
        return MTConfig(False, "shared", "", True)

    monkeypatch.setattr(ut, "multitenancy_config", _off)          # viewer_for (not reached)
    monkeypatch.setattr(core_ten, "multitenancy_config", _off)    # submission_scope in-func import

    class Req:
        pass

    r = Req()
    r.user = User.objects.create_user("mtoffsub", "mtoffsub@x.com", "x")
    r.data = {"visibility": "private"}  # explicit request must be IGNORED when MT is off
    assert ut.submission_scope(r) == (None, "public")


def _mk_user(username, tenant=None, is_tenant_admin=False, is_superuser=False):
    from users.models import UserProfile

    u = User.objects.create_user(username, f"{username}@x.com", "x")
    if is_superuser:
        u.is_superuser = True
        u.is_staff = True
        u.save()
    p = UserProfile.objects.get(user=u)  # auto-created by signal
    p.tenant = tenant
    p.is_tenant_admin = is_tenant_admin
    p.save()
    return User.objects.get(pk=u.pk)  # re-fetch so the cached userprofile reflects the saved tenant


@pytest.mark.django_db
def test_can_ban_user_tenant_admin_only_within_own_tenant(mt_enabled):
    """The priv-esc the finding names: a tenant admin may ban members of their OWN tenant, but NOT another
    tenant's users (ban deactivates the account + revokes API keys + bans all their tasks)."""
    from users.models import Tenant
    from users.tenancy import can_ban_user

    acme = Tenant.objects.create(slug="acme", name="Acme")
    globex = Tenant.objects.create(slug="globex", name="Globex")
    admin_a = _mk_user("admin_a", tenant=acme, is_tenant_admin=True)
    member_a = _mk_user("member_a", tenant=acme)
    member_b = _mk_user("member_b", tenant=globex)
    assert can_ban_user(admin_a, member_a.id) is True          # own tenant -> allowed
    assert can_ban_user(admin_a, member_b.id) is False         # OTHER tenant -> denied (priv-esc closed)


@pytest.mark.django_db
def test_can_ban_user_plain_member_denied(mt_enabled):
    """A non-admin member (even is_staff, which upstream would allow) cannot ban anyone under MT."""
    from users.models import Tenant
    from users.tenancy import can_ban_user

    acme = Tenant.objects.create(slug="acme", name="Acme")
    member = _mk_user("m1", tenant=acme)          # not a tenant admin
    victim = _mk_user("v1", tenant=acme)
    assert can_ban_user(member, victim.id) is False


@pytest.mark.django_db
def test_can_ban_user_breakglass_superuser_crosses_tenants(mt_enabled):
    """local_admins_manage_all_tenants is on (mt_enabled fixture) -> a superuser is break-glass and bans
    across tenants, preserving the operator escape hatch."""
    from users.models import Tenant
    from users.tenancy import can_ban_user

    Tenant.objects.create(slug="acme", name="Acme")
    globex = Tenant.objects.create(slug="globex", name="Globex")
    su = _mk_user("root", tenant=None, is_superuser=True)
    victim = _mk_user("vv", tenant=globex)
    assert can_ban_user(su, victim.id) is True


@pytest.mark.django_db
def test_can_ban_user_missing_target_fails_closed(mt_enabled):
    """A tenant admin targeting a nonexistent user id must be denied (fail closed on resolution error),
    never defaulted to allow."""
    from users.models import Tenant
    from users.tenancy import can_ban_user

    acme = Tenant.objects.create(slug="acme", name="Acme")
    admin_a = _mk_user("admin_a", tenant=acme, is_tenant_admin=True)
    assert can_ban_user(admin_a, 999999) is False


@pytest.mark.django_db
def test_can_ban_user_mt_disabled_requires_staff(mt_disabled):
    """PRIV-ESC guard: with MT OFF, viewer_for makes EVERY principal is_local_admin (back-compat see-all),
    so can_ban_user must NOT fall through to the break-glass arm -- it keeps upstream's staff/superuser-only
    boundary, else any authenticated user (the views gate solely on this) could ban accounts."""
    from users.tenancy import can_ban_user

    plain = _mk_user("plain")            # not staff, not superuser
    staff = User.objects.create_user("st", "st@x.com", "x")
    staff.is_staff = True
    staff.save()
    su = User.objects.create_user("su", "su@x.com", "x")
    su.is_superuser = True
    su.save()
    victim = _mk_user("vic")
    assert can_ban_user(plain, victim.id) is False   # non-staff must be denied (upstream boundary)
    assert can_ban_user(staff, victim.id) is True
    assert can_ban_user(su, victim.id) is True


@pytest.mark.django_db
def test_can_ban_user_tenant_admin_cannot_ban_privileged_or_self(mt_enabled):
    """A tenant admin may ban a plain member of their tenant, but NOT a superuser/staff operator (privilege
    inversion) nor themselves -- even within their own tenant."""
    from users.models import Tenant, UserProfile
    from users.tenancy import can_ban_user

    acme = Tenant.objects.create(slug="acme", name="Acme")
    admin_a = _mk_user("admin_a", tenant=acme, is_tenant_admin=True)
    member = _mk_user("member", tenant=acme)
    op_super = _mk_user("op_super", tenant=acme, is_superuser=True)  # operator who is an acme member
    staff = User.objects.create_user("stf", "stf@x.com", "x")
    staff.is_staff = True
    staff.save()
    sp = UserProfile.objects.get(user=staff)
    sp.tenant = acme
    sp.save()
    assert can_ban_user(admin_a, member.id) is True             # plain member of own tenant -> allowed
    assert can_ban_user(admin_a, op_super.id) is False          # superuser target -> refused
    assert can_ban_user(admin_a, staff.id) is False             # staff target -> refused
    assert can_ban_user(admin_a, admin_a.id) is False           # self-ban -> refused
