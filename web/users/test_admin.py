"""Tenancy-privilege admin fields are superuser-only (adversarial-review MEDIUM).

reconcile_tenant() trusts Tenant.idp_groups / admin_idp_groups (and UserProfile.tenant /
is_tenant_admin) as the sole authority for a user's tenant + tenant-admin status on SSO login.
A non-superuser staff member holding a delegated change_tenant / change_userprofile grant must not
be able to edit those fields (privilege escalation) -- the admin renders them readonly for
non-superusers, editable only for superusers.
"""
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User

from users.admin import ProfileInline, TenantAdmin, _PROFILE_PRIV_FIELDS, _TENANT_PRIV_FIELDS
from users.models import Tenant


class _Req:
    def __init__(self, is_superuser):
        self.user = type("U", (), {"is_superuser": is_superuser})()


def test_tenant_priv_fields_readonly_for_nonsuperuser_only():
    ta = TenantAdmin(Tenant, AdminSite())
    su_ro = set(ta.get_readonly_fields(_Req(True)))
    staff_ro = set(ta.get_readonly_fields(_Req(False)))
    assert not (set(_TENANT_PRIV_FIELDS) & su_ro), "superuser should be able to edit the tenancy maps"
    assert set(_TENANT_PRIV_FIELDS) <= staff_ro, "non-superuser must NOT edit idp_groups/admin_idp_groups"


def test_profile_priv_fields_readonly_for_nonsuperuser_only():
    pi = ProfileInline(User, AdminSite())
    su_ro = set(pi.get_readonly_fields(_Req(True)))
    staff_ro = set(pi.get_readonly_fields(_Req(False)))
    assert not (set(_PROFILE_PRIV_FIELDS) & su_ro), "superuser should be able to set tenant/is_tenant_admin"
    assert set(_PROFILE_PRIV_FIELDS) <= staff_ro, "non-superuser must NOT edit tenant/is_tenant_admin"
