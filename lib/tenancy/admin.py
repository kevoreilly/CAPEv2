"""Django Admin registration for `GroupSandboxPolicy`, `Tenant`, and `UserTenantMembership`."""

from __future__ import annotations

import sys

sys.modules.setdefault("cape_tenancy.admin", sys.modules[__name__])

try:
    from django.contrib import admin
    from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
    from django.contrib.auth.models import Group

    from lib.tenancy.models import GroupSandboxPolicy, Tenant, UserTenantMembership

    HAVE_DJANGO_ADMIN = True
except ImportError:  # pragma: no cover
    HAVE_DJANGO_ADMIN = False


_TENANT_PRIV_FIELDS = ("idp_groups", "admin_idp_groups")
_MEMBERSHIP_PRIV_FIELDS = ("tenant", "is_tenant_admin")
_GROUP_POLICY_PRIV_FIELDS = (
    "parent_group",
    "inherit_parent_resources",
    "inherit_parent_tasks",
    "tenant",
    "is_tenant_boundary",
    "is_tenant_admin_group",
    "allowed_machines",
    "allowed_tags",
    "allowed_routes",
    "default_route",
    "default_visibility",
    "forced_machine_tags",
    "allow_all_vms",
    "allow_interactive",
    "max_timeout",
    "idp_groups",
)


if HAVE_DJANGO_ADMIN:

    class GroupSandboxPolicyInline(admin.StackedInline):
        model = GroupSandboxPolicy
        can_delete = True
        extra = 0
        verbose_name = "Sandbox Resource Policy (VMs, Routes, Tags)"
        verbose_name_plural = "Sandbox Resource Policy (VMs, Routes, Tags)"

        def get_readonly_fields(self, request, obj=None):
            ro = tuple(super().get_readonly_fields(request, obj))
            if not getattr(request.user, "is_superuser", False):
                ro = ro + _GROUP_POLICY_PRIV_FIELDS
            return ro

    class SandboxGroupAdmin(BaseGroupAdmin):
        inlines = (*getattr(BaseGroupAdmin, "inlines", ()), GroupSandboxPolicyInline)

    try:
        admin.site.unregister(Group)
    except admin.sites.NotRegistered:
        pass
    admin.site.register(Group, SandboxGroupAdmin)

    @admin.register(GroupSandboxPolicy)
    class GroupSandboxPolicyAdmin(admin.ModelAdmin):
        list_display = (
            "group",
            "parent_group",
            "is_tenant_boundary",
            "tenant",
            "priority",
            "default_route",
            "default_visibility",
            "allow_all_vms",
            "allow_interactive",
            "max_timeout",
            "active",
        )
        list_filter = (
            "active",
            "is_tenant_boundary",
            "inherit_parent_resources",
            "inherit_parent_tasks",
            "allow_all_vms",
            "allow_interactive",
            "tenant",
        )
        search_fields = ("group__name", "tenant__slug", "default_route")

        def get_readonly_fields(self, request, obj=None):
            ro = tuple(super().get_readonly_fields(request, obj))
            if not getattr(request.user, "is_superuser", False):
                ro = ro + _GROUP_POLICY_PRIV_FIELDS
            return ro

    @admin.register(Tenant)
    class TenantAdmin(admin.ModelAdmin):
        list_display = ("slug", "name", "active", "created_at")
        search_fields = ("slug", "name")
        list_filter = ("active",)

        def get_readonly_fields(self, request, obj=None):
            ro = tuple(super().get_readonly_fields(request, obj))
            if not getattr(request.user, "is_superuser", False):
                ro = ro + _TENANT_PRIV_FIELDS
            return ro

    @admin.register(UserTenantMembership)
    class UserTenantMembershipAdmin(admin.ModelAdmin):
        list_display = ("user", "tenant", "is_tenant_admin")
        list_filter = ("is_tenant_admin", "tenant")
        search_fields = ("user__username", "user__email", "tenant__slug")

        def get_readonly_fields(self, request, obj=None):
            ro = tuple(super().get_readonly_fields(request, obj))
            if not getattr(request.user, "is_superuser", False):
                ro = ro + _MEMBERSHIP_PRIV_FIELDS
            return ro
