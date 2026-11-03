"""Django models for `lib.tenancy`: `Tenant`, `UserTenantMembership`, and `GroupSandboxPolicy`."""

from __future__ import annotations

import sys

from lib.tenancy.resources import reconcile_idp_groups_to_django_groups

sys.modules.setdefault("cape_tenancy.models", sys.modules[__name__])

try:
    from django.conf import settings as _dj_settings

    if _dj_settings.configured:
        from django.contrib.auth.models import Group, User
        from django.db import models

        HAVE_DJANGO = True
    else:
        HAVE_DJANGO = False
        models = None  # type: ignore[assignment]
        Group = None  # type: ignore[assignment]
        User = None  # type: ignore[assignment]
except Exception:  # pragma: no cover
    HAVE_DJANGO = False
    models = None  # type: ignore[assignment]
    Group = None  # type: ignore[assignment]
    User = None  # type: ignore[assignment]


if HAVE_DJANGO:

    class Tenant(models.Model):
        """Isolation boundary for tasks, reports, and group sandbox policies."""

        slug = models.SlugField(max_length=48, unique=True)
        name = models.CharField(max_length=128)
        idp_groups = models.JSONField(default=list, blank=True)
        admin_idp_groups = models.JSONField(default=list, blank=True)
        active = models.BooleanField(default=True)
        created_at = models.DateTimeField(auto_now_add=True)

        class Meta:
            app_label = "cape_tenancy"
            ordering = ("slug",)

        def __str__(self) -> str:
            return self.slug

    class UserTenantMembership(models.Model):
        """Optional direct user-to-tenant assignment (complements GroupSandboxPolicy.tenant)."""

        user = models.OneToOneField(
            User,
            on_delete=models.CASCADE,
            related_name="tenant_membership",
        )
        tenant = models.ForeignKey(
            Tenant,
            null=True,
            blank=True,
            on_delete=models.SET_NULL,
            related_name="user_memberships",
        )
        is_tenant_admin = models.BooleanField(default=False)

        class Meta:
            app_label = "cape_tenancy"

        def __str__(self) -> str:
            return f"{self.user.username} -> {self.tenant.slug if self.tenant else 'none'}"

    class GroupSandboxPolicy(models.Model):
        """Per-Django-Group sandbox resource visibility and submission entitlements."""

        group = models.OneToOneField(
            Group,
            on_delete=models.CASCADE,
            related_name="sandbox_policy",
        )
        parent_group = models.ForeignKey(
            Group,
            null=True,
            blank=True,
            on_delete=models.SET_NULL,
            related_name="child_sandbox_policies",
            help_text=(
                "Optional parent/main Django Group (e.g. 'Company-Main'). Members of this sub-group "
                "automatically inherit the parent group's VMs/routes/tags and can read the parent group's "
                "shared tasks, while members of the parent group cannot see this sub-group's tasks."
            ),
        )
        inherit_parent_resources = models.BooleanField(
            default=True,
            help_text="Automatically inherit allowed_machines, allowed_routes, and allowed_tags from parent_group.",
        )
        inherit_parent_tasks = models.BooleanField(
            default=True,
            help_text=(
                "Allow members of this sub-group to read shared ('tenant') analyses from parent_group "
                "(one-way: parent_group members cannot see this sub-group's analyses)."
            ),
        )
        tenant = models.ForeignKey(
            Tenant,
            null=True,
            blank=True,
            on_delete=models.SET_NULL,
            related_name="group_policies",
            help_text=(
                "Optional shared Tenant override. Leave blank so this Django Group's own ID "
                "(group.id) acts directly as the tenant_id for shared ('tenant') analyses."
            ),
        )
        is_tenant_boundary = models.BooleanField(
            default=True,
            help_text=(
                "When True (default), this Django Group is a tenant boundary (group.id is used as "
                "tenant_id unless 'tenant' is set). Set False for pure capability/role add-on groups "
                "(e.g. 'role-internet-access') that grant VMs/routes without creating a separate report silo."
            ),
        )
        is_tenant_admin_group = models.BooleanField(
            default=False,
            help_text="Grant tenant-admin privileges for this group's tenant to members of this group.",
        )
        priority = models.IntegerField(
            default=0,
            help_text="Higher priority wins when resolving single-valued defaults (e.g. default_route) across groups.",
        )
        allowed_machines = models.JSONField(
            default=list,
            blank=True,
            help_text="Allowed VM names or glob patterns (e.g. ['win10_tier1_*', 'win11_x64'] or ['*']).",
        )
        allowed_tags = models.JSONField(
            default=list,
            blank=True,
            help_text="Allowed machine tags (e.g. ['win10', 'x64', 'office2021'] or ['*']).",
        )
        allowed_routes = models.JSONField(
            default=list,
            blank=True,
            help_text=(
                "Allowed routing options (e.g. ['none', 'inetsim', 'tor', 'internet', "
                "'vpn:vpn_uk', 'socks5:*', 'exit:*'] or ['*'])."
            ),
        )
        default_route = models.CharField(
            max_length=64,
            blank=True,
            default="",
            help_text="Default route pre-selected in the UI and applied when route is omitted on submission.",
        )
        default_visibility = models.CharField(
            max_length=16,
            blank=True,
            default="",
            help_text=(
                "Optional default task visibility for members of this group ('private', 'tenant', or 'public'). "
                "Leave blank to use cuckoo.conf [multitenancy] default_visibility. Users can always choose "
                "'private' on individual submissions so only they and their group's admins can see their task."
            ),
        )
        forced_machine_tags = models.JSONField(
            default=list,
            blank=True,
            help_text=(
                "Machine tags automatically injected when a user submits with machine='' ('First available') "
                "so the scheduler only selects VMs in this group's pool."
            ),
        )
        allow_all_vms = models.BooleanField(
            default=False,
            help_text="Allow members to submit with machine='all' (scoped to their allowed_machines).",
        )
        allow_interactive = models.BooleanField(
            default=True,
            help_text="Allow members to launch interactive Guacamole desktop sessions.",
        )
        max_timeout = models.PositiveIntegerField(
            default=0,
            help_text="Maximum analysis timeout in seconds (0 = use server default / no group cap).",
        )
        idp_groups = models.JSONField(
            default=list,
            blank=True,
            help_text="Optional OIDC/SAML IdP group names that automatically map users into this Django Group.",
        )
        active = models.BooleanField(default=True)

        class Meta:
            app_label = "cape_tenancy"
            verbose_name = "Group Sandbox Policy"
            verbose_name_plural = "Group Sandbox Policies"
            ordering = ("-priority", "id")

        @property
        def effective_tenant_id(self) -> int | None:
            if not self.active or not self.is_tenant_boundary:
                return None
            if self.tenant_id is not None:
                return int(self.tenant_id)
            if self.group_id is not None:
                return int(self.group_id)
            return None

        def __str__(self) -> str:
            return f"SandboxPolicy({self.group.name})"


__all__ = [
    "HAVE_DJANGO",
    "reconcile_idp_groups_to_django_groups",
]
