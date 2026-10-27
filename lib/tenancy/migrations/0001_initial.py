"""Initial Django migration for `lib.tenancy` (`Tenant`, `UserTenantMembership`, `GroupSandboxPolicy`)."""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Tenant",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slug", models.SlugField(max_length=48, unique=True)),
                ("name", models.CharField(max_length=128)),
                ("idp_groups", models.JSONField(blank=True, default=list)),
                ("admin_idp_groups", models.JSONField(blank=True, default=list)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ("slug",),
            },
        ),
        migrations.CreateModel(
            name="UserTenantMembership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("is_tenant_admin", models.BooleanField(default=False)),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="user_memberships",
                        to="cape_tenancy.tenant",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tenant_membership",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="GroupSandboxPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("inherit_parent_resources", models.BooleanField(default=True)),
                ("inherit_parent_tasks", models.BooleanField(default=True)),
                ("is_tenant_boundary", models.BooleanField(default=True)),
                ("is_tenant_admin_group", models.BooleanField(default=False)),
                ("priority", models.IntegerField(default=0)),
                ("allowed_machines", models.JSONField(blank=True, default=list)),
                ("allowed_tags", models.JSONField(blank=True, default=list)),
                ("allowed_routes", models.JSONField(blank=True, default=list)),
                ("default_route", models.CharField(blank=True, default="", max_length=64)),
                ("default_visibility", models.CharField(blank=True, default="", max_length=16)),
                ("forced_machine_tags", models.JSONField(blank=True, default=list)),
                ("allow_all_vms", models.BooleanField(default=False)),
                ("allow_interactive", models.BooleanField(default=True)),
                ("max_timeout", models.PositiveIntegerField(default=0)),
                ("idp_groups", models.JSONField(blank=True, default=list)),
                ("active", models.BooleanField(default=True)),
                (
                    "group",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sandbox_policy",
                        to="auth.group",
                    ),
                ),
                (
                    "parent_group",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="child_sandbox_policies",
                        to="auth.group",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="group_policies",
                        to="cape_tenancy.tenant",
                    ),
                ),
            ],
            options={
                "verbose_name": "Group Sandbox Policy",
                "verbose_name_plural": "Group Sandbox Policies",
                "ordering": ("-priority", "id"),
            },
        ),
    ]
