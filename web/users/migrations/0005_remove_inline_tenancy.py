# Multi-tenancy moved to lib.tenancy (auth.Group-based); retire the inline Tenant model from 0004.
#
# 0004 was applied on deployments that ran the in-core multitenancy, so it is kept (deleting an
# applied migration leaves its columns behind). On those databases userprofile.is_tenant_admin is
# NOT NULL with no database default, which makes every User creation fail once the model stops
# setting it, so that column is dropped. users_tenant and userprofile.tenant_id are only removed
# from Django's state: they are nullable, and they hold the membership data an operator needs to
# map legacy tenants onto lib.tenancy groups.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0004_tenant_userprofile_is_tenant_admin_and_more"),
    ]

    operations = [
        migrations.RemoveField(model_name="userprofile", name="is_tenant_admin"),
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(model_name="userprofile", name="tenant"),
                migrations.DeleteModel(name="Tenant"),
            ],
            database_operations=[],
        ),
    ]
