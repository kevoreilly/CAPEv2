from django.db import connection, migrations


def migrate(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'users_userprofile';")
        elif connection.vendor == "sqlite":
            cursor.execute("SELECT sql FROM sqlite_master WHERE tbl_name = 'users_userprofile' AND type = 'table';")
        columns = [el[0] for el in cursor.fetchall()]
        if "suscription" in columns:
            cursor.execute("ALTER TABLE users_userprofile RENAME COLUMN suscription TO subscription;")


def reverse_migrate(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'users_userprofile';")
        elif connection.vendor == "sqlite":
            cursor.execute("SELECT sql FROM sqlite_master WHERE tbl_name = 'users_userprofile' AND type = 'table';")
        columns = [el[0] for el in cursor.fetchall()]
        if "subscription" in columns:
            cursor.execute("ALTER TABLE users_userprofile RENAME COLUMN subscription TO suscription;")


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_reports"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
