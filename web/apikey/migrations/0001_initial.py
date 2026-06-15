from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ApiKey",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(help_text="A human-readable label (e.g. 'ci-bot', 'personal-laptop').", max_length=100)),
                ("key", models.CharField(db_index=True, max_length=64, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "revoked_at",
                    models.DateTimeField(
                        blank=True,
                        help_text=(
                            "Set when the key is explicitly revoked OR when the owner is disabled. "
                            "A non-null value means the key MUST NOT authenticate."
                        ),
                        null=True,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="api_keys",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="apikey",
            index=models.Index(fields=["user", "revoked_at"], name="apikey_apik_user_id_42b89d_idx"),
        ),
    ]
