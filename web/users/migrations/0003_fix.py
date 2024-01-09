from django.db import migrations, models
from users.models import UserProfile


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_reports"),
    ]

    operations = list()

    userprofile_fields = [f.name for f in UserProfile._meta.get_fields()]
    if "suscription" in userprofile_fields:
        operations.append(
            migrations.RenameField(
                model_name="UserProfile",
                old_name="suscription",
                new_name="subscription",
            )
        )
    if "subscription" not in userprofile_fields:
        operations.append(
            migrations.AddField(
                model_name="UserProfile",
                name="subscription",
                field=models.CharField(default="5/m", max_length=50),
            )
        )
    if "reports" not in userprofile_fields:
        operations.append(
            migrations.AddField(
                model_name="UserProfile",
                name="reports",
                field=models.BooleanField(default=False),
            )
        )
