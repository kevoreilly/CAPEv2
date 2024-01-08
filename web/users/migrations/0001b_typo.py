from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="userprofile",
            old_name="suscription",
            new_name="subscription",
        ),
    ]
