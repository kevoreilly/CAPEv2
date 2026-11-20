from django.apps import apps
from django.db import models

from users.apps import UsersConfig


def test_users_app_pins_legacy_auto_field_for_django6_compatibility():
    """Django 6.0 changed the default DEFAULT_AUTO_FIELD to BigAutoField; keep AutoField to match 0001_initial."""
    assert UsersConfig.default_auto_field == "django.db.models.AutoField"
    user_profile = apps.get_model("users", "UserProfile")
    assert type(user_profile._meta.pk) is models.AutoField
