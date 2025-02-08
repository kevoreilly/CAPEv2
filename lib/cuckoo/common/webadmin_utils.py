# Copyright (C) 2015 KillerInstinct, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.contrib.auth.models import User


# admin utils
def disable_user(user_id: int) -> bool:
    """
    Disables a user by setting their 'is_active' status to False.

    Args:
        user_id (int): The ID of the user to disable.

    Returns:
        bool: True if the user was successfully disabled, False otherwise.
    """
    user = User.objects.get(id=user_id)
    if user:
        user.is_active = False
        user.save()
        return True
    return False
