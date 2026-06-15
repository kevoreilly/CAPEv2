"""Disable-cascades-revoke for API keys.

When a Django ``User`` flips ``is_active`` from True to False, every
``ApiKey`` that user owns gets its ``revoked_at`` stamped. Combined with
the runtime ``user.is_active`` check in ``ApiKeyAuthentication``, this
gives us two independent barriers — the runtime check is the security
guarantee, the signal-driven revocation is the audit trail.

Re-enabling a previously-disabled user does NOT auto-restore old keys;
they stay revoked. That's the safer default for the
contractor-offboarded-then-re-onboarded case. New keys must be issued
explicitly after re-enable.
"""

from django.conf import settings
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone


@receiver(pre_save, sender=settings.AUTH_USER_MODEL)
def _capture_previous_is_active(sender, instance, **kwargs):
    """Stash the pre-save ``is_active`` value so the post_save handler
    can detect the True→False transition. Skip new users (no pk yet)."""
    if not instance.pk:
        instance._previous_is_active = True  # treat new users as active
        return
    # Optimization: if update_fields is given and excludes is_active, its value
    # can't have changed — skip the extra SELECT. This fires on every login
    # (Django saves with update_fields=["last_login"]).
    update_fields = kwargs.get("update_fields")
    if update_fields is not None and "is_active" not in update_fields:
        instance._previous_is_active = instance.is_active
        return
    try:
        previous = sender.objects.only("is_active").get(pk=instance.pk)
        instance._previous_is_active = previous.is_active
    except sender.DoesNotExist:
        instance._previous_is_active = True


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def _revoke_keys_on_user_disable(sender, instance, created, **kwargs):
    """If is_active just transitioned from True to False, revoke every
    one of this user's API keys. Idempotent — keys already revoked are
    left alone (revoked_at is only set if currently null)."""
    if created:
        return
    was_active = getattr(instance, "_previous_is_active", True)
    if was_active and not instance.is_active:
        # Local import dodges AppRegistryNotReady at import time.
        from .models import ApiKey
        ApiKey.objects.filter(user=instance, revoked_at__isnull=True).update(
            revoked_at=timezone.now()
        )
