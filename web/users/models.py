from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class Tenant(models.Model):
    """A customer/tenant — the isolation boundary jobs, rulesets and API keys
    belong to. Membership + tenant-admin status are driven by IdP group claims
    (see web/web/allauth_adapters.py); CAPE owns the row (hybrid model)."""

    slug = models.SlugField(max_length=48, unique=True)
    name = models.CharField(max_length=128)
    idp_groups = models.JSONField(default=list, blank=True)  # groups -> membership
    admin_idp_groups = models.JSONField(default=list, blank=True)  # groups -> tenant-admin
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.slug


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    subscription = models.CharField(max_length=50, default="5/m")
    reports = models.BooleanField(default=False)
    tenant = models.ForeignKey(
        "Tenant", null=True, blank=True, on_delete=models.SET_NULL, related_name="members"
    )
    is_tenant_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    if hasattr(instance, "userprofile"):
        instance.userprofile.save()
