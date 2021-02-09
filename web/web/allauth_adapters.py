from django import forms
from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter

from allauth.account.signals import user_signed_up, email_confirmed
from django.dispatch import receiver
from django.contrib.auth.models import User

disposable_domain_list = list()
if hasattr(settings, "DISPOSABLE_DOMAIN_LIST"):
    disposable_domain_list = [domain.strip() for domain in open(settings.DISPOSABLE_DOMAIN_LIST, "r").readlines()]

class DisposableEmails(DefaultAccountAdapter):
    # https://fluffycloudsandlines.blog/using-django-allauth-for-google-login-to-any-django-app/
    def clean_email(self, email):
        if email.split('@')[-1] in disposable_domain_list:
            raise forms.ValidationError("Admin banned disposable email services")
        else:
            return email

    # Enable/disable registration
    def is_open_for_signup(self, request):
        return settings.REGISTRATION_ENABLED

if settings.EMAIL_CONFIRMATION is False:
    @receiver(user_signed_up)
    def user_signed_up_(request, user, **kwargs):
        user.is_active = not settings.MANUAL_APPROVE
        user.save()

@receiver(email_confirmed)
def email_confirmed_(request, email_address, **kwargs):
    user = User.objects.get(email=email_address.email)
    user.is_active = not settings.MANUAL_APPROVE
    user.save()
