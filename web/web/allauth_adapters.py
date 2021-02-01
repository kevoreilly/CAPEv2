from django import forms
from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter

from allauth.account.signals import user_signed_up, email_confirmed
from django.dispatch import receiver
from django.contrib.auth.models import User
from allauth.account.models import EmailAddress

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

@receiver(user_signed_up)
def user_signed_up_(request, user, **kwargs):
    user.is_active = False
    user.save()

@receiver(email_confirmed)
def email_confirmed_(request, *args, **kwargs):
    user = request.user
    new_email_address = EmailAddress.objects.get(email=kwargs['email_address'].email)
    user = User.objects.get(email=new_email_address.user)
    user.is_active = False
    user.save()
