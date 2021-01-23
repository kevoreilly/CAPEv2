from django import forms
from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter

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
