from django import forms
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox


class CaptchedSignUpForm(forms.Form):
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)

    def signup(self, request, user):
        pass
