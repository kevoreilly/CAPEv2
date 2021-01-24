from django import forms
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3

class CaptchedSignUpForm(forms.Form):
    captcha = ReCaptchaField(widget=ReCaptchaV3)

    def signup(self, request, user):
        pass
