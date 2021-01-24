from django import forms
from captcha.fields import ReCaptchaField

class CaptchedSignUpForm(forms.Form):
    captcha = ReCaptchaField()

    def signup(self, request, user):
        pass
