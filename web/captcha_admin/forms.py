from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3
from django.contrib.admin.forms import AdminAuthenticationForm as _AdminAuthenticationForm


class AdminAuthenticationForm(_AdminAuthenticationForm):
    captcha = ReCaptchaField(widget=ReCaptchaV3)
