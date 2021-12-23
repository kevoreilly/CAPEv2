from django.contrib.admin.forms import AdminAuthenticationForm as _AdminAuthenticationForm

from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3


class AdminAuthenticationForm(_AdminAuthenticationForm):
    captcha = ReCaptchaField(widget=ReCaptchaV3)
