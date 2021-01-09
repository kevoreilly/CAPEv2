from django.contrib import admin

from .forms import AdminAuthenticationForm
from .mixins import AdminSiteRegistryFix


class AdminSite(admin.AdminSite, AdminSiteRegistryFix):
    login_form = AdminAuthenticationForm
    login_template = 'admin/captcha_login.html'

site = AdminSite()
admin.site = site
