# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from analysis import views as analysis_views
from dashboard import views as dashboard_views
from django.conf import settings
from django.conf.urls import include

# from django.contrib.auth import views as auth_views
from django.urls import path, re_path
from django.views.generic.base import TemplateView

if settings.NOCAPTCHA:
    from captcha_admin import admin
else:
    from django.contrib import admin

if settings.TWOFA:
    from django_otp.admin import OTPAdminSite

    admin.site.__class__ = OTPAdminSite

admin.site.site_header = "CAPE Administration"
admin.site.site_title = "CAPE Administration"

from analysis import urls as analysis
from apiv2 import urls as apiv2
from compare import urls as compare
from dashboard import urls as dashboard
from submission import urls as submission

handler403 = "web.views.handler403"
handler404 = "web.views.handler404"

urlpatterns = [
    path("accounts/", include("allauth.urls")),
    path("robots.txt", TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    re_path(r"^$", dashboard_views.index, name="dashboard"),
    re_path(r"^admin/", admin.site.urls),
    re_path(r"^analysis/", include(analysis)),
    re_path(r"^compare/", include(compare)),
    re_path(r"^submit/", include(submission)),
    re_path(r"^apiv2/", include(apiv2)),
    re_path(r"^file/(?P<category>\w+)/(?P<task_id>\d+)/(?P<dlfile>\w+)/$", analysis_views.file, name="file"),
    re_path(
        r"^vtupload/(?P<category>\w+)/(?P<task_id>\d+)/(?P<filename>.+)/(?P<dlfile>\w+)/$", analysis_views.vtupload, name="vtupload"
    ),
    re_path(r"^filereport/(?P<task_id>\w+)/(?P<category>\w+)/$", analysis_views.filereport, name="filereport"),
    re_path(r"^full_memory/(?P<analysis_number>\w+)/$", analysis_views.full_memory_dump_file, name="full_memory_dump_file"),
    re_path(
        r"^full_memory_strings/(?P<analysis_number>\w+)/$", analysis_views.full_memory_dump_strings, name="full_memory_dump_strings"
    ),
    re_path(r"^dashboard/", include(dashboard)),
    re_path(r"statistics/(?P<days>\d+)/$", analysis_views.statistics_data, name="statistics_data"),
]
