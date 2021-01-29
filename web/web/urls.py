# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from django.conf.urls import include, url
from django.urls import path
from django.views.generic.base import TemplateView
from django.contrib.auth import views as auth_views
from dashboard import views as dashboard_views
from analysis import views as analysis_views
from django.conf import settings

if settings.NOCAPTCHA:
    from captcha_admin import admin
else:
    from django.contrib import admin

if settings.TWOFA:
    from django_otp.admin import OTPAdminSite
    admin.site.__class__ = OTPAdminSite

admin.site.site_header = "CAPE Administration"
admin.site.site_title = "CAPE Administration"

from dashboard import urls as dashboard
from analysis import urls as analysis
from compare import urls as compare
from submission import urls as submission
from api import urls as api
from apiv2 import urls as apiv2

handler403 = 'web.views.handler403'

urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path("robots.txt", TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    url(r"^$", dashboard_views.index, name="dashboard"),
    url(r"^admin/", admin.site.urls),
    url(r"^analysis/", include(analysis)),
    url(r"^compare/", include(compare)),
    url(r"^submit/", include(submission)),
    url(r"^api/", include(api)),
    url(r"^apiv2/", include(apiv2)),
    url(r"^file/(?P<category>\w+)/(?P<task_id>\d+)/(?P<dlfile>\w+)/$", analysis_views.file, name="file"),
    url(r"^vtupload/(?P<category>\w+)/(?P<task_id>\d+)/(?P<filename>.+)/(?P<dlfile>\w+)/$", analysis_views.vtupload, name="vtupload"),
    url(r"^filereport/(?P<task_id>\w+)/(?P<category>\w+)/$", analysis_views.filereport, name="filereport"),
    url(r"^full_memory/(?P<analysis_number>\w+)/$", analysis_views.full_memory_dump_file, name="full_memory_dump_file"),
    url(r"^full_memory_strings/(?P<analysis_number>\w+)/$", analysis_views.full_memory_dump_strings, name="full_memory_dump_strings"),
    url(r"^dashboard/", include(dashboard)),
    url(r"statistics/(?P<days>\d+)/$", analysis_views.statistics_data, name='statistics_data')
]
