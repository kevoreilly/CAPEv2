# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from __future__ import absolute_import
from django.conf.urls import url
from compare import views

urlpatterns = [
    url(r"^(?P<left_id>\d+)/$", views.left, name="compare_left"),
    url(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/$", views.both, name="compare_both"),
    url(r"^(?P<left_id>\d+)/(?P<right_hash>\w+)/$", views.hash, name="compare_hash"),
]
