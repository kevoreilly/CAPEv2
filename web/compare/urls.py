# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import re_path

from compare import views

urlpatterns = [
    re_path(r"^(?P<left_id>\d+)/$", views.left, name="compare_left"),
    re_path(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/$", views.both, name="compare_both"),
    re_path(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/diff/$", views.diff, name="compare_diff"),
    re_path(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/diff/data/$", views.diff_data, name="compare_diff_data"),
    re_path(r"^(?P<left_id>\d+)/(?P<right_hash>\w+)/$", views.hash, name="compare_hash"),
]
