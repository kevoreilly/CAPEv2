# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import path

from compare import views

urlpatterns = [
    path("<int:left_id>/", views.left, name="compare_left"),
    path("<int:left_id>/<int:right_id>/", views.both, name="compare_both"),
    path("<int:left_id>/<int:right_id>/diff/", views.diff, name="compare_diff"),
    path("<int:left_id>/<int:right_id>/diff/data/", views.diff_data, name="compare_diff_data"),
    path("<int:left_id>/<str:right_hash>/", views.hash, name="compare_hash"),
]
